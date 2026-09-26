"""Testes da Fase 1D-D-A — Monitoring & Correlation: Fundação Local."""
from datetime import datetime, timedelta, timezone
import importlib.util
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import incident_replay
import monitoring_foundation as monitoring
import navigation_registry


def metrics(cpu=20.0, memory=30.0, disk_free=50.0):
    return {
        "cpu_usage": {"value": cpu, "unit": "%", "source": "fixture"},
        "memory_usage": {"value": memory, "unit": "%", "source": "fixture"},
        "system_disk_free": {"value": disk_free, "unit": "%", "source": "fixture"},
    }


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI monitoring ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = monitoring.MonitoringStore(self.temp.name)

    def _run(self, hostname="MONITOR-HOST", interval=60):
        return self.store.start_run(hostname=hostname, interval_seconds=interval)

    def test_01_schema_migration_is_idempotent_and_preserves_layers(self):
        other = tempfile.TemporaryDirectory(prefix="Configurador TI migration ç ")
        self.addCleanup(other.cleanup)
        legacy = incident_replay.IncidentReplayStore(other.name)
        event = legacy.record_event(
            event_id="preserved-event", source="Fixture", category="SYSTEM",
            severity="INFO", status="OBSERVED", summary="Preservar",
            hostname="MIGRATION-HOST",
        )
        session = legacy.create_from_timeline_event(event["id"])
        migrated = monitoring.MonitoringStore(other.name)
        reopened = monitoring.MonitoringStore(other.name)
        with sqlite3.connect(migrated.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
            names = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        self.assertTrue({"monitoring_runs", "monitoring_observations", "monitoring_metric_state"} <= names)
        self.assertEqual(reopened.get_event(event["id"])["summary"], "Preservar")
        self.assertEqual(reopened.get_session(session["session_id"])["status"], "OPEN")

    def test_02_monitoring_run_creation(self):
        run = self._run(interval=60)
        self.assertEqual(run["status"], "RUNNING")
        self.assertEqual(run["interval_seconds"], 60)
        self.assertEqual(self.store.get_run(run["run_id"])["hostname"], "MONITOR-HOST")

    def test_03_pause_resume_stop_lifecycle(self):
        service = monitoring.MonitoringService(self.store)
        service.start(60)
        self.assertEqual(service.pause()["status"], "PAUSED")
        self.assertEqual(service.resume()["status"], "RUNNING")
        stopped = service.stop("fixture")
        self.assertEqual(stopped["status"], "STOPPED")
        self.assertIsNotNone(stopped["stopped_at_utc"])

    def test_04_observations_persist_after_reopen(self):
        run = self._run()
        self.store.record_cycle(run["run_id"], metrics())
        reopened = monitoring.MonitoringStore(self.temp.name)
        self.assertEqual(reopened.count_observations(hostname="MONITOR-HOST"), 3)

    def test_08_failed_metric_is_indeterminate_without_hiding_others(self):
        run = self._run()
        cycle = self.store.record_cycle(run["run_id"], metrics(cpu=None, memory=25, disk_free=70))
        by_key = {item["metric_key"]: item for item in cycle["observations"]}
        self.assertEqual(by_key["cpu_usage"]["derived_state"], "INDETERMINATE")
        self.assertEqual(by_key["memory_usage"]["derived_state"], "NORMAL")

    def test_09_thresholds_are_declarative(self):
        self.assertEqual(monitoring.derive_state("cpu_usage", 84.9), "NORMAL")
        self.assertEqual(monitoring.derive_state("cpu_usage", 85), "ATTENTION")
        self.assertEqual(monitoring.derive_state("memory_usage", 95), "CRITICAL")
        self.assertEqual(monitoring.derive_state("system_disk_free", 15), "ATTENTION")
        self.assertEqual(monitoring.derive_state("system_disk_free", 5), "CRITICAL")
        self.assertIn("threshold_text", monitoring.METRIC_RULES["cpu_usage"])

    def test_10_one_peak_does_not_confirm_attention(self):
        run = self._run()
        self.store.record_cycle(run["run_id"], metrics(cpu=20))
        self.store.record_cycle(run["run_id"], metrics(cpu=20))
        cycle = self.store.record_cycle(run["run_id"], metrics(cpu=90))
        cpu = next(item for item in cycle["observations"] if item["metric_key"] == "cpu_usage")
        self.assertEqual(cpu["derived_state"], "ATTENTION")
        self.assertEqual(cpu["confirmed_state"], "NORMAL")

    def test_11_three_samples_confirm_worsening(self):
        run = self._run()
        for _ in range(3):
            cycle = self.store.record_cycle(run["run_id"], metrics(cpu=90))
        cpu = next(item for item in cycle["observations"] if item["metric_key"] == "cpu_usage")
        self.assertEqual(cpu["confirmed_state"], "ATTENTION")
        self.assertEqual(cpu["debounce_count"], 3)

    def test_12_recovery_requires_two_stable_samples(self):
        run = self._run()
        for _ in range(3):
            self.store.record_cycle(run["run_id"], metrics(cpu=98))
        first = self.store.record_cycle(run["run_id"], metrics(cpu=20))
        first_cpu = next(x for x in first["observations"] if x["metric_key"] == "cpu_usage")
        self.assertEqual(first_cpu["confirmed_state"], "CRITICAL")
        second = self.store.record_cycle(run["run_id"], metrics(cpu=20))
        second_cpu = next(x for x in second["observations"] if x["metric_key"] == "cpu_usage")
        self.assertEqual(second_cpu["confirmed_state"], "NORMAL")

    def test_13_anti_flapping_resets_candidate(self):
        current, candidate, count = "NORMAL", None, 0
        for derived in ("ATTENTION", "NORMAL", "ATTENTION", "NORMAL"):
            current, candidate, count, _changed, _required = monitoring.debounce_state(
                current, derived, candidate, count
            )
        self.assertEqual(current, "NORMAL")
        self.assertIsNone(candidate)
        self.assertEqual(count, 0)

    def test_15_interval_change_is_restricted_and_persisted(self):
        service = monitoring.MonitoringService(self.store)
        run = service.start(60)
        service.set_interval(120)
        self.assertEqual(self.store.get_run(run["run_id"])["interval_seconds"], 120)
        with self.assertRaises(ValueError):
            service.set_interval(5)

    def test_16_timeline_does_not_receive_each_sample(self):
        run = self._run()
        before = self.store.count_events(source="MONITORING")
        for _ in range(5):
            self.store.record_cycle(run["run_id"], metrics(cpu=None, memory=None, disk_free=None))
        self.assertEqual(self.store.count_events(source="MONITORING"), before)

    def test_17_timeline_receives_confirmed_transition(self):
        run = self._run()
        for _ in range(3):
            self.store.record_cycle(run["run_id"], metrics(cpu=90))
        transitions = self.store.list_transitions(hostname="MONITOR-HOST")
        cpu = next(item for item in transitions if item["metric_key"] == "cpu_usage")
        event = self.store.get_event(cpu["transition_event_id"])
        self.assertIn("INDETERMINATE", event["summary"])
        self.assertIn("ATTENTION", event["summary"])

    def test_18_temporal_context_explicitly_rejects_causality(self):
        context = self.store.temporal_context(
            hostname="MONITOR-HOST", occurred_at_utc=datetime.now(timezone.utc)
        )
        self.assertEqual(context["relation"], "TEMPORAL_CONTEXT")
        self.assertIn("Não inferida", context["causality"])

    def test_19_temporal_context_never_crosses_hostname(self):
        now = datetime.now(timezone.utc)
        self.store.record_event(
            event_id="same-host", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="mesmo host", hostname="MONITOR-HOST", timestamp_utc=now,
        )
        self.store.record_event(
            event_id="other-host", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="outro host", hostname="OTHER-HOST", timestamp_utc=now,
        )
        context = self.store.temporal_context(hostname="MONITOR-HOST", occurred_at_utc=now)
        ids = {item["id"] for item in context["timeline_events"]}
        self.assertIn("same-host", ids)
        self.assertNotIn("other-host", ids)

    def test_20_temporal_window_is_respected(self):
        now = datetime.now(timezone.utc)
        self.store.record_event(
            event_id="outside-window", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="fora", hostname="MONITOR-HOST",
            timestamp_utc=now - timedelta(minutes=11),
        )
        context = self.store.temporal_context(hostname="MONITOR-HOST", occurred_at_utc=now)
        self.assertNotIn("outside-window", {item["id"] for item in context["timeline_events"]})

    def test_21_open_investigation_uses_timeline_transition(self):
        run = self._run()
        for _ in range(3):
            self.store.record_cycle(run["run_id"], metrics(cpu=90))
        transition = next(x for x in self.store.list_transitions(hostname="MONITOR-HOST")
                          if x["metric_key"] == "cpu_usage")
        session = self.store.create_investigation_from_observation(transition["observation_id"])
        items = self.store.list_items(session["session_id"])
        self.assertEqual(items[0]["item_type"], "TIMELINE_EVENT")
        self.assertEqual(items[0]["referenced_id"], transition["transition_event_id"])

    def test_22_retention_removes_only_old_monitoring_observations(self):
        run = self._run()
        old = datetime.now(timezone.utc) - timedelta(days=31)
        self.store.record_cycle(run["run_id"], metrics(), observed_at_utc=old)
        self.store.record_cycle(run["run_id"], metrics())
        self.assertEqual(self.store.purge_observations(retention_days=30), 3)
        self.assertEqual(self.store.count_observations(hostname="MONITOR-HOST"), 3)

    def test_23_retention_preserves_timeline_changes_and_sessions(self):
        event = self.store.record_event(
            event_id="retain-event", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="preservar", hostname="MONITOR-HOST",
        )
        session = self.store.create_from_timeline_event(event["id"])
        self.store.purge_observations(retention_days=1)
        self.assertIsNotNone(self.store.get_event(event["id"]))
        self.assertIsNotNone(self.store.get_session(session["session_id"]))

    def test_24_observation_pagination(self):
        run = self._run()
        for _ in range(3):
            self.store.record_cycle(run["run_id"], metrics())
        page1 = self.store.list_observations(hostname="MONITOR-HOST", limit=4, offset=0)
        page2 = self.store.list_observations(hostname="MONITOR-HOST", limit=4, offset=4)
        self.assertEqual(len(page1), 4)
        self.assertEqual(len(page2), 4)
        self.assertFalse({x["observation_id"] for x in page1} & {x["observation_id"] for x in page2})

    def test_29_navigation_registry_preserves_monitoring_deep_link(self):
        module = navigation_registry.module("monitoring")
        self.assertEqual(module.domain, "observability")
        self.assertEqual(module.route, "_pagina_monitoramento")
        self.assertEqual(module.view_index, 5)


class CollectorAndServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI service ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = monitoring.MonitoringStore(self.temp.name)

    def test_05_cpu_collection_contract(self):
        with patch.object(monitoring, "_cpu_percent", return_value=(12.5, "fixture cpu", {})), \
             patch.object(monitoring, "_memory_percent", return_value=(20, "fixture ram", {})), \
             patch.object(monitoring, "_disk_free_percent", return_value=(50, "fixture disk", {})):
            snapshot = monitoring.collect_local_metrics()
        self.assertEqual(snapshot["metrics"]["cpu_usage"]["value"], 12.5)

    def test_06_memory_collection_includes_available_context(self):
        detail = {"available_bytes": 100, "total_bytes": 200}
        with patch.object(monitoring, "_cpu_percent", return_value=(10, "cpu", {})), \
             patch.object(monitoring, "_memory_percent", return_value=(50, "ram", detail)), \
             patch.object(monitoring, "_disk_free_percent", return_value=(40, "disk", {})):
            snapshot = monitoring.collect_local_metrics()
        self.assertEqual(snapshot["metrics"]["memory_usage"]["details"], detail)

    def test_07_disk_collection_is_free_percentage(self):
        with patch.object(monitoring, "_cpu_percent", return_value=(10, "cpu", {})), \
             patch.object(monitoring, "_memory_percent", return_value=(20, "ram", {})), \
             patch.object(monitoring, "_disk_free_percent", return_value=(4.0, "disk", {"free_bytes": 4})):
            snapshot = monitoring.collect_local_metrics()
        disk = snapshot["metrics"]["system_disk_free"]
        self.assertEqual(disk["value"], 4.0)
        self.assertEqual(monitoring.derive_state("system_disk_free", disk["value"]), "CRITICAL")

    def test_14_no_overlap(self):
        entered, release = threading.Event(), threading.Event()

        def collector(cancel_callback=None):
            entered.set()
            release.wait(2)
            return {"metrics": metrics(), "observed_at_utc": datetime.now(timezone.utc)}

        service = monitoring.MonitoringService(self.store, collector=collector)
        service.start(60)
        result = []
        thread = threading.Thread(target=lambda: result.append(service.collect_once()))
        thread.start()
        self.assertTrue(entered.wait(1))
        skipped = service.collect_once()
        self.assertEqual(skipped["skipped"], "overlap")
        release.set()
        thread.join(3)
        self.assertTrue(result[0]["ok"])

    def test_25_best_effort_action_contains_failure(self):
        self.assertIsNone(monitoring.monitoring_action_safe(
            object(), None, lambda _obj: (_ for _ in ()).throw(RuntimeError("fixture"))
        ))

    def test_26_close_stops_service_without_persistent_worker(self):
        service = monitoring.MonitoringService(
            self.store,
            collector=lambda cancel_callback=None: {
                "metrics": metrics(), "observed_at_utc": datetime.now(timezone.utc),
            },
        )
        run = service.start(60)
        service.close()
        self.assertEqual(service.status, "STOPPED")
        self.assertEqual(self.store.get_run(run["run_id"])["status"], "STOPPED")
        self.assertFalse(service._collect_lock.locked())

    def test_metric_failure_isolated_by_collector(self):
        with patch.object(monitoring, "_cpu_percent", side_effect=OSError("fixture")), \
             patch.object(monitoring, "_memory_percent", return_value=(20, "ram", {})), \
             patch.object(monitoring, "_disk_free_percent", return_value=(50, "disk", {})):
            snapshot = monitoring.collect_local_metrics()
        self.assertIsNone(snapshot["metrics"]["cpu_usage"]["value"])
        self.assertEqual(snapshot["metrics"]["memory_usage"]["value"], 20)


@unittest.skipUnless(importlib.util.find_spec("PyQt6"), "PyQt6 indisponível neste runtime")
class QtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests()
        self.case.setUp()
        self.w = self.case.w

    def tearDown(self):
        self.case.tearDown()

    def test_27_monitoring_page_offscreen(self):
        self.w._pagina_monitoramento()
        self.base.app.processEvents()
        self.assertEqual(self.w.pages.currentIndex(), 5)
        self.assertEqual(tuple(self.w.monitoring_panel.interval_combo.itemData(i)
                               for i in range(self.w.monitoring_panel.interval_combo.count())),
                         monitoring.ALLOWED_INTERVALS)
        self.assertIn("30 dias", self.w.monitoring_panel.retention_label.text())

    def test_28_observability_hub_opens_monitoring(self):
        self.w._open_domain("observability")
        self.w._open_module("monitoring")
        self.base.app.processEvents()
        self.assertEqual(self.w.pages.currentIndex(), 5)
        self.assertTrue(next(b for b in self.w.nav_buttons
                             if b.property("domain_id") == "observability").isChecked())


if __name__ == "__main__":
    unittest.main(verbosity=2)
