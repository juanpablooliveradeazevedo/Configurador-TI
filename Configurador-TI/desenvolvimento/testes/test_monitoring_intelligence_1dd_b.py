"""Testes da Fase 1D-D-B — Alerts, Trends & Correlation."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import monitoring_foundation as foundation
import monitoring_intelligence as intelligence
import navigation_registry


def metrics(cpu=20.0, memory=30.0, disk_free=50.0):
    return {
        "cpu_usage": {"value": cpu, "unit": "%", "source": "fixture"},
        "memory_usage": {"value": memory, "unit": "%", "source": "fixture"},
        "system_disk_free": {"value": disk_free, "unit": "%", "source": "fixture"},
    }


class MonitoringIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI 1D-D-B ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = intelligence.MonitoringIntelligenceStore(self.temp.name)
        self.hostname = "ALERT-HOST"
        self.run = self.store.start_run(hostname=self.hostname, interval_seconds=60)
        self.base_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        self.step = 0

    def record(self, cpu=20, memory=30, disk_free=50, *, at=None):
        when = at or (self.base_time + timedelta(minutes=self.step))
        self.step += 1
        return self.store.record_cycle(
            self.run["run_id"], metrics(cpu, memory, disk_free), observed_at_utc=when
        )

    def open_attention(self):
        for _ in range(3):
            self.record(cpu=90)
        return self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")[0]

    def open_critical(self):
        for _ in range(3):
            self.record(cpu=98)
        return self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")[0]

    def resolve_cpu(self):
        self.record(cpu=20)
        self.record(cpu=20)
        return self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")[0]

    def test_01_schema_4_to_5_preserves_foundation_data(self):
        other = tempfile.TemporaryDirectory(prefix="Configurador TI schema 4 ç ")
        self.addCleanup(other.cleanup)
        legacy = foundation.MonitoringStore(other.name)
        run = legacy.start_run(hostname="PRESERVED", interval_seconds=60)
        legacy.record_cycle(run["run_id"], metrics())
        migrated = intelligence.MonitoringIntelligenceStore(other.name)
        with sqlite3.connect(migrated.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
        self.assertEqual(migrated.count_observations(hostname="PRESERVED"), 3)

    def test_02_schema_5_reopen_is_idempotent(self):
        reopened = intelligence.MonitoringIntelligenceStore(self.temp.name)
        self.assertEqual(reopened.count_alerts(), 0)
        with sqlite3.connect(reopened.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)

    def test_03_alert_tables_and_active_unique_index_exist(self):
        with sqlite3.connect(self.store.path) as connection:
            names = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','index')"
            )}
        self.assertIn("monitoring_alerts", names)
        self.assertIn("monitoring_alert_events", names)
        self.assertIn("idx_monitor_alert_one_active", names)

    def test_04_derived_anomaly_without_confirmation_does_not_open(self):
        self.record(cpu=90)
        self.record(cpu=90)
        self.assertEqual(self.store.count_alerts(hostname=self.hostname), 0)

    def test_05_single_peak_does_not_open_alert(self):
        self.record(cpu=20)
        self.record(cpu=20)
        self.record(cpu=99)
        self.assertEqual(self.store.count_alerts(hostname=self.hostname), 0)

    def test_06_confirmed_attention_opens_alert(self):
        alert = self.open_attention()
        self.assertEqual((alert["status"], alert["severity"]), ("OPEN", "ATTENTION"))

    def test_07_confirmed_critical_opens_alert(self):
        alert = self.open_critical()
        self.assertEqual((alert["status"], alert["severity"]), ("OPEN", "CRITICAL"))

    def test_08_active_alert_is_deduplicated_by_host_and_metric(self):
        alert = self.open_attention()
        for _ in range(4):
            self.record(cpu=90)
        self.assertEqual(self.store.count_alerts(hostname=self.hostname, metric_key="cpu_usage"), 1)
        self.assertEqual(self.store.list_alerts(hostname=self.hostname)[0]["alert_id"], alert["alert_id"])

    def test_09_same_confirmed_state_updates_without_event_noise(self):
        alert = self.open_attention()
        before = self.store.list_alert_events(alert["alert_id"])
        self.record(cpu=91)
        updated = self.store.get_alert(alert["alert_id"])
        self.assertEqual(len(self.store.list_alert_events(alert["alert_id"])), len(before))
        self.assertEqual(updated["current_value"], 91.0)

    def test_10_attention_to_critical_reuses_id_and_increments_occurrence(self):
        alert = self.open_attention()
        for _ in range(3):
            self.record(cpu=98)
        updated = self.store.get_alert(alert["alert_id"])
        self.assertEqual(updated["severity"], "CRITICAL")
        self.assertEqual(updated["occurrence_count"], 2)

    def test_11_critical_to_attention_reuses_id_without_increment(self):
        alert = self.open_critical()
        self.record(cpu=90)
        self.record(cpu=90)
        updated = self.store.get_alert(alert["alert_id"])
        self.assertEqual(updated["severity"], "ATTENTION")
        self.assertEqual(updated["occurrence_count"], 1)

    def test_12_confirmed_normal_resolves(self):
        alert = self.open_attention()
        resolved = self.resolve_cpu()
        self.assertEqual(resolved["alert_id"], alert["alert_id"])
        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertIsNotNone(resolved["resolved_at_utc"])

    def test_13_indeterminate_does_not_resolve(self):
        alert = self.open_attention()
        self.record(cpu=None)
        self.record(cpu=None)
        self.assertNotEqual(self.store.get_alert(alert["alert_id"])["status"], "RESOLVED")

    def test_14_new_episode_after_resolution_has_new_id(self):
        first = self.open_attention()
        self.resolve_cpu()
        for _ in range(3):
            self.record(cpu=90)
        alerts = self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")
        self.assertEqual(len(alerts), 2)
        self.assertNotEqual(alerts[0]["alert_id"], first["alert_id"])

    def test_15_acknowledgement_persists_local_identity_and_note(self):
        alert = self.open_attention()
        acknowledged = self.store.acknowledge_alert(
            alert["alert_id"], acknowledged_by="DOMINIO\\tecnico", note="Em análise"
        )
        self.assertEqual(acknowledged["status"], "ACKNOWLEDGED")
        self.assertEqual(acknowledged["acknowledged_by"], "DOMINIO\\tecnico")
        self.assertEqual(acknowledged["acknowledgement_note"], "Em análise")

    def test_16_acknowledgement_never_resolves(self):
        alert = self.open_attention()
        self.store.acknowledge_alert(alert["alert_id"], acknowledged_by="fixture")
        self.assertIsNone(self.store.get_alert(alert["alert_id"])["resolved_at_utc"])

    def test_17_resolved_alert_cannot_be_acknowledged(self):
        alert = self.open_attention()
        self.resolve_cpu()
        with self.assertRaises(ValueError):
            self.store.acknowledge_alert(alert["alert_id"])

    def assert_timeline_kind(self, alert_id, expected):
        rows = self.store.list_alert_events(alert_id)
        action = next(row for row in rows if row["event_kind"] == expected)
        event = self.store.get_event(action["timeline_event_id"])
        details = json.loads(event["details_json"])
        self.assertEqual(event["source"], "MONITORING_ALERT")
        self.assertEqual(details["event_kind"], f"ALERT_{expected}")

    def test_18_opening_is_a_structured_timeline_event(self):
        alert = self.open_attention()
        self.assert_timeline_kind(alert["alert_id"], "OPENED")

    def test_19_acknowledgement_is_a_structured_timeline_event(self):
        alert = self.open_attention()
        self.store.acknowledge_alert(alert["alert_id"], acknowledged_by="fixture")
        self.assert_timeline_kind(alert["alert_id"], "ACKNOWLEDGED")

    def test_20_severity_change_is_a_structured_timeline_event(self):
        alert = self.open_attention()
        for _ in range(3):
            self.record(cpu=98)
        self.assert_timeline_kind(alert["alert_id"], "SEVERITY_CHANGED")

    def test_21_resolution_is_a_structured_timeline_event(self):
        alert = self.open_attention()
        self.resolve_cpu()
        self.assert_timeline_kind(alert["alert_id"], "RESOLVED")

    def test_22_regular_samples_do_not_generate_alert_timeline_noise(self):
        for _ in range(10):
            self.record(cpu=20)
        self.assertEqual(self.store.count_events(source="MONITORING_ALERT"), 0)

    def trend_for(self, period, values=(10, 20, 30, 40)):
        for value in values:
            self.record(cpu=value)
        return self.store.trend_summary(
            hostname=self.hostname, metric_key="cpu_usage", period=period,
            now_utc=self.base_time + timedelta(minutes=self.step + 1),
        )

    def test_23_trend_accepts_1h_period(self):
        self.assertEqual(self.trend_for("1h")["period"], "1h")

    def test_24_trend_accepts_6h_period(self):
        self.assertEqual(self.trend_for("6h")["period"], "6h")

    def test_25_trend_accepts_24h_period(self):
        self.assertEqual(self.trend_for("24h")["period"], "24h")

    def test_26_trend_accepts_7d_period(self):
        self.assertEqual(self.trend_for("7d")["period"], "7d")

    def test_27_trend_statistics_are_exact(self):
        trend = self.trend_for("1h", (10, 20, 30, 40))
        self.assertEqual(trend["current"], 40.0)
        self.assertEqual((trend["minimum"], trend["maximum"]), (10.0, 40.0))
        self.assertEqual(trend["average"], 25.0)
        self.assertEqual(trend["sample_count"], 4)

    def test_28_rising_direction_is_deterministic(self):
        self.assertEqual(self.trend_for("1h", (10, 10, 30, 30))["trend_direction"], "RISING")

    def test_29_stable_direction_uses_explicit_tolerance(self):
        self.assertEqual(self.trend_for("1h", (50, 50, 51, 51))["trend_direction"], "STABLE")

    def test_30_falling_direction_is_deterministic(self):
        self.assertEqual(self.trend_for("1h", (80, 80, 40, 40))["trend_direction"], "FALLING")

    def test_31_insufficient_data_is_explicit(self):
        trend = self.trend_for("1h", (10, 20, 30))
        self.assertEqual(trend["trend_direction"], "INSUFFICIENT_DATA")

    def test_32_trend_has_no_forecast_or_ml_contract(self):
        trend = self.trend_for("1h")
        self.assertNotIn("forecast", trend)
        self.assertNotIn("prediction", trend)
        self.assertIn("Sem previsão", trend["criterion"])

    def test_33_context_never_crosses_hostname(self):
        alert = self.open_attention()
        anchor = datetime.fromisoformat(alert["first_seen_utc"].replace("Z", "+00:00"))
        self.store.record_event(
            event_id="other-host", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="outro host", hostname="OTHER", timestamp_utc=anchor,
        )
        ids = {item["referenced_id"] for item in self.store.alert_context(alert["alert_id"])["items"]}
        self.assertNotIn("other-host", ids)

    def test_34_context_respects_plus_minus_ten_minutes(self):
        alert = self.open_attention()
        anchor = datetime.fromisoformat(alert["first_seen_utc"].replace("Z", "+00:00"))
        self.store.record_event(
            event_id="outside", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="fora", hostname=self.hostname,
            timestamp_utc=anchor + timedelta(minutes=11),
        )
        ids = {item["referenced_id"] for item in self.store.alert_context(alert["alert_id"])["items"]}
        self.assertNotIn("outside", ids)

    def test_35_same_operation_is_prioritized_over_temporal_context(self):
        alert = self.open_attention()
        anchor = datetime.fromisoformat(alert["first_seen_utc"].replace("Z", "+00:00"))
        self.store.record_event(
            event_id="same-operation", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="mesma operação", hostname=self.hostname,
            operation_id=self.run["run_id"], timestamp_utc=anchor,
        )
        context = self.store.alert_context(alert["alert_id"])
        item = next(x for x in context["items"] if x["referenced_id"] == "same-operation")
        self.assertEqual(item["relation"], "SAME_OPERATION")
        self.assertLess(context["items"].index(item), len(context["items"]))

    def test_36_same_correlation_is_detected_when_available(self):
        alert = self.open_attention()
        event_id = alert["first_transition_event_id"]
        anchor = datetime.fromisoformat(alert["first_seen_utc"].replace("Z", "+00:00"))
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("UPDATE events SET correlation_id='corr-fixture' WHERE id=?", (event_id,))
        self.store.record_event(
            event_id="same-correlation", source="Fixture", category="SYSTEM", severity="INFO",
            status="OBSERVED", summary="mesma correlação", hostname=self.hostname,
            correlation_id="corr-fixture", timestamp_utc=anchor,
        )
        item = next(x for x in self.store.alert_context(alert["alert_id"])["items"]
                    if x["referenced_id"] == "same-correlation")
        self.assertEqual(item["relation"], "SAME_CORRELATION")

    def test_37_context_can_include_changes_sessions_and_other_alerts(self):
        for _ in range(3):
            self.record(cpu=90, memory=90)
        alerts = self.store.list_alerts(hostname=self.hostname)
        cpu = next(x for x in alerts if x["metric_key"] == "cpu_usage")
        anchor = cpu["first_seen_utc"]
        event = self.store.record_event(
            event_id="session-evidence", source="Fixture", category="SYSTEM",
            severity="INFO", status="OBSERVED", summary="sessão", hostname=self.hostname,
            timestamp_utc=anchor,
        )
        self.store.create_from_timeline_event(event["id"])
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("""
                INSERT INTO change_groups (
                    operation_id, schema_version, detected_at_utc, hostname, source,
                    counts_json, coverage_json, summary, created_at
                ) VALUES ('change-fixture', 1, ?, ?, 'Fixture', '{}', '{}', 'mudança', ?)
            """, (anchor, self.hostname, anchor))
        types = {item["item_type"] for item in self.store.alert_context(cpu["alert_id"])["items"]}
        self.assertTrue({"CHANGE_GROUP", "INVESTIGATION_SESSION", "MONITORING_ALERT"} <= types)

    def test_38_context_explicitly_rejects_causality(self):
        alert = self.open_attention()
        self.assertIn("Não inferida", self.store.alert_context(alert["alert_id"])["causality"])

    def test_39_alert_opens_incident_replay_with_timeline_reference(self):
        alert = self.open_attention()
        session = self.store.create_investigation_from_alert(alert["alert_id"])
        items = self.store.list_items(session["session_id"])
        self.assertEqual(items[0]["item_type"], "TIMELINE_EVENT")

    def test_40_alert_reopens_archived_investigation_without_duplication(self):
        alert = self.open_attention()
        first = self.store.create_investigation_from_alert(alert["alert_id"])
        self.store.archive_session(first["session_id"])
        second = self.store.create_investigation_from_alert(alert["alert_id"])
        self.assertEqual(second["session_id"], first["session_id"])
        self.assertEqual(second["status"], "OPEN")

    def test_41_alert_survives_observation_retention(self):
        self.base_time = datetime.now(timezone.utc) - timedelta(days=31, minutes=10)
        alert = self.open_attention()
        self.store.purge_observations(retention_days=30)
        self.assertIsNotNone(self.store.get_alert(alert["alert_id"]))

    def test_42_expired_observation_reference_is_signalled(self):
        self.base_time = datetime.now(timezone.utc) - timedelta(days=31, minutes=10)
        alert = self.open_attention()
        self.store.purge_observations(retention_days=30)
        self.assertEqual(self.store.get_alert(alert["alert_id"])["original_observation_expired"], 1)

    def test_43_alert_filters_and_pagination_are_bounded(self):
        for _ in range(3):
            self.record(cpu=90, memory=90)
        critical = self.store.list_alerts(hostname=self.hostname, severity="CRITICAL")
        page = self.store.list_alerts(hostname=self.hostname, limit=1, offset=1)
        self.assertEqual(critical, [])
        self.assertEqual(len(page), 1)

    def test_44_trend_query_plan_uses_host_metric_index(self):
        plan = " ".join(self.store.trend_query_plan(
            hostname=self.hostname, metric_key="cpu_usage",
            since_utc=self.base_time, until_utc=datetime.now(timezone.utc),
        )).casefold()
        self.assertIn("idx_monitor_obs_host_metric", plan)

    def test_45_summary_counts_open_ack_critical_and_recent_resolved(self):
        attention = self.open_attention()
        self.store.acknowledge_alert(attention["alert_id"], acknowledged_by="fixture")
        for _ in range(3):
            self.record(memory=98, cpu=90)
        summary = self.store.alert_summary(hostname=self.hostname, now_utc=datetime.now(timezone.utc))
        self.assertEqual(summary["acknowledged_count"], 1)
        self.assertEqual(summary["critical_active_count"], 1)

    def test_46_foundation_thresholds_debounce_retention_are_unchanged(self):
        self.assertEqual(foundation.RETENTION_DAYS, 30)
        self.assertEqual(foundation.ALLOWED_INTERVALS, (30, 60, 120, 300))
        self.assertEqual(foundation.derive_state("cpu_usage", 85), "ATTENTION")
        self.assertEqual(foundation.debounce_state("NORMAL", "ATTENTION", None, 0)[4], 3)


@unittest.skipUnless(importlib.util.find_spec("PyQt6"), "PyQt6 indisponível neste runtime")
class MonitoringIntelligenceQtTests(unittest.TestCase):
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

    def test_47_monitoring_page_exposes_alert_trend_and_context_sections(self):
        panel = self.w.monitoring_panel
        self.assertEqual(panel.alerts_table.columnCount(), 8)
        self.assertEqual(panel.trend_table.columnCount(), 7)
        self.assertEqual(panel.alert_context_table.columnCount(), 4)

    def test_48_last_and_next_cycle_remain_single_line_at_1366x768(self):
        self.w.resize(1366, 768)
        self.w._pagina_monitoramento()
        self.base.app.processEvents()
        panel = self.w.monitoring_panel
        self.assertFalse(panel.last_cycle_label.wordWrap())
        self.assertFalse(panel.next_cycle_label.wordWrap())
        self.assertGreaterEqual(panel.last_cycle_label.minimumWidth(), 270)
        self.assertGreaterEqual(panel.next_cycle_label.minimumWidth(), 270)

    def test_49_monitoring_and_incident_deep_links_remain_available(self):
        definition = navigation_registry.module("monitoring")
        self.assertEqual((definition.domain, definition.view_index), ("observability", 5))
        self.assertTrue(callable(getattr(self.w, "_criar_investigacao_alerta", None)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
