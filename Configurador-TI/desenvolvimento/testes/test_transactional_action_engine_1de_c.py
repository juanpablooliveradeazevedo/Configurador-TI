"""Cobertura da 1D-E-C — Transactional Action Engine Foundation."""
from dataclasses import replace
import ast
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import assist as assist
import app_status
import release_metadata
from endpoint_posture import EndpointPostureStore
from monitoring_foundation import ALLOWED_INTERVALS, MonitoringService
from desenvolvimento.testes.test_assist_1de_a import metrics


class TransactionalActionEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI 1DEC ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = assist.AssistStore(self.temp.name)
        self.hostname = socket.gethostname() or "Não disponível"
        run = self.store.start_run(hostname=self.hostname, interval_seconds=60)
        for minute in range(3):
            self.store.record_cycle(
                run["run_id"], metrics(cpu=95),
                observed_at_utc=f"2026-09-21T12:0{minute}:00Z",
            )
        alert = self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")[0]
        context = self.store.create_context("ALERT", alert["alert_id"])
        self.session = self.store.start_session(
            context["context_id"], "MONITORING_ALERT_REVIEW"
        )
        self.step = next(
            item for item in self.session["steps"]
            if item["definition"].get("action_ref") == "SET_MONITORING_INTERVAL"
        )
        self.service = MonitoringService(self.store)

    def prepare(self, value=120):
        return self.store.prepare_action(
            self.session["session_id"], self.step["step_id"],
            monitoring_service=self.service,
            parameters={"interval_seconds": value}, requested_by="Técnico fixture",
        )

    def execute(self, value=120):
        run = self.prepare(value)
        self.store.confirm_action(run["action_run_id"])
        return self.store.execute_action(
            run["action_run_id"], monitoring_service=self.service
        )

    def timeline_kinds(self):
        result = []
        for event in self.store.query_events(source="Assistente Técnico", limit=200):
            details = json.loads(event.get("details_json") or "{}")
            if details.get("event_kind"):
                result.append(details["event_kind"])
        return result

    def test_01_schema_eight_migrates_to_nine(self):
        other = tempfile.TemporaryDirectory(prefix="Configurador TI schema8 ")
        self.addCleanup(other.cleanup)
        old = EndpointPostureStore(other.name)
        with sqlite3.connect(old.path) as connection:
            connection.execute("PRAGMA user_version=8")
        migrated = assist.AssistStore(other.name)
        with sqlite3.connect(migrated.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 9)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(action_runs)")}
        self.assertTrue({"before_json", "actual_after_json", "resource_key"} <= columns)

    def test_02_schema_nine_reopen_is_idempotent(self):
        assist.AssistStore(self.temp.name)
        reopened = assist.AssistStore(self.temp.name)
        self.assertEqual(reopened.get_monitoring_configuration()["interval_seconds"], 60)

    def test_03_legacy_read_only_definition_stays_valid(self):
        self.assertTrue(assist.validate_action_registry((assist.ACTION_REGISTRY[0],)))

    def test_04_local_reversible_change_is_allowed(self):
        action = assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"]
        self.assertTrue(assist.validate_action_registry((action,)))

    def test_05_privileged_change_is_rejected(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], side_effect_class="PRIVILEGED_CHANGE")
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_06_destructive_change_is_rejected(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], side_effect_class="DESTRUCTIVE")
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_07_mutation_requires_rollback(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], rollback_ref=None)
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_08_mutation_requires_snapshotter(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], snapshotter_ref=None)
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_09_mutation_requires_validator(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], validator_ref="missing")
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_10_allowlisted_parameter_is_sanitized(self):
        run = self.prepare(120)
        self.assertEqual(run["parameters"], {"interval_seconds": 120})

    def test_11_invalid_parameter_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.plan_action(
                self.session["session_id"], self.step["step_id"],
                parameters={"interval_seconds": "120"},
            )

    def test_12_snapshot_before_is_persisted(self):
        run = self.prepare(120)
        self.assertEqual(run["before"]["old_interval_seconds"], 60)
        self.assertEqual(run["before_evidence_ref"]["type"], "ACTION_SNAPSHOT")

    def test_13_dry_run_does_not_change_state(self):
        run = self.prepare(120)
        self.assertEqual(run["status"], "READY")
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)
        self.assertEqual(self.service.interval_seconds, 60)

    def test_14_confirmation_is_mandatory(self):
        run = self.prepare(120)
        with self.assertRaises(ValueError):
            self.store.execute_action(run["action_run_id"], monitoring_service=self.service)

    def test_15_executor_never_runs_without_confirmation(self):
        run = self.prepare(120)
        with self.assertRaises(ValueError):
            self.store.execute_action(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)

    def test_16_set_interval_sixty_to_one_twenty(self):
        completed = self.execute(120)
        self.assertEqual(completed["status"], "SUCCEEDED")
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 120)

    def test_17_validator_confirms_runtime_and_persistence(self):
        completed = self.execute(120)
        self.assertEqual(completed["validator_outcome"]["result"], "SUCCESS")
        self.assertEqual(completed["actual_after"]["runtime_interval_seconds"], 120)

    def test_18_proof_of_work_v2_has_before_after(self):
        proof = self.execute(120)["proof_of_work"]
        self.assertEqual(proof["before"]["old_interval_seconds"], 60)
        self.assertEqual(proof["planned_change"]["interval_seconds"], 120)
        self.assertEqual(proof["after"]["interval_seconds"], 120)

    def test_19_rollback_restores_one_twenty_to_sixty(self):
        completed = self.execute(120)
        rolled = self.store.rollback_action(
            completed["action_run_id"], monitoring_service=self.service
        )
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)
        self.assertEqual(rolled["status"], "ROLLED_BACK")

    def test_20_rollback_validator_is_persisted(self):
        completed = self.execute(120)
        rolled = self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        self.assertTrue(rolled["rollback_outcome"]["validation"]["ok"])

    def test_21_executor_failure_before_change(self):
        run = self.prepare(120); self.store.confirm_action(run["action_run_id"])
        original = assist._ACTION_EXECUTOR_ALLOWLIST["set_monitoring_interval"]
        def fail_before(*_args, **_kwargs): raise RuntimeError("fixture")
        assist._ACTION_EXECUTOR_ALLOWLIST["set_monitoring_interval"] = fail_before
        self.addCleanup(assist._ACTION_EXECUTOR_ALLOWLIST.__setitem__, "set_monitoring_interval", original)
        failed = self.store.execute_action(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(failed["status"], "FAILED")
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)

    def test_22_executor_failure_after_partial_change(self):
        run = self.prepare(120); self.store.confirm_action(run["action_run_id"])
        original = assist._ACTION_EXECUTOR_ALLOWLIST["set_monitoring_interval"]
        def fail_after(store, runtime, action_run, **_kwargs):
            store.set_monitoring_configuration(120, expected_interval=60)
            runtime["monitoring_service"].set_interval(120)
            raise RuntimeError("fixture partial")
        assist._ACTION_EXECUTOR_ALLOWLIST["set_monitoring_interval"] = fail_after
        self.addCleanup(assist._ACTION_EXECUTOR_ALLOWLIST.__setitem__, "set_monitoring_interval", original)
        completed = self.store.execute_action(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(completed["status"], "ROLLED_BACK")

    def test_23_partial_failure_triggers_rollback(self):
        self.test_22_executor_failure_after_partial_change()
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)

    def test_24_rollback_failure_is_explicit(self):
        run = self.prepare(120); self.store.confirm_action(run["action_run_id"])
        original_executor = assist._ACTION_EXECUTOR_ALLOWLIST["set_monitoring_interval"]
        original_rollback = assist._ACTION_ROLLBACK_ALLOWLIST["rollback_monitoring_interval"]
        def fail_after(store, runtime, action_run, **_kwargs):
            store.set_monitoring_configuration(120, expected_interval=60)
            runtime["monitoring_service"].set_interval(120)
            raise RuntimeError("partial")
        def fail_rollback(*_args, **_kwargs): raise RuntimeError("rollback fixture")
        assist._ACTION_EXECUTOR_ALLOWLIST["set_monitoring_interval"] = fail_after
        assist._ACTION_ROLLBACK_ALLOWLIST["rollback_monitoring_interval"] = fail_rollback
        self.addCleanup(assist._ACTION_EXECUTOR_ALLOWLIST.__setitem__, "set_monitoring_interval", original_executor)
        self.addCleanup(assist._ACTION_ROLLBACK_ALLOWLIST.__setitem__, "rollback_monitoring_interval", original_rollback)
        failed = self.store.execute_action(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(failed["status"], "ROLLBACK_FAILED")

    def test_25_status_rolled_back_is_terminal(self):
        completed = self.execute(120)
        rolled = self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        self.assertEqual((rolled["status"], rolled["result"]), ("ROLLED_BACK", "ROLLED_BACK"))

    def _abandon(self):
        run = self.prepare(120)
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("UPDATE action_runs SET status='RUNNING' WHERE action_run_id=?", (run["action_run_id"],))
        return run

    def test_26_abandoned_run_becomes_recovery_required(self):
        run = self._abandon()
        reopened = assist.AssistStore(self.temp.name)
        self.assertEqual(reopened.get_action_run(run["action_run_id"])["status"], "RECOVERY_REQUIRED")

    def test_27_restart_does_not_reexecute_mutation(self):
        self._abandon(); assist.AssistStore(self.temp.name)
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)

    def test_28_revalidate_recovery_observes_before(self):
        run = self._abandon(); reopened = assist.AssistStore(self.temp.name)
        result = reopened.revalidate_recovery(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(result["status"], "ROLLED_BACK")

    def test_29_timeline_action_started(self):
        self.execute(120); self.assertIn("ACTION_STARTED", self.timeline_kinds())

    def test_30_timeline_action_succeeded(self):
        self.execute(120); self.assertIn("ACTION_SUCCEEDED", self.timeline_kinds())

    def test_31_timeline_action_failed(self):
        run = self.prepare(120); self.store.confirm_action(run["action_run_id"])
        self.store.set_monitoring_configuration(300, expected_interval=60)
        self.store.execute_action(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(self.store.get_action_run(run["action_run_id"])["status"], "FAILED")
        self.assertIn("ACTION_FAILED", self.timeline_kinds())

    def test_32_timeline_rollback_started_and_completed(self):
        completed = self.execute(120)
        self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        kinds = self.timeline_kinds()
        self.assertIn("ACTION_ROLLBACK_STARTED", kinds)
        self.assertIn("ACTION_ROLLED_BACK", kinds)

    def test_33_action_events_include_rollback(self):
        completed = self.execute(120)
        rolled = self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        types = [event["event_type"] for event in rolled["events"]]
        self.assertIn("ROLLBACK_STARTED", types); self.assertIn("ROLLED_BACK", types)

    def test_34_dry_run_creates_no_timeline_action_event(self):
        self.prepare(120)
        self.assertFalse(any(kind.startswith("ACTION_") for kind in self.timeline_kinds()))

    def test_35_equivalent_transactions_do_not_overlap(self):
        self.prepare(120)
        with self.assertRaises(ValueError): self.prepare(300)

    def test_36_configuration_compare_and_swap_is_atomic(self):
        with self.assertRaises(RuntimeError):
            self.store.set_monitoring_configuration(120, expected_interval=300)
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)

    def test_37_active_monitoring_keeps_same_service_and_run(self):
        self.service.start(60); service_id, run_id = id(self.service), self.service.run_id
        self.execute(120)
        self.assertEqual(id(self.service), service_id)
        self.assertEqual(self.service.run_id, run_id)
        self.assertEqual(self.store.get_run(run_id)["interval_seconds"], 120)

    def test_38_all_safe_intervals_are_accepted(self):
        for value in ALLOWED_INTERVALS:
            action = assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"]
            self.assertEqual(
                assist.AssistStore._action_parameters(action, {"interval_seconds": value})["interval_seconds"], value
            )

    def test_39_values_outside_allowlist_are_rejected(self):
        action = assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"]
        for value in (0, 45, 301, "60", "cmd.exe"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assist.AssistStore._action_parameters(action, {"interval_seconds": value})

    def test_40_release_metadata_is_central(self):
        self.assertEqual(app_status.VERSION, release_metadata.VERSION)
        self.assertEqual(release_metadata.PHASE_ID, "2B")

    def test_41_status_label_identifies_source_and_exe(self):
        self.assertEqual(release_metadata.status_label("Fonte"), "Configurador TI 2B | Fonte")
        self.assertEqual(release_metadata.status_label("EXE"), "Configurador TI 2B | EXE")

    def test_42_build_date_is_current(self):
        self.assertEqual(app_status.BUILD_DATE, "2026-09-25")

    def test_43_no_forbidden_dynamic_execution_calls(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("assist.py", "monitoring_foundation.py", "release_metadata.py"):
            tree = ast.parse((root / name).read_text(encoding="utf-8"))
            calls = {
                node.func.id for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertFalse({"eval", "exec"} & calls)

    def test_44_mutation_requires_no_elevation(self):
        action = assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"]
        self.assertFalse(action.requires_elevation)
        self.assertNotIn("UAC", action.expected_effect.upper())

    def test_45_only_one_mutable_action_is_enabled(self):
        mutable = [a.action_id for a in assist.ACTION_REGISTRY if a.side_effect_class != "READ_ONLY"]
        self.assertEqual(mutable, [
            "SET_MONITORING_INTERVAL", "SET_MONITORING_RETENTION_POLICY",
        ])


@unittest.skipUnless(__import__("importlib").util.find_spec("PyQt6"), "PyQt6 indisponível")
class TransactionalActionEngineQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from desenvolvimento.testes import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests(); self.case.setUp(); self.w = self.case.w

    def tearDown(self): self.case.tearDown()

    def test_46_qt_offscreen_action_panel(self):
        self.w._pagina_assist(); self.base.app.processEvents()
        self.assertEqual(self.w.assist_panel.action_parameter_combo.count(), 4)
        self.assertFalse(self.w.assist_panel.recovery_banner.isVisible())

    def test_47_layout_1366x768_and_footer(self):
        self.w.resize(1366, 768); self.w.show(); self.base.app.processEvents()
        self.assertIn("2B", self.w.version_label.text())
        self.assertIn("Fonte", self.w.version_label.text())
        self.assertGreaterEqual(self.w.assist_panel.width(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
