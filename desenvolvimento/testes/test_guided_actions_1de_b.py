import ast
from dataclasses import replace
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import unittest

import assist as assist
import endpoint_posture as posture
from endpoint_posture import EndpointPostureService, EndpointPostureStore
from monitoring_foundation import MonitoringService
from desenvolvimento.testes.test_assist_1de_a import limited_checks, metrics


def good_checks():
    return [
        {
            "check_key": key, "capability_state": "AVAILABLE", "assessment": "OK",
            "observed_state": "Disponível", "summary": "Leitura local concluída.",
            "source": "Fixture somente leitura", "evidence": {"available": True},
        }
        for key in posture.CHECK_KEYS
    ]


class Collector:
    def __init__(self, checks=None, failure=None):
        self.checks = checks or good_checks()
        self.failure = failure
        self.calls = 0

    def collect_all(self, **_kwargs):
        self.calls += 1
        if self.failure:
            raise self.failure
        return self.checks


class GuidedActionFoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI 1DEB ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = assist.AssistStore(self.temp.name)
        self.hostname = socket.gethostname() or "Não disponível"

    def posture_session(self, assessment="ATTENTION"):
        checks = good_checks()
        checks[0] = dict(checks[0], assessment=assessment, summary="Revisão necessária")
        snapshot = self.store.record_snapshot(checks, hostname=self.hostname)
        context = self.store.create_context("POSTURE_CHECK", snapshot["checks"][0]["check_id"])
        return self.store.start_session(context["context_id"], "ENDPOINT_POSTURE_REVIEW")

    def posture_step(self, session):
        return next(item for item in session["steps"] if item["definition"].get("action_ref") == "REFRESH_ENDPOINT_POSTURE")

    def posture_service(self, checks=None, failure=None):
        collector = Collector(checks, failure)
        return EndpointPostureService(self.store, collector=collector), collector

    def alert_session(self):
        run = self.store.start_run(hostname=self.hostname, interval_seconds=60)
        for minute in range(3):
            self.store.record_cycle(run["run_id"], metrics(cpu=95), observed_at_utc=f"2026-09-17T12:0{minute}:00Z")
        alert = self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")[0]
        context = self.store.create_context("ALERT", alert["alert_id"])
        return self.store.start_session(context["context_id"], "MONITORING_ALERT_REVIEW")

    def monitoring_service(self, values=None):
        payload = values or metrics(cpu=20, memory=30, disk=60)
        def collector(cancel_callback=None):
            if cancel_callback and cancel_callback():
                raise InterruptedError()
            return {"hostname": self.hostname, "observed_at_utc": "2026-09-17T13:00:00Z", "metrics": payload}
        return MonitoringService(self.store, collector=collector)

    def prepare_posture(self, *, checks=None):
        session = self.posture_session()
        step = self.posture_step(session)
        service, collector = self.posture_service(checks)
        run = self.store.prepare_action(
            session["session_id"], step["step_id"], posture_service=service,
            requested_by="Técnico fixture",
        )
        return session, step, service, collector, run

    def execute_posture(self, *, checks=None):
        session, step, service, collector, run = self.prepare_posture(checks=checks)
        self.store.confirm_action(run["action_run_id"])
        completed = self.store.execute_action(run["action_run_id"], posture_service=service)
        return session, step, service, collector, completed

    def action_kinds(self):
        result = []
        for event in self.store.query_events(source="Assistente Técnico", limit=100):
            details = json.loads(event.get("details_json") or "{}")
            if details.get("event_kind", "").startswith("ACTION_"):
                result.append(details["event_kind"])
        return result

    def test_01_schema_seven_migrates_to_eight(self):
        other = tempfile.TemporaryDirectory(prefix="Configurador TI schema7 ")
        self.addCleanup(other.cleanup)
        old = EndpointPostureStore(other.name)
        with sqlite3.connect(old.path) as connection:
            connection.execute("PRAGMA user_version=7")
        migrated = assist.AssistStore(other.name)
        with sqlite3.connect(migrated.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 9)

    def test_02_schema_eight_reopen_is_idempotent(self):
        assist.AssistStore(self.temp.name)
        reopened = assist.AssistStore(self.temp.name)
        self.assertEqual(reopened.list_action_runs(), [])

    def test_03_action_tables_and_indexes_exist(self):
        with sqlite3.connect(self.store.path) as connection:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        self.assertTrue({"action_runs", "action_run_events", "idx_action_runs_action"} <= names)

    def test_04_registry_has_unique_ids(self):
        ids = [item.action_id for item in assist.ACTION_REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_05_registry_requires_versions(self):
        bad = replace(assist.ACTION_REGISTRY[0], action_id="BAD", version=0)
        with self.assertRaises(ValueError):
            assist.validate_action_registry((bad,))

    def test_06_registry_allows_only_read_only(self):
        bad = replace(assist.ACTION_REGISTRY[0], action_id="BAD", side_effect_class="LOCAL_CHANGE")
        with self.assertRaises(ValueError):
            assist.validate_action_registry((bad,))

    def test_07_registry_requires_no_elevation(self):
        bad = replace(assist.ACTION_REGISTRY[0], action_id="BAD", requires_elevation=True)
        with self.assertRaises(ValueError):
            assist.validate_action_registry((bad,))

    def test_08_registry_requires_not_required_rollback(self):
        bad = replace(assist.ACTION_REGISTRY[0], action_id="BAD", rollback_mode="AUTOMATIC")
        with self.assertRaises(ValueError):
            assist.validate_action_registry((bad,))

    def test_09_executor_resolves_only_allowlist(self):
        bad = replace(assist.ACTION_REGISTRY[0], action_id="BAD", executor_ref="command.exe")
        with self.assertRaises(ValueError):
            assist.validate_action_registry((bad,))

    def test_10_unallowlisted_action_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.action_definition("RUN_ARBITRARY")

    def test_11_initial_actions_are_exact(self):
        self.assertEqual(set(assist.ACTION_BY_ID), {
            "REFRESH_ENDPOINT_POSTURE", "COLLECT_MONITORING_SAMPLE_NOW",
            "SET_MONITORING_INTERVAL", "SET_MONITORING_RETENTION_POLICY",
        })

    def test_12_registry_contains_no_command_string(self):
        encoded = json.dumps([item.__dict__ for item in assist.ACTION_REGISTRY])
        self.assertNotIn("powershell", encoded.casefold())
        self.assertNotIn("cmd.exe", encoded.casefold())

    def test_13_preconditions_pass_with_approved_service(self):
        *_, run = self.prepare_posture()
        self.assertEqual(run["status"], "READY")

    def test_14_precondition_failure_does_not_execute(self):
        session = self.posture_session()
        step = self.posture_step(session)
        run = self.store.prepare_action(session["session_id"], step["step_id"], posture_service=None)
        self.assertEqual(run["status"], "PRECHECK_FAILED")
        self.assertNotIn("ACTION_STARTED", self.action_kinds())

    def test_15_dry_run_does_not_execute_collector(self):
        *_, collector, run = self.prepare_posture()
        self.assertEqual(collector.calls, 0)
        self.assertFalse(run["dry_run"]["executed"])

    def test_16_dry_run_explains_effect_uac_and_rollback(self):
        *_, run = self.prepare_posture()
        self.assertEqual(run["dry_run"]["side_effect_class"], "READ_ONLY")
        self.assertFalse(run["dry_run"]["requires_uac"])
        self.assertEqual(run["dry_run"]["rollback_mode"], "NOT_REQUIRED")

    def test_17_confirmation_is_required(self):
        *_, service, _collector, run = self.prepare_posture()
        with self.assertRaises(ValueError):
            self.store.execute_action(run["action_run_id"], posture_service=service)

    def test_18_cancel_before_execution_has_no_action_started(self):
        *_, run = self.prepare_posture()
        cancelled = self.store.cancel_action(run["action_run_id"])
        self.assertEqual(cancelled["result"], "CANCELLED")
        self.assertNotIn("ACTION_STARTED", self.action_kinds())

    def test_19_action_run_lifecycle_reaches_succeeded(self):
        *_, completed = self.execute_posture()
        self.assertEqual((completed["status"], completed["result"]), ("SUCCEEDED", "SUCCESS"))

    def test_20_action_run_persists(self):
        *_, run = self.prepare_posture()
        reopened = assist.AssistStore(self.temp.name).get_action_run(run["action_run_id"])
        self.assertEqual(reopened["status"], "READY")

    def test_21_before_evidence_is_reference_only(self):
        *_, run = self.prepare_posture()
        self.assertEqual(set(run["before_evidence_ref"]), {"type", "id"})

    def test_22_after_evidence_is_reference_only(self):
        *_, completed = self.execute_posture()
        self.assertEqual(set(completed["after_evidence_ref"]), {"type", "id"})

    def test_23_validator_can_prove_success(self):
        *_, completed = self.execute_posture()
        self.assertEqual(completed["result"], "SUCCESS")
        self.assertIn("persistidos", completed["validator_summary"])

    def test_24_validator_reports_indeterminate_partial_collection(self):
        *_, completed = self.execute_posture(checks=limited_checks())
        self.assertEqual(completed["result"], "INDETERMINATE")

    def test_25_executor_failure_becomes_failed(self):
        session = self.posture_session()
        step = self.posture_step(session)
        service, _collector = self.posture_service(failure=RuntimeError("boom"))
        run = self.store.prepare_action(session["session_id"], step["step_id"], posture_service=service)
        self.store.confirm_action(run["action_run_id"])
        completed = self.store.execute_action(run["action_run_id"], posture_service=service)
        self.assertEqual((completed["status"], completed["result"]), ("FAILED", "FAILURE"))

    def test_26_no_success_from_absence_of_exception(self):
        class EmptyService:
            status = "STOPPED"
            def collect_once(self, **_kwargs): return {"ok": True}
        session = self.posture_session()
        step = self.posture_step(session)
        run = self.store.prepare_action(session["session_id"], step["step_id"], posture_service=EmptyService())
        self.store.confirm_action(run["action_run_id"])
        completed = self.store.execute_action(run["action_run_id"], posture_service=EmptyService())
        self.assertEqual(completed["result"], "FAILURE")

    def test_27_timeline_records_action_started(self):
        self.execute_posture()
        self.assertIn("ACTION_STARTED", self.action_kinds())

    def test_28_timeline_records_action_succeeded(self):
        self.execute_posture()
        self.assertIn("ACTION_SUCCEEDED", self.action_kinds())

    def test_29_timeline_records_action_failed(self):
        session = self.posture_session()
        step = self.posture_step(session)
        service, _collector = self.posture_service(failure=RuntimeError("boom"))
        run = self.store.prepare_action(session["session_id"], step["step_id"], posture_service=service)
        self.store.confirm_action(run["action_run_id"])
        self.store.execute_action(run["action_run_id"], posture_service=service)
        self.assertIn("ACTION_FAILED", self.action_kinds())

    def test_30_timeline_has_no_dry_run_spam(self):
        self.prepare_posture()
        self.assertEqual(self.action_kinds(), [])

    def test_31_posture_playbook_has_safe_action(self):
        refs = [s.action_ref for s in assist.PLAYBOOK_BY_ID["ENDPOINT_POSTURE_REVIEW"].steps if s.action_ref]
        self.assertEqual(refs, ["REFRESH_ENDPOINT_POSTURE"])

    def test_32_monitoring_playbook_has_safe_action(self):
        refs = [s.action_ref for s in assist.PLAYBOOK_BY_ID["MONITORING_ALERT_REVIEW"].steps if s.action_ref]
        self.assertEqual(refs, ["COLLECT_MONITORING_SAMPLE_NOW", "SET_MONITORING_INTERVAL"])

    def test_33_storage_has_no_cleanup_action(self):
        self.assertFalse(any(s.action_ref for s in assist.PLAYBOOK_BY_ID["STORAGE_SPACE_REVIEW"].steps))

    def test_34_network_has_no_correction_action(self):
        self.assertFalse(any(s.action_ref for s in assist.PLAYBOOK_BY_ID["NETWORK_CHANGE_REVIEW"].steps))

    def test_35_action_step_is_not_done_by_dry_run(self):
        session, step, *_rest, run = self.prepare_posture()
        current = self.store.get_session_details(session["session_id"])
        state = next(item for item in current["steps"] if item["step_id"] == step["step_id"])
        self.assertEqual((run["status"], state["status"]), ("READY", "PENDING"))

    def test_36_success_marks_action_step_done(self):
        session, step, *_rest, completed = self.execute_posture()
        current = self.store.get_session_details(session["session_id"])
        state = next(item for item in current["steps"] if item["step_id"] == step["step_id"])
        self.assertEqual((completed["result"], state["status"]), ("SUCCESS", "DONE"))

    def test_37_proof_of_work_reopens_after_restart(self):
        *_, completed = self.execute_posture()
        reopened = assist.AssistStore(self.temp.name).get_action_run(completed["action_run_id"])
        self.assertEqual(set(reopened["proof_of_work"]), {
            "before", "planned_change", "action", "after", "validation",
            "rollback", "result",
        })

    def test_38_parameters_are_typed_and_empty(self):
        *_, run = self.prepare_posture()
        self.assertEqual(run["parameters"], {})

    def test_39_secret_parameters_are_rejected(self):
        session = self.posture_session()
        step = self.posture_step(session)
        with self.assertRaises(ValueError):
            self.store.plan_action(session["session_id"], step["step_id"], parameters={"token": "x"})

    def test_40_no_arbitrary_execution_apis_in_assist(self):
        tree = ast.parse(Path(assist.__file__).read_text(encoding="utf-8"))
        forbidden = {"system", "Popen", "check_call", "check_output", "eval", "exec"}
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        } | {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(calls & forbidden)

    def test_41_no_overlap_rejects_equivalent_running_action(self):
        session, step, *_rest, run = self.prepare_posture()
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("UPDATE action_runs SET status='RUNNING' WHERE action_run_id=?", (run["action_run_id"],))
        with self.assertRaises(ValueError):
            self.store.plan_action(session["session_id"], step["step_id"])

    def test_42_cooperative_cancellation_is_persisted(self):
        session = self.posture_session()
        step = self.posture_step(session)
        service, _collector = self.posture_service()
        run = self.store.prepare_action(session["session_id"], step["step_id"], posture_service=service)
        self.store.confirm_action(run["action_run_id"])
        completed = self.store.execute_action(
            run["action_run_id"], posture_service=service, cancel_callback=lambda: True
        )
        self.assertEqual(completed["result"], "CANCELLED")

    def test_43_posture_check_context_uses_reference(self):
        session = self.posture_session()
        context = self.store.get_context(session["context_id"])
        self.assertEqual(context["source_type"], "POSTURE_CHECK")
        self.assertIn("POSTURE_CHECK", {item["type"] for item in context["evidence_refs"]})

    def test_44_posture_attention_gets_recommendation(self):
        session = self.posture_session("ATTENTION")
        self.assertEqual(self.store.recommend(session["context_id"])[0]["playbook_id"], "ENDPOINT_POSTURE_REVIEW")

    def test_45_posture_indeterminate_gets_recommendation(self):
        session = self.posture_session("INDETERMINATE")
        self.assertEqual(self.store.recommend(session["context_id"])[0]["playbook_id"], "ENDPOINT_POSTURE_REVIEW")

    def test_46_posture_ok_does_not_invent_recommendation(self):
        session = self.posture_session("OK")
        self.assertEqual(self.store.recommend(session["context_id"]), [])

    def test_47_opening_posture_check_assist_creates_no_timeline_event(self):
        before = self.store.count_events(source="Assistente Técnico")
        checks = self.store.record_snapshot(good_checks(), hostname=self.hostname)["checks"]
        self.store.create_context("POSTURE_CHECK", checks[0]["check_id"])
        self.assertEqual(self.store.count_events(source="Assistente Técnico"), before)

    def test_48_monitoring_action_persists_new_observation(self):
        session = self.alert_session()
        step = next(item for item in session["steps"] if item["definition"].get("action_ref") == "COLLECT_MONITORING_SAMPLE_NOW")
        service = self.monitoring_service()
        run = self.store.prepare_action(session["session_id"], step["step_id"], monitoring_service=service)
        self.store.confirm_action(run["action_run_id"])
        completed = self.store.execute_action(run["action_run_id"], monitoring_service=service)
        self.assertEqual(completed["result"], "SUCCESS")

    def test_49_indeterminate_requires_explicit_acceptance(self):
        session, step, *_rest, completed = self.execute_posture(checks=limited_checks())
        current = self.store.get_session_details(session["session_id"])
        self.assertEqual(next(x for x in current["steps"] if x["step_id"] == step["step_id"])["status"], "PENDING")
        self.store.accept_indeterminate(completed["action_run_id"])
        current = self.store.get_session_details(session["session_id"])
        self.assertEqual(next(x for x in current["steps"] if x["step_id"] == step["step_id"])["status"], "DONE")


class GuidedActionGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from desenvolvimento.testes import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests()
        self.case.setUp()
        self.w = self.case.w

    def tearDown(self):
        self.case.tearDown()

    def test_50_empty_states_are_explicit(self):
        panel = self.w.assist_panel
        self.assertIn("Abra o Assistente Técnico", panel.context_empty_state.text())
        self.assertIn("Nenhum playbook é aplicável", panel.recommendation_empty_state.text())

    def test_51_guided_action_panel_and_buttons_exist(self):
        panel = self.w.assist_panel
        self.assertEqual(panel.prepare_action_button.text(), "Preparar ação")
        self.assertIn("dry-run", panel.execute_action_button.text())
        self.assertEqual(panel.proof_of_work.text(), "Nenhuma tentativa de ação registrada nesta etapa.")

    def test_52_posture_current_check_can_open_assist(self):
        panel = self.w.endpoint_posture_panel
        self.assertEqual(panel.current_assist_button.text(), "Abrir no Assistente Técnico")
        self.assertFalse(panel.current_assist_button.isEnabled())

    def test_53_layout_remains_usable_at_1366x768(self):
        self.w.resize(1366, 768)
        self.w._pagina_assist()
        self.base.app.processEvents()
        self.assertGreaterEqual(self.w.pages.width(), 800)


if __name__ == "__main__":
    unittest.main(verbosity=2)
