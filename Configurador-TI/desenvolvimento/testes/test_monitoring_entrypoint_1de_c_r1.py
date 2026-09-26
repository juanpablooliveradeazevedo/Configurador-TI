"""Cobertura da 1D-E-C-R1 — Monitoring Transaction Entrypoint."""
import ast
import socket
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import assist as assist
import release_metadata
from monitoring_foundation import MonitoringService
from desenvolvimento.testes.test_assist_1de_a import metrics


class MonitoringTransactionEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI 1DECR1 ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = assist.AssistStore(self.temp.name)
        self.service = MonitoringService(self.store)
        self.hostname = socket.gethostname() or "Não disponível"

    def settings_context(self, **values):
        return self.store.create_context(
            "MONITORING_SETTINGS", "monitoring_configuration:1",
            monitoring_state=values.get("monitoring_state", self.service.status),
            monitoring_run_id=values.get("monitoring_run_id", self.service.run_id),
        )

    def settings_session(self):
        context = self.settings_context()
        session = self.store.start_session(
            context["context_id"], "MONITORING_SETTINGS_REVIEW"
        )
        step = next(
            item for item in session["steps"]
            if item["definition"].get("action_ref") == "SET_MONITORING_INTERVAL"
        )
        return context, session, step

    def prepare(self, value=120):
        _context, session, step = self.settings_session()
        return self.store.prepare_action(
            session["session_id"], step["step_id"],
            monitoring_service=self.service,
            parameters={"interval_seconds": value}, requested_by="Técnico fixture",
        )

    def execute(self, value=120):
        run = self.prepare(value)
        self.store.confirm_action(run["action_run_id"])
        return self.store.execute_action(
            run["action_run_id"], monitoring_service=self.service
        )

    def test_01_context_type_and_playbook_are_registered(self):
        self.assertIn("MONITORING_SETTINGS", assist.CONTEXT_TYPES)
        self.assertIn("MONITORING_SETTINGS_REVIEW", assist.PLAYBOOK_BY_ID)

    def test_02_context_is_created_without_alert(self):
        self.assertEqual(self.store.count_alerts(hostname=self.hostname), 0)
        context = self.settings_context()
        self.assertEqual(context["source_type"], "MONITORING_SETTINGS")
        self.assertEqual(self.store.count_alerts(hostname=self.hostname), 0)

    def test_03_context_contains_current_persisted_interval(self):
        context = self.settings_context()
        self.assertIn("intervalo persistido 60 s", context["summary"])

    def test_04_context_contains_service_run_configuration_and_timestamp(self):
        self.service.start(60)
        context = self.settings_context()
        self.assertIn("serviço RUNNING", context["summary"])
        self.assertIn(self.service.run_id, context["summary"])
        self.assertIn("consultado em", context["summary"])
        refs = {(item["type"], item["id"]) for item in context["evidence_refs"]}
        self.assertIn(("MONITORING_CONFIGURATION", "singleton:1"), refs)
        self.assertIn(("MONITORING_RUN", self.service.run_id), refs)

    def test_05_opening_context_creates_no_timeline_event_or_action(self):
        before_events = self.store.count_events()
        self.settings_context()
        self.assertEqual(self.store.count_events(), before_events)
        self.assertEqual(self.store.list_action_runs(limit=20), [])

    def test_06_deterministic_explainable_recommendation(self):
        recommendation = self.store.recommend(self.settings_context())[0]
        self.assertEqual(recommendation["rule_id"], "RULE_MONITORING_SETTINGS_REVIEW")
        self.assertEqual(recommendation["title"], "Revisar configuração de monitoramento")
        self.assertIn("abriu a configuração local", recommendation["rationale"])

    def test_07_playbook_starts_without_alert_and_without_timeline(self):
        context = self.settings_context()
        before_events = self.store.count_events()
        session = self.store.start_session(context["context_id"], "MONITORING_SETTINGS_REVIEW")
        self.assertEqual(session["source_context_type"], "MONITORING_SETTINGS")
        self.assertEqual(self.store.count_events(), before_events)

    def test_08_safe_action_step_points_to_existing_action(self):
        _context, session, step = self.settings_session()
        self.assertEqual(step["definition"]["step_type"], "EXISTING_SAFE_ACTION")
        self.assertFalse(step["definition"]["required"])
        self.assertEqual(step["definition"]["action_ref"], "SET_MONITORING_INTERVAL")

    def test_09_dry_run_sixty_to_one_twenty(self):
        run = self.prepare(120)
        self.assertEqual(run["before"]["old_interval_seconds"], 60)
        self.assertEqual(run["dry_run"]["proposed_after"]["interval_seconds"], 120)
        self.assertEqual(run["dry_run"]["side_effect_class"], "LOCAL_REVERSIBLE_CHANGE")
        self.assertFalse(run["dry_run"]["requires_uac"])

    def test_10_dry_run_preserves_persistence_and_runtime(self):
        self.prepare(120)
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)
        self.assertEqual(self.service.interval_seconds, 60)

    def test_11_confirmation_is_required(self):
        run = self.prepare(120)
        with self.assertRaises(ValueError):
            self.store.execute_action(run["action_run_id"], monitoring_service=self.service)

    def test_12_execution_and_validator_confirm_one_twenty(self):
        completed = self.execute(120)
        self.assertEqual(completed["status"], "SUCCEEDED")
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 120)
        self.assertEqual(self.service.interval_seconds, 120)
        self.assertEqual(completed["validator_outcome"]["result"], "SUCCESS")

    def test_13_proof_of_work_records_before_and_after(self):
        proof = self.execute(120)["proof_of_work"]
        self.assertEqual(proof["before"]["old_interval_seconds"], 60)
        self.assertEqual(proof["after"]["interval_seconds"], 120)

    def test_14_rollback_and_validator_restore_sixty(self):
        completed = self.execute(120)
        rolled = self.store.rollback_action(
            completed["action_run_id"], monitoring_service=self.service
        )
        self.assertEqual(rolled["status"], "ROLLED_BACK")
        self.assertEqual(self.store.get_monitoring_configuration()["interval_seconds"], 60)
        self.assertEqual(self.service.interval_seconds, 60)
        self.assertTrue(rolled["rollback_outcome"]["validation"]["ok"])

    def test_15_restart_preserves_sixty_and_does_not_reexecute(self):
        completed = self.execute(120)
        rolled = self.store.rollback_action(
            completed["action_run_id"], monitoring_service=self.service
        )
        reopened = assist.AssistStore(self.temp.name)
        self.assertEqual(reopened.get_monitoring_configuration()["interval_seconds"], 60)
        self.assertEqual(reopened.get_action_run(rolled["action_run_id"])["status"], "ROLLED_BACK")

    def test_16_alert_path_remains_available(self):
        run = self.store.start_run(hostname=self.hostname, interval_seconds=60)
        for minute in range(3):
            self.store.record_cycle(
                run["run_id"], metrics(cpu=95),
                observed_at_utc=f"2026-09-21T13:0{minute}:00Z",
            )
        alert = self.store.list_alerts(hostname=self.hostname, metric_key="cpu_usage")[0]
        context = self.store.create_context("ALERT", alert["alert_id"])
        recommendations = self.store.recommend(context)
        self.assertIn("MONITORING_ALERT_REVIEW", [item["playbook_id"] for item in recommendations])

    def test_17_metadata_identifies_source_and_exe(self):
        self.assertEqual(release_metadata.PHASE_ID, "2B")
        self.assertEqual(release_metadata.status_label("Fonte"), "Configurador TI 2B | Fonte")
        self.assertEqual(release_metadata.status_label("EXE"), "Configurador TI 2B | EXE")

    def test_18_schema_nine_and_mutable_catalog_are_preserved(self):
        self.assertEqual(assist.DATABASE_SCHEMA_VERSION, 9)
        mutable = [item.action_id for item in assist.ACTION_REGISTRY if item.side_effect_class != "READ_ONLY"]
        self.assertEqual(mutable, [
            "SET_MONITORING_INTERVAL", "SET_MONITORING_RETENTION_POLICY",
        ])

    def test_19_no_forbidden_dynamic_execution_or_shell(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("assist.py", "monitoring_gui.py", "main_gui.py"):
            tree = ast.parse((root / name).read_text(encoding="utf-8"))
            calls = {
                node.func.id for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertFalse({"eval", "exec", "system"} & calls)
        action = assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"]
        self.assertFalse(action.requires_elevation)

    def test_20_playbook_text_does_not_claim_alert_or_best_interval(self):
        playbook = assist.PLAYBOOK_BY_ID["MONITORING_SETTINGS_REVIEW"]
        text = " ".join((playbook.title, playbook.description) + tuple(
            step.description for step in playbook.steps
        )).casefold()
        self.assertNotIn("resolve alerta", text)
        self.assertNotIn("melhor intervalo", text)


@unittest.skipUnless(__import__("importlib").util.find_spec("PyQt6"), "PyQt6 indisponível")
class MonitoringTransactionEntrypointQtTests(unittest.TestCase):
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

    def test_21_button_is_available_without_alerts_and_opens_settings(self):
        panel = self.w.monitoring_panel
        self.assertEqual(self.w._get_monitoring_store().count_alerts(hostname=socket.gethostname()), 0)
        self.assertEqual(panel.assist_interval_button.text(), "Ajustar intervalo via Assistente Técnico")
        with patch.object(self.w, "_abrir_assist_contexto") as open_context:
            panel.assist_interval_button.click()
            open_context.assert_called_once()
            args, kwargs = open_context.call_args
            self.assertEqual(args[:2], ("MONITORING_SETTINGS", "monitoring_configuration:1"))
            self.assertIn("monitoring_state", kwargs)

    def test_22_persistent_selector_remains_protected(self):
        self.assertFalse(self.w.monitoring_panel.interval_combo.isEnabled())

    def test_23_layout_1366x768_and_r1_footer(self):
        self.w.resize(1366, 768)
        self.w.show()
        self.w._pagina_monitoramento()
        self.base.app.processEvents()
        self.assertTrue(self.w.monitoring_panel.assist_interval_button.isVisible())
        self.assertIn("2B", self.w.version_label.text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
