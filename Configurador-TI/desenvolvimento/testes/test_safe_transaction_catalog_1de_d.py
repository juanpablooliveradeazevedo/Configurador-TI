"""Cobertura da 1D-E-D — catálogo seguro e guardrails de política."""
from dataclasses import replace
import json
import socket
import tempfile
import unittest
from unittest.mock import patch

import assist as assist
import release_metadata
from monitoring_foundation import MonitoringService


class SafeTransactionCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI 1DED ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = assist.AssistStore(self.temp.name)
        self.service = MonitoringService(self.store)
        self.hostname = socket.gethostname() or "Não disponível"
        context = self.store.create_context(
            "MONITORING_SETTINGS", "monitoring_configuration:1",
            monitoring_state=self.service.status,
        )
        self.session = self.store.start_session(
            context["context_id"], "MONITORING_SETTINGS_REVIEW"
        )
        self.interval_step = self._step("SET_MONITORING_INTERVAL")
        self.retention_step = self._step("SET_MONITORING_RETENTION_POLICY")

    def _step(self, action_id):
        return next(
            item for item in self.session["steps"]
            if item["definition"].get("action_ref") == action_id
        )

    def prepare_interval(self, value=120):
        return self.store.prepare_action(
            self.session["session_id"], self.interval_step["step_id"],
            monitoring_service=self.service,
            parameters={"interval_seconds": value}, requested_by="Técnico fixture",
        )

    def prepare_retention(self, value=60):
        return self.store.prepare_action(
            self.session["session_id"], self.retention_step["step_id"],
            monitoring_service=self.service,
            parameters={"retention_days": value}, requested_by="Técnico fixture",
        )

    def execute(self, run):
        self.store.confirm_action(run["action_run_id"])
        return self.store.execute_action(
            run["action_run_id"], monitoring_service=self.service
        )

    def test_01_metadata_1de_d(self):
        self.assertEqual(release_metadata.PHASE_ID, "2B")

    def test_02_catalog_lists_read_only_and_reversible(self):
        catalog = self.store.action_catalog(monitoring_service=self.service)
        self.assertIn("READ_ONLY", {item["action_kind"] for item in catalog})
        self.assertIn("REVERSIBLE", {item["action_kind"] for item in catalog})

    def test_03_guardrails_accept_read_only(self):
        self.assertTrue(assist.validate_action_registry((assist.ACTION_REGISTRY[0],)))

    def test_04_guardrails_accept_low_reversible(self):
        self.assertTrue(assist.validate_action_registry((assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"],)))

    def test_05_guardrails_reject_privileged(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], side_effect_class="PRIVILEGED_CHANGE")
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_06_guardrails_reject_destructive(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], side_effect_class="DESTRUCTIVE")
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_07_guardrails_reject_uac(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], requires_elevation=True)
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_08_guardrails_require_rollback(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], rollback_ref=None)
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_09_guardrails_require_validator(self):
        action = replace(assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"], validator_ref="missing")
        with self.assertRaises(ValueError): assist.validate_action_registry((action,))

    def test_10_catalog_explains_availability(self):
        available = self.store.action_catalog(monitoring_service=self.service)
        retention = next(item for item in available if item["action_id"] == "SET_MONITORING_RETENTION_POLICY")
        self.assertEqual(retention["availability_state"], "AVAILABLE")
        unavailable = self.store.action_catalog(monitoring_service=None)
        retention = next(item for item in unavailable if item["action_id"] == "SET_MONITORING_RETENTION_POLICY")
        self.assertEqual(retention["availability_state"], "UNAVAILABLE_CAPABILITY")
        self.assertTrue(retention["availability_reason"])

    def test_11_interval_still_changes_sixty_to_one_twenty(self):
        completed = self.execute(self.prepare_interval())
        self.assertEqual(completed["status"], "SUCCEEDED")
        self.assertEqual(self.service.interval_seconds, 120)

    def test_12_interval_validator(self):
        completed = self.execute(self.prepare_interval())
        self.assertEqual(completed["validator_outcome"]["result"], "SUCCESS")

    def test_13_interval_rollback(self):
        completed = self.execute(self.prepare_interval())
        rolled = self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        self.assertEqual(rolled["status"], "ROLLED_BACK")
        self.assertEqual(self.service.interval_seconds, 60)

    def test_15_same_interval_resource_does_not_overlap(self):
        self.prepare_interval()
        with self.assertRaises(ValueError): self.prepare_interval(300)

    def test_16_interval_recovery(self):
        run = self.prepare_interval()
        with self.store._connect() as connection:
            connection.execute("UPDATE action_runs SET status='RUNNING' WHERE action_run_id=?", (run["action_run_id"],))
        reopened = assist.AssistStore(self.temp.name)
        recovered = reopened.revalidate_recovery(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(recovered["status"], "ROLLED_BACK")

    def test_17_proof_of_work_is_uniform(self):
        interval = self.execute(self.prepare_interval())["proof_of_work"]
        rolled = self.store.rollback_action(
            next(item["action_run_id"] for item in self.store.list_action_runs(action_id="SET_MONITORING_INTERVAL")),
            monitoring_service=self.service,
        )
        retention = self.execute(self.prepare_retention())["proof_of_work"]
        self.assertEqual(set(interval), set(retention))
        self.assertEqual(set(interval), {"before", "planned_change", "action", "after", "validation", "rollback", "result"})
        self.assertEqual(rolled["status"], "ROLLED_BACK")

    def test_18_dry_run_does_not_spam_timeline(self):
        before = self.store.count_events()
        self.prepare_retention()
        self.assertEqual(self.store.count_events(), before)

    def test_19_retention_definition_is_valid(self):
        action = assist.ACTION_BY_ID["SET_MONITORING_RETENTION_POLICY"]
        self.assertTrue(assist.validate_action_registry((action,)))

    def test_20_retention_parameters_are_allowlisted(self):
        self.assertEqual(self.prepare_retention(90)["parameters"], {"retention_days": 90})

    def test_21_invalid_retention_is_rejected(self):
        with self.assertRaises(ValueError): self.prepare_retention(365)

    def test_22_retention_snapshot(self):
        run = self.prepare_retention()
        self.assertEqual(run["before"]["old_retention_days"], 30)

    def test_23_retention_dry_run_does_not_change_policy(self):
        self.prepare_retention()
        self.assertEqual(self.store.get_monitoring_configuration()["retention_days"], 30)
        self.assertEqual(self.service.retention_days, 30)

    def test_24_retention_execution_changes_policy(self):
        self.execute(self.prepare_retention())
        self.assertEqual(self.store.get_monitoring_configuration()["retention_days"], 60)
        self.assertEqual(self.service.retention_days, 60)

    def test_25_retention_execution_does_not_purge(self):
        with patch.object(self.store, "purge_observations", wraps=self.store.purge_observations) as purge:
            completed = self.execute(self.prepare_retention())
        purge.assert_not_called()
        self.assertFalse(completed["executor_outcome"]["purge_executed"])

    def test_26_retention_validator(self):
        completed = self.execute(self.prepare_retention())
        self.assertEqual(completed["validator_outcome"]["result"], "SUCCESS")
        self.assertFalse(completed["actual_after"]["purge_executed"])

    def test_27_retention_rollback(self):
        completed = self.execute(self.prepare_retention())
        rolled = self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        self.assertEqual(rolled["status"], "ROLLED_BACK")
        self.assertEqual(self.service.retention_days, 30)

    def test_28_retention_rollback_validator(self):
        completed = self.execute(self.prepare_retention())
        rolled = self.store.rollback_action(completed["action_run_id"], monitoring_service=self.service)
        self.assertTrue(rolled["rollback_outcome"]["validation"]["ok"])

    def test_29_same_retention_resource_does_not_overlap(self):
        self.prepare_retention()
        with self.assertRaises(ValueError): self.prepare_retention(90)

    def test_30_retention_recovery(self):
        run = self.prepare_retention()
        self.store.set_monitoring_configuration(retention_days=60, expected_retention=30)
        self.service.set_retention_days(60)
        with self.store._connect() as connection:
            connection.execute("UPDATE action_runs SET status='RUNNING' WHERE action_run_id=?", (run["action_run_id"],))
        reopened = assist.AssistStore(self.temp.name)
        recovered = reopened.revalidate_recovery(run["action_run_id"], monitoring_service=self.service)
        self.assertEqual(recovered["status"], "SUCCEEDED")

    def test_31_retention_persists_after_restart(self):
        self.execute(self.prepare_retention(90))
        reopened = assist.AssistStore(self.temp.name)
        self.assertEqual(reopened.get_monitoring_configuration()["retention_days"], 90)

    def test_32_interval_and_retention_resources_coexist(self):
        interval = self.prepare_interval()
        retention = self.prepare_retention()
        self.assertNotEqual(interval["resource_key"], retention["resource_key"])
        self.assertEqual({interval["status"], retention["status"]}, {"READY"})

    def test_33_rollback_does_not_cross_resources(self):
        interval = self.execute(self.prepare_interval())
        retention = self.execute(self.prepare_retention())
        rolled = self.store.rollback_action(retention["action_run_id"], monitoring_service=self.service)
        self.assertEqual(rolled["status"], "ROLLED_BACK")
        self.assertEqual(self.service.interval_seconds, 120)
        self.assertEqual(self.service.retention_days, 30)
        self.assertEqual(interval["status"], "SUCCEEDED")


@unittest.skipUnless(__import__("importlib").util.find_spec("PyQt6"), "PyQt6 indisponível")
class SafeTransactionCatalogQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from desenvolvimento.testes import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests(); self.case.setUp(); self.w = self.case.w

    def tearDown(self): self.case.tearDown()

    def test_14_selector_preserves_last_executed_value(self):
        panel = self.w.assist_panel
        action = assist.ACTION_BY_ID["SET_MONITORING_INTERVAL"]
        panel._last_action_parameter_values[action.action_id] = 120
        panel._show_action_definition(action)
        self.assertEqual(panel.action_parameter_combo.currentData(), 120)

    def test_34_qt_offscreen_and_1366x768(self):
        self.w.resize(1366, 768); self.w.show(); self.w._pagina_assist()
        self.base.app.processEvents()
        self.assertGreaterEqual(self.w.assist_panel.width(), 1)

    def test_35_source_and_exe_metadata(self):
        self.assertEqual(release_metadata.status_label("Fonte"), "Configurador TI 2B | Fonte")
        self.assertEqual(release_metadata.status_label("EXE"), "Configurador TI 2B | EXE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
