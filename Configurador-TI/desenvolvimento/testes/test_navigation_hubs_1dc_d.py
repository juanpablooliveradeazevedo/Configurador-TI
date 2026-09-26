"""Testes da Fase 1D-C-D — Navigation & Domain Hubs."""
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import incident_replay as replay
import navigation_registry as registry


EXPECTED_DOMAINS = (
    "overview", "operations", "network", "security", "investigation",
    "observability", "deployment", "company",
)
EXPECTED_MODULES = {
    "dashboard", "maintenance", "processes_services", "assist", "network_dns",
    "network_inventory", "defensive_analysis", "endpoint_posture", "audit_timeline",
    "investigation_replay", "monitoring", "reports", "logs",
    "deployment_tools", "company_central",
}


class RegistryTests(unittest.TestCase):
    def test_01_registry_loads_all_expected_modules(self):
        self.assertEqual({item.module_id for item in registry.modules()}, EXPECTED_MODULES)
        self.assertEqual(tuple(item.domain_id for item in registry.domains()), EXPECTED_DOMAINS)

    def test_02_module_ids_are_unique_and_domains_valid(self):
        ids = [item.module_id for item in registry.MODULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(item.domain in registry.DOMAIN_IDS for item in registry.MODULES))
        self.assertTrue(registry.validate_registry())

    def test_03_order_is_deterministic(self):
        first = [(item.domain, item.order, item.module_id) for item in registry.modules()]
        second = [(item.domain, item.order, item.module_id) for item in registry.modules()]
        self.assertEqual(first, second)
        for domain in registry.domains():
            values = registry.modules_for_domain(domain.domain_id)
            self.assertEqual(list(values), sorted(values, key=lambda item: (item.order, item.module_id)))


class StoreArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI hubs archive ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = replay.IncidentReplayStore(self.temp.name)
        self.event = self.store.record_event(
            event_id="archive-event", source="Fixture", category="OPERATION",
            severity="INFO", status="OBSERVED", summary="Evidência preservada",
            hostname="ARCHIVE-HOST", timestamp_utc=datetime.now(timezone.utc),
        )
        self.session = self.store.create_from_timeline_event(self.event["id"])

    def test_04_archive_is_hidden_by_default_and_visible_on_request(self):
        self.store.archive_session(self.session["session_id"])
        self.assertEqual(self.store.get_session(self.session["session_id"])["status"], "ARCHIVED")
        self.assertNotIn(self.session["session_id"], {item["session_id"] for item in self.store.list_sessions()})
        self.assertIn(self.session["session_id"], {
            item["session_id"] for item in self.store.list_sessions(include_archived=True)
        })

    def test_05_restore_returns_session_to_active_view(self):
        self.store.archive_session(self.session["session_id"])
        restored = self.store.restore_session(self.session["session_id"])
        self.assertEqual(restored["status"], "OPEN")
        self.assertIn(self.session["session_id"], {item["session_id"] for item in self.store.list_sessions()})

    def test_06_archive_never_removes_items_or_original_evidence(self):
        before_items = self.store.list_items(self.session["session_id"])
        self.store.archive_session(self.session["session_id"])
        self.assertEqual(self.store.list_items(self.session["session_id"]), before_items)
        self.assertEqual(self.store.get_event(self.event["id"])["summary"], "Evidência preservada")


class GuiTests(unittest.TestCase):
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

    def test_07_routes_resolve_and_all_principal_modules_are_accessible(self):
        for definition in registry.modules():
            with self.subTest(module=definition.module_id):
                self.assertTrue(callable(getattr(self.w, definition.route, None)))
                self.assertGreaterEqual(definition.view_index, 0)
                self.assertLess(definition.view_index, 14)

    def test_08_sidebar_contains_only_expected_domains(self):
        self.assertEqual(len(self.w.nav_buttons), 8)
        self.assertEqual(tuple(button.property("domain_id") for button in self.w.nav_buttons), EXPECTED_DOMAINS)
        self.assertEqual(self.w.pages.count(), 21)

    def _assert_hub_and_module(self, domain_id, module_id, expected_view, expected_tab=None):
        self.w._open_domain(domain_id)
        self.base.app.processEvents()
        self.assertEqual(self.w.pages.currentIndex(), self.w.domain_page_indexes[domain_id])
        self.assertIn(module_id, self.w.domain_hubs[domain_id].module_buttons)
        if module_id == "processes_services":
            with patch.object(self.w, "_atualizar_processos"), patch.object(self.w, "_carregar_servicos"):
                self.w._open_module(module_id)
        else:
            self.w._open_module(module_id)
        self.base.app.processEvents()
        self.assertEqual(self.w.pages.currentIndex(), expected_view)
        if expected_tab is not None:
            self.assertEqual(self.w.abas_processos.currentIndex(), expected_tab)
        active = next(button for button in self.w.nav_buttons if button.property("domain_id") == domain_id)
        self.assertTrue(active.isChecked())

    def test_09_operations_hub_opens_maintenance_and_processes(self):
        self._assert_hub_and_module("operations", "maintenance", 2)
        self._assert_hub_and_module("operations", "processes_services", 6, 0)

    def test_10_network_hub_opens_network_and_inventory(self):
        self._assert_hub_and_module("network", "network_dns", 1)
        self._assert_hub_and_module("network", "network_inventory", 3)

    def test_11_security_hub_opens_existing_defensive_analysis(self):
        self._assert_hub_and_module("security", "defensive_analysis", 6, 2)

    def test_12_investigation_hub_opens_timeline_and_investigation(self):
        with patch.object(self.w.audit_panel, "refresh"):
            self._assert_hub_and_module("investigation", "audit_timeline", 10)
        with patch.object(self.w.investigation_panel, "refresh"), patch.object(self.w.investigation_panel, "refresh_sessions"):
            self._assert_hub_and_module("investigation", "investigation_replay", 11)

    def test_13_observability_hub_opens_monitoring_reports_and_logs(self):
        for module_id, view in (("monitoring", 5), ("reports", 4), ("logs", 9)):
            self._assert_hub_and_module("observability", module_id, view)

    def test_14_deployment_and_company_hubs_open_existing_views(self):
        self._assert_hub_and_module("deployment", "deployment_tools", 8)
        self._assert_hub_and_module("company", "company_central", 7)

    def test_15_return_to_hub_and_context_are_preserved(self):
        self.w._open_module("network_dns")
        self.assertFalse(self.w.navigation_context.isHidden())
        self.assertIn("Rede", self.w.navigation_context_label.text())
        self.w.return_hub_button.click()
        self.assertEqual(self.w.pages.currentIndex(), self.w.domain_page_indexes["network"])
        self.assertTrue(self.w.navigation_context.isHidden())

    def test_16_legacy_and_session_deep_links_remain_compatible(self):
        with patch.object(self.w.investigation_panel, "refresh"):
            self.w._abrir_investigacao("operation-fixture")
        self.assertEqual(self.w.pages.currentIndex(), 11)
        self.assertEqual(self.w.investigation_panel._operation_filter, "operation-fixture")
        temp = tempfile.TemporaryDirectory(prefix="Configurador TI nav deeplink ç ")
        self.addCleanup(temp.cleanup)
        store = replay.IncidentReplayStore(temp.name)
        event = store.record_event(
            event_id="nav-event", source="Fixture", category="OPERATION", severity="INFO",
            status="OBSERVED", summary="Navegação", hostname="NAV-HOST",
        )
        self.w._audit_store = store
        self.w._change_store = store
        self.w._incident_store = store
        with patch.object(self.w.investigation_panel, "refresh_sessions"):
            self.w._criar_investigacao_evento(event["id"])
        self.assertEqual(self.w.pages.currentIndex(), 11)
        self.assertIsNotNone(self.w.investigation_panel._session_id)

    def test_17_hubs_offscreen_fit_1366x768_without_critical_break(self):
        self.w.resize(1366, 768)
        for domain_id in EXPECTED_DOMAINS:
            self.w._open_domain(domain_id)
            self.base.app.processEvents()
            self.assertTrue(self.w.nav_buttons[EXPECTED_DOMAINS.index(domain_id)].isVisible())
        self.assertGreaterEqual(self.w.pages.width(), 800)

    def test_18_archive_restore_confirmation_and_filter_controls(self):
        temp = tempfile.TemporaryDirectory(prefix="Configurador TI nav archive GUI ç ")
        self.addCleanup(temp.cleanup)
        store = replay.IncidentReplayStore(temp.name)
        session = store.create_session(title="Sessão acidental", hostname="GUI", source="MANUAL")
        self.w._incident_store = store
        panel = self.w.investigation_panel
        panel._sessions = [session]
        panel._session_id = session["session_id"]
        with patch.object(panel, "refresh_sessions"), patch(
            "change_intelligence_gui.QMessageBox.question",
            return_value=self.base.gui.QMessageBox.StandardButton.Yes,
        ):
            panel.toggle_archive_session()
        self.assertEqual(store.get_session(session["session_id"])["status"], "ARCHIVED")
        panel.show_archived_sessions.setChecked(True)
        panel._sessions = [store.get_session(session["session_id"])]
        panel._session_id = session["session_id"]
        with patch.object(panel, "refresh_sessions"), patch(
            "change_intelligence_gui.QMessageBox.question",
            return_value=self.base.gui.QMessageBox.StandardButton.Yes,
        ):
            panel.toggle_archive_session()
        self.assertEqual(store.get_session(session["session_id"])["status"], "OPEN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
