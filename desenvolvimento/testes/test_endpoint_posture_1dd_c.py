"""Cobertura da Fase 1D-D-C — Endpoint Posture & Health Intelligence."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

import endpoint_posture as posture


NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def check_set(state="indeterminate"):
    return [posture._source_limited(key, "Fonte de teste", state) for key in posture.CHECK_KEYS]


class AssessmentTests(unittest.TestCase):
    def test_01_bitlocker_enabled_is_ok(self):
        result = posture.assess_bitlocker({"available": True, "protection_status": "On", "volume_status": "FullyEncrypted", "encryption_percentage": 100})
        self.assertEqual((result["capability_state"], result["assessment"]), ("AVAILABLE", "OK"))

    def test_02_bitlocker_off_is_attention(self):
        self.assertEqual(posture.assess_bitlocker({"available": True, "protection_status": "Off"})["assessment"], "ATTENTION")

    def test_03_bitlocker_partial_is_attention(self):
        self.assertEqual(posture.assess_bitlocker({"available": True, "protection_status": "On", "volume_status": "EncryptionInProgress", "encryption_percentage": 55})["assessment"], "ATTENTION")

    def test_04_bitlocker_unavailable_is_not_disabled(self):
        result = posture.assess_bitlocker({"available": False})
        self.assertEqual((result["capability_state"], result["assessment"]), ("UNAVAILABLE", "NOT_APPLICABLE"))

    def test_05_bitlocker_permission_is_indeterminate(self):
        result = posture.assess_bitlocker({"source_error": "permission"})
        self.assertEqual((result["capability_state"], result["assessment"]), ("LIMITED", "INDETERMINATE"))

    def test_06_tpm_ready_is_ok(self):
        self.assertEqual(posture.assess_tpm({"present": True, "ready": True})["assessment"], "OK")

    def test_07_tpm_not_ready_is_attention(self):
        self.assertEqual(posture.assess_tpm({"present": True, "ready": False})["assessment"], "ATTENTION")

    def test_08_tpm_absent_separates_capability(self):
        result = posture.assess_tpm({"present": False, "ready": False})
        self.assertEqual((result["capability_state"], result["assessment"]), ("UNAVAILABLE", "ATTENTION"))

    def test_09_secure_boot_enabled_is_ok(self):
        self.assertEqual(posture.assess_secure_boot({"supported": True, "enabled": True})["assessment"], "OK")

    def test_10_secure_boot_disabled_is_attention(self):
        self.assertEqual(posture.assess_secure_boot({"supported": True, "enabled": False})["assessment"], "ATTENTION")

    def test_11_secure_boot_legacy_is_not_applicable(self):
        result = posture.assess_secure_boot({"supported": False, "enabled": None})
        self.assertEqual((result["capability_state"], result["assessment"]), ("UNAVAILABLE", "NOT_APPLICABLE"))

    def test_12_defender_active_is_ok(self):
        raw = {"defender_source_available": True, "security_center_available": False,
               "defender": {"antivirus_enabled": True, "real_time_enabled": True}, "providers": []}
        self.assertEqual(posture.assess_antivirus(raw)["assessment"], "OK")

    def test_13_third_party_active_is_ok(self):
        raw = {"defender_source_available": True, "security_center_available": True,
               "defender": {"antivirus_enabled": False},
               "providers": [{"name": "Produto X", "product_state": 0x1000}]}
        result = posture.assess_antivirus(raw)
        self.assertEqual((result["assessment"], result["observed_state"]), ("OK", "THIRD_PARTY_ACTIVE"))

    def test_14_defender_off_does_not_imply_no_antivirus(self):
        raw = {"defender_source_available": True, "security_center_available": False,
               "defender": {"antivirus_enabled": False}, "providers": []}
        self.assertEqual(posture.assess_antivirus(raw)["assessment"], "INDETERMINATE")

    def test_15_confirmed_no_active_provider_is_attention(self):
        raw = {"defender_source_available": True, "security_center_available": True,
               "defender": {"antivirus_enabled": False},
               "providers": [{"name": "Produto X", "product_state": 0x0000}]}
        self.assertEqual(posture.assess_antivirus(raw)["assessment"], "ATTENTION")

    def test_16_conflicting_antivirus_sources_are_indeterminate(self):
        raw = {"defender_source_available": True, "security_center_available": True,
               "defender": {"antivirus_enabled": True},
               "providers": [{"name": "Microsoft Defender", "product_state": 0x0000}]}
        self.assertEqual(posture.assess_antivirus(raw)["observed_state"], "SOURCES_CONFLICT")

    def test_17_recent_defender_signature_is_ok(self):
        raw = {"defender_source_available": True, "defender": {"antivirus_enabled": True, "signature_last_updated": (NOW - timedelta(days=1)).isoformat()}, "providers": []}
        self.assertEqual(posture.assess_defender_signature(raw, now_utc=NOW)["assessment"], "OK")

    def test_18_old_defender_signature_is_attention(self):
        raw = {"defender_source_available": True, "defender": {"antivirus_enabled": True, "signature_last_updated": (NOW - timedelta(days=4)).isoformat()}, "providers": []}
        self.assertEqual(posture.assess_defender_signature(raw, now_utc=NOW)["assessment"], "ATTENTION")

    def test_19_third_party_makes_defender_signature_not_applicable(self):
        raw = {"defender_source_available": True, "defender": {"antivirus_enabled": False}, "providers": [{"name": "Produto X", "product_state": 0x1000}]}
        self.assertEqual(posture.assess_defender_signature(raw, now_utc=NOW)["assessment"], "NOT_APPLICABLE")

    def test_20_missing_signature_date_is_indeterminate(self):
        raw = {"defender_source_available": True, "defender": {"antivirus_enabled": True}, "providers": []}
        self.assertEqual(posture.assess_defender_signature(raw, now_utc=NOW)["assessment"], "INDETERMINATE")

    def test_21_all_firewall_profiles_enabled_is_ok(self):
        raw = {"profiles": [{"name": name, "enabled": True} for name in ("Domain", "Private", "Public")]}
        self.assertEqual(posture.assess_firewall(raw)["assessment"], "OK")

    def test_22_disabled_firewall_profile_is_attention(self):
        raw = {"profiles": [{"name": "Domain", "enabled": True}, {"name": "Private", "enabled": False}, {"name": "Public", "enabled": True}]}
        self.assertEqual(posture.assess_firewall(raw)["assessment"], "ATTENTION")

    def test_23_incomplete_firewall_profiles_are_limited(self):
        result = posture.assess_firewall({"profiles": [{"name": "Public", "enabled": True}]})
        self.assertEqual((result["capability_state"], result["assessment"]), ("LIMITED", "INDETERMINATE"))

    def test_24_assessments_never_create_critical(self):
        payloads = [posture.assess_tpm({}), posture.assess_secure_boot({}), posture.assess_firewall({})]
        self.assertNotIn("CRITICAL", json.dumps(payloads))


class SafetyAndCollectorTests(unittest.TestCase):
    def test_25_evidence_removes_recovery_keys(self):
        sanitized = posture.sanitize_evidence({"RecoveryPassword": "segredo", "protection_status": "On"})
        self.assertNotIn("RecoveryPassword", sanitized)
        self.assertEqual(sanitized["protection_status"], "On")

    def test_26_evidence_removes_nested_secrets(self):
        sanitized = posture.sanitize_evidence({"outer": {"token": "x", "ready": True}})
        self.assertEqual(sanitized, {"outer": {"ready": True}})

    def test_27_powershell_scripts_are_read_only(self):
        scripts = posture.BITLOCKER_SCRIPT + posture.TPM_SCRIPT + posture.SECURE_BOOT_SCRIPT + posture.ANTIVIRUS_SCRIPT + posture.FIREWALL_SCRIPT
        forbidden = ("Set-", "Enable-", "Disable-", "manage-bde", "Install-", "WindowsUpdate")
        self.assertFalse(any(term.casefold() in scripts.casefold() for term in forbidden))

    def test_28_no_bitlocker_protector_collection(self):
        self.assertNotIn("KeyProtector", posture.BITLOCKER_SCRIPT)
        self.assertNotIn("RecoveryPassword", posture.BITLOCKER_SCRIPT)

    def test_29_runner_uses_shell_false(self):
        fake = mock.Mock()
        fake.poll.return_value = 0
        fake.communicate.return_value = (b'{"ok":true}', b'')
        fake.returncode = 0
        with mock.patch.object(posture.subprocess, "Popen", return_value=fake) as popen:
            result = posture.run_powershell_json("'x'", timeout=1)
        self.assertTrue(result["ok"])
        self.assertIs(popen.call_args.kwargs["shell"], False)

    def test_30_runner_maps_missing_powershell(self):
        with mock.patch.object(posture.subprocess, "Popen", side_effect=FileNotFoundError):
            with self.assertRaises(posture.PostureSourceError) as caught:
                posture.run_powershell_json("'x'", timeout=1)
        self.assertEqual(caught.exception.kind, "unavailable")

    def test_31_runner_honors_cooperative_cancellation(self):
        fake = mock.Mock()
        fake.poll.return_value = None
        with mock.patch.object(posture.subprocess, "Popen", return_value=fake):
            with self.assertRaises(posture.PostureCancelled):
                posture.run_powershell_json("'x'", timeout=1, cancel_callback=lambda: True)
        fake.terminate.assert_called_once()

    def test_31a_runner_enforces_timeout(self):
        fake = mock.Mock()
        fake.poll.return_value = None
        with mock.patch.object(posture.subprocess, "Popen", return_value=fake):
            with self.assertRaises(TimeoutError):
                posture.run_powershell_json("'x'", timeout=0.01)
        fake.kill.assert_called_once()

    def test_32_non_windows_collector_is_conservative(self):
        result = posture.EndpointPostureCollector(platform_name="posix").collect_all()
        self.assertEqual(len(result), 6)
        self.assertTrue(all(item["assessment"] == "INDETERMINATE" for item in result))

    def test_33_collector_isolates_one_source_failure(self):
        calls = {"n": 0}
        def runner(_script, **_kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise posture.PostureSourceError("permission")
            return {}
        result = posture.EndpointPostureCollector(runner=runner, platform_name="nt").collect_all(now_utc=NOW)
        self.assertEqual(len(result), 6)
        self.assertEqual(result[0]["capability_state"], "LIMITED")

    def test_34_collector_cancellation_stops_scan(self):
        with self.assertRaises(posture.PostureCancelled):
            posture.EndpointPostureCollector(platform_name="nt").collect_all(cancel_callback=lambda: True)

    def test_35_check_enum_rejects_unknown_assessment(self):
        with self.assertRaises(ValueError):
            posture._check("tpm", "AVAILABLE", "CRITICAL", "X", "x", "x")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI postura ç ")
        self.store = posture.EndpointPostureStore(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_36_schema_is_six_and_tables_exist(self):
        with sqlite3.connect(self.store.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 6)
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"endpoint_posture_runs", "endpoint_posture_checks", "endpoint_posture_state", "endpoint_posture_changes"} <= names)

    def test_37_schema_initialization_is_idempotent(self):
        posture.EndpointPostureStore(self.temp.name)
        posture.EndpointPostureStore(self.temp.name)

    def test_38_first_snapshot_is_baseline_without_change(self):
        result = self.store.record_snapshot(check_set(), hostname="PC-01")
        self.assertEqual((len(result["checks"]), len(result["changes"])), (6, 0))

    def test_39_second_identical_snapshot_has_no_change(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        result = self.store.record_snapshot(check_set(), hostname="PC-01")
        self.assertEqual(result["changes"], [])

    def test_40_changed_assessment_creates_one_change(self):
        first = check_set()
        self.store.record_snapshot(first, hostname="PC-01")
        second = check_set()
        second[0] = posture.assess_bitlocker({"available": True, "protection_status": "Off"})
        result = self.store.record_snapshot(second, hostname="PC-01")
        self.assertEqual(len(result["changes"]), 1)

    def test_41_cosmetic_summary_change_is_ignored(self):
        first = check_set()
        self.store.record_snapshot(first, hostname="PC-01")
        second = check_set()
        second[0]["summary"] = "Texto cosmético diferente"
        self.assertEqual(self.store.record_snapshot(second, hostname="PC-01")["changes"], [])

    def test_42_evidence_only_change_is_ignored(self):
        first = check_set()
        self.store.record_snapshot(first, hostname="PC-01")
        second = check_set()
        second[0]["evidence"] = {"signature_version": "2"}
        self.assertEqual(self.store.record_snapshot(second, hostname="PC-01")["changes"], [])

    def test_43_change_creates_structured_timeline_event(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        second = check_set(); second[1] = posture.assess_tpm({"present": True, "ready": True})
        change = self.store.record_snapshot(second, hostname="PC-01")["changes"][0]
        self.assertTrue(change["timeline_event_id"])
        event = self.store.get_event(change["timeline_event_id"])
        self.assertEqual(event["source"], "ENDPOINT_POSTURE")
        self.assertIn("Mudança", event["details_json"])

    def test_44_latest_snapshot_returns_six_checks(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        snapshot = self.store.get_latest_snapshot(hostname="PC-01")
        self.assertEqual(len(snapshot["checks"]), 6)
        self.assertEqual(snapshot["counts"]["INDETERMINATE"], 6)

    def test_45_hosts_are_isolated(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        self.assertIsNone(self.store.get_latest_snapshot(hostname="PC-02"))

    def test_46_invalid_duplicate_check_is_rejected(self):
        checks = check_set(); checks[1] = checks[0]
        with self.assertRaises(ValueError):
            self.store.record_snapshot(checks, hostname="PC-01")

    def test_47_changes_are_ordered_recent_first(self):
        self.store.record_snapshot(check_set(), hostname="PC-01", collected_at_utc="2026-09-17T10:00:00Z")
        second = check_set(); second[0] = posture.assess_bitlocker({"available": True, "protection_status": "Off"})
        self.store.record_snapshot(second, hostname="PC-01", collected_at_utc="2026-09-17T10:01:00Z")
        third = check_set(); third[0] = posture.assess_bitlocker({"available": True, "protection_status": "On", "volume_status": "FullyEncrypted", "encryption_percentage": 100})
        self.store.record_snapshot(third, hostname="PC-01", collected_at_utc="2026-09-17T10:02:00Z")
        changes = self.store.list_changes(hostname="PC-01")
        self.assertGreater(changes[0]["changed_at_utc"], changes[1]["changed_at_utc"])

    def test_48_context_is_same_host_and_declares_no_causality(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        self.store.record_event(source="TEST", category="SYSTEM", severity="INFO", status="OBSERVED", summary="Mesmo host", hostname="PC-01")
        second = check_set(); second[2] = posture.assess_secure_boot({"supported": True, "enabled": True})
        change = self.store.record_snapshot(second, hostname="PC-01")["changes"][0]
        context = self.store.posture_context(change["change_id"])
        self.assertEqual(context["hostname"], "PC-01")
        self.assertIn("Não inferida", context["causality"])

    def test_49_investigation_reuses_timeline_reference(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        second = check_set(); second[2] = posture.assess_secure_boot({"supported": True, "enabled": True})
        change = self.store.record_snapshot(second, hostname="PC-01")["changes"][0]
        first = self.store.create_investigation_from_posture_change(change["change_id"])
        second_session = self.store.create_investigation_from_posture_change(change["change_id"])
        self.assertEqual(first["session_id"], second_session["session_id"])

    def test_50_archived_investigation_is_restored(self):
        self.store.record_snapshot(check_set(), hostname="PC-01")
        second = check_set(); second[3] = posture.assess_antivirus({"defender_source_available": True, "defender": {"antivirus_enabled": True}, "providers": []})
        change = self.store.record_snapshot(second, hostname="PC-01")["changes"][0]
        session = self.store.create_investigation_from_posture_change(change["change_id"])
        self.store.archive_session(session["session_id"])
        restored = self.store.create_investigation_from_posture_change(change["change_id"])
        self.assertEqual(restored["status"], "OPEN")


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = posture.EndpointPostureStore(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_51_service_records_successful_snapshot(self):
        collector = mock.Mock(); collector.collect_all.return_value = check_set()
        result = posture.EndpointPostureService(self.store, collector=collector).collect_once()
        self.assertTrue(result["ok"])

    def test_52_service_reports_cancellation_without_snapshot(self):
        collector = mock.Mock(); collector.collect_all.side_effect = posture.PostureCancelled()
        result = posture.EndpointPostureService(self.store, collector=collector).collect_once()
        self.assertTrue(result["cancelled"])
        self.assertIsNone(self.store.get_latest_snapshot())

    def test_53_service_prevents_overlap(self):
        service = posture.EndpointPostureService(self.store, collector=mock.Mock())
        service._lock.acquire()
        try:
            self.assertEqual(service.collect_once()["skipped"], "overlap")
        finally:
            service._lock.release()

    def test_54_safe_action_contains_store_failure(self):
        self.assertIsNone(posture.posture_action_safe(self.store, None, lambda _store: 1 / 0))


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt6.QtWidgets import QApplication, QTabWidget
        import test_ux_global as base
        cls.QApplication = QApplication
        cls.QTabWidget = QTabWidget
        cls.base = base
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.case = self.base.UxTests()
        self.case.setUp()
        self.w = self.case.w

    def tearDown(self):
        self.case.tearDown()

    def test_55_security_hub_exposes_endpoint_posture(self):
        modules = {item.module_id for item in __import__("navigation_registry").modules_for_domain("security")}
        self.assertEqual(modules, {"defensive_analysis", "endpoint_posture"})

    def test_56_posture_route_opens_dedicated_page(self):
        self.w._pagina_postura_endpoint()
        self.assertEqual(self.w.pages.currentIndex(), 12)

    def test_57_posture_view_has_no_nested_tabs(self):
        self.assertEqual(len(self.w.endpoint_posture_panel.findChildren(self.QTabWidget)), 0)

    def test_58_posture_view_has_six_check_contract(self):
        self.assertEqual(tuple(posture.CHECK_KEYS), ("bitlocker", "tpm", "secure_boot", "antivirus", "defender_signature", "firewall"))
        self.assertEqual(self.w.endpoint_posture_panel.checks_table.columnCount(), 6)

    def test_59_opening_view_does_not_start_collection(self):
        with mock.patch.object(self.w, "_get_posture_service") as getter:
            self.w._pagina_postura_endpoint()
            self.app.processEvents()
        getter.assert_not_called()

    def test_60_window_contains_twenty_pages(self):
        self.assertEqual(self.w.pages.count(), 21)

    def test_61_posture_layout_fits_1366x768_offscreen(self):
        self.w.resize(1366, 768)
        self.w._pagina_postura_endpoint()
        self.app.processEvents()
        panel = self.w.endpoint_posture_panel
        self.assertGreater(panel.checks_table.width(), 500)
        self.assertTrue(panel.update_button.isVisible())


if __name__ == "__main__":
    unittest.main(verbosity=2)
