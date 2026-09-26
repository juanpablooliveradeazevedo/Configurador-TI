"""Cobertura da Fase 1D-E-A — Assistente Técnico & Safe Playbooks Foundation."""
from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import assist as assist
import endpoint_posture as posture
import navigation_registry


def metrics(cpu=20.0, memory=30.0, disk=50.0):
    return {
        "cpu_usage": {"value": cpu, "unit": "%", "source": "fixture"},
        "memory_usage": {"value": memory, "unit": "%", "source": "fixture"},
        "system_disk_free": {"value": disk, "unit": "%", "source": "fixture"},
    }


def limited_checks():
    return [posture._source_limited(key, "Fixture", "indeterminate") for key in posture.CHECK_KEYS]


class RegistrySafetyTests(unittest.TestCase):
    def test_01_catalog_has_only_allowlisted_playbooks(self):
        self.assertEqual({item.playbook_id for item in assist.PLAYBOOKS}, {
            "STORAGE_SPACE_REVIEW", "ENDPOINT_POSTURE_REVIEW",
            "MONITORING_ALERT_REVIEW", "NETWORK_CHANGE_REVIEW",
            "MONITORING_SETTINGS_REVIEW",
        })

    def test_02_catalog_ids_are_unique(self):
        ids = [item.playbook_id for item in assist.PLAYBOOKS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_03_catalog_versions_are_explicit(self):
        self.assertTrue(all(item.version == 1 for item in assist.PLAYBOOKS))

    def test_04_step_ids_are_unique_per_playbook(self):
        for playbook in assist.PLAYBOOKS:
            ids = [step.step_id for step in playbook.steps]
            self.assertEqual(len(ids), len(set(ids)))

    def test_05_only_allowed_step_types_exist(self):
        self.assertTrue(all(
            step.step_type in assist.STEP_TYPES
            for playbook in assist.PLAYBOOKS for step in playbook.steps
        ))

    def test_06_catalog_safe_actions_resolve_only_static_allowlist(self):
        self.assertEqual(assist.SAFE_ACTION_ALLOWLIST, {
            "REFRESH_ENDPOINT_POSTURE", "COLLECT_MONITORING_SAMPLE_NOW",
            "SET_MONITORING_INTERVAL", "SET_MONITORING_RETENTION_POLICY",
        })
        self.assertTrue(all(
            step.action_ref in assist.SAFE_ACTION_ALLOWLIST
            for playbook in assist.PLAYBOOKS for step in playbook.steps
            if step.step_type == "EXISTING_SAFE_ACTION"
        ))

    def test_07_unallowlisted_safe_action_is_rejected(self):
        bad_step = assist.StepDefinition("bad", "Bad", "Bad", "EXISTING_SAFE_ACTION", True, "none", action_ref="RUN")
        bad = replace(assist.PLAYBOOKS[0], playbook_id="BAD", steps=(bad_step,))
        with self.assertRaises(ValueError):
            assist.validate_registry((bad,))

    def test_08_unknown_step_type_is_rejected(self):
        bad_step = assist.StepDefinition("bad", "Bad", "Bad", "SHELL", True, "none")
        bad = replace(assist.PLAYBOOKS[0], playbook_id="BAD", steps=(bad_step,))
        with self.assertRaises(ValueError):
            assist.validate_registry((bad,))

    def test_09_unknown_context_is_rejected(self):
        bad = replace(assist.PLAYBOOKS[0], playbook_id="BAD", applicable_contexts=("REMOTE",))
        with self.assertRaises(ValueError):
            assist.validate_registry((bad,))

    def test_10_duplicate_playbook_id_is_rejected(self):
        with self.assertRaises(ValueError):
            assist.validate_registry((assist.PLAYBOOKS[0], assist.PLAYBOOKS[0]))

    def test_11_notes_reject_secrets(self):
        for value in ("senha=123", "token abc", "recovery key: x", "credencial local"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assist.sanitize_note(value)

    def test_12_notes_are_bounded_and_plain(self):
        self.assertEqual(len(assist.sanitize_note("x" * 900)), 500)

    def test_13_module_has_no_process_execution_calls(self):
        tree = ast.parse(Path(assist.__file__).read_text(encoding="utf-8"))
        forbidden = {"eval", "exec", "compile", "system", "Popen", "run", "call", "check_call", "check_output"}
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        } | {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"system", "Popen", "run", "call", "check_call", "check_output"}
        }
        self.assertFalse(calls & forbidden)

    def test_14_routes_are_fixed_module_ids(self):
        allowed = {item.module_id for item in navigation_registry.MODULES}
        for playbook in assist.PLAYBOOKS:
            for step in playbook.steps:
                if step.target_route:
                    self.assertIn(step.target_route, allowed)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Assistente Técnico ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = assist.AssistStore(self.temp.name)

    def timeline_context(self, summary="Mudança observada na rede DNS", source="NETWORK_INTELLIGENCE"):
        event = self.store.record_event(
            source=source, category="OPERATION", severity="NOTICE",
            status="OBSERVED", summary=summary, hostname="ASSIST-HOST",
        )
        return self.store.create_context("TIMELINE_EVENT", event["id"])

    def alert_context(self, *, disk=False):
        run = self.store.start_run(hostname="ASSIST-HOST", interval_seconds=60)
        for minute in range(3):
            values = metrics(cpu=20 if disk else 90, disk=4 if disk else 50)
            self.store.record_cycle(
                run["run_id"], values,
                observed_at_utc=datetime(2026, 9, 17, 12, minute, tzinfo=timezone.utc),
            )
        key = "system_disk_free" if disk else "cpu_usage"
        alert = self.store.list_alerts(hostname="ASSIST-HOST", metric_key=key)[0]
        return self.store.create_context("ALERT", alert["alert_id"])

    def posture_context(self):
        self.store.record_snapshot(limited_checks(), hostname="ASSIST-HOST")
        changed = limited_checks()
        changed[1] = posture.assess_tpm({"present": True, "ready": False})
        change = self.store.record_snapshot(changed, hostname="ASSIST-HOST")["changes"][0]
        return self.store.create_context("POSTURE_CHANGE", change["change_id"])

    def test_15_schema_six_migrates_to_current(self):
        other = tempfile.TemporaryDirectory(prefix="Configurador TI schema6 ç ")
        self.addCleanup(other.cleanup)
        old = posture.EndpointPostureStore(other.name)
        with sqlite3.connect(old.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 6)
        migrated = assist.AssistStore(other.name)
        with sqlite3.connect(migrated.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 9)

    def test_16_current_schema_reopen_is_idempotent(self):
        assist.AssistStore(self.temp.name)
        reopened = assist.AssistStore(self.temp.name)
        with sqlite3.connect(reopened.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 9)

    def test_17_schema_tables_and_indexes_exist(self):
        with sqlite3.connect(self.store.path) as connection:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        self.assertTrue({"assist_contexts", "playbook_sessions", "playbook_session_steps"} <= names)
        self.assertIn("idx_playbook_session_updated", names)

    def test_18_historical_store_accepts_schema_seven(self):
        self.assertIsNotNone(posture.EndpointPostureStore(self.temp.name))

    def test_19_timeline_context_references_without_raw_payload(self):
        context = self.timeline_context()
        self.assertEqual(context["source_type"], "TIMELINE_EVENT")
        self.assertEqual(set(context), {
            "context_id", "schema_version", "hostname", "source_type", "source_id",
            "summary", "created_at_utc", "updated_at_utc", "evidence_refs", "limitations",
            "investigation_session_id",
        })

    def test_20_same_source_context_is_deduplicated(self):
        context = self.timeline_context()
        again = self.store.create_context("TIMELINE_EVENT", context["source_id"])
        self.assertEqual(context["context_id"], again["context_id"])

    def test_21_manual_context_is_bounded_and_has_limitation(self):
        context = self.store.create_context("MANUAL_CONTEXT", summary="Revisão manual")
        self.assertIn("revisão humana", " ".join(context["limitations"]))

    def test_22_missing_source_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create_context("ALERT", "missing")

    def test_23_unknown_source_type_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create_context("REMOTE", "x")

    def test_24_alert_context_keeps_local_references(self):
        context = self.alert_context()
        self.assertIn("ALERT", {item["type"] for item in context["evidence_refs"]})

    def test_25_disk_alert_gets_storage_and_monitoring_rules(self):
        ids = {item["playbook_id"] for item in self.store.recommend(self.alert_context(disk=True))}
        self.assertEqual(ids, {"STORAGE_SPACE_REVIEW", "MONITORING_ALERT_REVIEW"})

    def test_26_cpu_alert_gets_monitoring_rule_only(self):
        ids = {item["playbook_id"] for item in self.store.recommend(self.alert_context())}
        self.assertEqual(ids, {"MONITORING_ALERT_REVIEW"})

    def test_27_posture_attention_gets_posture_rule(self):
        recommendations = self.store.recommend(self.posture_context())
        self.assertEqual(recommendations[0]["playbook_id"], "ENDPOINT_POSTURE_REVIEW")

    def test_28_network_timeline_gets_network_rule(self):
        recommendations = self.store.recommend(self.timeline_context())
        self.assertEqual(recommendations[0]["playbook_id"], "NETWORK_CHANGE_REVIEW")

    def test_29_unrelated_timeline_has_no_invented_recommendation(self):
        self.assertEqual(self.store.recommend(self.timeline_context("Relatório local concluído", source="REPORTS")), [])

    def test_30_recommendation_is_deterministic(self):
        context = self.timeline_context()
        self.assertEqual(self.store.recommend(context), self.store.recommend(context))

    def test_31_recommendation_explains_rule_evidence_and_limit(self):
        item = self.store.recommend(self.timeline_context())[0]
        self.assertTrue(item["rule_id"] and item["rationale"] and item["evidence_refs"] and item["limitations"])

    def test_32_recommendation_has_no_probability_or_score(self):
        item = self.store.recommend(self.timeline_context())[0]
        self.assertFalse({"probability", "score", "risk_score"} & set(item))

    def test_33_start_session_persists_definition_version(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW", created_by="fixture")
        self.assertEqual((session["playbook_id"], session["playbook_version"]), ("NETWORK_CHANGE_REVIEW", 1))
        self.assertEqual(session["definition"]["version"], 1)

    def test_34_duplicate_open_session_is_reused(self):
        context = self.timeline_context()
        first = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        second = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        self.assertEqual(first["session_id"], second["session_id"])

    def test_35_initial_progress_is_pending(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        self.assertTrue(all(item["status"] == "PENDING" for item in session["steps"]))

    def test_36_step_can_be_completed_with_sanitized_note(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        updated = self.store.update_step(session["session_id"], session["steps"][0]["step_id"], "DONE", note="Revisado pelo técnico")
        self.assertEqual(updated["steps"][0]["note"], "Revisado pelo técnico")

    def test_37_required_step_cannot_be_skipped(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        with self.assertRaises(ValueError):
            self.store.update_step(session["session_id"], session["steps"][0]["step_id"], "SKIPPED")

    def test_38_optional_step_can_be_skipped(self):
        context = self.alert_context()
        session = self.store.start_session(context["context_id"], "MONITORING_ALERT_REVIEW")
        optional = next(item for item in session["steps"] if not item["definition"]["required"])
        updated = self.store.update_step(session["session_id"], optional["step_id"], "SKIPPED")
        self.assertEqual(next(item for item in updated["steps"] if item["step_id"] == optional["step_id"])["status"], "SKIPPED")

    def test_39_incomplete_required_steps_block_completion(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        with self.assertRaises(ValueError):
            self.store.complete_session(session["session_id"])

    def _complete_all_required(self, session):
        for step in session["steps"]:
            if step["definition"]["required"]:
                session = self.store.update_step(session["session_id"], step["step_id"], "DONE")
            elif step["status"] == "PENDING":
                session = self.store.update_step(session["session_id"], step["step_id"], "SKIPPED")
        return session

    def test_40_completed_session_is_persisted(self):
        context = self.timeline_context()
        session = self._complete_all_required(self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW"))
        self.assertEqual(self.store.complete_session(session["session_id"])["status"], "COMPLETED")

    def test_41_aborted_session_is_persisted(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        self.assertEqual(self.store.abort_session(session["session_id"])["status"], "ABORTED")

    def test_42_closed_session_can_be_reopened_with_same_version(self):
        context = self.timeline_context()
        session = self.store.abort_session(self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")["session_id"])
        reopened = self.store.reopen_session(session["session_id"])
        self.assertEqual((reopened["status"], reopened["playbook_version"]), ("OPEN", 1))

    def test_43_lifecycle_events_only_for_start_complete_abort(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        before = self.store.count_events(source="Assistente Técnico")
        self.store.update_step(session["session_id"], session["steps"][0]["step_id"], "DONE")
        self.assertEqual(self.store.count_events(source="Assistente Técnico"), before)
        self.store.abort_session(session["session_id"])
        self.assertEqual(self.store.count_events(source="Assistente Técnico"), before + 1)

    def test_44_lifecycle_details_reference_ids_not_payloads(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        event = self.store.query_events(source="Assistente Técnico", limit=1)[0]
        details = json.loads(event["details_json"])
        self.assertEqual(details["playbook_session_id"], session["session_id"])
        self.assertNotIn("definition", details)

    def test_45_history_is_bounded_and_paginated(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        self.store.abort_session(session["session_id"])
        self.assertEqual(len(self.store.list_playbook_sessions(limit=1, offset=0)), 1)
        self.assertEqual(self.store.list_playbook_sessions(limit=1, offset=1), [])

    def test_46_investigation_context_preserves_bidirectional_reference(self):
        investigation = self.store.create_session(
            title="Análise de rede", summary="Revisar DNS da rede", hostname="ASSIST-HOST", source="MANUAL"
        )
        context = self.store.create_context("INVESTIGATION_SESSION", investigation["session_id"])
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        self.assertEqual(session["investigation_session_id"], investigation["session_id"])

    def test_47_note_evidence_reference_is_structured(self):
        context = self.timeline_context()
        session = self.store.start_session(context["context_id"], "NETWORK_CHANGE_REVIEW")
        step = session["steps"][0]
        updated = self.store.update_step(
            session["session_id"], step["step_id"], "DONE",
            evidence_ref={"type": "TIMELINE_EVENT", "id": context["source_id"], "raw": "ignored"},
        )
        self.assertEqual(updated["steps"][0]["evidence_ref"], {"type": "TIMELINE_EVENT", "id": context["source_id"]})

    def test_48_invalid_playbook_context_pair_is_rejected(self):
        context = self.timeline_context()
        with self.assertRaises(ValueError):
            self.store.start_session(context["context_id"], "STORAGE_SPACE_REVIEW")

    def test_48a_network_change_group_uses_persisted_change_metadata(self):
        now = "2026-09-17T12:00:00.000000Z"
        with self.store._connect() as connection:
            connection.execute("""
                INSERT INTO change_groups (
                    operation_id,schema_version,detected_at_utc,hostname,source,
                    counts_json,coverage_json,summary,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
            """, ("network-group", 1, now, "ASSIST-HOST", "BASELINE", "{}", "{}", "Comparação local", now))
            connection.execute("""
                INSERT INTO changes (
                    change_id,schema_version,detected_at_utc,hostname,source,entity_type,
                    identity_key,change_type,coverage_state,evidence_json,operation_id,summary,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, ("network-change", 1, now, "ASSIST-HOST", "Network Intelligence", "Adaptador de rede",
                  "Ethernet", "CHANGED", "COMPLETE", "{}", "network-group", "DNS alterado", now))
        context = self.store.create_context("CHANGE_GROUP", "network-group")
        self.assertEqual(self.store.recommend(context)[0]["playbook_id"], "NETWORK_CHANGE_REVIEW")


class GuiContractTests(unittest.TestCase):
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

    def test_49_assist_is_inside_operations_hub(self):
        modules = {item.module_id for item in navigation_registry.modules_for_domain("operations")}
        self.assertIn("assist", modules)
        self.assertEqual(len(self.w.nav_buttons), 8)

    def test_50_assist_route_opens_dedicated_page(self):
        self.w._pagina_assist()
        self.assertEqual(self.w.pages.currentIndex(), 13)

    def test_51_assist_page_has_no_nested_tabs(self):
        from PyQt6.QtWidgets import QTabWidget
        self.assertEqual(self.w.assist_panel.findChildren(QTabWidget), [])

    def test_52_context_shortcuts_are_present(self):
        self.assertTrue(hasattr(self.w.audit_panel, "assist_button"))
        self.assertTrue(hasattr(self.w.endpoint_posture_panel, "assist_button"))
        self.assertTrue(hasattr(self.w.investigation_panel, "session_assist_button"))

    def test_53_posture_technical_evidence_is_dark_theme_target(self):
        self.assertEqual(self.w.endpoint_posture_panel.technical.objectName(), "PostureTechnicalEvidence")
        self.assertTrue(self.w.endpoint_posture_panel.technical.isReadOnly())
        qss = Path(__file__).resolve().parents[2].joinpath("style.qss").read_text(encoding="utf-8")
        self.assertIn("QPlainTextEdit#PostureTechnicalEvidence", qss)
        self.assertIn("background: #111d2d", qss)

    def test_54_layout_remains_usable_at_1366_width(self):
        self.w.resize(1366, 768)
        self.w._pagina_assist()
        self.base.app.processEvents()
        self.assertGreaterEqual(self.w.pages.width(), 800)


if __name__ == "__main__":
    unittest.main(verbosity=2)
