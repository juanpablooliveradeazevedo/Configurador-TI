"""Testes da Fase 1D-C-C — Correlation & Incident Replay MVP."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import incident_replay as replay


BASE = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


def utc(minutes=0):
    return (BASE + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI replay ç ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = replay.IncidentReplayStore(self.root)
        self._seed()

    def _event(self, event_id, minute, *, host="LAB", source="SourceA", operation=None,
               correlation=None, summary=None):
        return self.store.record_event(
            event_id=event_id, source=source, category="OPERATION", severity="INFO",
            status="OBSERVED", summary=summary or event_id, timestamp_utc=utc(minute),
            hostname=host, operation_id=operation, correlation_id=correlation,
            details={"evidence": event_id},
        )

    @staticmethod
    def _change(change_id, minute, operation, identity, source="SourceA", host="LAB",
                correlation=None):
        return {
            "change_id": change_id, "schema_version": 1,
            "detected_at_utc": utc(minute), "hostname": host, "source": source,
            "entity_type": "Processo", "identity_key": identity,
            "change_type": "CHANGED", "coverage_state": "OBSERVED",
            "before_json": '{"v":1}', "after_json": '{"v":2}',
            "evidence_json": '{"reason":"fixture"}', "baseline_id": "baseline-fixture",
            "baseline_revision": utc(-30), "operation_id": operation,
            "correlation_id": correlation, "timeline_event_id": None,
            "summary": f"Alterado: {identity}", "created_at": utc(minute),
        }

    def _group(self, operation, minute, changes, correlation=None, host="LAB", source="Baseline defensivo"):
        return {
            "operation_id": operation, "schema_version": 1,
            "detected_at_utc": utc(minute), "hostname": host, "source": source,
            "baseline_id": "baseline-fixture", "baseline_revision": utc(-30),
            "correlation_id": correlation, "timeline_event_id": None,
            "counts": {"NEW": 0, "CHANGED": len(changes), "ABSENT": 0, "INDETERMINATE": 0},
            "coverage": {"reference_complete": True, "current_complete": True},
            "changes": changes, "created_at": utc(minute),
        }

    def _seed(self):
        self._event("event-before", -2)
        self._event("event-main", 0, operation="op-main", correlation="corr-main")
        self._event("event-correlation", 1, source="SourceX", operation="op-other", correlation="corr-main")
        self._event("event-temporal", 2)
        self._event("event-after", 3)
        self._event("event-far", 20)
        self._event("event-other-host", 2, host="OTHER")
        main_change = self._change("change-main", 0, "op-main", "entity-a", correlation="corr-main")
        second_change = self._change("change-second", 0, "op-main", "entity-b", source="SourceB", correlation="corr-main")
        self.store.record_comparison(self._group("op-main", 0, [main_change, second_change], "corr-main"))
        entity_change = self._change("change-entity", 4, "op-entity", "entity-a")
        self.store.record_comparison(self._group("op-entity", 4, [entity_change]))

    def main_session(self):
        return self.store.create_from_timeline_event("event-main")

    def test_01_schema_migration_is_idempotent_and_indexed(self):
        reopened = replay.IncidentReplayStore(self.root)
        self.assertIsNotNone(reopened)
        with sqlite3.connect(self.store.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"events", "change_groups", "changes", "investigation_sessions", "investigation_items"}.issubset(tables))
            indexes = {row[1] for row in connection.execute("PRAGMA index_list(investigation_items)")}
            self.assertTrue({"idx_items_session", "idx_items_observed", "idx_items_reference", "idx_items_relation"}.issubset(indexes))

    def test_02_create_session_has_explicit_window_and_status(self):
        session = self.store.create_session(title="Sessão manual", hostname="LAB", source="MANUAL",
                                            window_start_utc=utc(-1), window_end_utc=utc(1))
        self.assertEqual(session["status"], "OPEN")
        self.assertEqual(session["hostname"], "LAB")
        self.assertLessEqual(session["window_start_utc"], session["window_end_utc"])

    def test_03_persistence_after_reopen(self):
        session = self.main_session()
        reopened = replay.IncidentReplayStore(self.root)
        self.assertEqual(reopened.get_session(session["session_id"])["title"], session["title"])
        self.assertEqual(len(reopened.list_items(session["session_id"])), 1)

    def test_04_timeline_group_change_and_baseline_items(self):
        session = self.main_session()
        sid = session["session_id"]
        self.store.add_item(sid, item_type="CHANGE_GROUP", referenced_id="op-main", relation_type="SAME_OPERATION")
        self.store.add_item(sid, item_type="CHANGE", referenced_id="change-main", relation_type="SAME_OPERATION")
        self.store.add_item(sid, item_type="BASELINE_REFERENCE", referenced_id="baseline-fixture", relation_type="MANUAL")
        self.assertEqual({item["item_type"] for item in self.store.list_items(sid)}, set(replay.ITEM_TYPES))

    def test_05_duplicate_item_is_prevented(self):
        sid = self.main_session()["session_id"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.add_item(sid, item_type="TIMELINE_EVENT", referenced_id="event-main")

    def _relations(self, sid):
        return {(item["item_type"], item["referenced_id"]): item["relation_type"]
                for item in self.store.suggest_related(sid, limit=200)}

    def test_06_same_operation_has_highest_priority(self):
        relations = self._relations(self.main_session()["session_id"])
        self.assertEqual(relations[("CHANGE_GROUP", "op-main")], "SAME_OPERATION")
        self.assertEqual(relations[("CHANGE", "change-main")], "SAME_OPERATION")

    def test_07_same_correlation_is_explicit(self):
        relations = self._relations(self.main_session()["session_id"])
        self.assertEqual(relations[("TIMELINE_EVENT", "event-correlation")], "SAME_CORRELATION")

    def test_08_same_entity_after_human_selection(self):
        sid = self.main_session()["session_id"]
        self.store.add_item(sid, item_type="CHANGE", referenced_id="change-main", relation_type="SAME_OPERATION")
        relations = self._relations(sid)
        self.assertEqual(relations[("CHANGE", "change-entity")], "SAME_ENTITY")

    def test_09_temporal_near_is_weak_and_never_causal(self):
        sid = self.main_session()["session_id"]
        suggestions = self.store.suggest_related(sid, limit=200)
        temporal = next(item for item in suggestions if item["referenced_id"] == "event-temporal")
        self.assertEqual((temporal["relation_type"], temporal["strength"]), ("TEMPORAL_NEAR", "WEAK"))
        summary = self.store.session_summary(sid)
        self.assertFalse(summary["causality_inferred"])
        self.assertIn("Nenhuma causalidade", summary["text"])

    def test_10_different_hosts_are_not_suggested_automatically(self):
        suggestions = self.store.suggest_related(self.main_session()["session_id"], limit=200)
        self.assertNotIn("event-other-host", {item["referenced_id"] for item in suggestions})

    def test_11_temporal_window_is_respected(self):
        suggestions = self.store.suggest_related(self.main_session()["session_id"], limit=200)
        self.assertNotIn("event-far", {item["referenced_id"] for item in suggestions})

    def test_12_add_remove_and_relevance_levels(self):
        sid = self.main_session()["session_id"]
        item = self.store.add_item(sid, item_type="TIMELINE_EVENT", referenced_id="event-temporal",
                                   relation_type="TEMPORAL_NEAR")
        for level in replay.RELEVANCE_LEVELS:
            self.assertEqual(self.store.update_item(item["item_id"], relevance=level)["relevance"], level)
        self.assertTrue(self.store.remove_item(item["item_id"]))
        self.assertIsNone(self.store.get_item(item["item_id"]))

    def test_13_manual_note_is_limited_plain_and_sanitized(self):
        sid = self.main_session()["session_id"]
        item = self.store.list_items(sid)[0]
        updated = self.store.update_item(item["item_id"], note="token=SECRET_SENTINEL " + "x" * 800)
        self.assertNotIn("SECRET_SENTINEL", updated["note"])
        self.assertLessEqual(len(updated["note"]), replay.MAX_NOTE_CHARS)

    def test_14_chronological_replay_and_before_during_after(self):
        sid = self.main_session()["session_id"]
        self.store.add_item(sid, item_type="TIMELINE_EVENT", referenced_id="event-before", relation_type="TEMPORAL_NEAR")
        self.store.add_item(sid, item_type="TIMELINE_EVENT", referenced_id="event-after", relation_type="TEMPORAL_NEAR")
        result = self.store.build_replay(sid)
        self.assertEqual([item["referenced_id"] for item in result], ["event-before", "event-main", "event-after"])
        self.assertEqual([item["phase"] for item in result], ["ANTES", "DURANTE", "DEPOIS"])

    def test_15_replay_falls_back_to_simple_sequence(self):
        session = self.store.create_session(title="Sem eixo", hostname="LAB", source="MANUAL",
                                            window_start_utc=utc(-5), window_end_utc=utc(5))
        self.store.add_item(session["session_id"], item_type="TIMELINE_EVENT",
                            referenced_id="event-before", relation_type="MANUAL")
        self.assertEqual(self.store.build_replay(session["session_id"])[0]["phase"], "SEQUÊNCIA")

    def test_16_summary_counts_types_and_relation_strength(self):
        sid = self.main_session()["session_id"]
        self.store.add_item(sid, item_type="CHANGE_GROUP", referenced_id="op-main", relation_type="SAME_OPERATION")
        self.store.add_item(sid, item_type="TIMELINE_EVENT", referenced_id="event-temporal", relation_type="TEMPORAL_NEAR")
        summary = self.store.session_summary(sid)
        self.assertEqual((summary["events"], summary["change_groups"], summary["strong_relations"], summary["weak_relations"]), (2, 1, 2, 1))

    def test_17_session_filters_and_pagination(self):
        for index in range(5):
            self.store.create_session(title=f"Filtro {index}", hostname="LAB", source="MANUAL",
                                      status="REVIEWED" if index % 2 else "OPEN")
        self.assertEqual(len(self.store.list_sessions(limit=2)), 2)
        self.assertEqual(self.store.count_sessions(status="REVIEWED"), 2)
        self.assertEqual(len(self.store.list_sessions(text="Filtro", limit=10, offset=2)), 3)

    def test_18_create_from_group_and_change_deep_links(self):
        group = self.store.create_from_change_group("op-main")
        change = self.store.create_from_change("change-main")
        self.assertEqual(self.store.list_items(group["session_id"])[0]["item_type"], "CHANGE_GROUP")
        self.assertEqual(self.store.list_items(change["session_id"])[0]["item_type"], "CHANGE")

    def test_19_invalid_reference_and_window_fail_controlled(self):
        with self.assertRaises(ValueError):
            self.store.create_from_timeline_event("missing")
        with self.assertRaises(ValueError):
            self.store.create_session(title="Inválida", hostname="LAB", source="MANUAL",
                                      window_start_utc=utc(2), window_end_utc=utc(-2))

    def test_20_best_effort_does_not_leak_or_raise(self):
        logger = MagicMock()
        result = replay.investigation_action_safe(None, logger, lambda _store: None)
        self.assertIsNone(result)
        self.assertIn("RuntimeError", " ".join(map(str, logger.error.call_args_list)))

    def test_21_queries_are_bounded(self):
        self.assertEqual(replay.MAX_QUERY_LIMIT, 200)
        self.assertEqual(len(self.store.suggest_related(self.main_session()["session_id"], limit=9999)),
                         len(self.store.suggest_related(self.store.list_sessions()[0]["session_id"], limit=200)))


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests()
        self.case.setUp()
        self.w = self.case.w
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI replay GUI ç ")
        self.addCleanup(self.temp.cleanup)
        self.store = replay.IncidentReplayStore(self.temp.name)
        self.w._audit_store = self.store
        self.w._change_store = self.store
        self.w._incident_store = self.store
        self.event = self.store.record_event(
            event_id="gui-event", source="GUI", category="OPERATION", severity="INFO",
            status="OBSERVED", summary="Evento GUI", hostname="GUI-HOST", operation_id="gui-op",
        )

    def tearDown(self):
        self.case.tearDown()

    def _wait(self):
        deadline = time.monotonic() + 5
        while self.w._workers and time.monotonic() < deadline:
            self.base.app.processEvents()
            time.sleep(0.005)
        self.assertFalse(self.w._workers)

    def test_22_timeline_to_session_deep_link(self):
        self.w._criar_investigacao_evento(self.event["id"])
        self._wait()
        first = self.w.investigation_panel._session_id
        self.w._criar_investigacao_evento(self.event["id"])
        self._wait()
        self.assertEqual(self.w.pages.currentIndex(), 11)
        self.assertEqual(self.w.investigation_panel._session_id, first)
        self.assertEqual(self.store.count_sessions(), 1)

    def test_23_change_intelligence_to_session_deep_link(self):
        change = StoreTests._change("gui-change", 0, "gui-group", "gui-entity", host="GUI-HOST")
        self.store.record_comparison(StoreTests._group(self, "gui-group", 0, [change], host="GUI-HOST"))
        self.w._criar_investigacao_mudanca("gui-change")
        self._wait()
        self.assertEqual(self.store.list_items(self.w.investigation_panel._session_id)[0]["item_type"], "CHANGE")

    def test_24_qt_offscreen_session_replay_details_and_suggestions(self):
        session = self.store.create_from_timeline_event(self.event["id"])
        panel = self.w.investigation_panel
        panel._session_id = session["session_id"]
        payload = panel._session_query()
        panel._present_session(payload)
        self.assertEqual(panel.replay_table.rowCount(), 1)
        panel.replay_table.selectRow(0)
        self.base.app.processEvents()
        self.assertIn("Causalidade inferida: NÃO", panel.session_details.toPlainText())
        self.assertIn("Nenhuma causalidade", panel.session_summary.text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
