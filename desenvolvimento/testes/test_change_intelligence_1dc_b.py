"""Testes da Fase 1D-C-B — Change Intelligence + Investigation View MVP."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import audit_timeline as audit
import change_intelligence as ci
from baseline_defensivo import BaselineStore, compare, snapshot, unknown_coverage


def full_coverage():
    coverage = unknown_coverage()
    for entry in coverage["sources"].values():
        entry["state"] = "Disponível"
        entry["reasons"] = []
    return coverage


def evidence(name, *, size=10, path=None):
    path = path or rf"C:\Apps\{name}.exe"
    return snapshot({
        "Tipo": "Processo", "Nome": name, "Fonte": "Win32_Process",
        "Caminho": path, "ContextoUsuario": "LAB", "Existe": True,
        "TamanhoBytes": size, "ModificadoUtc": "2026-09-16T10:00:00Z",
        "Comando": rf'"{path}" --token SECRET_SENTINEL_1DC_B',
    }, lambda value: value)


def prepared(records, coverage=None):
    coverage = coverage or full_coverage()
    return {"complete": all(x["state"] == "Disponível" for x in coverage["sources"].values()),
            "coverage": coverage, "records": records}


def weak_service(name):
    return snapshot({
        "Tipo": "Serviço", "Nome": name, "Fonte": "Win32_Service",
        "NomeTecnico": None, "Existe": True, "TamanhoBytes": None,
        "ModificadoUtc": None,
    }, lambda value: value)


def comparison_fixture():
    before = evidence("alterado", size=10)
    after = evidence("alterado", size=20)
    new = evidence("novo")
    absent = evidence("ausente")
    weak = weak_service("fraco")
    stable = evidence("estavel")
    reference = prepared([before, absent, stable])
    current = prepared([after, new, weak, stable])
    return compare(reference, current), reference, current


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI change intelligence ç ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit = audit.AuditTimelineStore(self.root)
        self.store = ci.ChangeIntelligenceStore(self.root)

    def persist(self, operation="operation-fixture"):
        comparison, reference, current = comparison_fixture()
        result = ci.persist_comparison_safe(
            self.store, self.audit, comparison=comparison, reference=reference,
            current=current, operation_id=operation, baseline_id="a" * 64,
        )
        return result, comparison, reference, current

    def test_schema_migration_is_idempotent_and_timeline_compatible(self):
        path = self.root / "dados/auditoria/timeline.db"
        with sqlite3.connect(path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            self.assertTrue({"events", "change_groups", "changes"}.issubset(tables))
            indexes = {row[1] for row in connection.execute("PRAGMA index_list(changes)")}
            self.assertTrue({"idx_changes_detected", "idx_changes_type", "idx_changes_source",
                             "idx_changes_entity", "idx_changes_operation", "idx_changes_baseline"}.issubset(indexes))
        ci.ChangeIntelligenceStore(self.root)
        audit.AuditTimelineStore(self.root).record_event(
            source="Sistema", category="SYSTEM", severity="INFO", status="OBSERVED",
            summary="Timeline após migração",
        )

    def test_persists_all_four_types_and_skips_unchanged(self):
        result, comparison, reference, current = self.persist()
        self.assertTrue(result["persisted"])
        rows = self.store.query_changes(operation_id=result["operation_id"])
        self.assertEqual({row["change_type"] for row in rows}, set(ci.CHANGE_TYPES))
        self.assertEqual(len(rows), 4)
        self.assertEqual(comparison["counts"]["Sem alteração"], 1)

    def test_changed_before_after_only_contains_real_differences(self):
        result, *_ = self.persist()
        row = self.store.query_changes(
            operation_id=result["operation_id"], change_type="CHANGED"
        )[0]
        before = json.loads(row["before_json"])
        after = json.loads(row["after_json"])
        self.assertEqual(before, {"TamanhoBytes": 10})
        self.assertEqual(after, {"TamanhoBytes": 20})

    def test_new_and_absent_do_not_invent_missing_side(self):
        result, *_ = self.persist()
        new = self.store.query_changes(operation_id=result["operation_id"], change_type="NEW")[0]
        absent = self.store.query_changes(operation_id=result["operation_id"], change_type="ABSENT")[0]
        self.assertIsNone(new["before_json"])
        self.assertIsNotNone(new["after_json"])
        self.assertIsNotNone(absent["before_json"])
        self.assertIsNone(absent["after_json"])

    def test_sanitization_omits_command_and_secrets(self):
        result, *_ = self.persist()
        raw = " ".join(str(row) for row in self.store.query_changes(
            operation_id=result["operation_id"]
        ))
        self.assertNotIn("SECRET_SENTINEL_1DC_B", raw)
        self.assertIn("[OMITIDO]", raw)

    def test_operation_group_timeline_relation_and_summary_counts(self):
        result, *_ = self.persist()
        group = self.store.get_group(result["operation_id"])
        self.assertEqual(group["counts"], {kind: 1 for kind in ci.CHANGE_TYPES})
        self.assertEqual(group["timeline_event_id"], result["timeline_event_id"])
        rows = self.store.query_changes(operation_id=result["operation_id"])
        self.assertEqual({row["operation_id"] for row in rows}, {result["operation_id"]})
        self.assertEqual({row["timeline_event_id"] for row in rows}, {result["timeline_event_id"]})
        event = self.audit.get_event(result["timeline_event_id"])
        details = json.loads(event["details_json"])
        self.assertEqual(details["change_operation_id"], result["operation_id"])
        self.assertEqual(details["counts"], {kind: 1 for kind in ci.CHANGE_TYPES})

    def test_period_type_source_entity_text_and_pagination(self):
        result, *_ = self.persist()
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.assertEqual(self.store.count_changes(since_utc=since), 4)
        self.assertEqual(self.store.count_changes(change_type="NEW"), 1)
        self.assertEqual(self.store.count_changes(source="Win32_Process"), 3)
        self.assertEqual(self.store.count_changes(source="Win32_Service"), 1)
        self.assertEqual(self.store.count_changes(entity_type="Processo"), 3)
        self.assertEqual(self.store.count_changes(text="alterado"), 1)
        first = self.store.query_changes(operation_id=result["operation_id"], limit=2)
        second = self.store.query_changes(operation_id=result["operation_id"], limit=2, offset=2)
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 2)
        self.assertFalse({row["change_id"] for row in first} & {row["change_id"] for row in second})

    def test_persistence_after_reopen(self):
        result, *_ = self.persist()
        reopened = ci.ChangeIntelligenceStore(self.root)
        self.assertEqual(reopened.count_changes(operation_id=result["operation_id"]), 4)
        self.assertEqual(reopened.get_group(result["operation_id"])["counts"]["NEW"], 1)

    def test_store_failure_is_best_effort_and_comparison_survives(self):
        broken = MagicMock()
        broken.record_comparison.side_effect = sqlite3.OperationalError("SECRET_SENTINEL")
        logger = MagicMock()
        comparison, reference, current = comparison_fixture()
        result = ci.persist_comparison_safe(
            broken, self.audit, comparison=comparison, reference=reference,
            current=current, operation_id="broken-operation", logger=logger,
        )
        self.assertFalse(result["persisted"])
        self.assertEqual(result["counts"]["NEW"], 1)
        logged = " ".join(map(str, logger.error.call_args_list))
        self.assertIn("OperationalError", logged)
        self.assertNotIn("SECRET_SENTINEL", logged)

    def test_partial_coverage_and_indeterminate_are_preserved(self):
        coverage = full_coverage()
        coverage["sources"]["Win32_Process"] = {
            "state": "Indisponível", "reasons": ["Processos:coleta_indisponivel"]
        }
        reference = prepared([], coverage)
        current = prepared([evidence("novo-parcial")])
        comparison = compare(reference, current)
        self.assertEqual(comparison["rows"][0]["state"], "Indeterminado")
        group = ci.structure_comparison_changes(
            comparison, reference=reference, current=current,
            operation_id="partial-operation",
        )
        self.assertFalse(group["coverage"]["reference_complete"])
        self.assertEqual(group["changes"][0]["change_type"], "INDETERMINATE")
        self.assertEqual(group["changes"][0]["coverage_state"], "INDETERMINATE")

    def test_new_absent_and_duplicate_identity_use_existing_engine(self):
        comparison, _reference, _current = comparison_fixture()
        self.assertEqual(comparison["counts"]["Novo"], 1)
        self.assertEqual(comparison["counts"]["Ausente"], 1)
        self.assertEqual(comparison["counts"]["Indeterminado"], 1)
        duplicate = evidence("duplicado")
        result = compare(prepared([duplicate, duplicate]), prepared([duplicate]))
        self.assertTrue(result["rows"])
        self.assertTrue(all(row["state"] == "Indeterminado" for row in result["rows"]))


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests()
        self.case.setUp()
        self.w = self.case.w
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI investigation GUI ç ")
        self.addCleanup(self.temp.cleanup)
        self.w._audit_store = audit.AuditTimelineStore(self.temp.name)
        self.w._change_store = ci.ChangeIntelligenceStore(self.temp.name)
        comparison, reference, current = comparison_fixture()
        self.result = ci.persist_comparison_safe(
            self.w._change_store, self.w._audit_store, comparison=comparison,
            reference=reference, current=current, operation_id="gui-operation",
            baseline_id="b" * 64,
        )

    def tearDown(self):
        self.case.tearDown()

    def _wait_workers(self):
        deadline = time.monotonic() + 5
        while self.w._workers and time.monotonic() < deadline:
            self.base.app.processEvents()
            time.sleep(0.005)
        self.assertFalse(self.w._workers)

    def test_investigation_offscreen_filters_summary_details_and_empty(self):
        panel = self.w.investigation_panel
        panel.period.setCurrentIndex(panel.period.findData(None))
        payload = panel._query(0, panel._filter_snapshot())
        panel._present(payload)
        self.assertEqual(panel.table.rowCount(), 4)
        self.assertIn("Novo: 1", panel.summary.text())
        panel.table.selectRow(0)
        self.base.app.processEvents()
        self.assertIn("BEFORE", panel.details.toPlainText())
        self.assertIn("EVIDÊNCIAS", panel.details.toPlainText())
        panel.change_type.setCurrentIndex(panel.change_type.findData("NEW"))
        filtered = panel._query(0, panel._filter_snapshot())
        self.assertEqual(filtered["total"], 1)
        panel.search.setText("inexistente")
        empty = panel._query(0, panel._filter_snapshot())
        panel._present(empty)
        self.assertIn("Nenhuma mudança", panel.status.text())

    def test_timeline_to_investigation_navigation(self):
        panel = self.w.audit_panel
        panel.period.setCurrentIndex(panel.period.findData(None))
        panel._present(panel._query(0, panel._filter_snapshot()))
        target = next(index for index, event in enumerate(panel._events)
                      if event["id"] == self.result["timeline_event_id"])
        panel.table.selectRow(target)
        self.base.app.processEvents()
        self.assertTrue(panel.investigate_button.isEnabled())
        panel.open_investigation()
        self._wait_workers()
        self.assertEqual(self.w.pages.currentIndex(), 11)
        self.assertEqual(self.w.investigation_panel._operation_filter, "gui-operation")
        self.assertEqual(self.w.investigation_panel._total, 4)

    def test_baseline_panel_persists_current_comparison_best_effort(self):
        panel = self.w.baseline_panel
        panel.store = BaselineStore(
            self.temp.name, "c" * 64, lambda value: value, MagicMock()
        )
        reference = prepared([evidence("integrado", size=10)])
        panel.store.save(reference, None, explicit=True)
        current_item = evidence("integrado", size=20)["evidence"]
        panel.receive({
            "Sucesso": True, "Cancelada": False, "Itens": [current_item],
            "FontesIndisponiveis": [], "Defender": {"Disponivel": True},
            "Contexto": {"StartupUser": "informada", "StartupCommon": "informada"},
        })
        self._wait_workers()
        self.assertTrue(panel.last_change_operation_id)
        self.assertTrue(panel.investigation_button.isEnabled())
        self.assertEqual(
            self.w._change_store.count_changes(
                operation_id=panel.last_change_operation_id, change_type="CHANGED"
            ), 1,
        )
        events = self.w._audit_store.query_events()
        self.assertTrue(any(
            event["status"] == "OBSERVED" and
            json.loads(event["details_json"] or "{}").get("change_operation_id") == panel.last_change_operation_id
            for event in events
        ))

    def test_investigation_store_failure_does_not_mutate_other_layers(self):
        panel = self.w.investigation_panel
        with patch.object(self.w, "_get_change_store", return_value=None):
            payload = panel._query(0, panel._filter_snapshot())
        panel._present(payload)
        self.assertFalse(payload["ok"])
        self.assertIn("indisponível", panel.status.text())
        self.assertIsNotNone(self.w._audit_store.get_event(self.result["timeline_event_id"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
