"""Testes da fundação local Audit & Timeline 1D-C-A."""
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


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI audit timeline ç ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = audit.AuditTimelineStore(self.root)

    def event(self, **changes):
        values = dict(
            source="Manutenção", category="MAINTENANCE", severity="INFO",
            status="OBSERVED", summary="Evento de teste",
        )
        values.update(changes)
        return self.store.record_event(**values)

    def test_schema_creation_is_idempotent_versioned_and_indexed(self):
        path = self.root / "dados/auditoria/timeline.db"
        self.assertTrue(path.is_file())
        reopened = audit.AuditTimelineStore(self.root)
        self.assertEqual(reopened.path, path)
        with sqlite3.connect(path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
            self.assertTrue({
                "id", "schema_version", "timestamp_utc", "hostname", "source",
                "category", "severity", "status", "summary", "details_json",
                "operation_id", "correlation_id", "created_at",
            }.issubset(columns))
            indexes = {row[1] for row in connection.execute("PRAGMA index_list(events)")}
            self.assertTrue({"idx_events_timestamp", "idx_events_source", "idx_events_severity"}.issubset(indexes))

    def test_insert_valid_event_and_get_by_id(self):
        event = self.event(
            status="STARTED", details={"item": "limpeza"},
            operation_id="operation-fixture", correlation_id="correlation-fixture",
        )
        stored = self.store.get_event(event["id"])
        self.assertEqual(stored["schema_version"], 1)
        self.assertEqual(stored["source"], "Manutenção")
        self.assertTrue(stored["timestamp_utc"].endswith("Z"))
        self.assertEqual(json.loads(stored["details_json"]), {"item": "limpeza"})

    def test_enums_normalize_known_values_and_reject_unknown(self):
        event = self.event(category="maintenance", severity="notice", status="completed")
        self.assertEqual((event["category"], event["severity"], event["status"]),
                         ("MAINTENANCE", "NOTICE", "COMPLETED"))
        for field, value in (("category", "SECURITY_DIAGNOSIS"),
                             ("severity", "CRITICAL"), ("status", "UNKNOWN")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.event(**{field: value})

    def test_details_serializable_and_nonserializable_never_break_insert(self):
        class Unsupported:
            pass
        event = self.event(details={"path": self.root, "unsupported": Unsupported()})
        details = json.loads(event["details_json"])
        self.assertEqual(details["path"], str(self.root))
        self.assertEqual(details["unsupported"], "[não serializável: Unsupported]")

    def test_sensitive_and_command_fields_are_sanitized(self):
        secret = "SECRET_SENTINEL_1DC_A"
        event = self.event(details={
            "senha": secret, "api_key": secret, "nested": {"token": secret},
            "PowerShellScript": "Get-Secret " + secret, "safe": "contagem=3",
        })
        raw = event["details_json"]
        self.assertNotIn(secret, raw)
        details = json.loads(raw)
        self.assertEqual(details["senha"], "[REDACTED]")
        self.assertEqual(details["PowerShellScript"], "[OMITIDO]")
        self.assertEqual(details["safe"], "contagem=3")

    def test_details_size_is_bounded_as_valid_json(self):
        event = self.event(details={f"field_{index}": "x" * 1200 for index in range(64)})
        self.assertLessEqual(len(event["details_json"].encode("utf-8")), audit.MAX_DETAILS_BYTES)
        self.assertTrue(json.loads(event["details_json"])["truncated"])

    def test_query_period_source_severity_and_summary_text(self):
        old = datetime.now(timezone.utc) - timedelta(days=40)
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        self.event(source="Baseline defensivo", category="BASELINE", severity="NOTICE",
                   summary="Baseline carregado", timestamp_utc=recent)
        self.event(source="Relatórios", category="REPORT", severity="ERROR",
                   summary="Relatório falhou", timestamp_utc=recent)
        self.event(source="Baseline defensivo", category="BASELINE", severity="NOTICE",
                   summary="Baseline antigo", timestamp_utc=old)
        since = datetime.now(timezone.utc) - timedelta(days=7)
        self.assertEqual(len(self.store.query_events(since_utc=since)), 2)
        self.assertEqual(len(self.store.query_events(source="Relatórios")), 1)
        self.assertEqual(len(self.store.query_events(severity="ERROR")), 1)
        found = self.store.query_events(text="carregado")
        self.assertEqual([item["summary"] for item in found], ["Baseline carregado"])

    def test_recent_first_limit_offset_and_count(self):
        base = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        for index in range(7):
            self.event(summary=f"Evento {index}", timestamp_utc=base + timedelta(minutes=index))
        first = self.store.query_events(limit=3, offset=0)
        second = self.store.query_events(limit=3, offset=3)
        self.assertEqual([row["summary"] for row in first], ["Evento 6", "Evento 5", "Evento 4"])
        self.assertEqual([row["summary"] for row in second], ["Evento 3", "Evento 2", "Evento 1"])
        self.assertEqual(self.store.count_events(), 7)

    def test_persistence_after_reopening_store(self):
        event = self.event(summary="Persistência confirmada")
        reopened = audit.AuditTimelineStore(self.root)
        self.assertEqual(reopened.get_event(event["id"])["summary"], "Persistência confirmada")

    def test_safe_record_failure_does_not_escape_or_leak_details(self):
        logger = MagicMock()
        broken = MagicMock()
        broken.record_event.side_effect = sqlite3.OperationalError("SECRET_SENTINEL")
        result = audit.record_event_safe(
            broken, logger=logger, source="Sistema", category="SYSTEM",
            severity="ERROR", status="FAILED", summary="fixture",
        )
        self.assertIsNone(result)
        logged = " ".join(map(str, logger.error.call_args.args))
        self.assertIn("OperationalError", logged)
        self.assertNotIn("SECRET_SENTINEL", logged)

    def test_database_never_uses_meipass(self):
        meipass = self.root / "_MEI"
        meipass.mkdir()
        with patch.object(audit.sys, "_MEIPASS", str(meipass), create=True), \
                self.assertRaises(ValueError):
            audit.AuditTimelineStore(meipass)


class GuiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_ux_global as base
        cls.base = base

    def setUp(self):
        self.case = self.base.UxTests()
        self.case.setUp()
        self.w = self.case.w
        self.temp = tempfile.TemporaryDirectory(prefix="Configurador TI audit GUI ç ")
        self.addCleanup(self.temp.cleanup)
        self.w._audit_store = audit.AuditTimelineStore(self.temp.name)

    def tearDown(self):
        self.case.tearDown()

    def _wait_workers(self):
        deadline = time.monotonic() + 5
        while self.w._workers and time.monotonic() < deadline:
            self.base.app.processEvents()
            time.sleep(0.005)
        self.assertFalse(self.w._workers)

    def test_worker_lifecycle_records_start_and_completion_once(self):
        self.w._run(
            lambda: (True, "ok"), label="Fixture auditada",
            operation_key="audit_fixture", blocks_navigation=False,
            audit_source="Manutenção", audit_category="MAINTENANCE",
            audit_summary="Operação de manutenção fixture",
        )
        self._wait_workers()
        events = list(reversed(self.w._audit_store.query_events()))
        self.assertEqual([event["status"] for event in events], ["STARTED", "COMPLETED"])
        self.assertEqual(len({event["operation_id"] for event in events}), 1)

    def test_worker_failure_and_cancel_are_structured(self):
        def failure():
            raise RuntimeError("falha fixture")
        with patch.object(self.base.gui, "error_dialog"):
            self.w._run(
                failure, label="Fixture falha", operation_key="audit_failure",
                blocks_navigation=False, audit_source="Manutenção",
                audit_category="MAINTENANCE", audit_summary="Falha fixture",
            )
            self._wait_workers()
        statuses = [event["status"] for event in self.w._audit_store.query_events()]
        self.assertEqual(statuses[:2], ["FAILED", "STARTED"])

        worker = MagicMock()
        worker._audit_context = {
            "source": "Manutenção", "category": "MAINTENANCE",
            "summary": "Cancelamento fixture", "operation_id": "cancel-fixture",
        }
        self.w._audit_finish_worker(worker, "CANCELLED", "NOTICE")
        self.assertEqual(self.w._audit_store.query_events()[0]["status"], "CANCELLED")

    def test_audit_store_failure_does_not_block_main_operation(self):
        self.w._audit_store = None
        with patch.object(self.base.gui, "AuditTimelineStore", side_effect=OSError("sem banco")), \
                patch.object(self.base.gui.core_logic.logger, "exception"):
            self.w._run(
                lambda: (True, "principal concluída"), label="Principal",
                operation_key="principal", blocks_navigation=False,
                audit_source="Relatórios", audit_category="REPORT",
                audit_summary="Operação principal",
            )
            self._wait_workers()
        self.assertFalse(self.w._operation_workers)

    def test_minimum_integration_metadata_is_centralized(self):
        source = Path(self.base.gui.__file__).read_text(encoding="utf-8")
        baseline_source = (Path(self.base.gui.__file__).with_name("baseline_defensivo_gui.py")).read_text(encoding="utf-8")
        self.assertIn('audit_category="MAINTENANCE"', source)
        self.assertIn('audit_category="REPORT"', source)
        self.assertIn("audit_category='BASELINE'", baseline_source)
        self.assertIn("persist_comparison_safe", baseline_source)

    def test_timeline_page_offscreen_filters_details_and_empty_error_states(self):
        store = self.w._audit_store
        store.record_event(
            source="Relatórios", category="REPORT", severity="ERROR", status="FAILED",
            summary="Relatório falhou", details={"code": 5},
        )
        store.record_event(
            source="Baseline defensivo", category="BASELINE", severity="NOTICE",
            status="COMPLETED", summary="Baseline carregado",
        )
        panel = self.w.audit_panel
        panel.period.setCurrentIndex(panel.period.findData(None))
        payload = panel._query(0)
        panel._present(payload)
        self.assertEqual(panel.table.rowCount(), 2)
        self.assertEqual(panel.table.item(0, 0).text().count("/"), 2)
        panel.table.selectRow(0)
        self.base.app.processEvents()
        self.assertIn("Timestamp UTC:", panel.details.toPlainText())
        self.assertIn("Details JSON:", panel.details.toPlainText())
        panel.source.setCurrentIndex(panel.source.findData("Relatórios"))
        panel.severity.setCurrentIndex(panel.severity.findData("ERROR"))
        panel.search.setText("falhou")
        filtered = panel._query(0)
        self.assertEqual(len(filtered["events"]), 1)
        panel._present(filtered)
        self.assertIn("exibindo 1 de 1", panel.summary.text())

        with patch.object(self.w, "_get_audit_store", return_value=None):
            error_payload = panel._query(0)
        panel._present(error_payload)
        self.assertIn("não foi possível", panel.status.text().lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
