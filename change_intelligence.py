"""Persistência local de mudanças derivadas da comparação defensiva existente.

Este módulo não classifica itens. Ele consome o resultado de ``compare`` e
estrutura somente fatos já decididos pelo motor aprovado de baseline.
"""
from __future__ import annotations

from collections import Counter
import json
import socket
import sqlite3
import uuid

from audit_timeline import (
    AuditTimelineStore, _clean_text, _utc_text, record_event_safe,
    sanitize_details,
)
from baseline_defensivo import (
    coverage_complete, logical_key, required_sources, unknown_coverage,
)


DATABASE_SCHEMA_VERSION = 2
CHANGE_SCHEMA_VERSION = 1
CHANGE_TYPES = ("NEW", "CHANGED", "ABSENT", "INDETERMINATE")
STATE_MAP = {
    "Novo": "NEW",
    "Alterado": "CHANGED",
    "Ausente": "ABSENT",
    "Indeterminado": "INDETERMINATE",
}
MAX_CHANGES_PER_GROUP = 3000
MAX_QUERY_LIMIT = 200


def _json_or_none(value):
    return sanitize_details(value) if value is not None else None


def _loads(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _coverage_view(coverage, evidence):
    coverage = coverage or unknown_coverage()
    names = required_sources(evidence or {})
    return {
        name: coverage["sources"][name]["state"]
        for name in names
        if name in coverage.get("sources", {})
    }


def _compact_evidence(evidence):
    if not isinstance(evidence, dict):
        return None
    return {key: value for key, value in evidence.items() if value is not None}


def _before_after(row, change_type):
    before = row.get("before")
    after = row.get("after")
    if change_type == "CHANGED":
        changed = row.get("changes") or []
        return (
            {field: old for field, old, _new in changed},
            {field: new for field, _old, new in changed},
        )
    if change_type == "NEW":
        return None, _compact_evidence(after)
    if change_type == "ABSENT":
        return _compact_evidence(before), None
    return _compact_evidence(before), _compact_evidence(after)


def _entity_name(evidence):
    if not isinstance(evidence, dict):
        return "Entidade sem nome disponível"
    return next((str(evidence.get(field)).strip() for field in (
        "Nome", "NomeTecnico", "ArquivoStartup", "CaminhoTarefa", "Caminho",
    ) if evidence.get(field)), "Entidade sem nome disponível")


def structure_comparison_changes(comparison, *, reference, current,
                                 operation_id, baseline_id=None,
                                 correlation_id=None, detected_at_utc=None,
                                 hostname=None):
    """Converte linhas já classificadas sem reavaliar estado ou cobertura."""
    if not isinstance(comparison, dict) or not isinstance(comparison.get("rows"), list):
        raise ValueError("Comparação defensiva inválida para Change Intelligence.")
    if len(comparison["rows"]) > MAX_CHANGES_PER_GROUP:
        raise ValueError("Comparação defensiva excede o limite local.")
    operation_id = _clean_text(operation_id, 100, required=True)
    detected = _utc_text(detected_at_utc)
    host = _clean_text(hostname or socket.gethostname() or "Não disponível", 255)
    reference_coverage = (reference or {}).get("coverage") or unknown_coverage()
    current_coverage = (current or {}).get("coverage") or unknown_coverage()
    baseline_revision = (reference or {}).get("updated")
    records = []
    for row in comparison["rows"]:
        if not isinstance(row, dict):
            continue
        change_type = STATE_MAP.get(row.get("state"))
        if change_type is None:  # inclui "Sem alteração": não persistir em massa.
            continue
        evidence = row.get("after") or row.get("before") or {}
        before, after = _before_after(row, change_type)
        try:
            identity_key = logical_key(evidence)
        except Exception:
            identity_key = None
        entity_type = _clean_text(evidence.get("Tipo") or "Não disponível", 100)
        name = _entity_name(evidence)
        source = _clean_text(evidence.get("Fonte") or "Baseline defensivo", 120)
        changed_fields = [item[0] for item in (row.get("changes") or [])
                          if isinstance(item, (list, tuple)) and len(item) == 3]
        evidence_json = {
            "reason": row.get("reason") or "Evidência não detalhada.",
            "changed_fields": changed_fields,
            "reference_coverage": _coverage_view(reference_coverage, evidence),
            "current_coverage": _coverage_view(current_coverage, evidence),
            "classification_origin": "baseline_defensivo.compare",
        }
        label = {
            "NEW": "Novo", "CHANGED": "Alterado", "ABSENT": "Ausente",
            "INDETERMINATE": "Indeterminado",
        }[change_type]
        records.append({
            "change_id": uuid.uuid4().hex,
            "schema_version": CHANGE_SCHEMA_VERSION,
            "detected_at_utc": detected,
            "hostname": host,
            "source": source,
            "entity_type": entity_type,
            "identity_key": _clean_text(identity_key, 128) or None,
            "change_type": change_type,
            "coverage_state": "INDETERMINATE" if change_type == "INDETERMINATE" else "OBSERVED",
            "before_json": _json_or_none(before),
            "after_json": _json_or_none(after),
            "evidence_json": _json_or_none(evidence_json),
            "baseline_id": _clean_text(baseline_id, 128) or None,
            "baseline_revision": _clean_text(baseline_revision, 80) or None,
            "operation_id": operation_id,
            "correlation_id": _clean_text(correlation_id, 100) or None,
            "timeline_event_id": None,
            "summary": _clean_text(f"{label}: {entity_type} — {name}", 300, required=True),
            "created_at": _utc_text(),
        })
    counts = Counter(record["change_type"] for record in records)
    return {
        "operation_id": operation_id,
        "schema_version": CHANGE_SCHEMA_VERSION,
        "detected_at_utc": detected,
        "hostname": host,
        "source": "Baseline defensivo",
        "baseline_id": _clean_text(baseline_id, 128) or None,
        "baseline_revision": _clean_text(baseline_revision, 80) or None,
        "correlation_id": _clean_text(correlation_id, 100) or None,
        "timeline_event_id": None,
        "counts": {kind: counts[kind] for kind in CHANGE_TYPES},
        "coverage": {
            "reference_complete": coverage_complete(reference_coverage),
            "current_complete": coverage_complete(current_coverage),
            "reference": reference_coverage,
            "current": current_coverage,
        },
        "changes": records,
        "created_at": _utc_text(),
    }


def operational_summary(counts, partial=False):
    total = sum(int(counts.get(kind, 0) or 0) for kind in CHANGE_TYPES)
    if total:
        text = (
            f"Última comparação: {counts.get('NEW', 0)} novos, "
            f"{counts.get('CHANGED', 0)} alterados, "
            f"{counts.get('ABSENT', 0)} ausentes e "
            f"{counts.get('INDETERMINATE', 0)} indeterminados."
        )
    else:
        text = "Nenhuma mudança observada com evidência suficiente nesta comparação."
    if partial:
        text += " Comparação com cobertura parcial; alguns itens podem permanecer indeterminados."
    return text


class ChangeIntelligenceStore(AuditTimelineStore):
    """Store no mesmo SQLite da Timeline, com conexões curtas e SQL isolado."""

    def __init__(self, root, logger=None, timeout=5.0):
        super().__init__(root, logger=logger, timeout=timeout)
        self._initialize_changes()

    def _initialize_changes(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (1, DATABASE_SCHEMA_VERSION, 3, 4, 5, 6, 7, 8, 9):
                raise RuntimeError("Versão do banco de Change Intelligence não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS change_groups (
                        operation_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        detected_at_utc TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        source TEXT NOT NULL,
                        baseline_id TEXT,
                        baseline_revision TEXT,
                        correlation_id TEXT,
                        timeline_event_id TEXT,
                        counts_json TEXT NOT NULL,
                        coverage_json TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(timeline_event_id) REFERENCES events(id)
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS changes (
                        change_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        detected_at_utc TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        source TEXT NOT NULL,
                        entity_type TEXT NOT NULL,
                        identity_key TEXT,
                        change_type TEXT NOT NULL,
                        coverage_state TEXT NOT NULL,
                        before_json TEXT,
                        after_json TEXT,
                        evidence_json TEXT NOT NULL,
                        baseline_id TEXT,
                        baseline_revision TEXT,
                        operation_id TEXT NOT NULL,
                        correlation_id TEXT,
                        timeline_event_id TEXT,
                        summary TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(operation_id) REFERENCES change_groups(operation_id) ON DELETE CASCADE,
                        FOREIGN KEY(timeline_event_id) REFERENCES events(id)
                    )
                """)
                for name, expression in (
                    ("idx_changes_detected", "detected_at_utc DESC"),
                    ("idx_changes_type", "change_type"),
                    ("idx_changes_source", "source"),
                    ("idx_changes_entity", "entity_type"),
                    ("idx_changes_operation", "operation_id"),
                    ("idx_changes_baseline", "baseline_id"),
                ):
                    connection.execute(f"CREATE INDEX IF NOT EXISTS {name} ON changes({expression})")
                if current < DATABASE_SCHEMA_VERSION:
                    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
        finally:
            connection.close()

    def record_comparison(self, group):
        changes = group.get("changes")
        if not isinstance(changes, list) or len(changes) > MAX_CHANGES_PER_GROUP:
            raise ValueError("Grupo de mudanças inválido.")
        counts_json = _json_or_none(group["counts"])
        coverage_json = _json_or_none(group["coverage"])
        partial = not (group["coverage"]["reference_complete"] and
                       group["coverage"]["current_complete"])
        summary = operational_summary(group["counts"], partial)
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO change_groups (
                        operation_id, schema_version, detected_at_utc, hostname,
                        source, baseline_id, baseline_revision, correlation_id,
                        timeline_event_id, counts_json, coverage_json, summary, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    group["operation_id"], group["schema_version"],
                    group["detected_at_utc"], group["hostname"], group["source"],
                    group.get("baseline_id"), group.get("baseline_revision"),
                    group.get("correlation_id"), group.get("timeline_event_id"),
                    counts_json, coverage_json, summary, group["created_at"],
                ))
                if changes:
                    connection.executemany("""
                        INSERT INTO changes (
                            change_id, schema_version, detected_at_utc, hostname,
                            source, entity_type, identity_key, change_type,
                            coverage_state, before_json, after_json, evidence_json,
                            baseline_id, baseline_revision, operation_id,
                            correlation_id, timeline_event_id, summary, created_at
                        ) VALUES (
                            :change_id, :schema_version, :detected_at_utc, :hostname,
                            :source, :entity_type, :identity_key, :change_type,
                            :coverage_state, :before_json, :after_json, :evidence_json,
                            :baseline_id, :baseline_revision, :operation_id,
                            :correlation_id, :timeline_event_id, :summary, :created_at
                        )
                    """, changes)
        finally:
            connection.close()
        return {"operation_id": group["operation_id"], "counts": dict(group["counts"]),
                "summary": summary, "partial": partial, "persisted": True}

    def link_timeline_event(self, operation_id, event_id):
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE change_groups SET timeline_event_id=? WHERE operation_id=?",
                    (_clean_text(event_id, 64, required=True),
                     _clean_text(operation_id, 100, required=True)),
                )
                connection.execute(
                    "UPDATE changes SET timeline_event_id=? WHERE operation_id=?",
                    (_clean_text(event_id, 64, required=True),
                     _clean_text(operation_id, 100, required=True)),
                )
        finally:
            connection.close()

    @staticmethod
    def _change_filters(*, since_utc=None, change_type=None, source=None,
                        entity_type=None, text=None, operation_id=None):
        clauses, params = [], {}
        if since_utc:
            clauses.append("detected_at_utc >= :since_utc")
            params["since_utc"] = _utc_text(since_utc)
        if change_type:
            normalized = str(change_type).strip().upper()
            if normalized not in CHANGE_TYPES:
                raise ValueError("Tipo de mudança inválido.")
            clauses.append("change_type = :change_type")
            params["change_type"] = normalized
        if source:
            clauses.append("source = :source")
            params["source"] = _clean_text(source, 120, required=True)
        if entity_type:
            clauses.append("entity_type = :entity_type")
            params["entity_type"] = _clean_text(entity_type, 100, required=True)
        if operation_id:
            clauses.append("operation_id = :operation_id")
            params["operation_id"] = _clean_text(operation_id, 100, required=True)
        if text:
            clean = _clean_text(text, 120).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(summary LIKE :text ESCAPE '\\' OR identity_key LIKE :text ESCAPE '\\')")
            params["text"] = f"%{clean}%"
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def query_changes(self, *, limit=100, offset=0, **filters):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        where, params = self._change_filters(**filters)
        params.update(limit=limit, offset=offset)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM changes" + where +
                " ORDER BY detected_at_utc DESC, created_at DESC, change_id DESC LIMIT :limit OFFSET :offset",
                params,
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def count_changes(self, **filters):
        where, params = self._change_filters(**filters)
        connection = self._connect()
        try:
            return int(connection.execute("SELECT COUNT(*) FROM changes" + where, params).fetchone()[0])
        finally:
            connection.close()

    def summarize_changes(self, **filters):
        where, params = self._change_filters(**filters)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT change_type, COUNT(*) FROM changes" + where + " GROUP BY change_type", params
            ).fetchall()
            counts = {kind: 0 for kind in CHANGE_TYPES}
            counts.update({row[0]: int(row[1]) for row in rows})
            return counts
        finally:
            connection.close()

    def sources_for(self, **filters):
        where, params = self._change_filters(**filters)
        connection = self._connect()
        try:
            return [row[0] for row in connection.execute(
                "SELECT DISTINCT source FROM changes" + where +
                " ORDER BY source COLLATE NOCASE", params
            ).fetchall()]
        finally:
            connection.close()

    def get_change(self, change_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM changes WHERE change_id=?",
                (_clean_text(change_id, 64, required=True),),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def get_group(self, operation_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM change_groups WHERE operation_id=?",
                (_clean_text(operation_id, 100, required=True),),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["counts"] = _loads(result.pop("counts_json")) or {}
            result["coverage"] = _loads(result.pop("coverage_json")) or {}
            return result
        finally:
            connection.close()

    def list_sources(self):
        return self._distinct("source")

    def list_entity_types(self):
        return self._distinct("entity_type")

    def _distinct(self, column):
        if column not in {"source", "entity_type"}:
            raise ValueError("Coluna de filtro inválida.")
        connection = self._connect()
        try:
            return [row[0] for row in connection.execute(
                f"SELECT DISTINCT {column} FROM changes ORDER BY {column} COLLATE NOCASE"
            ).fetchall()]
        finally:
            connection.close()


def persist_comparison_safe(store, timeline_store, *, comparison, reference,
                            current, operation_id, baseline_id=None,
                            logger=None):
    """Best effort: histórico e Timeline nunca invalidam a comparação principal."""
    try:
        group = structure_comparison_changes(
            comparison, reference=reference, current=current,
            operation_id=operation_id, baseline_id=baseline_id,
        )
        result = store.record_comparison(group) if store is not None else {
            "operation_id": operation_id, "counts": group["counts"],
            "summary": operational_summary(group["counts"], True),
            "partial": True, "persisted": False,
        }
    except Exception as exc:
        if logger is not None:
            try:
                logger.error("CHANGE_INTELLIGENCE_FALHA | tipo=%s", type(exc).__name__)
            except Exception:
                pass
        counts = Counter(STATE_MAP.get(row.get("state")) for row in comparison.get("rows", [])
                         if isinstance(row, dict) and STATE_MAP.get(row.get("state")))
        result = {
            "operation_id": operation_id,
            "counts": {kind: counts[kind] for kind in CHANGE_TYPES},
            "summary": "Comparação concluída; histórico de mudanças indisponível nesta operação.",
            "partial": True, "persisted": False,
        }

    event = record_event_safe(
        timeline_store, logger=logger, source="Baseline defensivo",
        category="BASELINE", severity="NOTICE" if sum(result["counts"].values()) else "INFO",
        status="OBSERVED", summary=result["summary"],
        details={
            "change_operation_id": operation_id,
            "counts": result["counts"],
            "coverage_partial": result["partial"],
            "change_history_available": result["persisted"],
        }, operation_id=operation_id,
    )
    if event is not None and result["persisted"] and store is not None:
        try:
            store.link_timeline_event(operation_id, event["id"])
            result["timeline_event_id"] = event["id"]
        except Exception as exc:
            if logger is not None:
                try:
                    logger.error("CHANGE_TIMELINE_LINK_FALHA | tipo=%s", type(exc).__name__)
                except Exception:
                    pass
    return result
