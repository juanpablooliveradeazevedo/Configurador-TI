"""Sessões locais, correlação conservadora e replay investigativo.

Correlação expressa apenas relações observáveis. Nenhuma função deste módulo
infere causa, risco, incidente de segurança ou ação corretiva.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re
import socket
import uuid

from audit_timeline import _clean_text, _utc_text
from change_intelligence import ChangeIntelligenceStore, _loads


DATABASE_SCHEMA_VERSION = 3
SESSION_SCHEMA_VERSION = 1
CORRELATION_WINDOW_MINUTES = 10
SESSION_STATUSES = ("OPEN", "REVIEWED", "ARCHIVED")
ITEM_TYPES = ("TIMELINE_EVENT", "CHANGE_GROUP", "CHANGE", "BASELINE_REFERENCE")
RELATION_TYPES = ("SAME_OPERATION", "SAME_CORRELATION", "SAME_ENTITY", "TEMPORAL_NEAR", "MANUAL")
RELEVANCE_LEVELS = ("CONTEXT", "RELEVANT", "KEY")
STRONG_RELATIONS = frozenset({"SAME_OPERATION", "SAME_CORRELATION", "SAME_ENTITY"})
WEAK_RELATIONS = frozenset({"TEMPORAL_NEAR"})
MAX_QUERY_LIMIT = 200
MAX_CANDIDATES_PER_SOURCE = 500
MAX_NOTE_CHARS = 500
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|senha|token|secret|segredo|credential|credencial|authorization)\b\s*[:=]\s*\S+"
)


def _enum(value, allowed, field):
    normalized = str(value or "").strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{field} inválido para investigação.")
    return normalized


def sanitize_note(value):
    """Notas são texto inerte, limitado e com atribuições sensíveis redigidas."""
    text = _clean_text(value, MAX_NOTE_CHARS)
    return _SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "=[REDACTED]", text) or None


def _parsed_utc(value):
    return datetime.fromisoformat(_utc_text(value).replace("Z", "+00:00"))


def _window_around(value):
    center = _parsed_utc(value)
    delta = timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    return _utc_text(center - delta), _utc_text(center + delta)


class IncidentReplayStore(ChangeIntelligenceStore):
    """Amplia o mesmo timeline.db sem duplicar payloads das fontes."""

    def __init__(self, root, logger=None, timeout=5.0):
        super().__init__(root, logger=logger, timeout=timeout)
        self._initialize_investigations()

    def _initialize_investigations(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (2, DATABASE_SCHEMA_VERSION, 4, 5, 6, 7, 8, 9):
                raise RuntimeError("Versão do banco de investigação não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS investigation_sessions (
                        session_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        title TEXT NOT NULL,
                        summary TEXT,
                        status TEXT NOT NULL,
                        source TEXT NOT NULL,
                        primary_operation_id TEXT,
                        primary_correlation_id TEXT,
                        window_start_utc TEXT NOT NULL,
                        window_end_utc TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        notes TEXT
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS investigation_items (
                        item_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        item_type TEXT NOT NULL,
                        referenced_id TEXT NOT NULL,
                        observed_at_utc TEXT NOT NULL,
                        source_module TEXT NOT NULL,
                        relation_type TEXT NOT NULL,
                        relevance TEXT NOT NULL,
                        note TEXT,
                        created_at_utc TEXT NOT NULL,
                        FOREIGN KEY(session_id) REFERENCES investigation_sessions(session_id) ON DELETE CASCADE,
                        UNIQUE(session_id, item_type, referenced_id)
                    )
                """)
                for name, table, expression in (
                    ("idx_sessions_updated", "investigation_sessions", "updated_at_utc DESC"),
                    ("idx_sessions_hostname", "investigation_sessions", "hostname"),
                    ("idx_sessions_operation", "investigation_sessions", "primary_operation_id"),
                    ("idx_sessions_correlation", "investigation_sessions", "primary_correlation_id"),
                    ("idx_items_session", "investigation_items", "session_id"),
                    ("idx_items_observed", "investigation_items", "observed_at_utc"),
                    ("idx_items_reference", "investigation_items", "referenced_id"),
                    ("idx_items_relation", "investigation_items", "relation_type"),
                ):
                    connection.execute(
                        f"CREATE INDEX IF NOT EXISTS {name} ON {table}({expression})"
                    )
                if current < DATABASE_SCHEMA_VERSION:
                    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
        finally:
            connection.close()

    def create_session(self, *, title, hostname=None, summary=None, status="OPEN",
                       source="MANUAL", primary_operation_id=None,
                       primary_correlation_id=None, window_start_utc=None,
                       window_end_utc=None, created_by="Técnico local", notes=None,
                       session_id=None):
        now = _utc_text()
        if window_start_utc is None or window_end_utc is None:
            start, end = _window_around(now)
            window_start_utc = window_start_utc or start
            window_end_utc = window_end_utc or end
        start, end = _utc_text(window_start_utc), _utc_text(window_end_utc)
        if _parsed_utc(start) > _parsed_utc(end):
            raise ValueError("Janela temporal da investigação é inválida.")
        session = {
            "session_id": _clean_text(session_id or uuid.uuid4().hex, 64, required=True),
            "schema_version": SESSION_SCHEMA_VERSION,
            "created_at_utc": now,
            "updated_at_utc": now,
            "hostname": _clean_text(hostname or socket.gethostname() or "Não disponível", 255, required=True),
            "title": _clean_text(title, 180, required=True),
            "summary": _clean_text(summary, 600) or None,
            "status": _enum(status, SESSION_STATUSES, "Status"),
            "source": _clean_text(source, 100, required=True),
            "primary_operation_id": _clean_text(primary_operation_id, 100) or None,
            "primary_correlation_id": _clean_text(primary_correlation_id, 100) or None,
            "window_start_utc": start,
            "window_end_utc": end,
            "created_by": _clean_text(created_by, 100, required=True),
            "notes": sanitize_note(notes),
        }
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO investigation_sessions (
                        session_id, schema_version, created_at_utc, updated_at_utc,
                        hostname, title, summary, status, source,
                        primary_operation_id, primary_correlation_id,
                        window_start_utc, window_end_utc, created_by, notes
                    ) VALUES (
                        :session_id, :schema_version, :created_at_utc, :updated_at_utc,
                        :hostname, :title, :summary, :status, :source,
                        :primary_operation_id, :primary_correlation_id,
                        :window_start_utc, :window_end_utc, :created_by, :notes
                    )
                """, session)
        finally:
            connection.close()
        return dict(session)

    def get_session(self, session_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM investigation_sessions WHERE session_id=?",
                (_clean_text(session_id, 64, required=True),),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def list_sessions(self, *, status=None, hostname=None, text=None,
                      include_archived=False, limit=50, offset=0):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        clauses, params = [], {"limit": limit, "offset": offset}
        if status:
            clauses.append("status=:status")
            params["status"] = _enum(status, SESSION_STATUSES, "Status")
        elif not include_archived:
            clauses.append("status<>'ARCHIVED'")
        if hostname:
            clauses.append("hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        if text:
            clean = _clean_text(text, 120).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(title LIKE :text ESCAPE '\\' OR summary LIKE :text ESCAPE '\\')")
            params["text"] = f"%{clean}%"
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM investigation_sessions" + where
                + " ORDER BY updated_at_utc DESC, session_id DESC LIMIT :limit OFFSET :offset",
                params,
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def count_sessions(self, *, status=None, hostname=None, text=None,
                       include_archived=False):
        clauses, params = [], {}
        if status:
            clauses.append("status=:status")
            params["status"] = _enum(status, SESSION_STATUSES, "Status")
        elif not include_archived:
            clauses.append("status<>'ARCHIVED'")
        if hostname:
            clauses.append("hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        if text:
            clean = _clean_text(text, 120).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(title LIKE :text ESCAPE '\\' OR summary LIKE :text ESCAPE '\\')")
            params["text"] = f"%{clean}%"
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            return int(connection.execute(
                "SELECT COUNT(*) FROM investigation_sessions" + where, params
            ).fetchone()[0])
        finally:
            connection.close()

    def update_session(self, session_id, *, title=None, summary=None, status=None, notes=None):
        session = self.get_session(session_id)
        if session is None:
            raise ValueError("Sessão de investigação inexistente.")
        values = {
            "session_id": session["session_id"],
            "title": _clean_text(title if title is not None else session["title"], 180, required=True),
            "summary": _clean_text(summary if summary is not None else session.get("summary"), 600) or None,
            "status": _enum(status if status is not None else session["status"], SESSION_STATUSES, "Status"),
            "notes": sanitize_note(notes if notes is not None else session.get("notes")),
            "updated": _utc_text(),
        }
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE investigation_sessions SET title=:title, summary=:summary,
                    status=:status, notes=:notes, updated_at_utc=:updated
                    WHERE session_id=:session_id
                """, values)
        finally:
            connection.close()
        return self.get_session(session_id)

    def archive_session(self, session_id):
        """Oculta a sessão da visão ativa sem remover itens ou evidências."""
        return self.update_session(session_id, status="ARCHIVED")

    def restore_session(self, session_id):
        """Restaura uma sessão arquivada para revisão operacional."""
        session = self.get_session(session_id)
        if session is None:
            raise ValueError("Sessão de investigação inexistente.")
        if session["status"] != "ARCHIVED":
            return session
        return self.update_session(session_id, status="OPEN")

    def _reference_metadata(self, item_type, referenced_id):
        item_type = _enum(item_type, ITEM_TYPES, "Tipo de item")
        referenced_id = _clean_text(referenced_id, 128, required=True)
        if item_type == "TIMELINE_EVENT":
            row = self.get_event(referenced_id)
            if row:
                return dict(row, observed_at_utc=row["timestamp_utc"],
                            source_module=row["source"], referenced_id=row["id"],
                            item_type=item_type, identity_key=None)
        elif item_type == "CHANGE_GROUP":
            row = self.get_group(referenced_id)
            if row:
                return dict(row, observed_at_utc=row["detected_at_utc"],
                            source_module=row["source"], referenced_id=row["operation_id"],
                            item_type=item_type, identity_key=None)
        elif item_type == "CHANGE":
            row = self.get_change(referenced_id)
            if row:
                return dict(row, observed_at_utc=row["detected_at_utc"],
                            source_module=row["source"], referenced_id=row["change_id"],
                            item_type=item_type)
        else:
            connection = self._connect()
            try:
                row = connection.execute("""
                    SELECT * FROM change_groups WHERE baseline_id=?
                    ORDER BY detected_at_utc DESC LIMIT 1
                """, (referenced_id,)).fetchone()
            finally:
                connection.close()
            if row:
                data = dict(row)
                return dict(data, observed_at_utc=data["detected_at_utc"],
                            source_module="Baseline defensivo", referenced_id=referenced_id,
                            item_type=item_type, identity_key=None)
        raise ValueError("Referência original da investigação não foi encontrada.")

    def add_item(self, session_id, *, item_type, referenced_id, relation_type="MANUAL",
                 relevance="CONTEXT", note=None):
        session = self.get_session(session_id)
        if session is None:
            raise ValueError("Sessão de investigação inexistente.")
        reference = self._reference_metadata(item_type, referenced_id)
        normalized_relation = _enum(relation_type, RELATION_TYPES, "Relação")
        if reference.get("hostname") != session["hostname"] and normalized_relation != "MANUAL":
            raise ValueError("Item de outro equipamento não pode ser adicionado automaticamente.")
        item = {
            "item_id": uuid.uuid4().hex,
            "session_id": session["session_id"],
            "item_type": _enum(item_type, ITEM_TYPES, "Tipo de item"),
            "referenced_id": _clean_text(referenced_id, 128, required=True),
            "observed_at_utc": _utc_text(reference["observed_at_utc"]),
            "source_module": _clean_text(reference["source_module"], 120, required=True),
            "relation_type": normalized_relation,
            "relevance": _enum(relevance, RELEVANCE_LEVELS, "Relevância"),
            "note": sanitize_note(note),
            "created_at_utc": _utc_text(),
        }
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO investigation_items (
                        item_id, session_id, item_type, referenced_id,
                        observed_at_utc, source_module, relation_type,
                        relevance, note, created_at_utc
                    ) VALUES (
                        :item_id, :session_id, :item_type, :referenced_id,
                        :observed_at_utc, :source_module, :relation_type,
                        :relevance, :note, :created_at_utc
                    )
                """, item)
                connection.execute(
                    "UPDATE investigation_sessions SET updated_at_utc=? WHERE session_id=?",
                    (_utc_text(), session["session_id"]),
                )
        finally:
            connection.close()
        return dict(item)

    def update_item(self, item_id, *, relevance=None, note=None):
        item = self.get_item(item_id)
        if item is None:
            raise ValueError("Item de investigação inexistente.")
        relevance = _enum(relevance if relevance is not None else item["relevance"],
                          RELEVANCE_LEVELS, "Relevância")
        note = sanitize_note(note if note is not None else item.get("note"))
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE investigation_items SET relevance=?, note=? WHERE item_id=?",
                    (relevance, note, item["item_id"]),
                )
                connection.execute(
                    "UPDATE investigation_sessions SET updated_at_utc=? WHERE session_id=?",
                    (_utc_text(), item["session_id"]),
                )
        finally:
            connection.close()
        return self.get_item(item_id)

    def remove_item(self, item_id):
        item = self.get_item(item_id)
        if item is None:
            return False
        connection = self._connect()
        try:
            with connection:
                connection.execute("DELETE FROM investigation_items WHERE item_id=?", (item["item_id"],))
                connection.execute(
                    "UPDATE investigation_sessions SET updated_at_utc=? WHERE session_id=?",
                    (_utc_text(), item["session_id"]),
                )
        finally:
            connection.close()
        return True

    def get_item(self, item_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM investigation_items WHERE item_id=?",
                (_clean_text(item_id, 64, required=True),),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def find_session_for_reference(self, item_type, referenced_id):
        item_type = _enum(item_type, ITEM_TYPES, "Tipo de item")
        referenced_id = _clean_text(referenced_id, 128, required=True)
        connection = self._connect()
        try:
            row = connection.execute("""
                SELECT sessions.* FROM investigation_sessions AS sessions
                JOIN investigation_items AS items ON items.session_id=sessions.session_id
                WHERE items.item_type=? AND items.referenced_id=?
                  AND sessions.status<>'ARCHIVED'
                ORDER BY sessions.updated_at_utc DESC, sessions.session_id DESC LIMIT 1
            """, (item_type, referenced_id)).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def list_items(self, session_id, *, limit=100, offset=0):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        connection = self._connect()
        try:
            rows = connection.execute("""
                SELECT * FROM investigation_items WHERE session_id=?
                ORDER BY observed_at_utc ASC, created_at_utc ASC, item_id ASC
                LIMIT ? OFFSET ?
            """, (_clean_text(session_id, 64, required=True), limit, offset)).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def create_from_timeline_event(self, event_id, *, title=None):
        event = self.get_event(event_id)
        if event is None:
            raise ValueError("Evento da Timeline não encontrado.")
        start, end = _window_around(event["timestamp_utc"])
        session = self.create_session(
            title=title or f"Investigação — {event['summary']}", hostname=event["hostname"],
            summary="Sessão iniciada a partir de evento da Timeline.", source="TIMELINE",
            primary_operation_id=event.get("operation_id"),
            primary_correlation_id=event.get("correlation_id"),
            window_start_utc=start, window_end_utc=end,
        )
        relation = "SAME_OPERATION" if event.get("operation_id") else (
            "SAME_CORRELATION" if event.get("correlation_id") else "MANUAL"
        )
        self.add_item(session["session_id"], item_type="TIMELINE_EVENT",
                      referenced_id=event["id"], relation_type=relation, relevance="KEY")
        return self.get_session(session["session_id"])

    def create_from_change_group(self, operation_id, *, title=None):
        group = self.get_group(operation_id)
        if group is None:
            raise ValueError("Grupo de mudanças não encontrado.")
        start, end = _window_around(group["detected_at_utc"])
        session = self.create_session(
            title=title or f"Investigação — comparação {operation_id[:12]}",
            hostname=group["hostname"], summary="Sessão iniciada a partir de grupo de mudanças.",
            source="CHANGE_INTELLIGENCE", primary_operation_id=group["operation_id"],
            primary_correlation_id=group.get("correlation_id"),
            window_start_utc=start, window_end_utc=end,
        )
        self.add_item(session["session_id"], item_type="CHANGE_GROUP",
                      referenced_id=group["operation_id"], relation_type="SAME_OPERATION",
                      relevance="KEY")
        return self.get_session(session["session_id"])

    def create_from_change(self, change_id, *, title=None):
        change = self.get_change(change_id)
        if change is None:
            raise ValueError("Mudança não encontrada.")
        start, end = _window_around(change["detected_at_utc"])
        session = self.create_session(
            title=title or f"Investigação — {change['summary']}", hostname=change["hostname"],
            summary="Sessão iniciada a partir de mudança observada.", source="CHANGE_INTELLIGENCE",
            primary_operation_id=change.get("operation_id"),
            primary_correlation_id=change.get("correlation_id"),
            window_start_utc=start, window_end_utc=end,
        )
        relation = "SAME_OPERATION" if change.get("operation_id") else (
            "SAME_CORRELATION" if change.get("correlation_id") else "MANUAL"
        )
        self.add_item(session["session_id"], item_type="CHANGE", referenced_id=change["change_id"],
                      relation_type=relation, relevance="KEY")
        return self.get_session(session["session_id"])

    def _candidate_rows(self, session):
        params = (session["hostname"], session["window_start_utc"], session["window_end_utc"],
                  MAX_CANDIDATES_PER_SOURCE)
        connection = self._connect()
        try:
            rows = []
            for item_type, sql in (
                ("TIMELINE_EVENT", """SELECT id AS referenced_id, timestamp_utc AS observed_at_utc,
                    hostname, source AS source_module, operation_id, correlation_id,
                    NULL AS identity_key, summary FROM events
                    WHERE hostname=? AND timestamp_utc BETWEEN ? AND ?
                    ORDER BY timestamp_utc LIMIT ?"""),
                ("CHANGE_GROUP", """SELECT operation_id AS referenced_id,
                    detected_at_utc AS observed_at_utc, hostname, source AS source_module,
                    operation_id, correlation_id, NULL AS identity_key, summary
                    FROM change_groups WHERE hostname=? AND detected_at_utc BETWEEN ? AND ?
                    ORDER BY detected_at_utc LIMIT ?"""),
                ("CHANGE", """SELECT change_id AS referenced_id,
                    detected_at_utc AS observed_at_utc, hostname, source AS source_module,
                    operation_id, correlation_id, identity_key, summary
                    FROM changes WHERE hostname=? AND detected_at_utc BETWEEN ? AND ?
                    ORDER BY detected_at_utc LIMIT ?"""),
            ):
                rows.extend(dict(row, item_type=item_type) for row in connection.execute(sql, params).fetchall())
            return rows
        finally:
            connection.close()

    def suggest_related(self, session_id, *, limit=100, offset=0):
        session = self.get_session(session_id)
        if session is None:
            raise ValueError("Sessão de investigação inexistente.")
        selected = self.list_items(session_id, limit=MAX_QUERY_LIMIT)
        selected_keys = {(item["item_type"], item["referenced_id"]) for item in selected}
        metadata = []
        for item in selected:
            try:
                metadata.append(self._reference_metadata(item["item_type"], item["referenced_id"]))
            except ValueError:
                continue
        identities = {item.get("identity_key") for item in metadata if item.get("identity_key")}
        sources = {item.get("source_module") for item in metadata if item.get("source_module")}
        priority = {"SAME_OPERATION": 0, "SAME_CORRELATION": 1, "SAME_ENTITY": 2, "TEMPORAL_NEAR": 3}
        suggestions = []
        for candidate in self._candidate_rows(session):
            key = (candidate["item_type"], candidate["referenced_id"])
            if key in selected_keys:
                continue
            relation = None
            if session.get("primary_operation_id") and candidate.get("operation_id") == session["primary_operation_id"]:
                relation = "SAME_OPERATION"
            elif session.get("primary_correlation_id") and candidate.get("correlation_id") == session["primary_correlation_id"]:
                relation = "SAME_CORRELATION"
            elif candidate.get("identity_key") and candidate["identity_key"] in identities:
                relation = "SAME_ENTITY"
            elif candidate.get("source_module") in sources:
                relation = "TEMPORAL_NEAR"
            if relation:
                suggestions.append(dict(candidate, relation_type=relation,
                                        strength="WEAK" if relation in WEAK_RELATIONS else "STRONG"))
        suggestions.sort(key=lambda item: (
            priority[item["relation_type"]], item["observed_at_utc"], item["item_type"], item["referenced_id"]
        ))
        offset = max(0, int(offset))
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        return suggestions[offset:offset + limit]

    def resolve_item(self, item):
        reference = self._reference_metadata(item["item_type"], item["referenced_id"])
        if item["item_type"] == "TIMELINE_EVENT":
            evidence = _loads(reference.get("details_json"))
        elif item["item_type"] == "CHANGE_GROUP":
            evidence = {"counts": reference.get("counts"), "coverage": reference.get("coverage")}
        elif item["item_type"] == "CHANGE":
            evidence = {
                "before": _loads(reference.get("before_json")),
                "after": _loads(reference.get("after_json")),
                "evidence": _loads(reference.get("evidence_json")),
            }
        else:
            evidence = {"baseline_id": item["referenced_id"], "operation_id": reference.get("operation_id")}
        return dict(item, summary=reference.get("summary") or "Referência de baseline",
                    hostname=reference.get("hostname"), operation_id=reference.get("operation_id"),
                    correlation_id=reference.get("correlation_id"),
                    identity_key=reference.get("identity_key"), evidence=evidence,
                    evidence_available=bool(evidence))

    def build_replay(self, session_id):
        session = self.get_session(session_id)
        if session is None:
            raise ValueError("Sessão de investigação inexistente.")
        resolved = []
        for item in self.list_items(session_id, limit=MAX_QUERY_LIMIT):
            try:
                resolved.append(self.resolve_item(item))
            except ValueError:
                resolved.append(dict(item, summary="Referência original indisponível",
                                     hostname=session["hostname"], operation_id=None,
                                     correlation_id=None, identity_key=None, evidence=None,
                                     evidence_available=False))
        primary = [item for item in resolved if (
            (session.get("primary_operation_id") and item.get("operation_id") == session["primary_operation_id"])
            or (session.get("primary_correlation_id") and item.get("correlation_id") == session["primary_correlation_id"])
        )]
        if primary:
            central = [_parsed_utc(item["observed_at_utc"]) for item in primary]
            first, last = min(central), max(central)
            for item in resolved:
                if item in primary:
                    item["phase"] = "DURANTE"
                else:
                    observed = _parsed_utc(item["observed_at_utc"])
                    item["phase"] = "ANTES" if observed < first else ("DEPOIS" if observed > last else "CONTEXTO")
        else:
            for item in resolved:
                item["phase"] = "SEQUÊNCIA"
        return resolved

    def session_summary(self, session_id):
        session = self.get_session(session_id)
        if session is None:
            raise ValueError("Sessão de investigação inexistente.")
        items = self.list_items(session_id, limit=MAX_QUERY_LIMIT)
        types = Counter(item["item_type"] for item in items)
        relations = Counter(item["relation_type"] for item in items)
        result = dict(session)
        result.update({
            "total_items": len(items),
            "events": types["TIMELINE_EVENT"],
            "change_groups": types["CHANGE_GROUP"],
            "changes": types["CHANGE"],
            "baseline_references": types["BASELINE_REFERENCE"],
            "strong_relations": sum(relations[kind] for kind in STRONG_RELATIONS),
            "weak_relations": sum(relations[kind] for kind in WEAK_RELATIONS),
            "causality_inferred": False,
        })
        result["text"] = (
            f"Sessão com {len(items)} item(ns) entre {session['window_start_utc']} e "
            f"{session['window_end_utc']}. {result['strong_relations']} relação(ões) forte(s) "
            f"e {result['weak_relations']} temporal(is) fraca(s). Nenhuma causalidade foi inferida automaticamente."
        )
        return result


def investigation_action_safe(store, logger, action, *args, **kwargs):
    """Best effort para que a camada nova nunca derrube as camadas aprovadas."""
    try:
        if store is None:
            raise RuntimeError("Investigação indisponível.")
        return action(store, *args, **kwargs)
    except Exception as exc:
        if logger is not None:
            try:
                logger.error("INCIDENT_REPLAY_FALHA | tipo=%s", type(exc).__name__)
            except Exception:
                pass
        return None
