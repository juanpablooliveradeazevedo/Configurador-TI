"""Persistência local estruturada para Audit & Timeline.

O módulo não depende da GUI nem do log textual. Cada operação usa uma conexão
SQLite curta para manter o uso portátil e tolerar chamadas em Workers distintos.
"""
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import socket
import sqlite3
import sys
import uuid


SCHEMA_VERSION = 1
SUPPORTED_DATABASE_VERSIONS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
DATABASE_RELATIVE_PATH = Path("dados") / "auditoria" / "timeline.db"
EVENT_CATEGORIES = frozenset({
    "OPERATION", "MAINTENANCE", "BASELINE", "REPORT", "INVENTORY", "SYSTEM",
})
EVENT_SEVERITIES = frozenset({"INFO", "NOTICE", "WARNING", "ERROR"})
EVENT_STATUSES = frozenset({"STARTED", "COMPLETED", "FAILED", "CANCELLED", "OBSERVED"})
MAX_DETAILS_BYTES = 32 * 1024
MAX_SUMMARY_CHARS = 300
MAX_QUERY_LIMIT = 200
_SENSITIVE_KEYS = re.compile(
    r"(?:password|passwd|senha|token|secret|segredo|credential|credencial|api[_-]?key|authorization)",
    re.IGNORECASE,
)
_COMMAND_KEYS = re.compile(r"(?:command|comando|script|powershell|file[_-]?content|conteudo)", re.IGNORECASE)


def _utc_now():
    return datetime.now(timezone.utc)


def _utc_text(value=None):
    if value is None:
        parsed = _utc_now()
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    else:
        raise ValueError("Timestamp inválido para a timeline.")
    if parsed.tzinfo is None:
        raise ValueError("Timestamp da timeline deve possuir fuso horário.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def format_local_timestamp(value):
    """Converte UTC persistido apenas para apresentação local."""
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.astimezone().strftime("%d/%m/%Y %H:%M:%S")


def _clean_text(value, limit, *, required=False):
    text = " ".join(str(value or "").replace("\x00", " ").split())[:limit]
    if required and not text:
        raise ValueError("Campo obrigatório vazio na timeline.")
    return text


def _enum(value, allowed, field):
    normalized = str(value or "").strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{field} inválido para a timeline.")
    return normalized


def _sanitize_value(value, *, key="", depth=0):
    if _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if _COMMAND_KEYS.search(key):
        return "[OMITIDO]"
    if depth >= 6:
        return "[limite de profundidade]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return _clean_text(value, 1200)
    if isinstance(value, Path):
        return _clean_text(value, 1200)
    if isinstance(value, bytes):
        return "[dados binários omitidos]"
    if isinstance(value, dict):
        result = {}
        for index, (raw_key, item) in enumerate(value.items()):
            if index >= 64:
                result["_truncated"] = True
                break
            clean_key = _clean_text(raw_key, 80) or "campo"
            result[clean_key] = _sanitize_value(item, key=clean_key, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        sequence = list(value)
        result = [_sanitize_value(item, depth=depth + 1) for item in sequence[:64]]
        if len(sequence) > 64:
            result.append("[lista truncada]")
        return result
    return f"[não serializável: {type(value).__name__}]"


def sanitize_details(details):
    """Produz JSON seguro e limitado; nunca propaga falha de serialização."""
    if details is None:
        return None
    try:
        sanitized = _sanitize_value(details)
        encoded = json.dumps(sanitized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        encoded = '{"sanitization":"details indisponível"}'
    size = len(encoded.encode("utf-8"))
    if size > MAX_DETAILS_BYTES:
        encoded = json.dumps(
            {"truncated": True, "original_size_bytes": size},
            ensure_ascii=False, separators=(",", ":"),
        )
    return encoded


def new_operation_id():
    return uuid.uuid4().hex


class AuditTimelineStore:
    def __init__(self, root, logger=None, timeout=5.0):
        self.root = Path(root).resolve()
        self.path = self.root / DATABASE_RELATIVE_PATH
        self.logger = logger
        self.timeout = max(0.1, min(float(timeout), 30.0))
        self._validate_path()
        self._initialize()

    def _validate_path(self):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            try:
                if self.path.resolve().is_relative_to(Path(meipass).resolve()):
                    raise ValueError("Timeline não pode ser armazenada em _MEIPASS.")
            except OSError:
                pass
        current = self.path.parent
        while current != self.root:
            if current.exists() and (
                current.is_symlink()
                or (hasattr(current, "is_junction") and current.is_junction())
            ):
                raise ValueError("Diretório da timeline não admite link ou junção.")
            current = current.parent
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=self.timeout)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)}")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in SUPPORTED_DATABASE_VERSIONS:
                raise RuntimeError("Versão do banco de timeline não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        timestamp_utc TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        source TEXT NOT NULL,
                        category TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        details_json TEXT,
                        operation_id TEXT,
                        correlation_id TEXT,
                        created_at TEXT NOT NULL
                    )
                """)
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc DESC)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)"
                )
                # A Change Intelligence migra o mesmo banco para a versão 2.
                # Reabrir a Timeline nunca deve rebaixar essa versão.
                if current == 0:
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        finally:
            connection.close()

    def record_event(self, *, source, category, severity, status, summary,
                     details=None, operation_id=None, correlation_id=None,
                     timestamp_utc=None, hostname=None, event_id=None):
        event = {
            "id": _clean_text(event_id or uuid.uuid4().hex, 64, required=True),
            "schema_version": SCHEMA_VERSION,
            "timestamp_utc": _utc_text(timestamp_utc),
            "hostname": _clean_text(hostname or socket.gethostname() or "Não disponível", 255),
            "source": _clean_text(source, 100, required=True),
            "category": _enum(category, EVENT_CATEGORIES, "Categoria"),
            "severity": _enum(severity, EVENT_SEVERITIES, "Severidade"),
            "status": _enum(status, EVENT_STATUSES, "Status"),
            "summary": _clean_text(summary, MAX_SUMMARY_CHARS, required=True),
            "details_json": sanitize_details(details),
            "operation_id": _clean_text(operation_id, 100) or None,
            "correlation_id": _clean_text(correlation_id, 100) or None,
            "created_at": _utc_text(),
        }
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO events (
                        id, schema_version, timestamp_utc, hostname, source,
                        category, severity, status, summary, details_json,
                        operation_id, correlation_id, created_at
                    ) VALUES (
                        :id, :schema_version, :timestamp_utc, :hostname, :source,
                        :category, :severity, :status, :summary, :details_json,
                        :operation_id, :correlation_id, :created_at
                    )
                """, event)
        finally:
            connection.close()
        return dict(event)

    @staticmethod
    def _filters(*, since_utc=None, source=None, severity=None, text=None):
        clauses, params = [], {}
        if since_utc:
            clauses.append("timestamp_utc >= :since_utc")
            params["since_utc"] = _utc_text(since_utc)
        if source:
            clauses.append("source = :source")
            params["source"] = _clean_text(source, 100, required=True)
        if severity:
            clauses.append("severity = :severity")
            params["severity"] = _enum(severity, EVENT_SEVERITIES, "Severidade")
        if text:
            clauses.append("summary LIKE :text ESCAPE '\\'")
            clean = _clean_text(text, 120).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params["text"] = f"%{clean}%"
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def query_events(self, *, since_utc=None, source=None, severity=None, text=None,
                     limit=100, offset=0):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        where, params = self._filters(
            since_utc=since_utc, source=source, severity=severity, text=text
        )
        params.update(limit=limit, offset=offset)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM events" + where
                + " ORDER BY timestamp_utc DESC, created_at DESC, id DESC LIMIT :limit OFFSET :offset",
                params,
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def count_events(self, *, since_utc=None, source=None, severity=None, text=None):
        where, params = self._filters(
            since_utc=since_utc, source=source, severity=severity, text=text
        )
        connection = self._connect()
        try:
            return int(connection.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0])
        finally:
            connection.close()

    def get_event(self, event_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM events WHERE id = ?", (_clean_text(event_id, 64, required=True),)
            ).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def list_sources(self):
        connection = self._connect()
        try:
            return [row[0] for row in connection.execute(
                "SELECT DISTINCT source FROM events ORDER BY source COLLATE NOCASE"
            ).fetchall()]
        finally:
            connection.close()


def record_event_safe(store, logger=None, **event):
    """Best effort: a timeline nunca deve impedir a operação principal."""
    try:
        if store is None:
            return None
        return store.record_event(**event)
    except Exception as exc:
        if logger is not None:
            try:
                logger.error("AUDIT_TIMELINE_FALHA | tipo=%s", type(exc).__name__)
            except Exception:
                pass
        return None
