"""Fundação local, leve e explicável de Monitoring & Correlation.

Observações de CPU, memória e espaço livre são indicadores operacionais. Este
módulo não infere diagnóstico, causa, risco ou ação corretiva. A correlação
exposta é somente contexto temporal do mesmo equipamento.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ctypes
import math
import os
from pathlib import Path
import shutil
import socket
import threading
import time
import uuid

from audit_timeline import _clean_text, _utc_text, record_event_safe, sanitize_details
from change_intelligence import _loads
from incident_replay import IncidentReplayStore


DATABASE_SCHEMA_VERSION = 4
MONITORING_SCHEMA_VERSION = 1
RETENTION_DAYS = 30
CORRELATION_WINDOW_MINUTES = 10
ALLOWED_INTERVALS = (30, 60, 120, 300)
ALLOWED_RETENTION_DAYS = (7, 14, 30, 60, 90)
MONITOR_STATES = ("STOPPED", "RUNNING", "PAUSED", "ERROR")
SIGNAL_STATES = ("NORMAL", "ATTENTION", "CRITICAL", "INDETERMINATE")
METRIC_KEYS = ("cpu_usage", "memory_usage", "system_disk_free")
MAX_QUERY_LIMIT = 200

# Regras declarativas: os números não ficam espalhados pela GUI.
METRIC_RULES = {
    "cpu_usage": {
        "title": "CPU", "unit": "%", "direction": "high",
        "attention": 85.0, "critical": 95.0,
        "threshold_text": "Atenção a partir de 85%; crítico a partir de 95%.",
    },
    "memory_usage": {
        "title": "Memória", "unit": "%", "direction": "high",
        "attention": 85.0, "critical": 95.0,
        "threshold_text": "Atenção a partir de 85%; crítico a partir de 95%.",
    },
    "system_disk_free": {
        "title": "Disco do sistema — livre", "unit": "%", "direction": "low",
        "attention": 15.0, "critical": 5.0,
        "threshold_text": "Atenção com 15% livre ou menos; crítico com 5% ou menos.",
    },
}

STATE_TEXT = {
    "NORMAL": "Operação dentro do limite configurado.",
    "ATTENTION": "Valor sustentado acima/abaixo do limite de atenção.",
    "CRITICAL": "Valor sustentado no limite crítico.",
    "INDETERMINATE": "Não foi possível determinar o estado com evidência suficiente.",
}


def validate_interval(value):
    value = int(value)
    if value not in ALLOWED_INTERVALS:
        raise ValueError("Intervalo de monitoramento fora da lista segura.")
    return value


def validate_retention_days(value):
    value = int(value)
    if value not in ALLOWED_RETENTION_DAYS:
        raise ValueError("Retenção de monitoramento fora da lista segura.")
    return value


def derive_state(metric_key, value):
    """Classifica somente o valor observado segundo a regra declarativa."""
    rule = METRIC_RULES.get(metric_key)
    if rule is None:
        raise ValueError("Métrica de monitoramento desconhecida.")
    try:
        number = float(value)
        if not math.isfinite(number) or not 0.0 <= number <= 100.0:
            raise ValueError
    except (TypeError, ValueError):
        return "INDETERMINATE"
    if rule["direction"] == "high":
        if number >= rule["critical"]:
            return "CRITICAL"
        if number >= rule["attention"]:
            return "ATTENTION"
        return "NORMAL"
    if number <= rule["critical"]:
        return "CRITICAL"
    if number <= rule["attention"]:
        return "ATTENTION"
    return "NORMAL"


def debounce_state(current_state, derived_state, candidate_state=None, candidate_count=0):
    """Confirma piora após 3 amostras e recuperação após 2.

    INDETERMINATE é confirmado imediatamente quando a evidência desaparece;
    sair desse estado ainda exige estabilidade, evitando certeza prematura.
    """
    current = current_state if current_state in SIGNAL_STATES else "INDETERMINATE"
    derived = derived_state if derived_state in SIGNAL_STATES else "INDETERMINATE"
    if derived == current:
        return current, None, 0, False, 0
    if derived == "INDETERMINATE":
        return derived, None, 0, True, 1

    rank = {"NORMAL": 0, "ATTENTION": 1, "CRITICAL": 2}
    worsening = current == "INDETERMINATE" and derived != "NORMAL"
    if current != "INDETERMINATE":
        worsening = rank[derived] > rank[current]
    required = 3 if worsening else 2
    count = int(candidate_count) + 1 if candidate_state == derived else 1
    if count >= required:
        return derived, None, 0, True, required
    return current, derived, count, False, required


class MonitoringStore(IncidentReplayStore):
    """Evolui o mesmo timeline.db sem duplicar Timeline ou Investigação."""

    def __init__(self, root, logger=None, timeout=5.0):
        super().__init__(root, logger=logger, timeout=timeout)
        self._initialize_monitoring()

    def _initialize_monitoring(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (3, DATABASE_SCHEMA_VERSION, 5, 6, 7, 8, 9):
                raise RuntimeError("Versão do banco de monitoramento não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_runs (
                        run_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        started_at_utc TEXT NOT NULL,
                        stopped_at_utc TEXT,
                        hostname TEXT NOT NULL,
                        interval_seconds INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_observations (
                        observation_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        observed_at_utc TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        metric_key TEXT NOT NULL,
                        value_num REAL,
                        unit TEXT NOT NULL,
                        derived_state TEXT NOT NULL,
                        confirmed_state TEXT NOT NULL,
                        previous_confirmed_state TEXT,
                        debounce_count INTEGER NOT NULL,
                        source TEXT NOT NULL,
                        details_json TEXT,
                        transition_event_id TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(run_id) REFERENCES monitoring_runs(run_id),
                        FOREIGN KEY(transition_event_id) REFERENCES events(id)
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_metric_state (
                        hostname TEXT NOT NULL,
                        metric_key TEXT NOT NULL,
                        current_state TEXT NOT NULL,
                        state_since_utc TEXT NOT NULL,
                        last_value REAL,
                        last_observation_id TEXT,
                        candidate_state TEXT,
                        candidate_count INTEGER NOT NULL DEFAULT 0,
                        updated_at_utc TEXT NOT NULL,
                        PRIMARY KEY(hostname, metric_key)
                    )
                """)
                for name, table, expression in (
                    ("idx_monitor_runs_started", "monitoring_runs", "started_at_utc DESC"),
                    ("idx_monitor_runs_host", "monitoring_runs", "hostname"),
                    ("idx_monitor_obs_time", "monitoring_observations", "observed_at_utc DESC"),
                    ("idx_monitor_obs_host_metric", "monitoring_observations", "hostname, metric_key, observed_at_utc DESC"),
                    ("idx_monitor_obs_run", "monitoring_observations", "run_id"),
                    ("idx_monitor_obs_transition", "monitoring_observations", "transition_event_id"),
                    ("idx_monitor_state_updated", "monitoring_metric_state", "updated_at_utc DESC"),
                ):
                    connection.execute(
                        f"CREATE INDEX IF NOT EXISTS {name} ON {table}({expression})"
                    )
                if current < DATABASE_SCHEMA_VERSION:
                    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
        finally:
            connection.close()

    def start_run(self, *, interval_seconds=60, hostname=None, run_id=None):
        interval = validate_interval(interval_seconds)
        now = _utc_text()
        run = {
            "run_id": _clean_text(run_id or uuid.uuid4().hex, 64, required=True),
            "schema_version": MONITORING_SCHEMA_VERSION,
            "started_at_utc": now,
            "stopped_at_utc": None,
            "hostname": _clean_text(hostname or socket.gethostname() or "Não disponível", 255, required=True),
            "interval_seconds": interval,
            "status": "RUNNING",
            "created_at": now,
        }
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO monitoring_runs (
                        run_id, schema_version, started_at_utc, stopped_at_utc,
                        hostname, interval_seconds, status, created_at
                    ) VALUES (
                        :run_id, :schema_version, :started_at_utc, :stopped_at_utc,
                        :hostname, :interval_seconds, :status, :created_at
                    )
                """, run)
        finally:
            connection.close()
        self._record_lifecycle(run, "STARTED", "INFO", "Monitoramento local iniciado.")
        return dict(run)

    def get_run(self, run_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM monitoring_runs WHERE run_id=?",
                (_clean_text(run_id, 64, required=True),),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def update_interval(self, run_id, interval_seconds):
        interval = validate_interval(interval_seconds)
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE monitoring_runs SET interval_seconds=? WHERE run_id=?",
                    (interval, _clean_text(run_id, 64, required=True)),
                )
        finally:
            connection.close()
        return self.get_run(run_id)

    def set_run_status(self, run_id, status, *, reason=None):
        normalized = str(status or "").strip().upper()
        if normalized not in MONITOR_STATES:
            raise ValueError("Estado operacional do monitor inválido.")
        run = self.get_run(run_id)
        if run is None:
            raise ValueError("Execução de monitoramento inexistente.")
        stopped = _utc_text() if normalized == "STOPPED" else None
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE monitoring_runs SET status=?, stopped_at_utc=COALESCE(?, stopped_at_utc) WHERE run_id=?",
                    (normalized, stopped, run["run_id"]),
                )
        finally:
            connection.close()
        event_map = {
            "PAUSED": ("OBSERVED", "NOTICE", "Monitoramento local pausado."),
            "RUNNING": ("OBSERVED", "INFO", "Monitoramento local retomado."),
            "STOPPED": ("COMPLETED", "INFO", "Monitoramento local parado."),
            "ERROR": ("FAILED", "ERROR", "Monitoramento local encontrou erro persistente."),
        }
        event_status, severity, summary = event_map[normalized]
        updated = self.get_run(run_id)
        self._record_lifecycle(updated, event_status, severity, summary, reason=reason)
        return updated

    def _record_lifecycle(self, run, status, severity, summary, *, reason=None):
        return record_event_safe(
            self, logger=self.logger, source="MONITORING", category="SYSTEM",
            severity=severity, status=status, summary=summary,
            hostname=run["hostname"], operation_id=run["run_id"],
            details={
                "event_kind": "MONITOR_LIFECYCLE", "run_id": run["run_id"],
                "monitor_state": run["status"], "interval_seconds": run["interval_seconds"],
                "reason": _clean_text(reason, 240) or None,
                "principle": "Observação não é diagnóstico.",
            },
        )

    def _metric_state(self, connection, hostname, metric_key, observed_at):
        row = connection.execute(
            "SELECT * FROM monitoring_metric_state WHERE hostname=? AND metric_key=?",
            (hostname, metric_key),
        ).fetchone()
        if row:
            return dict(row)
        return {
            "hostname": hostname, "metric_key": metric_key,
            "current_state": "INDETERMINATE", "state_since_utc": observed_at,
            "last_value": None, "last_observation_id": None,
            "candidate_state": None, "candidate_count": 0,
            "updated_at_utc": observed_at,
        }

    def record_cycle(self, run_id, metrics, *, observed_at_utc=None):
        run = self.get_run(run_id)
        if run is None:
            raise ValueError("Execução de monitoramento inexistente.")
        observed = _utc_text(observed_at_utc)
        metrics = metrics if isinstance(metrics, dict) else {}
        transitions, observations = [], []
        connection = self._connect()
        try:
            with connection:
                for metric_key in METRIC_KEYS:
                    raw = metrics.get(metric_key)
                    raw = raw if isinstance(raw, dict) else {}
                    value = raw.get("value")
                    try:
                        value_num = float(value)
                        if not math.isfinite(value_num):
                            value_num = None
                    except (TypeError, ValueError):
                        value_num = None
                    derived = derive_state(metric_key, value_num)
                    state = self._metric_state(connection, run["hostname"], metric_key, observed)
                    previous = state["current_state"]
                    confirmed, candidate, count, changed, required = debounce_state(
                        previous, derived, state.get("candidate_state"), state.get("candidate_count", 0)
                    )
                    observation_id = uuid.uuid4().hex
                    details = {
                        "collector_details": raw.get("details"),
                        "threshold": METRIC_RULES[metric_key]["threshold_text"],
                        "candidate_state": candidate,
                        "candidate_count": count,
                        "required_samples": required,
                        "observation_only": True,
                    }
                    observation = {
                        "observation_id": observation_id,
                        "run_id": run["run_id"], "observed_at_utc": observed,
                        "hostname": run["hostname"], "metric_key": metric_key,
                        "value_num": value_num,
                        "unit": _clean_text(raw.get("unit") or METRIC_RULES[metric_key]["unit"], 20, required=True),
                        "derived_state": derived, "confirmed_state": confirmed,
                        "previous_confirmed_state": previous if changed else None,
                        "debounce_count": required if changed else count,
                        "source": _clean_text(raw.get("source") or "Coleta local indisponível", 160, required=True),
                        "details_json": sanitize_details(details),
                        "transition_event_id": None, "created_at": _utc_text(),
                    }
                    connection.execute("""
                        INSERT INTO monitoring_observations (
                            observation_id, run_id, observed_at_utc, hostname,
                            metric_key, value_num, unit, derived_state,
                            confirmed_state, previous_confirmed_state,
                            debounce_count, source, details_json,
                            transition_event_id, created_at
                        ) VALUES (
                            :observation_id, :run_id, :observed_at_utc, :hostname,
                            :metric_key, :value_num, :unit, :derived_state,
                            :confirmed_state, :previous_confirmed_state,
                            :debounce_count, :source, :details_json,
                            :transition_event_id, :created_at
                        )
                    """, observation)
                    state_since = observed if changed else state["state_since_utc"]
                    connection.execute("""
                        INSERT INTO monitoring_metric_state (
                            hostname, metric_key, current_state, state_since_utc,
                            last_value, last_observation_id, candidate_state,
                            candidate_count, updated_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(hostname, metric_key) DO UPDATE SET
                            current_state=excluded.current_state,
                            state_since_utc=excluded.state_since_utc,
                            last_value=excluded.last_value,
                            last_observation_id=excluded.last_observation_id,
                            candidate_state=excluded.candidate_state,
                            candidate_count=excluded.candidate_count,
                            updated_at_utc=excluded.updated_at_utc
                    """, (
                        run["hostname"], metric_key, confirmed, state_since,
                        value_num, observation_id, candidate, count, observed,
                    ))
                    observations.append(dict(observation))
                    if changed:
                        transitions.append(dict(observation))
        finally:
            connection.close()

        for transition in transitions:
            context = self.temporal_context(
                hostname=transition["hostname"], occurred_at_utc=transition["observed_at_utc"]
            ) if transition["confirmed_state"] in ("ATTENTION", "CRITICAL") else None
            value_text = (
                "indeterminado" if transition["value_num"] is None
                else f"{transition['value_num']:.1f}{transition['unit']}"
            )
            event = record_event_safe(
                self, logger=self.logger, source="MONITORING", category="SYSTEM",
                severity=("WARNING" if transition["confirmed_state"] in ("ATTENTION", "CRITICAL") else "NOTICE"),
                status="OBSERVED", hostname=transition["hostname"],
                operation_id=transition["run_id"],
                summary=(
                    f"{METRIC_RULES[transition['metric_key']]['title']} mudou de "
                    f"{transition['previous_confirmed_state']} para {transition['confirmed_state']} — {value_text}."
                ),
                details={
                    "event_kind": "METRIC_TRANSITION",
                    "metric_key": transition["metric_key"],
                    "before_state": transition["previous_confirmed_state"],
                    "after_state": transition["confirmed_state"],
                    "value": transition["value_num"], "unit": transition["unit"],
                    "run_id": transition["run_id"],
                    "observation_id": transition["observation_id"],
                    "debounce_samples": transition["debounce_count"],
                    "threshold": METRIC_RULES[transition["metric_key"]]["threshold_text"],
                    "temporal_context": context,
                    "principle": "Proximidade temporal não prova causalidade.",
                },
            )
            if event:
                transition["transition_event_id"] = event["id"]
                update = self._connect()
                try:
                    with update:
                        update.execute(
                            "UPDATE monitoring_observations SET transition_event_id=? WHERE observation_id=?",
                            (event["id"], transition["observation_id"]),
                        )
                finally:
                    update.close()
        return {"observed_at_utc": observed, "observations": observations, "transitions": transitions}

    def list_metric_states(self, *, hostname=None):
        hostname = _clean_text(hostname or socket.gethostname() or "Não disponível", 255, required=True)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM monitoring_metric_state WHERE hostname=? ORDER BY metric_key",
                (hostname,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def list_observations(self, *, hostname=None, metric_key=None, since_utc=None,
                          limit=50, offset=0):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        clauses, params = [], {"limit": limit, "offset": offset}
        if hostname:
            clauses.append("hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        if metric_key:
            if metric_key not in METRIC_KEYS:
                raise ValueError("Métrica inválida para consulta.")
            clauses.append("metric_key=:metric_key")
            params["metric_key"] = metric_key
        if since_utc:
            clauses.append("observed_at_utc>=:since")
            params["since"] = _utc_text(since_utc)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM monitoring_observations" + where
                + " ORDER BY observed_at_utc DESC, observation_id DESC LIMIT :limit OFFSET :offset",
                params,
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def count_observations(self, *, hostname=None, metric_key=None, since_utc=None):
        clauses, params = [], {}
        if hostname:
            clauses.append("hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        if metric_key:
            if metric_key not in METRIC_KEYS:
                raise ValueError("Métrica inválida para consulta.")
            clauses.append("metric_key=:metric_key")
            params["metric_key"] = metric_key
        if since_utc:
            clauses.append("observed_at_utc>=:since")
            params["since"] = _utc_text(since_utc)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            return int(connection.execute(
                "SELECT COUNT(*) FROM monitoring_observations" + where, params
            ).fetchone()[0])
        finally:
            connection.close()

    def list_transitions(self, *, hostname=None, limit=50, offset=0):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        clauses = ["previous_confirmed_state IS NOT NULL", "previous_confirmed_state<>confirmed_state"]
        params = {"limit": limit, "offset": offset}
        if hostname:
            clauses.append("hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        connection = self._connect()
        try:
            rows = connection.execute("""
                SELECT * FROM monitoring_observations WHERE """ + " AND ".join(clauses) + """
                ORDER BY observed_at_utc DESC, observation_id DESC
                LIMIT :limit OFFSET :offset
            """, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def temporal_context(self, *, hostname, occurred_at_utc, window_minutes=CORRELATION_WINDOW_MINUTES):
        hostname = _clean_text(hostname, 255, required=True)
        center = datetime.fromisoformat(_utc_text(occurred_at_utc).replace("Z", "+00:00"))
        window = max(1, min(int(window_minutes), 60))
        start, end = _utc_text(center - timedelta(minutes=window)), _utc_text(center + timedelta(minutes=window))
        connection = self._connect()
        try:
            events = [dict(row) for row in connection.execute("""
                SELECT id, timestamp_utc, source, operation_id, correlation_id, summary
                FROM events WHERE hostname=? AND timestamp_utc BETWEEN ? AND ?
                ORDER BY timestamp_utc DESC LIMIT 30
            """, (hostname, start, end)).fetchall()]
            groups = [dict(row) for row in connection.execute("""
                SELECT operation_id, detected_at_utc, source, correlation_id, summary
                FROM change_groups WHERE hostname=? AND detected_at_utc BETWEEN ? AND ?
                ORDER BY detected_at_utc DESC LIMIT 20
            """, (hostname, start, end)).fetchall()]
            operations = {item.get("operation_id") for item in events + groups if item.get("operation_id")}
            correlations = {item.get("correlation_id") for item in events + groups if item.get("correlation_id")}
            sessions = []
            for row in connection.execute("""
                SELECT session_id, title, primary_operation_id, primary_correlation_id
                FROM investigation_sessions
                WHERE hostname=? AND status='OPEN' ORDER BY updated_at_utc DESC LIMIT 30
            """, (hostname,)).fetchall():
                item = dict(row)
                if (item.get("primary_operation_id") in operations
                        or item.get("primary_correlation_id") in correlations):
                    sessions.append(item)
            return {
                "relation": "TEMPORAL_CONTEXT", "window_minutes": window,
                "hostname": hostname, "window_start_utc": start, "window_end_utc": end,
                "timeline_events": events, "change_groups": groups,
                "related_open_sessions": sessions,
                "causality": "Não inferida; itens apenas próximos no tempo e no mesmo equipamento.",
            }
        finally:
            connection.close()

    def create_investigation_from_observation(self, observation_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM monitoring_observations WHERE observation_id=?",
                (_clean_text(observation_id, 64, required=True),),
            ).fetchone()
        finally:
            connection.close()
        if row is None or not row["transition_event_id"]:
            raise ValueError("A transição não possui evento de Timeline disponível.")
        event_id = row["transition_event_id"]
        return (
            self.find_session_for_reference("TIMELINE_EVENT", event_id)
            or self.create_from_timeline_event(event_id)
        )

    def purge_observations(self, *, retention_days=RETENTION_DAYS, now_utc=None):
        days = max(1, min(int(retention_days), 365))
        now = datetime.fromisoformat(_utc_text(now_utc).replace("Z", "+00:00"))
        cutoff = _utc_text(now - timedelta(days=days))
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    "DELETE FROM monitoring_observations WHERE observed_at_utc<?", (cutoff,)
                )
                removed = max(0, int(cursor.rowcount))
        finally:
            connection.close()
        if self.logger is not None:
            try:
                self.logger.info(
                    "MONITORING_RETENTION | dias=%s | amostras_removidas=%s", days, removed
                )
            except Exception:
                pass
        return removed


def _cancelled(cancel_callback):
    try:
        return bool(cancel_callback and cancel_callback())
    except Exception:
        return False


def _read_proc_cpu():
    line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()
    values = [int(value) for value in line[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, sum(values)


def _cpu_percent(cancel_callback=None):
    if os.name == "nt":
        class FILETIME(ctypes.Structure):
            _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))

        def sample():
            idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
            if not ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
            ):
                raise OSError("GetSystemTimes indisponível")
            number = lambda value: (int(value.high) << 32) | int(value.low)
            return number(idle), number(kernel) + number(user)
        source = "Windows GetSystemTimes"
    else:
        sample = _read_proc_cpu
        source = "Sistema local /proc/stat"
    first_idle, first_total = sample()
    for _ in range(8):
        if _cancelled(cancel_callback):
            raise InterruptedError("Coleta cancelada")
        time.sleep(0.02)
    second_idle, second_total = sample()
    total = second_total - first_total
    idle = second_idle - first_idle
    if total <= 0:
        raise ValueError("Amostra de CPU sem intervalo válido")
    return round(max(0.0, min(100.0, (1.0 - idle / total) * 100.0)), 1), source, {}


def _memory_percent():
    if os.name == "nt":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = (
                ("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32),
                ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            )
        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError("GlobalMemoryStatusEx indisponível")
        return float(status.dwMemoryLoad), "Windows GlobalMemoryStatusEx", {
            "available_bytes": int(status.ullAvailPhys), "total_bytes": int(status.ullTotalPhys),
        }
    total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    available = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
    if total <= 0:
        raise ValueError("Memória total indisponível")
    return round((1.0 - available / total) * 100.0, 1), "Sistema local sysconf", {
        "available_bytes": int(available), "total_bytes": int(total),
    }


def _disk_free_percent():
    root = (os.environ.get("SystemDrive", "C:") + "\\") if os.name == "nt" else (Path.cwd().anchor or "/")
    usage = shutil.disk_usage(root)
    if usage.total <= 0:
        raise ValueError("Capacidade do disco do sistema indisponível")
    return round(usage.free / usage.total * 100.0, 1), "Sistema local shutil.disk_usage", {
        "root": root, "free_bytes": int(usage.free), "total_bytes": int(usage.total),
    }


def collect_local_metrics(cancel_callback=None):
    """Coleta independente por métrica; uma falha não invalida as demais."""
    collected = {}
    functions = {
        "cpu_usage": lambda: _cpu_percent(cancel_callback),
        "memory_usage": _memory_percent,
        "system_disk_free": _disk_free_percent,
    }
    for metric_key in METRIC_KEYS:
        if _cancelled(cancel_callback):
            raise InterruptedError("Coleta local cancelada cooperativamente.")
        try:
            value, source, details = functions[metric_key]()
            collected[metric_key] = {
                "value": value, "unit": "%", "source": source, "details": details,
            }
        except InterruptedError:
            raise
        except Exception as exc:
            collected[metric_key] = {
                "value": None, "unit": "%", "source": "Coleta local indisponível",
                "details": {"error_type": type(exc).__name__},
            }
    return {
        "hostname": socket.gethostname() or "Não disponível",
        "observed_at_utc": _utc_text(), "metrics": collected,
    }


class MonitoringService:
    """Lifecycle local; não cria thread, serviço, tarefa ou processo persistente."""

    def __init__(self, store, collector=collect_local_metrics, logger=None):
        self.store = store
        self.collector = collector
        self.logger = logger
        self.status = "STOPPED"
        self.run_id = None
        self.interval_seconds = 60
        self.retention_days = RETENTION_DAYS
        self._collect_lock = threading.Lock()
        self._persistent_error = False

    def start(self, interval_seconds=60):
        if self.status != "STOPPED":
            return self.store.get_run(self.run_id) if self.run_id else None
        self.interval_seconds = validate_interval(interval_seconds)
        run = self.store.start_run(interval_seconds=self.interval_seconds)
        self.run_id, self.status = run["run_id"], "RUNNING"
        self._persistent_error = False
        self.store.purge_observations(retention_days=self.retention_days)
        return run

    def pause(self):
        if self.status not in ("RUNNING", "ERROR") or not self.run_id:
            return None
        run = self.store.set_run_status(self.run_id, "PAUSED")
        self.status = "PAUSED"
        return run

    def resume(self):
        if self.status != "PAUSED" or not self.run_id:
            return None
        run = self.store.set_run_status(self.run_id, "RUNNING")
        self.status = "RUNNING"
        return run

    def stop(self, reason="Solicitação do técnico"):
        if self.status == "STOPPED" or not self.run_id:
            self.status = "STOPPED"
            return None
        run = self.store.set_run_status(self.run_id, "STOPPED", reason=reason)
        self.status = "STOPPED"
        return run

    def close(self):
        return self.stop("Encerramento do Configurador TI")

    def set_interval(self, interval_seconds):
        self.interval_seconds = validate_interval(interval_seconds)
        if self.run_id and self.status != "STOPPED":
            self.store.update_interval(self.run_id, self.interval_seconds)
        return self.interval_seconds

    def set_retention_days(self, retention_days):
        """Aplica somente a política usada em futuras rotinas normais de retenção.

        A alteração não remove observações e não dispara purge durante a transação.
        """
        self.retention_days = validate_retention_days(retention_days)
        return self.retention_days

    def collect_once(self, cancel_callback=None):
        if self.status not in ("RUNNING", "ERROR") or not self.run_id:
            return {"ok": False, "skipped": "not_running", "status": self.status}
        if not self._collect_lock.acquire(blocking=False):
            return {"ok": False, "skipped": "overlap", "status": self.status}
        try:
            if _cancelled(cancel_callback):
                return {"ok": False, "cancelled": True, "status": self.status}
            try:
                snapshot = self.collector(cancel_callback=cancel_callback)
                cycle = self.store.record_cycle(
                    self.run_id, snapshot.get("metrics"),
                    observed_at_utc=snapshot.get("observed_at_utc"),
                )
                if self._persistent_error or self.status == "ERROR":
                    self.store.set_run_status(
                        self.run_id, "RUNNING", reason="Coleta local voltou a produzir evidência."
                    )
                    self.status = "RUNNING"
                    self._persistent_error = False
                return {"ok": True, "status": self.status, "run_id": self.run_id, "cycle": cycle}
            except InterruptedError:
                return {"ok": False, "cancelled": True, "status": self.status}
            except Exception as exc:
                self.status = "ERROR"
                if not self._persistent_error:
                    try:
                        self.store.set_run_status(
                            self.run_id, "ERROR", reason=f"Falha controlada: {type(exc).__name__}"
                        )
                    except Exception:
                        pass
                self._persistent_error = True
                if self.logger is not None:
                    try:
                        self.logger.error("MONITORING_CYCLE_FAILURE | type=%s", type(exc).__name__)
                    except Exception:
                        pass
                return {"ok": False, "status": "ERROR", "error_type": type(exc).__name__}
        finally:
            self._collect_lock.release()


def monitoring_action_safe(service_or_store, logger, action, *args, **kwargs):
    """Best effort: falha do monitor nunca derruba as outras camadas."""
    try:
        if service_or_store is None:
            return None
        return action(service_or_store, *args, **kwargs)
    except Exception as exc:
        if logger is not None:
            try:
                logger.error("MONITORING_ACTION_FAILURE | type=%s", type(exc).__name__)
            except Exception:
                pass
        return None
