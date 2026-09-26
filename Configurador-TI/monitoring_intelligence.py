"""Alertas, tendências e correlação contextual sobre a fundação local.

Alerta não é incidente, tendência não é previsão e correlação não é
causalidade. Esta camada usa somente dados locais já persistidos pelo Configurador TI.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
import os
import socket
import uuid

from audit_timeline import _clean_text, _utc_text, record_event_safe, sanitize_details
from incident_replay import sanitize_note
from monitoring_foundation import METRIC_KEYS, METRIC_RULES, MonitoringStore


DATABASE_SCHEMA_VERSION = 5
ALERT_SCHEMA_VERSION = 1
ALERT_STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
ALERT_SEVERITIES = ("ATTENTION", "CRITICAL")
ALERT_EVENT_KINDS = ("OPENED", "ACKNOWLEDGED", "SEVERITY_CHANGED", "RESOLVED")
TREND_PERIODS = {"1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600, "7d": 7 * 24 * 3600}
TREND_DIRECTIONS = ("RISING", "STABLE", "FALLING", "INSUFFICIENT_DATA")
TREND_MIN_SAMPLES = 4
TREND_TOLERANCES = {
    key: {"absolute": 2.0, "relative": 0.05} for key in METRIC_KEYS
}
MAX_ALERT_QUERY = 200
MAX_CONTEXT_RESULTS = 100


def local_technical_identity():
    """Usa somente a identidade local já disponível, sem autenticação nova."""
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "Técnico local"
    domain = os.environ.get("USERDOMAIN")
    value = f"{domain}\\{user}" if domain and domain.casefold() != str(user).casefold() else user
    return _clean_text(value, 100, required=True)


def _parsed_utc(value):
    return datetime.fromisoformat(_utc_text(value).replace("Z", "+00:00"))


def _alert_enum(value, allowed, field):
    normalized = str(value or "").strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{field} inválido para alertas locais.")
    return normalized


class MonitoringIntelligenceStore(MonitoringStore):
    """Evolui o schema 4 sem alterar coleta, thresholds ou debounce da fundação."""

    def __init__(self, root, logger=None, timeout=5.0):
        super().__init__(root, logger=logger, timeout=timeout)
        self._initialize_intelligence()

    def _initialize_intelligence(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (4, DATABASE_SCHEMA_VERSION, 6, 7, 8, 9):
                raise RuntimeError("Versão do banco de alertas não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_alerts (
                        alert_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        hostname TEXT NOT NULL,
                        metric_key TEXT NOT NULL,
                        status TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        first_seen_utc TEXT NOT NULL,
                        last_seen_utc TEXT NOT NULL,
                        resolved_at_utc TEXT,
                        acknowledged_at_utc TEXT,
                        acknowledged_by TEXT,
                        acknowledgement_note TEXT,
                        first_observation_id TEXT,
                        last_observation_id TEXT,
                        first_transition_event_id TEXT,
                        last_transition_event_id TEXT,
                        opening_event_id TEXT,
                        last_event_id TEXT,
                        current_value REAL,
                        unit TEXT NOT NULL,
                        occurrence_count INTEGER NOT NULL,
                        investigation_session_id TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_alert_events (
                        alert_event_id TEXT PRIMARY KEY,
                        alert_id TEXT NOT NULL,
                        event_kind TEXT NOT NULL,
                        occurred_at_utc TEXT NOT NULL,
                        previous_status TEXT,
                        current_status TEXT NOT NULL,
                        previous_severity TEXT,
                        current_severity TEXT NOT NULL,
                        value_num REAL,
                        unit TEXT NOT NULL,
                        observation_id TEXT,
                        transition_event_id TEXT,
                        timeline_event_id TEXT,
                        details_json TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(alert_id) REFERENCES monitoring_alerts(alert_id) ON DELETE CASCADE
                    )
                """)
                for name, table, expression in (
                    ("idx_monitor_alert_status", "monitoring_alerts", "status, severity, last_seen_utc DESC"),
                    ("idx_monitor_alert_host_metric", "monitoring_alerts", "hostname, metric_key, last_seen_utc DESC"),
                    ("idx_monitor_alert_resolved", "monitoring_alerts", "resolved_at_utc DESC"),
                    ("idx_monitor_alert_session", "monitoring_alerts", "investigation_session_id"),
                    ("idx_monitor_alert_events_alert", "monitoring_alert_events", "alert_id, occurred_at_utc DESC"),
                    ("idx_monitor_alert_events_time", "monitoring_alert_events", "occurred_at_utc DESC"),
                ):
                    connection.execute(
                        f"CREATE INDEX IF NOT EXISTS {name} ON {table}({expression})"
                    )
                connection.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_monitor_alert_one_active
                    ON monitoring_alerts(hostname, metric_key)
                    WHERE status IN ('OPEN', 'ACKNOWLEDGED')
                """)
                if current < DATABASE_SCHEMA_VERSION:
                    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
        finally:
            connection.close()

    def record_cycle(self, run_id, metrics, *, observed_at_utc=None):
        cycle = super().record_cycle(
            run_id, metrics, observed_at_utc=observed_at_utc
        )
        transition_map = {
            item["observation_id"]: item for item in cycle.get("transitions") or []
        }
        alert_events = []
        for observation in cycle.get("observations") or []:
            transition = transition_map.get(observation["observation_id"])
            if transition:
                observation["transition_event_id"] = transition.get("transition_event_id")
            action = self._sync_alert_from_observation(observation)
            if action:
                alert_events.append(action)
        cycle["alert_events"] = alert_events
        return cycle

    def _active_alert(self, connection, hostname, metric_key):
        row = connection.execute("""
            SELECT * FROM monitoring_alerts
            WHERE hostname=? AND metric_key=?
              AND status IN ('OPEN', 'ACKNOWLEDGED')
            ORDER BY first_seen_utc DESC LIMIT 1
        """, (hostname, metric_key)).fetchone()
        return dict(row) if row else None

    def _latest_confirmed_anomaly(self, connection, hostname, metric_key):
        row = connection.execute("""
            SELECT * FROM monitoring_observations
            WHERE hostname=? AND metric_key=?
              AND previous_confirmed_state IS NOT NULL
              AND confirmed_state IN ('ATTENTION', 'CRITICAL')
            ORDER BY observed_at_utc DESC, observation_id DESC LIMIT 1
        """, (hostname, metric_key)).fetchone()
        return dict(row) if row else None

    def _insert_alert_event(self, connection, alert, kind, *, previous_status=None,
                            previous_severity=None, observation=None):
        event = {
            "alert_event_id": uuid.uuid4().hex,
            "alert_id": alert["alert_id"],
            "event_kind": _alert_enum(kind, ALERT_EVENT_KINDS, "Evento"),
            "occurred_at_utc": _utc_text(
                (observation or {}).get("observed_at_utc") or datetime.now(timezone.utc)
            ),
            "previous_status": previous_status,
            "current_status": alert["status"],
            "previous_severity": previous_severity,
            "current_severity": alert["severity"],
            "value_num": (observation or {}).get("value_num", alert.get("current_value")),
            "unit": _clean_text((observation or {}).get("unit") or alert["unit"], 20, required=True),
            "observation_id": (observation or {}).get("observation_id"),
            "transition_event_id": (observation or {}).get("transition_event_id"),
            "timeline_event_id": None,
            "details_json": sanitize_details({
                "principle": "Alerta não é incidente; correlação não prova causalidade."
            }),
            "created_at": _utc_text(),
        }
        connection.execute("""
            INSERT INTO monitoring_alert_events (
                alert_event_id, alert_id, event_kind, occurred_at_utc,
                previous_status, current_status, previous_severity,
                current_severity, value_num, unit, observation_id,
                transition_event_id, timeline_event_id, details_json, created_at
            ) VALUES (
                :alert_event_id, :alert_id, :event_kind, :occurred_at_utc,
                :previous_status, :current_status, :previous_severity,
                :current_severity, :value_num, :unit, :observation_id,
                :transition_event_id, :timeline_event_id, :details_json, :created_at
            )
        """, event)
        return event

    def _sync_alert_from_observation(self, observation):
        state = observation.get("confirmed_state")
        if state not in ("ATTENTION", "CRITICAL", "NORMAL", "INDETERMINATE"):
            return None
        connection = self._connect()
        action = None
        try:
            with connection:
                active = self._active_alert(
                    connection, observation["hostname"], observation["metric_key"]
                )
                now = _utc_text()
                if state in ALERT_SEVERITIES:
                    if active is None:
                        origin = observation if observation.get("previous_confirmed_state") else (
                            self._latest_confirmed_anomaly(
                                connection, observation["hostname"], observation["metric_key"]
                            )
                        )
                        if origin is None:
                            return None
                        alert = {
                            "alert_id": uuid.uuid4().hex,
                            "schema_version": ALERT_SCHEMA_VERSION,
                            "hostname": observation["hostname"],
                            "metric_key": observation["metric_key"],
                            "status": "OPEN", "severity": state,
                            "first_seen_utc": origin["observed_at_utc"],
                            "last_seen_utc": observation["observed_at_utc"],
                            "resolved_at_utc": None,
                            "acknowledged_at_utc": None,
                            "acknowledged_by": None,
                            "acknowledgement_note": None,
                            "first_observation_id": origin.get("observation_id"),
                            "last_observation_id": observation.get("observation_id"),
                            "first_transition_event_id": origin.get("transition_event_id"),
                            "last_transition_event_id": observation.get("transition_event_id") or origin.get("transition_event_id"),
                            "opening_event_id": None, "last_event_id": None,
                            "current_value": observation.get("value_num"),
                            "unit": observation.get("unit") or "%",
                            "occurrence_count": 1,
                            "investigation_session_id": None,
                            "created_at": now, "updated_at": now,
                        }
                        connection.execute("""
                            INSERT INTO monitoring_alerts (
                                alert_id, schema_version, hostname, metric_key,
                                status, severity, first_seen_utc, last_seen_utc,
                                resolved_at_utc, acknowledged_at_utc, acknowledged_by,
                                acknowledgement_note, first_observation_id,
                                last_observation_id, first_transition_event_id,
                                last_transition_event_id, opening_event_id,
                                last_event_id, current_value, unit, occurrence_count,
                                investigation_session_id, created_at, updated_at
                            ) VALUES (
                                :alert_id, :schema_version, :hostname, :metric_key,
                                :status, :severity, :first_seen_utc, :last_seen_utc,
                                :resolved_at_utc, :acknowledged_at_utc, :acknowledged_by,
                                :acknowledgement_note, :first_observation_id,
                                :last_observation_id, :first_transition_event_id,
                                :last_transition_event_id, :opening_event_id,
                                :last_event_id, :current_value, :unit, :occurrence_count,
                                :investigation_session_id, :created_at, :updated_at
                            )
                        """, alert)
                        action = self._insert_alert_event(
                            connection, alert, "OPENED", observation=observation
                        )
                    else:
                        previous_severity = active["severity"]
                        severity_changed = previous_severity != state
                        worse = previous_severity == "ATTENTION" and state == "CRITICAL"
                        connection.execute("""
                            UPDATE monitoring_alerts SET
                                severity=?, last_seen_utc=?, last_observation_id=?,
                                last_transition_event_id=COALESCE(?, last_transition_event_id),
                                current_value=?, unit=?,
                                occurrence_count=occurrence_count+?, updated_at=?
                            WHERE alert_id=?
                        """, (
                            state, observation["observed_at_utc"],
                            observation.get("observation_id"),
                            observation.get("transition_event_id"),
                            observation.get("value_num"), observation.get("unit") or "%",
                            1 if worse else 0, now, active["alert_id"],
                        ))
                        if severity_changed:
                            updated = dict(active, severity=state,
                                           last_seen_utc=observation["observed_at_utc"],
                                           current_value=observation.get("value_num"),
                                           unit=observation.get("unit") or "%")
                            action = self._insert_alert_event(
                                connection, updated, "SEVERITY_CHANGED",
                                previous_status=active["status"],
                                previous_severity=previous_severity,
                                observation=observation,
                            )
                elif state == "NORMAL" and active is not None:
                    connection.execute("""
                        UPDATE monitoring_alerts SET status='RESOLVED',
                            last_seen_utc=?, resolved_at_utc=?,
                            last_observation_id=?,
                            last_transition_event_id=COALESCE(?, last_transition_event_id),
                            current_value=?, unit=?, updated_at=?
                        WHERE alert_id=?
                    """, (
                        observation["observed_at_utc"], observation["observed_at_utc"],
                        observation.get("observation_id"),
                        observation.get("transition_event_id"),
                        observation.get("value_num"), observation.get("unit") or "%",
                        now, active["alert_id"],
                    ))
                    resolved = dict(active, status="RESOLVED",
                                    last_seen_utc=observation["observed_at_utc"],
                                    current_value=observation.get("value_num"),
                                    unit=observation.get("unit") or "%")
                    action = self._insert_alert_event(
                        connection, resolved, "RESOLVED",
                        previous_status=active["status"],
                        previous_severity=active["severity"],
                        observation=observation,
                    )
        finally:
            connection.close()
        if action:
            self._emit_alert_timeline_event(action)
        return action

    def _emit_alert_timeline_event(self, action):
        alert = self.get_alert(action["alert_id"])
        if alert is None:
            return None
        kind = action["event_kind"]
        title = METRIC_RULES[alert["metric_key"]]["title"]
        summaries = {
            "OPENED": f"Alerta local aberto: {title} em {alert['severity']}.",
            "ACKNOWLEDGED": f"Alerta local reconhecido: {title}.",
            "SEVERITY_CHANGED": (
                f"Severidade do alerta de {title} mudou de "
                f"{action.get('previous_severity') or '—'} para {alert['severity']}."
            ),
            "RESOLVED": f"Alerta local resolvido: {title} voltou a NORMAL confirmado.",
        }
        timeline = record_event_safe(
            self, logger=self.logger, source="MONITORING_ALERT", category="SYSTEM",
            severity=(
                "NOTICE" if kind in ("ACKNOWLEDGED", "RESOLVED")
                else "ERROR" if alert["severity"] == "CRITICAL" else "WARNING"
            ),
            status="OBSERVED", summary=summaries[kind],
            hostname=alert["hostname"], operation_id=alert["alert_id"],
            timestamp_utc=action["occurred_at_utc"],
            details={
                "event_kind": f"ALERT_{kind}", "alert_id": alert["alert_id"],
                "metric_key": alert["metric_key"], "alert_status": alert["status"],
                "severity": alert["severity"], "value": action.get("value_num"),
                "unit": action.get("unit"),
                "observation_id": action.get("observation_id"),
                "transition_event_id": action.get("transition_event_id"),
                "principle": "Alerta não é incidente; correlação não prova causalidade.",
            },
        )
        if timeline:
            connection = self._connect()
            try:
                with connection:
                    connection.execute(
                        "UPDATE monitoring_alert_events SET timeline_event_id=? WHERE alert_event_id=?",
                        (timeline["id"], action["alert_event_id"]),
                    )
                    connection.execute("""
                        UPDATE monitoring_alerts SET
                            opening_event_id=CASE WHEN ?='OPENED' THEN COALESCE(opening_event_id, ?) ELSE opening_event_id END,
                            last_event_id=?, updated_at=? WHERE alert_id=?
                    """, (kind, timeline["id"], timeline["id"], _utc_text(), alert["alert_id"]))
            finally:
                connection.close()
        return timeline

    def acknowledge_alert(self, alert_id, *, acknowledged_by=None, note=None):
        alert = self.get_alert(alert_id)
        if alert is None:
            raise ValueError("Alerta local inexistente.")
        if alert["status"] == "RESOLVED":
            raise ValueError("Alerta resolvido não pode ser reconhecido novamente.")
        if alert["status"] == "ACKNOWLEDGED":
            return alert
        identity = _clean_text(
            acknowledged_by or local_technical_identity(), 100, required=True
        )
        acknowledged_at = _utc_text()
        clean_note = sanitize_note(note)
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE monitoring_alerts SET status='ACKNOWLEDGED',
                        acknowledged_at_utc=?, acknowledged_by=?,
                        acknowledgement_note=?, updated_at=? WHERE alert_id=?
                """, (acknowledged_at, identity, clean_note, acknowledged_at, alert["alert_id"]))
                updated = dict(alert, status="ACKNOWLEDGED",
                               acknowledged_at_utc=acknowledged_at,
                               acknowledged_by=identity,
                               acknowledgement_note=clean_note)
                action = self._insert_alert_event(
                    connection, updated, "ACKNOWLEDGED",
                    previous_status=alert["status"],
                    previous_severity=alert["severity"],
                )
        finally:
            connection.close()
        self._emit_alert_timeline_event(action)
        return self.get_alert(alert["alert_id"])

    @staticmethod
    def _alert_filters(*, status=None, severity=None, metric_key=None,
                       hostname=None, since_utc=None):
        clauses, params = [], {}
        if status:
            clauses.append("a.status=:status")
            params["status"] = _alert_enum(status, ALERT_STATUSES, "Status")
        if severity:
            clauses.append("a.severity=:severity")
            params["severity"] = _alert_enum(severity, ALERT_SEVERITIES, "Severidade")
        if metric_key:
            if metric_key not in METRIC_KEYS:
                raise ValueError("Métrica inválida para alertas.")
            clauses.append("a.metric_key=:metric_key")
            params["metric_key"] = metric_key
        if hostname:
            clauses.append("a.hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        if since_utc:
            clauses.append("a.last_seen_utc>=:since_utc")
            params["since_utc"] = _utc_text(since_utc)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    @staticmethod
    def _alert_select():
        return """SELECT a.*,
            CASE WHEN a.first_observation_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM monitoring_observations o
                              WHERE o.observation_id=a.first_observation_id)
            THEN 1 ELSE 0 END AS original_observation_expired
            FROM monitoring_alerts a"""

    def get_alert(self, alert_id):
        connection = self._connect()
        try:
            row = connection.execute(
                self._alert_select() + " WHERE a.alert_id=?",
                (_clean_text(alert_id, 64, required=True),),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def list_alerts(self, *, status=None, severity=None, metric_key=None,
                    hostname=None, since_utc=None, limit=50, offset=0):
        limit = max(1, min(int(limit), MAX_ALERT_QUERY))
        offset = max(0, int(offset))
        where, params = self._alert_filters(
            status=status, severity=severity, metric_key=metric_key,
            hostname=hostname, since_utc=since_utc,
        )
        params.update(limit=limit, offset=offset)
        connection = self._connect()
        try:
            rows = connection.execute(
                self._alert_select() + where + """
                ORDER BY CASE
                    WHEN a.status='OPEN' AND a.severity='CRITICAL' THEN 0
                    WHEN a.status='ACKNOWLEDGED' AND a.severity='CRITICAL' THEN 1
                    WHEN a.status='OPEN' AND a.severity='ATTENTION' THEN 2
                    WHEN a.status='ACKNOWLEDGED' AND a.severity='ATTENTION' THEN 3
                    ELSE 4 END,
                    a.last_seen_utc DESC, a.alert_id DESC
                LIMIT :limit OFFSET :offset
                """, params,
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def count_alerts(self, **filters):
        where, params = self._alert_filters(**filters)
        connection = self._connect()
        try:
            return int(connection.execute(
                "SELECT COUNT(*) FROM monitoring_alerts a" + where, params
            ).fetchone()[0])
        finally:
            connection.close()

    def alert_summary(self, *, hostname=None, now_utc=None):
        clauses, params = [], {}
        if hostname:
            clauses.append("hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        base = " WHERE " + " AND ".join(clauses) if clauses else ""
        now = _parsed_utc(now_utc or datetime.now(timezone.utc))
        params["recent"] = _utc_text(now - timedelta(hours=24))
        connection = self._connect()
        try:
            row = connection.execute("""
                SELECT
                    SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) AS open_count,
                    SUM(CASE WHEN status='ACKNOWLEDGED' THEN 1 ELSE 0 END) AS acknowledged_count,
                    SUM(CASE WHEN status IN ('OPEN','ACKNOWLEDGED') AND severity='CRITICAL' THEN 1 ELSE 0 END) AS critical_active_count,
                    SUM(CASE WHEN status='RESOLVED' AND resolved_at_utc>=:recent THEN 1 ELSE 0 END) AS resolved_recent_count
                FROM monitoring_alerts
            """ + base, params).fetchone()
            return {key: int(row[key] or 0) for key in row.keys()}
        finally:
            connection.close()

    def list_alert_events(self, alert_id, *, limit=100):
        limit = max(1, min(int(limit), MAX_ALERT_QUERY))
        connection = self._connect()
        try:
            rows = connection.execute("""
                SELECT * FROM monitoring_alert_events WHERE alert_id=?
                ORDER BY occurred_at_utc ASC, created_at ASC LIMIT ?
            """, (_clean_text(alert_id, 64, required=True), limit)).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def trend_summary(self, *, hostname=None, metric_key, period="1h", now_utc=None):
        if metric_key not in METRIC_KEYS:
            raise ValueError("Métrica inválida para tendência.")
        period_key = str(period or "").strip().lower()
        if period_key not in TREND_PERIODS:
            raise ValueError("Período inválido para tendência.")
        hostname = _clean_text(
            hostname or socket.gethostname() or "Não disponível", 255, required=True
        )
        end = _parsed_utc(now_utc or datetime.now(timezone.utc))
        start = end - timedelta(seconds=TREND_PERIODS[period_key])
        params = (hostname, metric_key, _utc_text(start), _utc_text(end))
        connection = self._connect()
        try:
            row = connection.execute("""
                WITH base AS (
                    SELECT observation_id, observed_at_utc, value_num
                    FROM monitoring_observations
                    WHERE hostname=? AND metric_key=? AND value_num IS NOT NULL
                      AND observed_at_utc BETWEEN ? AND ?
                ), ranked AS (
                    SELECT observed_at_utc, value_num,
                           ROW_NUMBER() OVER (ORDER BY observed_at_utc, observation_id) AS rn,
                           COUNT(*) OVER () AS total
                    FROM base
                )
                SELECT COUNT(*) AS sample_count, MIN(value_num) AS minimum,
                       MAX(value_num) AS maximum, AVG(value_num) AS average,
                       MIN(observed_at_utc) AS first_observed_at,
                       MAX(observed_at_utc) AS last_observed_at,
                       AVG(CASE WHEN rn <= (total + 1) / 2 THEN value_num END) AS first_half_average,
                       AVG(CASE WHEN rn > (total + 1) / 2 THEN value_num END) AS second_half_average
                FROM ranked
            """, params).fetchone()
            current_row = connection.execute("""
                SELECT value_num, observed_at_utc FROM monitoring_observations
                WHERE hostname=? AND metric_key=? AND value_num IS NOT NULL
                  AND observed_at_utc BETWEEN ? AND ?
                ORDER BY observed_at_utc DESC, observation_id DESC LIMIT 1
            """, params).fetchone()
        finally:
            connection.close()
        count = int(row["sample_count"] or 0)
        first_average, second_average = row["first_half_average"], row["second_half_average"]
        direction = "INSUFFICIENT_DATA"
        tolerance = None
        if count >= TREND_MIN_SAMPLES and first_average is not None and second_average is not None:
            rule = TREND_TOLERANCES[metric_key]
            tolerance = max(rule["absolute"], abs(float(first_average)) * rule["relative"])
            delta = float(second_average) - float(first_average)
            direction = "STABLE" if abs(delta) <= tolerance else (
                "RISING" if delta > 0 else "FALLING"
            )
        return {
            "hostname": hostname, "metric_key": metric_key, "period": period_key,
            "current": float(current_row["value_num"]) if current_row else None,
            "minimum": float(row["minimum"]) if row["minimum"] is not None else None,
            "maximum": float(row["maximum"]) if row["maximum"] is not None else None,
            "average": float(row["average"]) if row["average"] is not None else None,
            "sample_count": count,
            "first_observed_at": row["first_observed_at"],
            "last_observed_at": row["last_observed_at"],
            "first_half_average": float(first_average) if first_average is not None else None,
            "second_half_average": float(second_average) if second_average is not None else None,
            "trend_direction": direction, "tolerance": tolerance,
            "criterion": (
                "Médias da primeira e segunda metade; estabilidade dentro de "
                "max(2 pontos percentuais, 5% da média inicial). Sem previsão."
            ),
        }

    def trend_query_plan(self, *, hostname, metric_key, since_utc, until_utc):
        if metric_key not in METRIC_KEYS:
            raise ValueError("Métrica inválida para tendência.")
        connection = self._connect()
        try:
            rows = connection.execute("""
                EXPLAIN QUERY PLAN SELECT observed_at_utc, value_num
                FROM monitoring_observations
                WHERE hostname=? AND metric_key=? AND value_num IS NOT NULL
                  AND observed_at_utc BETWEEN ? AND ?
                ORDER BY observed_at_utc
            """, (
                _clean_text(hostname, 255, required=True), metric_key,
                _utc_text(since_utc), _utc_text(until_utc),
            )).fetchall()
            return [" ".join(str(value) for value in row) for row in rows]
        finally:
            connection.close()

    def alert_context(self, alert_id, *, window_minutes=10, limit=50):
        alert = self.get_alert(alert_id)
        if alert is None:
            raise ValueError("Alerta local inexistente.")
        window = max(1, min(int(window_minutes), 60))
        limit = max(1, min(int(limit), MAX_CONTEXT_RESULTS))
        connection = self._connect()
        try:
            anchor_row = connection.execute("""
                SELECT * FROM monitoring_alert_events
                WHERE alert_id=? AND event_kind IN ('OPENED','SEVERITY_CHANGED')
                ORDER BY occurred_at_utc DESC, created_at DESC LIMIT 1
            """, (alert["alert_id"],)).fetchone()
            anchor = dict(anchor_row) if anchor_row else None
            anchor_time = (anchor or {}).get("occurred_at_utc") or alert["first_seen_utc"]
            center = _parsed_utc(anchor_time)
            start, end = _utc_text(center - timedelta(minutes=window)), _utc_text(center + timedelta(minutes=window))
            anchor_event_id = (anchor or {}).get("transition_event_id") or alert.get("opening_event_id")
            anchor_event = None
            if anchor_event_id:
                row = connection.execute("SELECT * FROM events WHERE id=?", (anchor_event_id,)).fetchone()
                anchor_event = dict(row) if row else None
            operation_id = (anchor_event or {}).get("operation_id")
            correlation_id = (anchor_event or {}).get("correlation_id")
            events = [dict(row) for row in connection.execute("""
                SELECT id, timestamp_utc, source, operation_id, correlation_id, summary
                FROM events WHERE hostname=? AND timestamp_utc BETWEEN ? AND ?
                ORDER BY timestamp_utc DESC LIMIT 30
            """, (alert["hostname"], start, end)).fetchall()]
            groups = [dict(row) for row in connection.execute("""
                SELECT operation_id, detected_at_utc, source, correlation_id, summary
                FROM change_groups WHERE hostname=? AND detected_at_utc BETWEEN ? AND ?
                ORDER BY detected_at_utc DESC LIMIT 20
            """, (alert["hostname"], start, end)).fetchall()]
            sessions = [dict(row) for row in connection.execute("""
                SELECT session_id, updated_at_utc, title, primary_operation_id,
                       primary_correlation_id, status
                FROM investigation_sessions
                WHERE hostname=? AND window_start_utc<=? AND window_end_utc>=?
                ORDER BY updated_at_utc DESC LIMIT 20
            """, (alert["hostname"], end, start)).fetchall()]
            other_alerts = [dict(row) for row in connection.execute("""
                SELECT alert_id, metric_key, status, severity, first_seen_utc,
                       last_seen_utc, resolved_at_utc
                FROM monitoring_alerts
                WHERE hostname=? AND alert_id<>? AND first_seen_utc<=?
                  AND COALESCE(resolved_at_utc, last_seen_utc)>=?
                ORDER BY first_seen_utc DESC LIMIT 20
            """, (alert["hostname"], alert["alert_id"], end, start)).fetchall()]
        finally:
            connection.close()

        def relation(item_operation=None, item_correlation=None, fallback="TEMPORAL_CONTEXT"):
            if operation_id and item_operation == operation_id:
                return "SAME_OPERATION"
            if correlation_id and item_correlation == correlation_id:
                return "SAME_CORRELATION"
            return fallback

        items = []
        for item in events:
            items.append({
                "item_type": "TIMELINE_EVENT", "referenced_id": item["id"],
                "observed_at_utc": item["timestamp_utc"],
                "relation": relation(item.get("operation_id"), item.get("correlation_id")),
                "summary": item["summary"], "source": item["source"],
            })
        for item in groups:
            items.append({
                "item_type": "CHANGE_GROUP", "referenced_id": item["operation_id"],
                "observed_at_utc": item["detected_at_utc"],
                "relation": relation(item.get("operation_id"), item.get("correlation_id")),
                "summary": item["summary"], "source": item["source"],
            })
        for item in sessions:
            items.append({
                "item_type": "INVESTIGATION_SESSION", "referenced_id": item["session_id"],
                "observed_at_utc": item["updated_at_utc"],
                "relation": relation(item.get("primary_operation_id"), item.get("primary_correlation_id")),
                "summary": item["title"], "source": "Incident Replay",
            })
        for item in other_alerts:
            metric_title = METRIC_RULES[item["metric_key"]]["title"]
            items.append({
                "item_type": "MONITORING_ALERT", "referenced_id": item["alert_id"],
                "observed_at_utc": item["first_seen_utc"],
                "relation": "SAME_METRIC" if item["metric_key"] == alert["metric_key"] else "TEMPORAL_CONTEXT",
                "summary": f"{metric_title} {item['severity']} — {item['status']}; período local sobreposto/próximo.",
                "source": "Alertas locais",
            })
        priority = {
            "SAME_OPERATION": 0, "SAME_CORRELATION": 1,
            "SAME_ENTITY": 2, "SAME_METRIC": 3, "TEMPORAL_CONTEXT": 4,
        }
        items.sort(key=lambda item: (
            priority.get(item["relation"], 9),
            abs((_parsed_utc(item["observed_at_utc"]) - center).total_seconds()),
        ))
        return {
            "alert_id": alert["alert_id"], "hostname": alert["hostname"],
            "anchor_utc": _utc_text(anchor_time), "window_minutes": window,
            "items": items[:limit],
            "causality": "Não inferida; os itens são apenas contexto do mesmo equipamento.",
        }

    def create_investigation_from_alert(self, alert_id):
        alert = self.get_alert(alert_id)
        if alert is None:
            raise ValueError("Alerta local inexistente.")
        session_id = alert.get("investigation_session_id")
        if session_id:
            session = self.get_session(session_id)
            if session:
                return self.restore_session(session_id) if session["status"] == "ARCHIVED" else session
        event_id = (
            alert.get("opening_event_id") or alert.get("first_transition_event_id")
            or alert.get("last_event_id") or alert.get("last_transition_event_id")
        )
        if not event_id:
            raise ValueError("Alerta sem evento de Timeline disponível para investigação.")
        session = (
            self.find_session_for_reference("TIMELINE_EVENT", event_id)
            or self.create_from_timeline_event(
                event_id,
                title=f"Investigação — alerta {METRIC_RULES[alert['metric_key']]['title']}",
            )
        )
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE monitoring_alerts SET investigation_session_id=?, updated_at=? WHERE alert_id=?",
                    (session["session_id"], _utc_text(), alert["alert_id"]),
                )
        finally:
            connection.close()
        return session
