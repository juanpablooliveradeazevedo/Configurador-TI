"""Primeira visão operacional da Audit & Timeline local."""
from datetime import datetime, timedelta, timezone
import json

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QComboBox, QLineEdit,
    QTextEdit, QTableWidgetItem, QHeaderView, QAbstractItemView,
)

from audit_timeline import EVENT_SEVERITIES, format_local_timestamp
from operational_ui import CollapsibleSection
from ui_components import FlowRow, UxTable


SEVERITY_LABELS = {
    "INFO": "Informação", "NOTICE": "Observação",
    "WARNING": "Atenção", "ERROR": "Erro",
}
CATEGORY_LABELS = {
    "OPERATION": "Operação", "MAINTENANCE": "Manutenção",
    "BASELINE": "Baseline", "REPORT": "Relatório",
    "INVENTORY": "Inventário", "SYSTEM": "Sistema",
}
STATUS_LABELS = {
    "STARTED": "Iniciada", "COMPLETED": "Concluída", "FAILED": "Falhou",
    "CANCELLED": "Cancelada", "OBSERVED": "Observada",
}


class AuditTimelinePanel(QWidget):
    PAGE_SIZE = 100

    def __init__(self, host, core):
        super().__init__(host)
        self.host = host
        self.core = core
        self._events = []
        self._total = 0
        self._loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        layout.addLayout(host._header(
            "Auditoria & Timeline",
            "Eventos estruturados observados ou executados pelo Configurador TI. O log técnico permanece separado.",
        ))

        self.summary = QLabel("Resumo operacional: nenhum evento carregado.")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.summary)

        filters = FlowRow()
        self.period = QComboBox()
        self.period.addItem("Hoje", "today")
        self.period.addItem("Últimos 7 dias", 7)
        self.period.addItem("Últimos 30 dias", 30)
        self.period.addItem("Todos", None)
        self.source = QComboBox()
        self.source.addItem("Todos os módulos", None)
        self.severity = QComboBox()
        self.severity.addItem("Todas as severidades", None)
        for value in ("INFO", "NOTICE", "WARNING", "ERROR"):
            self.severity.addItem(SEVERITY_LABELS[value], value)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar no resumo...")
        self.search.setClearButtonEnabled(True)
        self.update_button = QPushButton("Atualizar")
        self.update_button.setProperty("class", "ActionButton")
        self.update_button.clicked.connect(self.refresh)
        filters.addWidget(self.period)
        filters.addWidget(self.source)
        filters.addWidget(self.severity)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.update_button)
        layout.addLayout(filters)

        self.status = QLabel("Abra a página ou clique em Atualizar para consultar a timeline.")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)

        self.table = UxTable(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Data/hora local", "Módulo", "Categoria", "Severidade", "Resumo", "Status",
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setWordWrap(False)
        self.table.setMinimumHeight(260)
        header = self.table.horizontalHeader()
        for column, width in ((0, 155), (1, 145), (2, 110), (3, 105), (5, 105)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(column, width)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.show_details)
        layout.addWidget(self.table, 1)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(180)
        self.details_section = CollapsibleSection("Detalhes técnicos do evento", self.details)
        layout.addWidget(self.details_section)

        self.investigate_button = QPushButton("Abrir grupo na investigação")
        self.investigate_button.setProperty("class", "MenuButton")
        self.investigate_button.setEnabled(False)
        self.investigate_button.setVisible(False)
        self.investigate_button.clicked.connect(self.open_investigation)
        layout.addWidget(self.investigate_button)

        self.session_button = QPushButton("Criar investigação deste evento")
        self.session_button.setProperty("class", "ActionButton")
        self.session_button.setEnabled(False)
        self.session_button.setVisible(False)
        self.session_button.clicked.connect(self.create_investigation_session)
        layout.addWidget(self.session_button)

        self.assist_button = QPushButton("Abrir no Assistente Técnico")
        self.assist_button.setProperty("class", "MenuButton")
        self.assist_button.setEnabled(False)
        self.assist_button.setVisible(False)
        self.assist_button.clicked.connect(self.open_assist)
        layout.addWidget(self.assist_button)

        self.more_button = QPushButton("Carregar mais")
        self.more_button.setProperty("class", "MenuButton")
        self.more_button.setEnabled(False)
        self.more_button.clicked.connect(self.load_more)
        layout.addWidget(self.more_button)

    def _since_utc(self):
        value = self.period.currentData()
        if value is None:
            return None
        local_now = datetime.now().astimezone()
        if value == "today":
            local_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            local_start = local_now - timedelta(days=int(value))
        return local_start.astimezone(timezone.utc)

    def _filter_snapshot(self):
        """Lê widgets somente na thread da GUI antes de iniciar o Worker."""
        return {
            "since_utc": self._since_utc(),
            "source": self.source.currentData(),
            "severity": self.severity.currentData(),
            "text": self.search.text().strip() or None,
        }

    def _query(self, offset, filters=None):
        try:
            store = self.host._get_audit_store()
            if store is None:
                raise RuntimeError("Armazenamento local da timeline indisponível.")
            filters = dict(filters if filters is not None else self._filter_snapshot())
            return {
                "ok": True,
                "events": store.query_events(limit=self.PAGE_SIZE, offset=offset, **filters),
                "total": store.count_events(**filters),
                "sources": store.list_sources(),
                "offset": offset,
            }
        except Exception as exc:
            try:
                self.core.logger.exception("Falha ao consultar Audit & Timeline")
            except Exception:
                pass
            return {"ok": False, "error": type(exc).__name__, "offset": offset}

    def refresh(self, _checked=False):
        self._load(0)

    def load_more(self, _checked=False):
        self._load(len(self._events))

    def _load(self, offset):
        if self._loading or self.host._closing:
            return
        self._loading = True
        self.update_button.setEnabled(False)
        self.more_button.setEnabled(False)
        self.status.setText("Consultando eventos locais em segundo plano...")
        filters = self._filter_snapshot()

        def done(payload):
            self._loading = False
            self.update_button.setEnabled(True)
            self._present(payload)

        def finished(_state):
            if self._loading:
                self._loading = False
                self.update_button.setEnabled(True)
                self.status.setText("Consulta encerrada sem atualizar a timeline.")

        worker = self.host._run(
            lambda: self._query(offset, filters),
            label="Consultando Audit & Timeline",
            operation_key="audit_timeline_query",
            blocks_navigation=False,
            on_done=done,
            on_finally=finished,
            silent_if_busy=True,
        )
        if worker is None:
            self._loading = False
            self.update_button.setEnabled(True)

    def _update_sources(self, sources):
        selected = self.source.currentData()
        self.source.blockSignals(True)
        self.source.clear()
        self.source.addItem("Todos os módulos", None)
        for value in sources:
            self.source.addItem(value, value)
        index = self.source.findData(selected)
        self.source.setCurrentIndex(max(0, index))
        self.source.blockSignals(False)

    def _present(self, payload):
        if not payload.get("ok"):
            self.status.setText(
                "Não foi possível consultar a timeline. A operação principal do Configurador TI não foi afetada; consulte o log técnico."
            )
            self.more_button.setEnabled(False)
            return
        self._update_sources(payload.get("sources") or [])
        if payload.get("offset") == 0:
            self._events = []
            self.table.setRowCount(0)
            self.details.clear()
            self.details_section.set_expanded(False)
            self.investigate_button.setEnabled(False)
            self.investigate_button.setVisible(False)
            self.session_button.setEnabled(False)
            self.session_button.setVisible(False)
        self._events.extend(payload.get("events") or [])
        self._total = int(payload.get("total") or 0)
        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(len(self._events))
            for row, event in enumerate(self._events):
                values = (
                    format_local_timestamp(event["timestamp_utc"]),
                    event["source"],
                    CATEGORY_LABELS.get(event["category"], event["category"]),
                    SEVERITY_LABELS.get(event["severity"], event["severity"]),
                    event["summary"],
                    STATUS_LABELS.get(event["status"], event["status"]),
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setToolTip(str(value))
                    self.table.setItem(row, column, item)
        finally:
            self.table.setUpdatesEnabled(True)
        shown = len(self._events)
        if self._total == 0:
            self.summary.setText("Resumo operacional: nenhum evento corresponde aos filtros.")
            self.status.setText("A timeline está vazia para o período e filtros selecionados.")
        else:
            self.summary.setText(f"Resumo operacional: exibindo {shown} de {self._total} evento(s).")
            self.status.setText("Eventos mais recentes aparecem primeiro. Atualização manual concluída.")
        self.more_button.setEnabled(shown < self._total)

    def show_details(self):
        row = self.table.currentRow()
        if not (0 <= row < len(self._events)):
            self.details.clear()
            self.investigate_button.setEnabled(False)
            self.investigate_button.setVisible(False)
            self.session_button.setEnabled(False)
            self.session_button.setVisible(False)
            self.assist_button.setEnabled(False)
            self.assist_button.setVisible(False)
            return
        event = self._events[row]
        try:
            details = json.loads(event["details_json"]) if event.get("details_json") else None
            details_text = json.dumps(details, ensure_ascii=False, indent=2, sort_keys=True) if details is not None else "—"
        except Exception:
            details = None
            details_text = "Detalhes indisponíveis."
        lines = [
            f"ID: {event['id']}",
            f"Schema: {event['schema_version']}",
            f"Timestamp UTC: {event['timestamp_utc']}",
            f"Criado em UTC: {event['created_at']}",
            f"Hostname/equipamento: {event['hostname'] or '—'}",
            f"Módulo: {event['source']}",
            f"Categoria: {event['category']}",
            f"Severidade: {event['severity']}",
            f"Status: {event['status']}",
            f"Operation ID: {event.get('operation_id') or '—'}",
            f"Correlation ID: {event.get('correlation_id') or '—'}",
            "",
            "Details JSON:",
            details_text,
        ]
        self.details.setPlainText("\n".join(lines))
        self.details_section.set_expanded(True)
        operation_id = details.get("change_operation_id") if isinstance(details, dict) else None
        available = bool(details.get("change_history_available")) if isinstance(details, dict) else False
        self.investigate_button.setProperty("operation_id", operation_id or "")
        self.investigate_button.setVisible(bool(operation_id))
        self.investigate_button.setEnabled(bool(operation_id and available))
        self.investigate_button.setToolTip(
            "" if available else "O grupo não foi persistido nesta operação."
        )
        self.session_button.setProperty("event_id", event["id"])
        self.session_button.setVisible(True)
        self.session_button.setEnabled(True)
        self.assist_button.setProperty("event_id", event["id"])
        self.assist_button.setVisible(True)
        self.assist_button.setEnabled(True)

    def open_investigation(self, _checked=False):
        operation_id = self.investigate_button.property("operation_id")
        if operation_id:
            self.host._abrir_investigacao(operation_id)

    def create_investigation_session(self, _checked=False):
        event_id = self.session_button.property("event_id")
        if event_id:
            self.host._criar_investigacao_evento(event_id)

    def open_assist(self, _checked=False):
        event_id = self.assist_button.property("event_id")
        if event_id:
            self.host._abrir_assist_contexto("TIMELINE_EVENT", event_id)

    def focus_event(self, event_id):
        target = str(event_id or "").strip()[:64]
        self.period.setCurrentIndex(self.period.findData(None))
        try:
            store = self.host._get_audit_store()
            event = store.get_event(target) if store else None
            payload = {
                "ok": True, "events": [event] if event else [],
                "total": 1 if event else 0,
                "sources": store.list_sources() if store else [], "offset": 0,
            }
        except Exception as exc:
            payload = {"ok": False, "error": type(exc).__name__, "offset": 0}
        self._present(payload)
        for row, event in enumerate(self._events):
            if event.get("id") == target:
                self.table.selectRow(row)
                break
