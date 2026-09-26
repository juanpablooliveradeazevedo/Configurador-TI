"""Visão única e somente leitura da postura local do endpoint."""
from __future__ import annotations

import json
import socket

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QPlainTextEdit, QProgressBar, QPushButton, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from audit_timeline import format_local_timestamp
from endpoint_posture import ASSESSMENTS, CHECK_KEYS, CHECK_TITLES
from operational_ui import ResponsiveGrid
from ui_components import FlowRow, UxTable


CAPABILITY_TEXT = {
    "AVAILABLE": "Disponível", "LIMITED": "Limitada",
    "UNAVAILABLE": "Indisponível", "INDETERMINATE": "Indeterminada",
}
ASSESSMENT_TEXT = {
    "OK": "OK", "ATTENTION": "Atenção", "INDETERMINATE": "Indeterminada",
    "NOT_APPLICABLE": "Não aplicável",
}
RELATION_TEXT = {
    "SAME_OPERATION": "Mesma operação", "SAME_CORRELATION": "Mesma correlação",
    "SAME_ENTITY": "Mesmo equipamento", "TEMPORAL_CONTEXT": "Contexto temporal",
}


def _local(value):
    if not value:
        return "—"
    try:
        return format_local_timestamp(value)
    except (TypeError, ValueError):
        return "—"


class EndpointPosturePanel(QWidget):
    """Resumo, checks, mudanças, contexto e evidência sem subabas."""

    def __init__(self, host, core):
        super().__init__(host)
        self.host = host
        self.core = core
        self._checks = []
        self._changes = []
        self._selected_check_id = None
        self._selected_change_id = None
        self._pending_change_id = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(16)
        layout.addLayout(self.host._header(
            "Postura do Endpoint",
            "Retrato local somente leitura. Postura observada não é garantia de segurança; "
            "indisponível não significa desabilitado.",
        ))

        summary = self.host._card("Resumo operacional")
        summary_layout = QVBoxLayout(summary)
        actions = FlowRow()
        self.summary_label = QLabel("Nenhum snapshot de postura disponível.")
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextFormat(Qt.TextFormat.PlainText)
        actions.addWidget(self.summary_label, 1)
        self.update_button = QPushButton("Atualizar postura")
        self.update_button.setProperty("class", "ActionButton")
        self.update_button.clicked.connect(self.collect)
        actions.addWidget(self.update_button)
        summary_layout.addLayout(actions)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        summary_layout.addWidget(self.progress)
        self.notice = QLabel(
            "A coleta não altera configurações, não solicita elevação e não executa Windows Update."
        )
        self.notice.setWordWrap(True)
        summary_layout.addWidget(self.notice)
        layout.addWidget(summary)

        cards = []
        self.card_values = {}
        for assessment, title in (
            ("OK", "OK"), ("ATTENTION", "Atenção"),
            ("INDETERMINATE", "Indeterminados"),
            ("NOT_APPLICABLE", "Não aplicáveis"),
        ):
            card = self.host._card(title)
            card_layout = QVBoxLayout(card)
            value = QLabel("0")
            value.setObjectName("ValorCard")
            card_layout.addWidget(value)
            self.card_values[assessment] = value
            cards.append(card)
        layout.addWidget(ResponsiveGrid(cards, 210))

        checks = self.host._card("Informações principais — seis verificações locais")
        checks_layout = QVBoxLayout(checks)
        self.checks_table = UxTable(0, 6)
        self.checks_table.setHorizontalHeaderLabels([
            "Verificação", "Capacidade", "Avaliação", "Estado observado",
            "Resumo", "Atualização local",
        ])
        self._configure(self.checks_table, 240)
        header = self.checks_table.horizontalHeader()
        for column, width in ((0, 155), (1, 115), (2, 120), (3, 180), (5, 150)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(column, width)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.checks_table.itemSelectionChanged.connect(self._show_check_details)
        checks_layout.addWidget(self.checks_table)
        check_actions = FlowRow()
        self.current_assist_button = QPushButton("Abrir no Assistente Técnico")
        self.current_assist_button.setProperty("class", "MenuButton")
        self.current_assist_button.setEnabled(False)
        self.current_assist_button.clicked.connect(self._open_check_assist)
        check_actions.addWidget(self.current_assist_button)
        check_actions.addStretch()
        checks_layout.addLayout(check_actions)
        layout.addWidget(checks)

        changes = self.host._card("Mudanças significativas recentes")
        changes_layout = QVBoxLayout(changes)
        changes_note = QLabel(
            "Somente alterações de capacidade, avaliação ou estado observado entram na Timeline. "
            "Mudança não é incidente e correlação não prova causalidade."
        )
        changes_note.setWordWrap(True)
        changes_layout.addWidget(changes_note)
        self.changes_table = UxTable(0, 5)
        self.changes_table.setHorizontalHeaderLabels([
            "Hora local", "Verificação", "Antes", "Depois", "Resumo",
        ])
        self._configure(self.changes_table, 210)
        change_header = self.changes_table.horizontalHeader()
        for column, width in ((0, 150), (1, 150), (2, 180), (3, 180)):
            change_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            change_header.resizeSection(column, width)
        change_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.changes_table.itemSelectionChanged.connect(self._change_selected)
        changes_layout.addWidget(self.changes_table)
        change_actions = FlowRow()
        self.investigate_button = QPushButton("Abrir no Incident Replay")
        self.investigate_button.setProperty("class", "MenuButton")
        self.investigate_button.setEnabled(False)
        self.investigate_button.clicked.connect(self._investigate)
        change_actions.addWidget(self.investigate_button)
        self.assist_button = QPushButton("Abrir no Assistente Técnico")
        self.assist_button.setProperty("class", "MenuButton")
        self.assist_button.setEnabled(False)
        self.assist_button.clicked.connect(self._open_assist)
        change_actions.addWidget(self.assist_button)
        change_actions.addStretch()
        changes_layout.addLayout(change_actions)
        layout.addWidget(changes)

        context = self.host._card("Contexto operacional do mesmo equipamento")
        context_layout = QVBoxLayout(context)
        self.context_note = QLabel("Selecione uma mudança para consultar o contexto de ±10 minutos.")
        self.context_note.setWordWrap(True)
        context_layout.addWidget(self.context_note)
        self.context_table = UxTable(0, 5)
        self.context_table.setHorizontalHeaderLabels([
            "Relação", "Tipo", "Hora local", "Fonte", "Resumo",
        ])
        self._configure(self.context_table, 180)
        context_header = self.context_table.horizontalHeader()
        for column, width in ((0, 150), (1, 145), (2, 150), (3, 150)):
            context_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            context_header.resizeSection(column, width)
        context_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        context_layout.addWidget(self.context_table)
        layout.addWidget(context)

        technical = QGroupBox("Detalhes técnicos e evidência sanitizada")
        technical.setCheckable(True)
        technical.setChecked(False)
        technical_layout = QVBoxLayout(technical)
        self.technical = QPlainTextEdit()
        self.technical.setObjectName("PostureTechnicalEvidence")
        self.technical.setReadOnly(True)
        self.technical.setPlaceholderText("Evidência técnica sanitizada indisponível.")
        self.technical.setMinimumHeight(170)
        self.technical.setPlainText("Selecione uma verificação ou mudança.")
        technical_layout.addWidget(self.technical)
        layout.addWidget(technical)
        layout.addStretch()

    @staticmethod
    def _configure(table, minimum_height):
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setMinimumHeight(minimum_height)

    def refresh(self):
        self.host._run(
            self._load, label="Carregando postura persistida", progress=None,
            on_done=self._fill, operation_key="endpoint_posture_query",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _load(self):
        store = self.host._get_posture_store()
        if store is None:
            return {"snapshot": None, "changes": []}
        hostname = socket.gethostname() or "Não disponível"
        return {
            "snapshot": store.get_latest_snapshot(hostname=hostname),
            "changes": store.list_changes(hostname=hostname, limit=50),
        }

    def collect(self):
        from licensing.runtime import get_runtime
        gate = get_runtime()
        if not gate.is_allowed("endpoint_posture"):
            self.notice.setText(gate.explain("endpoint_posture"))
            return
        service = self.host._get_posture_service()
        if service is None:
            self.notice.setText("A persistência local de postura não está disponível.")
            return
        self.update_button.setEnabled(False)
        self.progress.show()
        self.host._run(
            service.collect_once, label="Atualizando postura local", progress=self.progress,
            on_done=self._collected, on_finally=self._collection_finalized,
            operation_key="endpoint_posture_scan", blocks_navigation=False,
            audit_source="ENDPOINT_POSTURE", audit_category="SYSTEM",
            audit_summary="Coleta local de postura do endpoint",
        )

    def _collection_finalized(self, _state):
        self.update_button.setEnabled(True)
        self.progress.hide()

    def _collected(self, result):
        if isinstance(result, dict) and result.get("ok"):
            change_count = len(result.get("snapshot", {}).get("changes") or [])
            self.notice.setText(
                f"Postura atualizada. {change_count} mudança(s) significativa(s) registrada(s)."
            )
            self.refresh()
        elif isinstance(result, dict) and result.get("cancelled"):
            self.notice.setText("Coleta cancelada sem alterar configurações.")
        elif isinstance(result, dict) and result.get("skipped") == "overlap":
            self.notice.setText("Já existe uma coleta de postura em andamento.")
        else:
            self.notice.setText("A coleta não pôde ser concluída; consulte o log técnico.")

    def _fill(self, payload):
        payload = payload if isinstance(payload, dict) else {}
        snapshot = payload.get("snapshot")
        self._checks = list((snapshot or {}).get("checks") or [])
        self._changes = list(payload.get("changes") or [])
        self._selected_check_id = None
        self.current_assist_button.setEnabled(False)
        self.checks_table.setRowCount(0)
        counts = {key: 0 for key in ASSESSMENTS}
        for check in self._checks:
            counts[check.get("assessment")] = counts.get(check.get("assessment"), 0) + 1
            row = self.checks_table.rowCount()
            self.checks_table.insertRow(row)
            values = (
                CHECK_TITLES.get(check.get("check_key"), check.get("check_key") or "—"),
                CAPABILITY_TEXT.get(check.get("capability_state"), check.get("capability_state") or "—"),
                ASSESSMENT_TEXT.get(check.get("assessment"), check.get("assessment") or "—"),
                check.get("observed_state") or "—", check.get("summary") or "—",
                _local(check.get("collected_at_utc")),
            )
            for column, value in enumerate(values):
                self.checks_table.setItem(row, column, QTableWidgetItem(str(value)))
        for key, label in self.card_values.items():
            label.setText(str(counts.get(key, 0)))
        if snapshot:
            run = snapshot.get("run") or {}
            self.summary_label.setText(
                f"{run.get('hostname') or 'Endpoint local'} • último snapshot: "
                f"{_local(run.get('completed_at_utc'))} • {len(self._checks)}/6 verificações."
            )
        else:
            self.summary_label.setText("Nenhum snapshot de postura disponível. Use Atualizar postura.")
        self._fill_changes()

    def _fill_changes(self):
        self.changes_table.setRowCount(0)
        for change in self._changes:
            before = self._json(change.get("before_json"))
            after = self._json(change.get("after_json"))
            row = self.changes_table.rowCount()
            self.changes_table.insertRow(row)
            values = (
                _local(change.get("changed_at_utc")),
                CHECK_TITLES.get(change.get("check_key"), change.get("check_key") or "—"),
                self._state_text(before), self._state_text(after),
                change.get("after_summary") or "—",
            )
            for column, value in enumerate(values):
                self.changes_table.setItem(row, column, QTableWidgetItem(str(value)))
        pending = self._pending_change_id
        self._selected_change_id = None
        self.investigate_button.setEnabled(False)
        self.assist_button.setEnabled(False)
        self.context_table.setRowCount(0)
        if pending:
            for row, change in enumerate(self._changes):
                if change.get("change_id") == pending:
                    self.changes_table.selectRow(row)
                    break
            self._pending_change_id = None

    @staticmethod
    def _json(value):
        if isinstance(value, dict):
            return value
        try:
            return json.loads(value or "{}")
        except (TypeError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _state_text(state):
        assessment = ASSESSMENT_TEXT.get(state.get("assessment"), state.get("assessment") or "—")
        capability = CAPABILITY_TEXT.get(state.get("capability_state"), state.get("capability_state") or "—")
        return f"{assessment} / {capability} / {state.get('observed_state') or '—'}"

    def _show_check_details(self):
        row = self.checks_table.currentRow()
        if not 0 <= row < len(self._checks):
            return
        check = self._checks[row]
        self._selected_check_id = check.get("check_id")
        self.current_assist_button.setEnabled(bool(self._selected_check_id))
        evidence = self._json(check.get("evidence_json"))
        self.technical.setPlainText(
            f"Verificação: {CHECK_TITLES.get(check.get('check_key'), check.get('check_key'))}\n"
            f"Fonte: {check.get('source') or '—'}\n"
            f"Capacidade: {check.get('capability_state') or '—'}\n"
            f"Avaliação: {check.get('assessment') or '—'}\n"
            f"Estado observado: {check.get('observed_state') or '—'}\n"
            f"Coleta local: {_local(check.get('collected_at_utc'))}\n\n"
            "Evidência sanitizada:\n" + json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True)
        )

    def _change_selected(self):
        row = self.changes_table.currentRow()
        if not 0 <= row < len(self._changes):
            return
        change = self._changes[row]
        self._selected_change_id = change.get("change_id")
        self.investigate_button.setEnabled(bool(change.get("timeline_event_id")))
        self.assist_button.setEnabled(bool(self._selected_change_id))
        self.technical.setPlainText(
            "Mudança significativa\n"
            f"Verificação: {CHECK_TITLES.get(change.get('check_key'), change.get('check_key'))}\n"
            f"Hora local: {_local(change.get('changed_at_utc'))}\n"
            f"Antes: {self._state_text(self._json(change.get('before_json')))}\n"
            f"Depois: {self._state_text(self._json(change.get('after_json')))}\n"
            f"Evento Timeline: {change.get('timeline_event_id') or '—'}\n"
            f"Sessão: {change.get('investigation_session_id') or '—'}"
        )
        self.host._run(
            lambda: self.host._get_posture_store().posture_context(
                self._selected_change_id, window_minutes=10, limit=50
            ),
            label="Carregando contexto da postura", progress=None,
            on_done=self._fill_context, operation_key="endpoint_posture_context",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _fill_context(self, context):
        context = context if isinstance(context, dict) else {}
        self.context_note.setText(context.get("causality") or "Nenhuma causalidade foi inferida.")
        self.context_table.setRowCount(0)
        for item in context.get("items") or []:
            row = self.context_table.rowCount()
            self.context_table.insertRow(row)
            values = (
                RELATION_TEXT.get(item.get("relation"), item.get("relation") or "—"),
                item.get("item_type") or "—", _local(item.get("observed_at_utc")),
                item.get("source") or "—", item.get("summary") or "—",
            )
            for column, value in enumerate(values):
                self.context_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _investigate(self):
        if self._selected_change_id:
            self.host._criar_investigacao_postura(self._selected_change_id)

    def _open_assist(self):
        if self._selected_change_id:
            self.host._abrir_assist_contexto("POSTURE_CHANGE", self._selected_change_id)

    def _open_check_assist(self):
        if self._selected_check_id:
            self.host._abrir_assist_contexto("POSTURE_CHECK", self._selected_check_id)

    def focus_check(self, check_id):
        target = str(check_id or "").strip()[:64]
        for row, check in enumerate(self._checks):
            if check.get("check_id") == target:
                self.checks_table.selectRow(row)
                return
        self.refresh()

    def focus_change(self, change_id):
        target = str(change_id or "").strip()[:64]
        self._pending_change_id = target or None
        self.refresh()
