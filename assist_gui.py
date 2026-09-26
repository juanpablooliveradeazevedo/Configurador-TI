"""Visão operacional única do Assistente Técnico e Safe Playbooks."""
from __future__ import annotations

import json

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from audit_timeline import format_local_timestamp
from assist import ACTION_BY_ID, PLAYBOOK_BY_ID
from monitoring_foundation import ALLOWED_INTERVALS
from ui_components import FlowRow, UxTable


SOURCE_TEXT = {
    "ALERT": "Alerta", "POSTURE_CHANGE": "Mudança de postura",
    "POSTURE_CHECK": "Check atual de postura",
    "TIMELINE_EVENT": "Evento Timeline", "CHANGE_GROUP": "Grupo de mudanças",
    "INVESTIGATION_SESSION": "Sessão de investigação",
    "MONITORING_SETTINGS": "Configuração de monitoramento",
    "MANUAL_CONTEXT": "Contexto manual",
}
STATUS_TEXT = {"OPEN": "Em andamento", "COMPLETED": "Concluído", "ABORTED": "Abortado"}
STEP_STATUS_TEXT = {"PENDING": "Pendente", "DONE": "Concluída", "SKIPPED": "Ignorada"}


def _local(value):
    try:
        return format_local_timestamp(value)
    except Exception:
        return "—"


class AssistPanel(QWidget):
    PAGE_SIZE = 50

    def __init__(self, host, core):
        super().__init__(host)
        self.host, self.core = host, core
        self._contexts, self._recommendations, self._history = [], [], []
        self._context = None
        self._session = None
        self._action_run = None
        self._action_catalog_entry = None
        self._last_action_parameter_values = {}
        self._pending_context_id = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        layout.addLayout(host._header(
            "Assistente Técnico",
            "Orientação local baseada em evidências. Assist recomenda; o técnico decide. Playbook não é script.",
        ))

        context_box = QGroupBox("Contexto")
        context_layout = QVBoxLayout(context_box)
        context_actions = FlowRow()
        self.context_selector = QComboBox()
        self.context_selector.setMinimumWidth(360)
        self.context_selector.currentIndexChanged.connect(self._context_changed)
        self.refresh_button = QPushButton("Atualizar")
        self.refresh_button.setProperty("class", "MenuButton")
        self.refresh_button.clicked.connect(self.refresh)
        self.open_evidence_button = QPushButton("Abrir evidência")
        self.open_evidence_button.setProperty("class", "MenuButton")
        self.open_evidence_button.clicked.connect(self.open_selected_evidence)
        context_actions.addWidget(self.context_selector, 1)
        context_actions.addWidget(self.refresh_button)
        context_actions.addWidget(self.open_evidence_button)
        context_layout.addLayout(context_actions)
        self.context_summary = QLabel("Nenhum contexto selecionado.")
        self.context_summary.setWordWrap(True)
        self.context_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.context_evidence = QLabel("Evidências: —")
        self.context_evidence.setWordWrap(True)
        self.context_evidence.setTextFormat(Qt.TextFormat.PlainText)
        self.context_limitations = QLabel("Limitações: —")
        self.context_limitations.setWordWrap(True)
        self.context_limitations.setTextFormat(Qt.TextFormat.PlainText)
        context_layout.addWidget(self.context_summary)
        context_layout.addWidget(self.context_evidence)
        context_layout.addWidget(self.context_limitations)
        self.context_empty_state = QLabel(
            "Abra o Assistente Técnico a partir de Timeline, Alertas, Postura do Endpoint, "
            "Monitoramento, Change Intelligence ou Investigação para criar um contexto baseado em evidências."
        )
        self.context_empty_state.setWordWrap(True)
        self.context_empty_state.setProperty("class", "OperationalCallout")
        context_layout.addWidget(self.context_empty_state)
        layout.addWidget(context_box)

        rec_box = QGroupBox("Recomendações explicáveis")
        rec_layout = QVBoxLayout(rec_box)
        self.recommendations_table = UxTable(0, 5)
        self.recommendations_table.setHorizontalHeaderLabels([
            "Recomendação", "Por quê", "Regra", "Evidência", "Playbook",
        ])
        self.recommendations_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.recommendations_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.recommendations_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        rec_header = self.recommendations_table.horizontalHeader()
        rec_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        rec_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        rec_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        rec_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        rec_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        rec_layout.addWidget(self.recommendations_table)
        self.recommendation_empty_state = QLabel(
            "Contexto carregado com sucesso. Nenhum playbook é aplicável a esta evidência com as regras atuais."
        )
        self.recommendation_empty_state.setWordWrap(True)
        self.recommendation_empty_state.setProperty("class", "OperationalCallout")
        self.recommendation_empty_state.hide()
        rec_layout.addWidget(self.recommendation_empty_state)
        self.start_button = QPushButton("Iniciar playbook selecionado")
        self.start_button.setProperty("class", "ActionButton")
        self.start_button.clicked.connect(self.start_selected_playbook)
        rec_layout.addWidget(self.start_button)
        layout.addWidget(rec_box)

        active_box = QGroupBox("Playbook ativo")
        active_layout = QVBoxLayout(active_box)
        self.active_summary = QLabel("Nenhum playbook ativo.")
        self.active_summary.setWordWrap(True)
        self.active_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        active_layout.addWidget(self.active_summary)
        active_layout.addWidget(self.progress)
        self.steps_table = UxTable(0, 5)
        self.steps_table.setHorizontalHeaderLabels(["Etapa", "Tipo", "Obrigatória", "Status", "Evidência esperada"])
        self.steps_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.steps_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.steps_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        step_header = self.steps_table.horizontalHeader()
        step_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            step_header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        step_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.steps_table.itemSelectionChanged.connect(self._step_selected)
        active_layout.addWidget(self.steps_table)
        self.step_description = QLabel("Selecione uma etapa para ver a orientação.")
        self.step_description.setWordWrap(True)
        self.step_description.setTextFormat(Qt.TextFormat.PlainText)
        active_layout.addWidget(self.step_description)
        step_actions = FlowRow()
        self.note = QLineEdit()
        self.note.setMaxLength(500)
        self.note.setPlaceholderText("Nota curta sem senhas, tokens ou credenciais (opcional)")
        self.navigate_button = QPushButton("Navegar")
        self.navigate_button.setProperty("class", "MenuButton")
        self.navigate_button.clicked.connect(self.navigate_selected_step)
        self.done_button = QPushButton("Concluir etapa")
        self.done_button.setProperty("class", "ActionButton")
        self.done_button.clicked.connect(lambda: self.update_selected_step("DONE"))
        self.skip_button = QPushButton("Ignorar opcional")
        self.skip_button.setProperty("class", "MenuButton")
        self.skip_button.clicked.connect(lambda: self.update_selected_step("SKIPPED"))
        step_actions.addWidget(self.note, 1)
        step_actions.addWidget(self.navigate_button)
        step_actions.addWidget(self.done_button)
        step_actions.addWidget(self.skip_button)
        active_layout.addLayout(step_actions)

        guided_box = QGroupBox("Ação guiada")
        guided_layout = QVBoxLayout(guided_box)
        self.action_summary = QLabel("Selecione uma etapa EXISTING_SAFE_ACTION para preparar uma ação.")
        self.action_summary.setWordWrap(True)
        self.action_summary.setTextFormat(Qt.TextFormat.PlainText)
        technical_box = QGroupBox("Detalhes técnicos da política")
        technical_box.setCheckable(True)
        technical_box.setChecked(False)
        technical_layout = QVBoxLayout(technical_box)
        self.action_technical_details = QLabel("Selecione uma ação para consultar a política.")
        self.action_technical_details.setWordWrap(True)
        self.action_technical_details.setTextFormat(Qt.TextFormat.PlainText)
        technical_layout.addWidget(self.action_technical_details)
        parameter_row = FlowRow()
        self.action_parameter_label = QLabel("Novo valor:")
        self.action_parameter_combo = QComboBox()
        for seconds in ALLOWED_INTERVALS:
            self.action_parameter_combo.addItem(f"{seconds} s", seconds)
        parameter_row.addWidget(self.action_parameter_label)
        parameter_row.addWidget(self.action_parameter_combo)
        parameter_row.addStretch()
        self.action_parameter_label.hide()
        self.action_parameter_combo.hide()
        self.action_dry_run = QLabel("Dry-run ainda não realizado.")
        self.action_dry_run.setWordWrap(True)
        self.action_dry_run.setTextFormat(Qt.TextFormat.PlainText)
        guided_layout.addWidget(self.action_summary)
        guided_layout.addWidget(technical_box)
        guided_layout.addLayout(parameter_row)
        guided_layout.addWidget(self.action_dry_run)
        self.recovery_banner = QLabel(
            "RECOVERY_REQUIRED — a transação foi interrompida. Revise o estado; nenhuma mutação será reexecutada automaticamente."
        )
        self.recovery_banner.setWordWrap(True)
        self.recovery_banner.setProperty("class", "OperationalCallout")
        self.recovery_banner.hide()
        guided_layout.addWidget(self.recovery_banner)
        guided_actions = FlowRow()
        self.prepare_action_button = QPushButton("Preparar ação")
        self.prepare_action_button.setProperty("class", "MenuButton")
        self.prepare_action_button.clicked.connect(self.prepare_selected_action)
        self.execute_action_button = QPushButton("Executar ação após dry-run")
        self.execute_action_button.setProperty("class", "ActionButton")
        self.execute_action_button.clicked.connect(self.execute_prepared_action)
        self.cancel_action_button = QPushButton("Cancelar")
        self.cancel_action_button.setProperty("class", "MenuButton")
        self.cancel_action_button.clicked.connect(self.cancel_guided_action)
        self.accept_indeterminate_button = QPushButton("Aceitar resultado indeterminado")
        self.accept_indeterminate_button.setProperty("class", "MenuButton")
        self.accept_indeterminate_button.clicked.connect(self.accept_indeterminate_result)
        self.rollback_action_button = QPushButton("Reverter alteração")
        self.rollback_action_button.setProperty("class", "MenuButton")
        self.rollback_action_button.clicked.connect(self.rollback_guided_action)
        guided_actions.addWidget(self.prepare_action_button)
        guided_actions.addWidget(self.execute_action_button)
        guided_actions.addWidget(self.cancel_action_button)
        guided_actions.addWidget(self.accept_indeterminate_button)
        guided_actions.addWidget(self.rollback_action_button)
        guided_layout.addLayout(guided_actions)
        recovery_actions = FlowRow()
        self.revalidate_recovery_button = QPushButton("Revalidar estado")
        self.revalidate_recovery_button.setProperty("class", "MenuButton")
        self.revalidate_recovery_button.clicked.connect(self.revalidate_recovery)
        self.rollback_recovery_button = QPushButton("Tentar rollback seguro")
        self.rollback_recovery_button.setProperty("class", "ActionButton")
        self.rollback_recovery_button.clicked.connect(self.rollback_guided_action)
        self.close_recovery_button = QPushButton("Encerrar como indeterminado")
        self.close_recovery_button.setProperty("class", "MenuButton")
        self.close_recovery_button.clicked.connect(self.close_recovery)
        recovery_actions.addWidget(self.revalidate_recovery_button)
        recovery_actions.addWidget(self.rollback_recovery_button)
        recovery_actions.addWidget(self.close_recovery_button)
        recovery_actions.addStretch()
        guided_layout.addLayout(recovery_actions)
        active_layout.addWidget(guided_box)

        proof_box = QGroupBox("Proof of Work")
        proof_box.setCheckable(True)
        proof_box.setChecked(False)
        proof_layout = QVBoxLayout(proof_box)
        self.proof_of_work = QLabel("Nenhuma tentativa de ação registrada nesta etapa.")
        self.proof_of_work.setWordWrap(True)
        self.proof_of_work.setTextFormat(Qt.TextFormat.PlainText)
        proof_layout.addWidget(self.proof_of_work)
        self.open_action_evidence_button = QPushButton("Abrir evidência")
        self.open_action_evidence_button.setProperty("class", "MenuButton")
        self.open_action_evidence_button.clicked.connect(self.open_action_evidence)
        proof_layout.addWidget(self.open_action_evidence_button)
        active_layout.addWidget(proof_box)
        session_actions = FlowRow()
        self.investigation_button = QPushButton("Abrir investigação associada")
        self.investigation_button.setProperty("class", "MenuButton")
        self.investigation_button.clicked.connect(self.open_investigation)
        self.complete_button = QPushButton("Concluir playbook")
        self.complete_button.setProperty("class", "ActionButton")
        self.complete_button.clicked.connect(self.complete_session)
        self.abort_button = QPushButton("Abortar playbook")
        self.abort_button.setProperty("class", "MenuButton")
        self.abort_button.clicked.connect(self.abort_session)
        session_actions.addWidget(self.investigation_button)
        session_actions.addStretch()
        session_actions.addWidget(self.complete_button)
        session_actions.addWidget(self.abort_button)
        active_layout.addLayout(session_actions)
        layout.addWidget(active_box)

        history_box = QGroupBox("Histórico recente")
        history_layout = QVBoxLayout(history_box)
        self.history_table = UxTable(0, 4)
        self.history_table.setHorizontalHeaderLabels(["Data local", "Playbook", "Status", "Origem"])
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        history_header = self.history_table.horizontalHeader()
        history_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        history_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        history_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        history_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.doubleClicked.connect(self.open_history_session)
        history_layout.addWidget(self.history_table)
        history_actions = FlowRow()
        self.open_history_button = QPushButton("Abrir sessão")
        self.open_history_button.setProperty("class", "MenuButton")
        self.open_history_button.clicked.connect(self.open_history_session)
        self.reopen_button = QPushButton("Reabrir sessão encerrada")
        self.reopen_button.setProperty("class", "MenuButton")
        self.reopen_button.clicked.connect(self.reopen_history_session)
        history_actions.addWidget(self.open_history_button)
        history_actions.addWidget(self.reopen_button)
        history_layout.addLayout(history_actions)
        layout.addWidget(history_box)
        self._set_action_buttons(False)

    def refresh(self, _checked=False):
        def query():
            store = self.host._get_assist_store()
            return {
                "contexts": store.list_contexts(limit=self.PAGE_SIZE),
                "history": store.list_playbook_sessions(limit=self.PAGE_SIZE),
            }
        self.host._run(
            query, label="Atualizando Assistente Técnico", progress=None,
            on_done=self._fill, operation_key="assist_refresh",
            blocks_navigation=False, silent_if_busy=True,
        )

    def focus_context(self, source_type, source_id=None, **values):
        self._pending_context_id = None
        def create():
            store = self.host._get_assist_store()
            context = store.create_context(source_type, source_id, **values)
            return {"context": context, "recommendations": store.recommend(context)}
        self.host._run(
            create, label="Preparando contexto do Assistente Técnico", progress=None,
            on_done=self._focused, operation_key="assist_context",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _focused(self, result):
        if not isinstance(result, dict) or not result.get("context"):
            return
        self._pending_context_id = result["context"]["context_id"]
        self.refresh()

    def _fill(self, result):
        result = result if isinstance(result, dict) else {}
        self._contexts = list(result.get("contexts") or [])
        self._history = list(result.get("history") or [])
        current_id = self._pending_context_id or (self._context or {}).get("context_id")
        self.context_selector.blockSignals(True)
        self.context_selector.clear()
        for context in self._contexts:
            label = f"{SOURCE_TEXT.get(context['source_type'], context['source_type'])} — {context['hostname']} — {_local(context['updated_at_utc'])}"
            self.context_selector.addItem(label, context["context_id"])
        if current_id:
            index = self.context_selector.findData(current_id)
            if index >= 0:
                self.context_selector.setCurrentIndex(index)
        self.context_selector.blockSignals(False)
        self._pending_context_id = None
        self.context_empty_state.setVisible(not bool(self._contexts))
        self._fill_history()
        self._context_changed()

    def _context_changed(self, _index=None):
        context_id = self.context_selector.currentData()
        self._context = next((item for item in self._contexts if item["context_id"] == context_id), None)
        if not self._context:
            self.context_summary.setText("Nenhum contexto selecionado.")
            self._fill_recommendations([])
            self.recommendation_empty_state.hide()
            self._show_session(None)
            return
        context = self._context
        self.context_summary.setText(
            f"{SOURCE_TEXT.get(context['source_type'], context['source_type'])} • {context['hostname']}\n{context['summary']}"
        )
        refs = context.get("evidence_refs") or []
        self.context_evidence.setText("Evidências: " + (", ".join(f"{r['type']} / {r['id']}" for r in refs) or "—"))
        self.context_limitations.setText("Limitações: " + (" • ".join(context.get("limitations") or []) or "—"))
        def query():
            store = self.host._get_assist_store()
            return {
                "context_id": context_id,
                "recommendations": store.recommend(context),
                "open_sessions": store.list_playbook_sessions(
                    status="OPEN", context_id=context_id, limit=1
                ),
            }
        self.host._run(
            query, label="Consultando orientações do Assistente Técnico", progress=None,
            on_done=self._fill_context_payload, operation_key="assist_recommend",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _fill_context_payload(self, payload):
        if not isinstance(payload, dict) or not self._context:
            return
        if payload.get("context_id") != self._context.get("context_id"):
            return
        self._fill_recommendations(payload.get("recommendations") or [])
        sessions = payload.get("open_sessions") or []
        self._show_session(sessions[0] if sessions else None)

    def _fill_recommendations(self, recommendations):
        self._recommendations = list(recommendations or [])
        self.recommendations_table.setRowCount(0)
        for recommendation in self._recommendations:
            row = self.recommendations_table.rowCount()
            self.recommendations_table.insertRow(row)
            values = (
                recommendation["title"], recommendation["rationale"], recommendation["rule_id"],
                str(len(recommendation.get("evidence_refs") or [])), recommendation["playbook_id"],
            )
            for column, value in enumerate(values):
                self.recommendations_table.setItem(row, column, QTableWidgetItem(str(value)))
        self.start_button.setEnabled(bool(self._recommendations))
        self.recommendation_empty_state.setVisible(bool(self._context) and not self._recommendations)
        if self._recommendations:
            self.recommendations_table.selectRow(0)

    def start_selected_playbook(self):
        from licensing.runtime import get_runtime
        gate = get_runtime()
        if not gate.is_allowed("assist.playbooks"):
            self.action_dry_run.setText(gate.explain("assist.playbooks"))
            return
        row = self.recommendations_table.currentRow()
        if not 0 <= row < len(self._recommendations) or not self._context:
            return
        recommendation = self._recommendations[row]
        self._run_session_action(
            lambda store: store.start_session(self._context["context_id"], recommendation["playbook_id"]),
            "Iniciando playbook seguro",
        )

    def _run_session_action(self, action, label):
        self.host._run(
            lambda: action(self.host._get_assist_store()), label=label, progress=None,
            on_done=self._session_done, operation_key="assist_session_action",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _session_done(self, session):
        if session:
            self._show_session(session)
            self.refresh()

    def _show_session(self, session):
        self._session = session
        self._action_run = None
        self._show_action_run(None)
        self.steps_table.setRowCount(0)
        if not session:
            self.active_summary.setText("Nenhum playbook ativo para este contexto.")
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            return
        definition = session.get("definition") or {}
        self.active_summary.setText(
            f"{definition.get('title') or session['playbook_id']} • versão {session['playbook_version']} • "
            f"{STATUS_TEXT.get(session['status'], session['status'])}\n{definition.get('description') or ''}"
        )
        completed = 0
        for step in session.get("steps") or []:
            info = step.get("definition") or {}
            row = self.steps_table.rowCount()
            self.steps_table.insertRow(row)
            values = (
                info.get("title") or step["step_id"], info.get("step_type") or "—",
                "Sim" if info.get("required") else "Não",
                STEP_STATUS_TEXT.get(step["status"], step["status"]), info.get("evidence_hint") or "—",
            )
            for column, value in enumerate(values):
                self.steps_table.setItem(row, column, QTableWidgetItem(str(value)))
            if step["status"] in ("DONE", "SKIPPED"):
                completed += 1
        total = max(1, len(session.get("steps") or []))
        self.progress.setRange(0, total)
        self.progress.setValue(completed)
        if session.get("steps"):
            self.steps_table.selectRow(0)
        active = session["status"] == "OPEN"
        for widget in (self.done_button, self.skip_button, self.complete_button, self.abort_button, self.note):
            widget.setEnabled(active)
        self.investigation_button.setEnabled(bool(session.get("investigation_session_id")))

    def _selected_step(self):
        row = self.steps_table.currentRow()
        steps = (self._session or {}).get("steps") or []
        return steps[row] if 0 <= row < len(steps) else None

    def _step_selected(self):
        step = self._selected_step()
        info = (step or {}).get("definition") or {}
        self.step_description.setText(info.get("description") or "Selecione uma etapa para ver a orientação.")
        self.navigate_button.setEnabled(bool(info.get("target_route")) and (self._session or {}).get("status") == "OPEN")
        self.skip_button.setEnabled(bool(step) and not info.get("required") and (self._session or {}).get("status") == "OPEN")
        is_action = info.get("step_type") == "EXISTING_SAFE_ACTION"
        self.done_button.setEnabled(bool(step) and not is_action and (self._session or {}).get("status") == "OPEN")
        self.note.setText((step or {}).get("note") or "")
        if not is_action or not self._session:
            self._show_action_definition(None)
            self._show_action_run(None)
            return
        action = ACTION_BY_ID.get(info.get("action_ref"))
        self._show_action_definition(action)
        def query():
            store = self.host._get_assist_store()
            runs = store.list_action_runs(
                session_id=self._session["session_id"], action_id=action.action_id, limit=20
            )
            catalog = store.action_catalog(**self._services(), hostname=self._session.get("hostname"))
            entry = next((item for item in catalog if item["action_id"] == action.action_id), None)
            return {
                "action": action,
                "catalog": entry,
                "run": next((item for item in runs if item.get("source_step_id") == step["step_id"]), None),
            }
        self.host._run(
            query, label="Consultando histórico da ação guiada", progress=None,
            on_done=self._action_history_loaded, operation_key="assist_action_history",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _action_history_loaded(self, payload):
        payload = payload if isinstance(payload, dict) else {}
        run = payload.get("run")
        if run:
            parameters = run.get("parameters") or {}
            if parameters:
                self._last_action_parameter_values[run.get("action_id")] = next(iter(parameters.values()))
        self._show_action_definition(payload.get("action"), payload.get("catalog"))
        self._show_action_run(run)

    @staticmethod
    def _parameter_definition(action):
        schema = (action.parameter_schema if action else None) or {}
        if len(schema) != 1:
            return None, None
        return next(iter(schema.items()))

    def _show_action_definition(self, action, catalog=None):
        self._action_catalog_entry = catalog
        if not action:
            self.action_summary.setText("Selecione uma etapa EXISTING_SAFE_ACTION para preparar uma ação.")
            self.action_dry_run.setText("Dry-run ainda não realizado.")
            self._set_action_buttons(False)
            self.action_parameter_label.hide()
            self.action_parameter_combo.hide()
            self.action_technical_details.setText("Selecione uma ação para consultar a política.")
            return
        kind = "Somente leitura" if action.side_effect_class == "READ_ONLY" else "Alteração local reversível"
        availability = (catalog or {}).get("availability_state") or "CONSULTANDO"
        availability_reason = (catalog or {}).get("availability_reason") or "Validando capacidades e pré-condições locais."
        self.action_summary.setText(
            f"{action.title} • versão {action.version}\n"
            f"Tipo: {kind} • Risco: {action.risk_level} • UAC: NÃO\n"
            f"Rollback: {'disponível' if action.rollback_mode == 'REQUIRED' else 'não necessário'} • "
            f"Estado: {availability}\n{action.description}\n{availability_reason}"
        )
        self.action_technical_details.setText(
            f"Classe: {action.side_effect_class} • dry-run: {'SIM' if action.supports_dry_run else 'NÃO'} • "
            f"modo de rollback: {action.rollback_mode}\n"
            f"Schema de parâmetros: {action.parameter_schema or 'nenhum'}\n"
            "Pré-condições: " + " • ".join(action.preconditions)
        )
        mutable = action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE"
        self.action_parameter_label.setVisible(mutable)
        self.action_parameter_combo.setVisible(mutable)
        if mutable:
            name, rule = self._parameter_definition(action)
            values = list((rule or {}).get("enum") or [])
            unit = "s" if name == "interval_seconds" else "dias"
            self.action_parameter_label.setText(
                "Novo intervalo:" if name == "interval_seconds" else "Nova retenção:"
            )
            self.action_parameter_combo.blockSignals(True)
            try:
                self.action_parameter_combo.clear()
                for value in values:
                    self.action_parameter_combo.addItem(f"{value} {unit}", value)
                service = self.host._get_monitoring_service()
                current = int(
                    service.interval_seconds if name == "interval_seconds"
                    else service.retention_days
                )
                preferred = self._last_action_parameter_values.get(action.action_id)
                if preferred not in values:
                    choices = [value for value in values if value != current]
                    preferred = choices[0] if choices else current
                index = self.action_parameter_combo.findData(preferred)
                self.action_parameter_combo.setCurrentIndex(max(0, index))
            finally:
                self.action_parameter_combo.blockSignals(False)
        self._set_action_buttons(True)

    def _set_action_buttons(self, selected):
        status = (self._action_run or {}).get("status")
        active_session = bool(self._session and self._session.get("status") == "OPEN")
        busy = ("RUNNING", "VALIDATING", "ROLLBACK_READY", "ROLLING_BACK", "RECOVERY_REQUIRED")
        catalog_available = (
            self._action_catalog_entry is None
            or self._action_catalog_entry.get("availability_state") == "AVAILABLE"
        )
        self.prepare_action_button.setEnabled(bool(
            selected and active_session and status not in busy and catalog_available
        ))
        self.execute_action_button.setEnabled(bool(selected and active_session and status == "READY"))
        self.cancel_action_button.setEnabled(bool(selected and status in ("PLANNED", "READY", "RUNNING")))
        self.accept_indeterminate_button.setEnabled(bool(
            selected and active_session and status == "SUCCEEDED"
            and (self._action_run or {}).get("result") == "INDETERMINATE"
            and not (self._action_run or {}).get("accepted_at")
        ))
        mutable = bool(
            self._action_run and
            ((self._action_run.get("definition") or {}).get("side_effect_class") == "LOCAL_REVERSIBLE_CHANGE")
        )
        self.rollback_action_button.setEnabled(bool(mutable and status == "SUCCEEDED"))
        recovery = status == "RECOVERY_REQUIRED"
        self.recovery_banner.setVisible(recovery)
        self.revalidate_recovery_button.setEnabled(recovery)
        self.rollback_recovery_button.setEnabled(bool(recovery and mutable))
        self.close_recovery_button.setEnabled(recovery)
        self.open_action_evidence_button.setEnabled(bool(
            self._action_run and (
                self._action_run.get("before_evidence_ref")
                or self._action_run.get("after_evidence_ref")
            )
        ))

    def _services(self):
        return {
            "posture_service": self.host._get_posture_service(),
            "monitoring_service": self.host._get_monitoring_service(),
        }

    def prepare_selected_action(self):
        step = self._selected_step()
        info = (step or {}).get("definition") or {}
        if not self._session or info.get("step_type") != "EXISTING_SAFE_ACTION":
            return
        services = self._services()
        action = ACTION_BY_ID.get(info.get("action_ref"))
        parameters = None
        if action and action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE":
            parameter_name, _rule = self._parameter_definition(action)
            parameters = {parameter_name: int(self.action_parameter_combo.currentData())}
        self.host._run(
            lambda: self.host._get_assist_store().prepare_action(
                self._session["session_id"], step["step_id"], parameters=parameters,
                **services
            ),
            label="Preparando ação guiada e dry-run", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_prepare",
            blocks_navigation=False, silent_if_busy=True,
        )

    def execute_prepared_action(self):
        from licensing.runtime import get_runtime
        gate = get_runtime()
        if not gate.is_allowed("guided_actions"):
            self.action_dry_run.setText(gate.explain("guided_actions"))
            return
        action_run = self._action_run
        if not action_run or action_run.get("status") != "READY":
            return
        action = ACTION_BY_ID[action_run["action_id"]]
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Question)
        dialog.setWindowTitle("Confirmar ação guiada")
        dry = action_run.get("dry_run") or {}
        before = dry.get("current_state") or {}
        proposed = dry.get("proposed_after") or {}
        rollback = dry.get("rollback_target") or {}
        if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE":
            parameter_name, _rule = self._parameter_definition(action)
            is_interval = parameter_name == "interval_seconds"
            before_key = "old_interval_seconds" if is_interval else "old_retention_days"
            proposed_key = "interval_seconds" if is_interval else "retention_days"
            noun = "intervalo de monitoramento" if is_interval else "política de retenção"
            unit = "s" if is_interval else "dias"
            dialog.setText(
                f"Alterar {noun} de {before.get(before_key)} {unit} para "
                f"{proposed.get(proposed_key)} {unit}."
            )
            dialog.setInformativeText(
                "ANTES: configuração e runtime usam "
                f"{before.get(before_key)} {unit}.\n"
                "DEPOIS: configuração e runtime usarão "
                f"{proposed.get(proposed_key)} {unit}.\n"
                f"EFEITO: {action.expected_effect}; nenhuma configuração do Windows"
                + (" e nenhum purge durante esta transação.\n" if not is_interval else ".\n") +
                "ROLLBACK: se a validação falhar, o Configurador TI tentará restaurar "
                f"{rollback.get(proposed_key)} {unit}."
            )
            execute_text = "Aplicar alteração"
        else:
            dialog.setText(action.expected_effect)
            dialog.setInformativeText(
                "ANTES/DEPOIS: somente novas evidências locais serão gravadas.\n"
                "EFEITO: leitura local allowlisted, sem alterar configuração.\n"
                "ROLLBACK: não aplicável a esta ação read-only.\n"
                "Não haverá solicitação de UAC."
            )
            execute_text = "Executar ação"
        execute_button = dialog.addButton(execute_text, QMessageBox.ButtonRole.AcceptRole)
        dialog.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()
        if dialog.clickedButton() is not execute_button:
            return
        services = self._services()
        store = self.host._get_assist_store()
        store.confirm_action(action_run["action_run_id"])
        self._action_run = dict(action_run, status="RUNNING", confirmed_at="pending")
        self._set_action_buttons(True)
        self.action_dry_run.setText("Transação allowlisted em andamento; aguarde execução e validação.")
        def execute(cancel_callback=None):
            return store.execute_action(
                action_run["action_run_id"], cancel_callback=cancel_callback, **services
            )
        self.host._run(
            execute, label="Executando ação guiada allowlisted", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_execute",
            blocks_navigation=False, silent_if_busy=True,
            on_finally=lambda state: self._action_execution_finalized(
                action_run["action_run_id"], state
            ),
        )

    def _action_execution_finalized(self, action_run_id, state):
        if state == "success":
            return
        store = self.host._get_assist_store()
        current = store.get_action_run(action_run_id)
        if state == "cancelled" and current and current.get("status") == "READY":
            current = store.cancel_action(action_run_id)
        self._show_action_run(current)
        self.refresh()

    def cancel_guided_action(self):
        action_run = self._action_run
        if not action_run:
            return
        if action_run.get("status") == "RUNNING":
            worker = self.host._operation_workers.get("configurador_ti_guided_action_execute")
            if worker is not None:
                worker.requestInterruption()
                self.action_dry_run.setText("Cancelamento cooperativo solicitado; aguardando ponto seguro.")
            return
        self.host._run(
            lambda: self.host._get_assist_store().cancel_action(action_run["action_run_id"]),
            label="Cancelando ação antes da execução", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_cancel",
            blocks_navigation=False, silent_if_busy=True,
        )

    def accept_indeterminate_result(self):
        if not self._action_run:
            return
        self.host._run(
            lambda: self.host._get_assist_store().accept_indeterminate(
                self._action_run["action_run_id"]
            ),
            label="Aceitando resultado indeterminado revisado", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_accept",
            blocks_navigation=False, silent_if_busy=True,
        )

    def rollback_guided_action(self):
        if not self._action_run:
            return
        run = self._action_run
        before = run.get("before") or {}
        action = ACTION_BY_ID.get(run.get("action_id"))
        parameter_name, _rule = self._parameter_definition(action)
        is_interval = parameter_name == "interval_seconds"
        before_key = "old_interval_seconds" if is_interval else "old_retention_days"
        noun = "intervalo anterior" if is_interval else "retenção anterior"
        unit = "s" if is_interval else "dias"
        answer = QMessageBox.question(
            self, "Confirmar rollback",
            f"Restaurar {noun} de {before.get(before_key, '—')} {unit} "
            "e validar persistência/runtime?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.host._run(
            lambda: self.host._get_assist_store().rollback_action(
                run["action_run_id"], monitoring_service=self.host._get_monitoring_service()
            ),
            label="Executando rollback local seguro", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_rollback",
            blocks_navigation=False, silent_if_busy=True,
        )

    def revalidate_recovery(self):
        if not self._action_run or self._action_run.get("status") != "RECOVERY_REQUIRED":
            return
        self.host._run(
            lambda: self.host._get_assist_store().revalidate_recovery(
                self._action_run["action_run_id"],
                monitoring_service=self.host._get_monitoring_service(),
            ),
            label="Revalidando transação interrompida", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_recovery",
            blocks_navigation=False, silent_if_busy=True,
        )

    def close_recovery(self):
        if not self._action_run or self._action_run.get("status") != "RECOVERY_REQUIRED":
            return
        answer = QMessageBox.question(
            self, "Encerrar recovery",
            "Encerrar como falha indeterminada sem reexecutar a mutação?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.host._run(
            lambda: self.host._get_assist_store().close_recovery_as_failure(
                self._action_run["action_run_id"]
            ),
            label="Encerrando recovery como indeterminado", progress=None,
            on_done=self._action_done, operation_key="configurador_ti_guided_action_recovery_close",
            blocks_navigation=False, silent_if_busy=True,
        )

    def _action_done(self, action_run):
        if action_run:
            parameters = action_run.get("parameters") or {}
            if parameters:
                self._last_action_parameter_values[action_run.get("action_id")] = next(
                    iter(parameters.values())
                )
        self._show_action_run(action_run)
        if action_run and action_run.get("action_id") == "SET_MONITORING_INTERVAL":
            try:
                service = self.host._get_monitoring_service()
                self.host.monitoring_panel.apply_transactional_interval(
                    service.interval_seconds
                )
            except Exception:
                pass
        if action_run and action_run.get("action_id") == "SET_MONITORING_RETENTION_POLICY":
            try:
                service = self.host._get_monitoring_service()
                self.host.monitoring_panel.apply_transactional_retention(
                    service.retention_days
                )
            except Exception:
                pass
        if action_run and action_run.get("status") in (
            "SUCCEEDED", "FAILED", "CANCELLED", "ROLLED_BACK", "ROLLBACK_FAILED"
        ):
            session_id = action_run.get("source_playbook_session_id")
            session = self.host._get_assist_store().get_session_details(session_id)
            if session:
                self._show_session(session)
                self._show_action_run(action_run)
        self.refresh()

    def _show_action_run(self, action_run):
        self._action_run = action_run if isinstance(action_run, dict) else None
        if not self._action_run:
            self.action_dry_run.setText("Dry-run ainda não realizado.")
            self.proof_of_work.setText("Nenhuma tentativa de ação registrada nesta etapa.")
            self._set_action_buttons(bool(self._selected_step() and ((self._selected_step().get("definition") or {}).get("step_type") == "EXISTING_SAFE_ACTION")))
            return
        run = self._action_run
        dry = run.get("dry_run") or {}
        preconditions = dry.get("preconditions") or []
        pre_text = " • ".join(
            f"{item.get('name')}: {'OK' if item.get('ok') else 'FALHOU'}" for item in preconditions
        ) or "—"
        self.action_dry_run.setText(
            f"Última tentativa: {run.get('status')} / {run.get('result') or 'sem resultado'}\n"
            f"Dry-run: efeito {dry.get('side_effect_class') or '—'} • UAC: "
            f"{'SIM' if dry.get('requires_uac') else 'NÃO'} • rollback: {dry.get('rollback_mode') or '—'}\n"
            f"Pré-condições: {pre_text}\n"
            f"Antes: {dry.get('current_state') or '—'}\n"
            f"Depois proposto: {dry.get('proposed_after') or '—'}\n"
            f"Rollback previsto: {dry.get('rollback_target') or '—'}"
        )
        proof = run.get("proof_of_work") or {}
        before, planned, action, after, validation, rollback, result = (
            proof.get("before"), proof.get("planned_change"),
            proof.get("action") or {}, proof.get("after"),
            proof.get("validation") or {}, proof.get("rollback") or {},
            proof.get("result") or {},
        )
        def ref_text(ref):
            if not isinstance(ref, dict):
                return "—"
            if ref.get("id"):
                return f"{ref.get('type')} / {ref.get('id')}"
            return json.dumps(ref, ensure_ascii=False, sort_keys=True)
        self.proof_of_work.setText(
            f"ANTES\n{ref_text(before)}\n\n"
            f"MUDANÇA PLANEJADA\n{ref_text(planned)}\n\n"
            f"AÇÃO\n{action.get('action_id') or run.get('action_id')} v{action.get('version') or run.get('action_version')} • "
            f"solicitada por {action.get('requested_by') or run.get('requested_by')} • "
            f"parâmetros {action.get('parameters') or {}}\n\n"
            f"DEPOIS REAL\n{ref_text(after)}\n\n"
            f"VALIDAÇÃO\n{validation.get('result') or '—'} • {validation.get('summary') or '—'}\n\n"
            f"ROLLBACK\n{rollback.get('status') or '—'} • alvo {rollback.get('target') or '—'}\n\n"
            f"RESULTADO\n{result.get('result') or '—'} • {result.get('validator_summary') or result.get('error_summary') or 'Aguardando validação.'}"
        )
        self._set_action_buttons(True)

    def open_action_evidence(self):
        run = self._action_run or {}
        reference = run.get("after_evidence_ref") or run.get("before_evidence_ref")
        if reference:
            self.host._abrir_evidencia_assist(reference.get("type"), reference.get("id"))

    def focus_action_run(self, action_run_id):
        self.host._run(
            lambda: self.host._get_assist_store().get_action_run(action_run_id),
            label="Abrindo Proof of Work", progress=None,
            on_done=self._show_action_run, operation_key="assist_action_open",
            blocks_navigation=False, silent_if_busy=True,
        )

    def navigate_selected_step(self):
        step = self._selected_step()
        route = ((step or {}).get("definition") or {}).get("target_route")
        if route:
            self.host._open_module(route)

    def update_selected_step(self, status):
        step = self._selected_step()
        if not step or not self._session:
            return
        note = self.note.text()
        self._run_session_action(
            lambda store: store.update_step(self._session["session_id"], step["step_id"], status, note=note),
            "Atualizando etapa do playbook",
        )

    def complete_session(self):
        if self._session:
            self._run_session_action(lambda store: store.complete_session(self._session["session_id"]), "Concluindo playbook")

    def abort_session(self):
        if not self._session:
            return
        answer = QMessageBox.question(self, "Abortar playbook", "Confirma o encerramento deste playbook sem conclusão?")
        if answer == QMessageBox.StandardButton.Yes:
            self._run_session_action(lambda store: store.abort_session(self._session["session_id"]), "Abortando playbook")

    def open_selected_evidence(self):
        refs = (self._context or {}).get("evidence_refs") or []
        if refs:
            self.host._abrir_evidencia_assist(refs[0]["type"], refs[0]["id"])

    def open_investigation(self):
        session_id = (self._session or {}).get("investigation_session_id")
        if session_id:
            self.host._abrir_sessao_investigacao(session_id)

    def _fill_history(self):
        self.history_table.setRowCount(0)
        for session in self._history:
            definition = session.get("definition") or {}
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            values = (
                _local(session.get("updated_at_utc")), definition.get("title") or session["playbook_id"],
                STATUS_TEXT.get(session["status"], session["status"]),
                SOURCE_TEXT.get(session["source_context_type"], session["source_context_type"]),
            )
            for column, value in enumerate(values):
                self.history_table.setItem(row, column, QTableWidgetItem(str(value)))
        if self._history:
            self.history_table.selectRow(0)

    def _selected_history(self):
        row = self.history_table.currentRow()
        return self._history[row] if 0 <= row < len(self._history) else None

    def open_history_session(self, _checked=False):
        session = self._selected_history()
        if session:
            self._show_session(session)

    def reopen_history_session(self):
        session = self._selected_history()
        if session and session["status"] != "OPEN":
            self._run_session_action(lambda store: store.reopen_session(session["session_id"]), "Reabrindo playbook")
