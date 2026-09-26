"""Investigation View MVP para mudanças já classificadas pelo baseline."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from audit_timeline import format_local_timestamp
from change_intelligence import CHANGE_TYPES
from incident_replay import RELEVANCE_LEVELS
from operational_ui import CollapsibleSection
from ui_components import FlowRow, UxTable


TYPE_LABELS = {
    "NEW": "Novo", "CHANGED": "Alterado", "ABSENT": "Ausente",
    "INDETERMINATE": "Indeterminado",
}


class ChangeIntelligencePanel(QWidget):
    PAGE_SIZE = 100

    def __init__(self, host, core):
        super().__init__(host)
        self.host = host
        self.core = core
        self._changes = []
        self._total = 0
        self._loading = False
        self._operation_filter = None
        self._pending_change_id = None
        self._selected_change_id = None
        self._sessions = []
        self._session_id = None
        self._replay = []
        self._suggestions = []
        self._session_loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        layout.addLayout(host._header(
            "Investigação",
            "Mudanças observadas pela comparação defensiva. Mudança não implica causa, incidente ou ameaça.",
        ))

        session_actions = FlowRow()
        self.session_selector = QComboBox()
        self.session_selector.setMinimumWidth(280)
        self.session_selector.addItem("Nenhuma sessão", None)
        self.session_selector.currentIndexChanged.connect(self._session_changed)
        self.session_refresh_button = QPushButton("Atualizar sessões")
        self.session_refresh_button.setProperty("class", "MenuButton")
        self.session_refresh_button.clicked.connect(self.refresh_sessions)
        self.session_new_button = QPushButton("Nova sessão manual")
        self.session_new_button.setProperty("class", "ActionButton")
        self.session_new_button.clicked.connect(self._new_manual_session)
        self.session_from_selection_button = QPushButton("Criar da seleção")
        self.session_from_selection_button.setProperty("class", "MenuButton")
        self.session_from_selection_button.clicked.connect(self._create_session_from_selection)
        self.show_archived_sessions = QCheckBox("Mostrar arquivadas")
        self.show_archived_sessions.toggled.connect(self.refresh_sessions)
        self.archive_session_button = QPushButton("Arquivar sessão")
        self.archive_session_button.setProperty("class", "MenuButton")
        self.archive_session_button.setEnabled(False)
        self.archive_session_button.clicked.connect(self.toggle_archive_session)
        self.session_assist_button = QPushButton("Abrir sessão no Assist")
        self.session_assist_button.setProperty("class", "MenuButton")
        self.session_assist_button.setEnabled(False)
        self.session_assist_button.clicked.connect(self._open_session_assist)
        session_actions.addWidget(self.session_selector, 1)
        session_actions.addWidget(self.session_refresh_button)
        session_actions.addWidget(self.session_new_button)
        session_actions.addWidget(self.session_from_selection_button)
        session_actions.addWidget(self.show_archived_sessions)
        session_actions.addWidget(self.archive_session_button)
        session_actions.addWidget(self.session_assist_button)
        layout.addLayout(session_actions)

        self.session_summary = QLabel(
            "Nenhuma sessão aberta. Correlação temporal/operacional não comprova causalidade."
        )
        self.session_summary.setWordWrap(True)
        self.session_summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.session_summary)

        self.replay_table = UxTable(0, 7)
        self.replay_table.setHorizontalHeaderLabels([
            "Fase", "Hora local", "Tipo", "Módulo", "Resumo", "Relação", "Relevância",
        ])
        self.replay_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.replay_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.replay_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.replay_table.setMinimumHeight(185)
        replay_header = self.replay_table.horizontalHeader()
        for column, width in ((0, 90), (1, 145), (2, 120), (3, 140), (5, 145), (6, 100)):
            replay_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            replay_header.resizeSection(column, width)
        replay_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.replay_table.itemSelectionChanged.connect(self.show_session_item_details)
        layout.addWidget(self.replay_table)

        item_actions = FlowRow()
        self.relevance = QComboBox()
        for value in RELEVANCE_LEVELS:
            self.relevance.addItem({"CONTEXT": "Contexto", "RELEVANT": "Relevante", "KEY": "Chave"}[value], value)
        self.item_note = QLineEdit()
        self.item_note.setMaxLength(500)
        self.item_note.setPlaceholderText("Nota curta em texto simples (opcional)")
        self.save_item_button = QPushButton("Salvar relevância/nota")
        self.save_item_button.setProperty("class", "MenuButton")
        self.save_item_button.clicked.connect(self.update_selected_item)
        self.remove_item_button = QPushButton("Remover da sessão")
        self.remove_item_button.setProperty("class", "MenuButton")
        self.remove_item_button.clicked.connect(self.remove_selected_item)
        self.open_original_button = QPushButton("Abrir item original")
        self.open_original_button.setProperty("class", "MenuButton")
        self.open_original_button.clicked.connect(self.open_selected_original)
        item_actions.addWidget(self.relevance)
        item_actions.addWidget(self.item_note, 1)
        item_actions.addWidget(self.save_item_button)
        item_actions.addWidget(self.remove_item_button)
        item_actions.addWidget(self.open_original_button)
        layout.addLayout(item_actions)

        self.session_details = QTextEdit()
        self.session_details.setReadOnly(True)
        self.session_details.setMinimumHeight(150)
        self.session_details_section = CollapsibleSection(
            "Evidência / detalhes técnicos do item", self.session_details
        )
        layout.addWidget(self.session_details_section)

        self.suggestions_table = UxTable(0, 6)
        self.suggestions_table.setHorizontalHeaderLabels([
            "Hora local", "Tipo", "Módulo", "Resumo", "Relação observada", "Força",
        ])
        self.suggestions_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.suggestions_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.suggestions_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.suggestions_table.setMinimumHeight(155)
        suggestion_header = self.suggestions_table.horizontalHeader()
        for column, width in ((0, 145), (1, 120), (2, 140), (4, 150), (5, 80)):
            suggestion_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            suggestion_header.resizeSection(column, width)
        suggestion_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        suggestions_widget = QWidget()
        suggestions_layout = QVBoxLayout(suggestions_widget)
        suggestions_layout.setContentsMargins(0, 0, 0, 0)
        suggestions_layout.addWidget(self.suggestions_table)
        self.add_suggestion_button = QPushButton("Adicionar item sugerido")
        self.add_suggestion_button.setProperty("class", "MenuButton")
        self.add_suggestion_button.clicked.connect(self.add_selected_suggestion)
        suggestions_layout.addWidget(self.add_suggestion_button)
        self.suggestions_section = CollapsibleSection("Itens relacionados sugeridos", suggestions_widget)
        layout.addWidget(self.suggestions_section)

        self.summary = QLabel("Resumo: nenhuma comparação carregada.")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.summary)
        self.context = QLabel("Período: Hoje. Nenhum grupo específico selecionado.")
        self.context.setWordWrap(True)
        self.context.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.context)

        filters = FlowRow()
        self.period = QComboBox()
        self.period.addItem("Hoje", "today")
        self.period.addItem("Últimos 7 dias", 7)
        self.period.addItem("Últimos 30 dias", 30)
        self.period.addItem("Todos", None)
        self.change_type = QComboBox()
        self.change_type.addItem("Todos os tipos", None)
        for value in CHANGE_TYPES:
            self.change_type.addItem(TYPE_LABELS[value], value)
        self.source = QComboBox()
        self.source.addItem("Todas as fontes", None)
        self.entity_type = QComboBox()
        self.entity_type.addItem("Todos os tipos de entidade", None)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar em nome, chave ou resumo...")
        self.search.setClearButtonEnabled(True)
        self.update_button = QPushButton("Atualizar")
        self.update_button.setProperty("class", "ActionButton")
        self.update_button.clicked.connect(self.refresh)
        filters.addWidget(self.period)
        filters.addWidget(self.change_type)
        filters.addWidget(self.source)
        filters.addWidget(self.entity_type)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.update_button)
        layout.addLayout(filters)

        group_actions = FlowRow()
        self.group_status = QLabel("Grupo: todos")
        self.group_status.setTextFormat(Qt.TextFormat.PlainText)
        self.clear_group_button = QPushButton("Limpar grupo")
        self.clear_group_button.setProperty("class", "MenuButton")
        self.clear_group_button.setVisible(False)
        self.clear_group_button.clicked.connect(self.clear_group)
        self.selection_assist_button = QPushButton("Abrir seleção no Assist")
        self.selection_assist_button.setProperty("class", "MenuButton")
        self.selection_assist_button.setEnabled(False)
        self.selection_assist_button.clicked.connect(self._open_selection_assist)
        group_actions.addWidget(self.group_status)
        group_actions.addWidget(self.clear_group_button)
        group_actions.addWidget(self.selection_assist_button)
        group_actions.addStretch()
        layout.addLayout(group_actions)

        self.status = QLabel("Abra a página ou clique em Atualizar.")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)

        self.table = UxTable(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Data/hora local", "Mudança", "Entidade", "Nome / chave", "Fonte", "Resumo",
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setWordWrap(False)
        self.table.setMinimumHeight(260)
        header = self.table.horizontalHeader()
        for column, width in ((0, 155), (1, 115), (2, 140), (3, 210), (4, 145)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(column, width)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.show_details)
        layout.addWidget(self.table, 1)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(210)
        self.details_section = CollapsibleSection(
            "Before, after e evidências técnicas", self.details
        )
        layout.addWidget(self.details_section)

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
        """Widgets são lidos somente na thread Qt antes do Worker."""
        return {
            "since_utc": self._since_utc(),
            "change_type": self.change_type.currentData(),
            "source": self.source.currentData(),
            "entity_type": self.entity_type.currentData(),
            "text": self.search.text().strip() or None,
            "operation_id": self._operation_filter,
        }

    def _query(self, offset, filters):
        try:
            store = self.host._get_change_store()
            if store is None:
                raise RuntimeError("Change Intelligence indisponível.")
            return {
                "ok": True,
                "changes": store.query_changes(limit=self.PAGE_SIZE, offset=offset, **filters),
                "total": store.count_changes(**filters),
                "counts": store.summarize_changes(**filters),
                "involved_sources": store.sources_for(**filters),
                "sources": store.list_sources(),
                "entity_types": store.list_entity_types(),
                "group": store.get_group(filters["operation_id"]) if filters.get("operation_id") else None,
                "offset": offset,
                "filters": filters,
            }
        except Exception as exc:
            try:
                self.core.logger.error(
                    "CHANGE_INTELLIGENCE_QUERY_FALHA | tipo=%s", type(exc).__name__
                )
            except Exception:
                pass
            return {"ok": False, "error": type(exc).__name__, "offset": offset}

    def refresh(self, _checked=False):
        self._load(0)

    def load_more(self, _checked=False):
        self._load(len(self._changes))

    def focus_operation(self, operation_id):
        self._operation_filter = str(operation_id or "").strip()[:100] or None
        # Deep-link mostra o grupo completo, sem herdar filtros visuais antigos.
        self.period.setCurrentIndex(self.period.findData(None))
        self.change_type.setCurrentIndex(0)
        self.source.setCurrentIndex(0)
        self.entity_type.setCurrentIndex(0)
        self.search.clear()
        self.group_status.setText(
            "Grupo: " + (self._operation_filter or "todos")
        )
        self.clear_group_button.setVisible(bool(self._operation_filter))
        self.selection_assist_button.setEnabled(bool(self._operation_filter))
        self.refresh()

    def focus_change(self, change_id):
        self._pending_change_id = str(change_id or "").strip()[:64] or None
        try:
            store = self.host._get_change_store()
            change = store.get_change(self._pending_change_id) if store and self._pending_change_id else None
        except Exception:
            change = None
        self.focus_operation(change.get("operation_id") if change else None)

    def clear_group(self, _checked=False):
        self._operation_filter = None
        self.group_status.setText("Grupo: todos")
        self.clear_group_button.setVisible(False)
        self.selection_assist_button.setEnabled(False)
        self.refresh()

    def _load(self, offset):
        if self._loading or self.host._closing:
            return
        self._loading = True
        self.update_button.setEnabled(False)
        self.more_button.setEnabled(False)
        self.status.setText("Consultando mudanças locais em segundo plano...")
        filters = self._filter_snapshot()

        def done(payload):
            self._loading = False
            self.update_button.setEnabled(True)
            self._present(payload)

        def finished(_state):
            if self._loading:
                self._loading = False
                self.update_button.setEnabled(True)
                self.status.setText("Consulta encerrada sem atualizar a investigação.")

        worker = self.host._run(
            lambda: self._query(offset, filters),
            label="Consultando Change Intelligence",
            operation_key="change_intelligence_query",
            blocks_navigation=False, on_done=done, on_finally=finished,
            silent_if_busy=True,
        )
        if worker is None:
            self._loading = False
            self.update_button.setEnabled(True)

    @staticmethod
    def _restore_combo(combo, title, values):
        selected = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(title, None)
        for value in values:
            combo.addItem(value, value)
        index = combo.findData(selected)
        combo.setCurrentIndex(max(0, index))
        combo.blockSignals(False)

    def _present(self, payload):
        if not payload.get("ok"):
            self.status.setText(
                "Histórico de mudanças indisponível. Baseline, comparação e Timeline não foram alterados."
            )
            self.more_button.setEnabled(False)
            return
        self._restore_combo(self.source, "Todas as fontes", payload.get("sources") or [])
        self._restore_combo(
            self.entity_type, "Todos os tipos de entidade", payload.get("entity_types") or []
        )
        if payload.get("offset") == 0:
            self._changes = []
            self.table.setRowCount(0)
            self.details.clear()
            self.details_section.set_expanded(False)
        self._changes.extend(payload.get("changes") or [])
        self._total = int(payload.get("total") or 0)
        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(len(self._changes))
            for row, change in enumerate(self._changes):
                key = change.get("identity_key") or self._entity_display_name(change)
                values = (
                    format_local_timestamp(change["detected_at_utc"]),
                    TYPE_LABELS.get(change["change_type"], change["change_type"]),
                    change["entity_type"], key or "—", change["source"], change["summary"],
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setToolTip(str(value))
                    self.table.setItem(row, column, item)
        finally:
            self.table.setUpdatesEnabled(True)
        counts = payload.get("counts") or {}
        self.summary.setText(
            f"Resumo: {self._total} mudança(s) — Novo: {counts.get('NEW', 0)} | "
            f"Alterado: {counts.get('CHANGED', 0)} | Ausente: {counts.get('ABSENT', 0)} | "
            f"Indeterminado: {counts.get('INDETERMINATE', 0)}."
        )
        sources = ", ".join(payload.get("involved_sources") or []) or "nenhuma"
        group = payload.get("group")
        coverage = group.get("coverage") if isinstance(group, dict) else None
        if coverage:
            coverage_text = (
                "completa" if coverage.get("reference_complete") and coverage.get("current_complete")
                else "parcial; conclusões indeterminadas foram preservadas"
            )
        else:
            coverage_text = "consulte o grupo/detalhe para a cobertura da coleta"
        self.context.setText(
            f"Fontes envolvidas: {sources}. Cobertura: {coverage_text}. "
            + (f"Operation ID: {self._operation_filter}." if self._operation_filter else "Visão consolidada do período/filtros.")
        )
        shown = len(self._changes)
        self.status.setText(
            "Nenhuma mudança corresponde aos filtros. Estados sem alteração não são persistidos em massa."
            if self._total == 0 else
            f"Exibindo {shown} de {self._total}; mais recentes primeiro."
        )
        self.more_button.setEnabled(shown < self._total)
        if self._pending_change_id:
            for row, change in enumerate(self._changes):
                if change.get("change_id") == self._pending_change_id:
                    self.table.selectRow(row)
                    self._pending_change_id = None
                    break

    @staticmethod
    def _parse_json(value):
        if not value:
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _entity_display_name(cls, change):
        for payload_name in ("after_json", "before_json"):
            payload = cls._parse_json(change.get(payload_name))
            if isinstance(payload, dict):
                for field in ("Nome", "NomeTecnico", "ArquivoStartup", "CaminhoTarefa", "Caminho"):
                    if payload.get(field):
                        return str(payload[field])
        return "—"

    def show_details(self):
        row = self.table.currentRow()
        if not (0 <= row < len(self._changes)):
            self.details.clear()
            self._selected_change_id = None
            self.selection_assist_button.setEnabled(bool(self._operation_filter))
            return
        change = self._changes[row]
        self._selected_change_id = change.get("change_id")
        self.selection_assist_button.setEnabled(bool(self._operation_filter))
        before = self._parse_json(change.get("before_json"))
        after = self._parse_json(change.get("after_json"))
        evidence = self._parse_json(change.get("evidence_json"))
        pretty = lambda value: json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) if value is not None else "—"
        lines = [
            f"Change ID: {change['change_id']}",
            f"Schema: {change['schema_version']}",
            f"Detectado em UTC: {change['detected_at_utc']}",
            f"Hostname/equipamento: {change['hostname']}",
            f"Tipo: {change['change_type']}",
            f"Entidade: {change['entity_type']}",
            f"Identity key: {change.get('identity_key') or '—'}",
            f"Fonte: {change['source']}",
            f"Confiança/cobertura: {change['coverage_state']}",
            f"Baseline ID: {change.get('baseline_id') or '—'}",
            f"Baseline/revisão: {change.get('baseline_revision') or '—'}",
            f"Operation ID: {change['operation_id']}",
            f"Correlation ID: {change.get('correlation_id') or '—'}",
            f"Timeline event ID: {change.get('timeline_event_id') or '—'}",
            "", "BEFORE", pretty(before), "", "AFTER", pretty(after),
            "", "EVIDÊNCIAS", pretty(evidence),
        ]
        self.details.setPlainText("\n".join(lines))
        self.details_section.set_expanded(True)

    def _session_changed(self, _index):
        self._session_id = self.session_selector.currentData()
        self.session_assist_button.setEnabled(bool(self._session_id))
        if self._session_id:
            self.refresh_sessions()

    def _session_query(self, include_archived=False):
        try:
            store = self.host._get_incident_store()
            if store is None:
                raise RuntimeError("Incident Replay indisponível.")
            sessions = store.list_sessions(limit=50, include_archived=include_archived)
            active = self._session_id
            if active and not any(item["session_id"] == active for item in sessions):
                active = None
            if active is None and sessions:
                active = sessions[0]["session_id"]
            return {
                "ok": True,
                "sessions": sessions,
                "active": active,
                "summary": store.session_summary(active) if active else None,
                "replay": store.build_replay(active) if active else [],
                "suggestions": store.suggest_related(active, limit=100) if active else [],
            }
        except Exception as exc:
            try:
                self.core.logger.error("INCIDENT_REPLAY_QUERY_FALHA | tipo=%s", type(exc).__name__)
            except Exception:
                pass
            return {"ok": False, "error": type(exc).__name__}

    def refresh_sessions(self, _checked=False):
        if self._session_loading or self.host._closing:
            return
        self._session_loading = True
        self.session_refresh_button.setEnabled(False)
        include_archived = self.show_archived_sessions.isChecked()

        def done(payload):
            self._session_loading = False
            self.session_refresh_button.setEnabled(True)
            self._present_session(payload)

        def finished(_state):
            if self._session_loading:
                self._session_loading = False
                self.session_refresh_button.setEnabled(True)

        worker = self.host._run(
            lambda: self._session_query(include_archived),
            label="Consultando sessões de investigação",
            operation_key="incident_replay_query", blocks_navigation=False,
            on_done=done, on_finally=finished, silent_if_busy=True,
        )
        if worker is None:
            self._session_loading = False
            self.session_refresh_button.setEnabled(True)

    def focus_session(self, session_id):
        self._session_id = str(session_id or "").strip()[:64] or None
        self.refresh_sessions()

    def _present_session(self, payload):
        if not payload.get("ok"):
            self.session_summary.setText(
                "Sessões/replay indisponíveis. Timeline e Change Intelligence permanecem funcionais."
            )
            return
        self._sessions = payload.get("sessions") or []
        self._session_id = payload.get("active")
        self.session_selector.blockSignals(True)
        self.session_selector.clear()
        self.session_selector.addItem("Nenhuma sessão", None)
        for session in self._sessions:
            self.session_selector.addItem(
                f"{session['title']} — {session['status']}", session["session_id"]
            )
        index = self.session_selector.findData(self._session_id)
        self.session_selector.setCurrentIndex(max(0, index))
        self.session_selector.blockSignals(False)
        self.session_assist_button.setEnabled(bool(self._session_id))
        summary = payload.get("summary")
        if summary:
            self.session_summary.setText(
                f"{summary['title']} | {summary['status']} | {summary['hostname']} | "
                f"Eventos: {summary['events']} | Grupos: {summary['change_groups']} | "
                f"Mudanças: {summary['changes']} | Fortes: {summary['strong_relations']} | "
                f"Fracas: {summary['weak_relations']}. {summary['text']}"
            )
            archived = summary["status"] == "ARCHIVED"
            self.archive_session_button.setText(
                "Restaurar sessão" if archived else "Arquivar sessão"
            )
            self.archive_session_button.setEnabled(True)
        else:
            self.session_summary.setText(
                "Nenhuma sessão aberta. Correlação temporal/operacional não comprova causalidade."
            )
            self.archive_session_button.setText("Arquivar sessão")
            self.archive_session_button.setEnabled(False)
        self._replay = payload.get("replay") or []
        self.replay_table.setRowCount(len(self._replay))
        for row, item in enumerate(self._replay):
            values = (
                item["phase"], format_local_timestamp(item["observed_at_utc"]),
                item["item_type"], item["source_module"], item["summary"],
                item["relation_type"], item["relevance"],
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setToolTip(str(value))
                self.replay_table.setItem(row, column, cell)
        self._suggestions = payload.get("suggestions") or []
        self.suggestions_table.setRowCount(len(self._suggestions))
        for row, item in enumerate(self._suggestions):
            values = (
                format_local_timestamp(item["observed_at_utc"]), item["item_type"],
                item["source_module"], item["summary"], item["relation_type"], item["strength"],
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setToolTip(str(value))
                self.suggestions_table.setItem(row, column, cell)

    def toggle_archive_session(self, _checked=False):
        if not self._session_id:
            return
        session = next(
            (item for item in self._sessions if item["session_id"] == self._session_id), None
        )
        if session is None:
            return
        restoring = session["status"] == "ARCHIVED"
        action = "restaurar" if restoring else "arquivar"
        answer = QMessageBox.question(
            self, ("Restaurar" if restoring else "Arquivar") + " sessão",
            f"Confirma {action} esta sessão? Eventos, mudanças, baseline e evidências originais não serão apagados.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            store = self.host._get_incident_store()
            if restoring:
                store.restore_session(self._session_id)
            else:
                store.archive_session(self._session_id)
                if not self.show_archived_sessions.isChecked():
                    self._session_id = None
            self.refresh_sessions()
        except Exception as exc:
            self.core.logger.error("INCIDENT_REPLAY_ARCHIVE_FALHA | tipo=%s", type(exc).__name__)

    def _new_manual_session(self, _checked=False):
        self.host._criar_investigacao_manual()

    def _open_session_assist(self, _checked=False):
        if self._session_id:
            self.host._abrir_assist_contexto("INVESTIGATION_SESSION", self._session_id)

    def _open_selection_assist(self, _checked=False):
        if self._operation_filter:
            self.host._abrir_assist_contexto("CHANGE_GROUP", self._operation_filter)

    def _create_session_from_selection(self, _checked=False):
        row = self.table.currentRow()
        if 0 <= row < len(self._changes):
            self.host._criar_investigacao_mudanca(self._changes[row]["change_id"])
        elif self._operation_filter:
            self.host._criar_investigacao_grupo(self._operation_filter)
        else:
            self.session_summary.setText(
                "Selecione uma mudança ou abra um grupo para iniciar a sessão com contexto."
            )

    def add_selected_suggestion(self, _checked=False):
        row = self.suggestions_table.currentRow()
        if not self._session_id or not (0 <= row < len(self._suggestions)):
            return
        candidate = self._suggestions[row]
        try:
            self.host._get_incident_store().add_item(
                self._session_id, item_type=candidate["item_type"],
                referenced_id=candidate["referenced_id"],
                relation_type=candidate["relation_type"], relevance="CONTEXT",
            )
            self.refresh_sessions()
        except Exception as exc:
            self.core.logger.error("INCIDENT_REPLAY_ADD_FALHA | tipo=%s", type(exc).__name__)

    def remove_selected_item(self, _checked=False):
        row = self.replay_table.currentRow()
        if not (0 <= row < len(self._replay)):
            return
        try:
            self.host._get_incident_store().remove_item(self._replay[row]["item_id"])
            self.refresh_sessions()
        except Exception as exc:
            self.core.logger.error("INCIDENT_REPLAY_REMOVE_FALHA | tipo=%s", type(exc).__name__)

    def update_selected_item(self, _checked=False):
        row = self.replay_table.currentRow()
        if not (0 <= row < len(self._replay)):
            return
        try:
            self.host._get_incident_store().update_item(
                self._replay[row]["item_id"], relevance=self.relevance.currentData(),
                note=self.item_note.text(),
            )
            self.refresh_sessions()
        except Exception as exc:
            self.core.logger.error("INCIDENT_REPLAY_UPDATE_FALHA | tipo=%s", type(exc).__name__)

    def show_session_item_details(self):
        row = self.replay_table.currentRow()
        if not (0 <= row < len(self._replay)):
            self.session_details.clear()
            return
        item = self._replay[row]
        self.relevance.setCurrentIndex(max(0, self.relevance.findData(item["relevance"])))
        self.item_note.setText(item.get("note") or "")
        evidence = json.dumps(item.get("evidence"), ensure_ascii=False, indent=2, sort_keys=True) if item.get("evidence") is not None else "—"
        self.session_details.setPlainText("\n".join([
            f"Item ID: {item['item_id']}",
            f"Referência original: {item['item_type']} / {item['referenced_id']}",
            f"Observado em UTC: {item['observed_at_utc']}",
            f"Hostname/equipamento: {item.get('hostname') or '—'}",
            f"Operation ID: {item.get('operation_id') or '—'}",
            f"Correlation ID: {item.get('correlation_id') or '—'}",
            f"Relação observada: {item['relation_type']}",
            f"Relevância humana: {item['relevance']}",
            "Causalidade inferida: NÃO",
            "", "EVIDÊNCIA ORIGINAL", evidence,
        ]))
        self.session_details_section.set_expanded(True)

    def open_selected_original(self, _checked=False):
        row = self.replay_table.currentRow()
        if not (0 <= row < len(self._replay)):
            return
        item = self._replay[row]
        self.host._abrir_item_original(item["item_type"], item["referenced_id"])
