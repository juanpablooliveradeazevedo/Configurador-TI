"""Página operacional de Monitoring & Correlation dentro de Observabilidade."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import socket

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QPushButton, QTableWidgetItem, QVBoxLayout, QWidget,
)

from audit_timeline import format_local_timestamp
from monitoring_foundation import (
    ALLOWED_INTERVALS, METRIC_KEYS, METRIC_RULES, RETENTION_DAYS, STATE_TEXT,
)
from monitoring_intelligence import TREND_PERIODS
from operational_ui import ResponsiveGrid, local_timestamp
from ui_components import FlowRow, UxTable


QTableWidget = UxTable
PAGE_SIZE = 50


class MonitoringPanel(QWidget):
    def __init__(self, host, core):
        super().__init__()
        self.host = host
        self.core = core
        self._sample_offset = 0
        self._sample_total = 0
        self._alert_offset = 0
        self._alert_total = 0
        self._alert_rows = []
        self._selected_alert_id = None
        self._transition_rows = []
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self.host._header(
            "Monitoramento local",
            "Observações leves desta estação enquanto o Configurador TI está aberto. Observação não é diagnóstico.",
        ))

        summary = self.host._card("Resumo operacional")
        summary_layout = QVBoxLayout(summary)
        row = QHBoxLayout()
        self.status_label = QLabel("Parado")
        self.status_label.setObjectName("ValorCard")
        row.addWidget(self.status_label)
        row.addStretch()
        self.retention_label = QLabel(f"Retenção de amostras: {RETENTION_DAYS} dias.")
        row.addWidget(self.retention_label)
        summary_layout.addLayout(row)
        self.info_label = QLabel(
            "O monitor inicia parado. CPU, memória e disco são indicadores operacionais, não diagnósticos."
        )
        self.info_label.setObjectName("SubtituloTela")
        self.info_label.setWordWrap(True)
        summary_layout.addWidget(self.info_label)

        facts = FlowRow()
        self.last_cycle_label = QLabel("Último ciclo: —")
        self.next_cycle_label = QLabel("Próximo ciclo: —")
        self.interval_label = QLabel("Intervalo: 60 s")
        for label in (self.last_cycle_label, self.next_cycle_label, self.interval_label):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            label.setProperty("noWrap", True)
            label.setProperty("preserveMinimumWidth", True)
            label.setWordWrap(False)
            label.setMinimumWidth(270 if label is not self.interval_label else 150)
            facts.addWidget(label)
        facts.addStretch()
        summary_layout.addLayout(facts)

        actions = FlowRow()
        self.start_button = QPushButton("Iniciar")
        self.start_button.setProperty("class", "ActionButton")
        self.start_button.clicked.connect(self.start)
        actions.addWidget(self.start_button)
        self.pause_button = QPushButton("Pausar")
        self.pause_button.setProperty("class", "MenuButton")
        self.pause_button.clicked.connect(self.pause_or_resume)
        actions.addWidget(self.pause_button)
        self.stop_button = QPushButton("Parar")
        self.stop_button.setProperty("class", "MenuButton")
        self.stop_button.clicked.connect(self.stop)
        actions.addWidget(self.stop_button)
        self.update_button = QPushButton("Atualizar agora")
        self.update_button.setProperty("class", "MenuButton")
        self.update_button.clicked.connect(self.request_collection)
        actions.addWidget(self.update_button)
        actions.addWidget(QLabel("Intervalo seguro:"))
        self.interval_combo = QComboBox()
        for seconds in ALLOWED_INTERVALS:
            self.interval_combo.addItem(f"{seconds} s", seconds)
        configured_interval = 60
        configured_retention = RETENTION_DAYS
        try:
            configured = self.host._get_monitoring_store().get_monitoring_configuration()
            configured_interval = int(configured["interval_seconds"])
            configured_retention = int(configured["retention_days"])
        except Exception:
            pass
        self.retention_label.setText(f"Retenção de amostras: {configured_retention} dias.")
        self.interval_combo.setCurrentIndex(self.interval_combo.findData(configured_interval))
        self.interval_combo.currentIndexChanged.connect(self.change_interval)
        self.interval_combo.setEnabled(False)
        self.interval_combo.setToolTip(
            "Alterações persistentes exigem transação no Assistente Técnico."
        )
        self.interval_label.setText(f"Intervalo: {configured_interval} s")
        actions.addWidget(self.interval_combo)
        self.assist_interval_button = QPushButton("Ajustar intervalo via Assistente Técnico")
        self.assist_interval_button.setProperty("class", "MenuButton")
        self.assist_interval_button.setToolTip(
            "Abre uma revisão controlada; nenhuma alteração é executada automaticamente."
        )
        self.assist_interval_button.clicked.connect(self.open_interval_assist)
        actions.addWidget(self.assist_interval_button)
        actions.addStretch()
        summary_layout.addLayout(actions)
        layout.addWidget(summary)

        layout.addWidget(QLabel("Sinais atuais"))
        cards = []
        self.metric_value_labels = {}
        self.metric_state_labels = {}
        self.metric_since_labels = {}
        for key in METRIC_KEYS:
            rule = METRIC_RULES[key]
            card = self.host._card(rule["title"])
            card_layout = QVBoxLayout(card)
            value = QLabel("—")
            value.setObjectName("ValorCard")
            state = QLabel("INDETERMINATE — " + STATE_TEXT["INDETERMINATE"])
            state.setWordWrap(True)
            since = QLabel("Desde: —")
            threshold = QLabel(rule["threshold_text"])
            threshold.setObjectName("SubtituloTela")
            threshold.setWordWrap(True)
            card.setToolTip(rule["threshold_text"])
            for widget in (value, state, since, threshold):
                widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                card_layout.addWidget(widget)
            self.metric_value_labels[key] = value
            self.metric_state_labels[key] = state
            self.metric_since_labels[key] = since
            cards.append(card)
        layout.addWidget(ResponsiveGrid(cards, 290))

        self._build_alerts(layout)
        self._build_trends(layout)
        self._build_alert_context(layout)

        transitions = self.host._card("Histórico recente — transições confirmadas")
        transitions_layout = QVBoxLayout(transitions)
        note = QLabel(
            "Proximidade temporal serve apenas como contexto e não prova causalidade. "
            "A investigação é aberta somente por decisão do técnico."
        )
        note.setWordWrap(True)
        transitions_layout.addWidget(note)
        self.transitions_table = QTableWidget(0, 7)
        self.transitions_table.setHorizontalHeaderLabels([
            "Hora", "Métrica", "Antes", "Depois", "Valor", "Evidência", "Ação",
        ])
        self._configure_table(self.transitions_table, 210)
        transitions_layout.addWidget(self.transitions_table)
        layout.addWidget(transitions)

        self.samples_group = QGroupBox("Amostras técnicas")
        self.samples_group.setCheckable(True)
        self.samples_group.setChecked(False)
        samples_layout = QVBoxLayout(self.samples_group)
        filters = FlowRow()
        filters.addWidget(QLabel("Período:"))
        self.period_combo = QComboBox()
        self.period_combo.addItem("24 horas", 1)
        self.period_combo.addItem("7 dias", 7)
        self.period_combo.addItem("30 dias", 30)
        self.period_combo.addItem("Todo o histórico retido", None)
        self.period_combo.currentIndexChanged.connect(self.reset_and_refresh_samples)
        filters.addWidget(self.period_combo)
        filters.addWidget(QLabel("Métrica:"))
        self.metric_combo = QComboBox()
        self.metric_combo.addItem("Todas", None)
        for key in METRIC_KEYS:
            self.metric_combo.addItem(METRIC_RULES[key]["title"], key)
        self.metric_combo.currentIndexChanged.connect(self.reset_and_refresh_samples)
        filters.addWidget(self.metric_combo)
        self.samples_count_label = QLabel("0 amostras")
        filters.addWidget(self.samples_count_label)
        filters.addStretch()
        samples_layout.addLayout(filters)
        self.samples_table = QTableWidget(0, 6)
        self.samples_table.setHorizontalHeaderLabels([
            "Hora", "Métrica", "Valor", "Estado derivado", "Estado confirmado", "Fonte",
        ])
        self._configure_table(self.samples_table, 230)
        samples_layout.addWidget(self.samples_table)
        self.more_samples_button = QPushButton("Carregar mais")
        self.more_samples_button.setProperty("class", "MenuButton")
        self.more_samples_button.clicked.connect(self.load_more_samples)
        samples_layout.addWidget(self.more_samples_button)
        layout.addWidget(self.samples_group)
        layout.addStretch()

        # Contratos de leitura das versões anteriores permanecem disponíveis,
        # mas a coleta ativa não executa rede, DNS ou Internet nesta fase.
        self._legacy_container = QWidget(self)
        self._legacy_container.hide()
        for name in (
            "monitor_interface", "monitor_ipv4", "monitor_gateway",
            "monitor_latencia_gateway", "monitor_dns", "monitor_dns_validacao",
            "monitor_internet", "monitor_falhas", "monitor_ultima_atualizacao",
        ):
            setattr(self, name, QLabel("—", self._legacy_container))
        self.monitor_dns.setText("Não disponível")
        self.monitor_dns_validacao.setText("Não disponível")
        self._sync_controls("STOPPED")

    def _build_alerts(self, layout):
        alerts = self.host._card("Alertas")
        alerts_layout = QVBoxLayout(alerts)
        note = QLabel(
            "Alertas nascem somente de condições confirmadas. Reconhecer não resolve; "
            "somente retorno confirmado a NORMAL encerra o episódio."
        )
        note.setWordWrap(True)
        alerts_layout.addWidget(note)

        cards = []
        self.alert_summary_labels = {}
        for key, title in (
            ("open_count", "Abertos"),
            ("acknowledged_count", "Reconhecidos"),
            ("critical_active_count", "Críticos ativos"),
            ("resolved_recent_count", "Resolvidos — 24 h"),
        ):
            card = self.host._card(title)
            card_layout = QVBoxLayout(card)
            value = QLabel("0")
            value.setObjectName("ValorCard")
            card_layout.addWidget(value)
            self.alert_summary_labels[key] = value
            cards.append(card)
        alerts_layout.addWidget(ResponsiveGrid(cards, 220))

        filters = FlowRow()
        filters.addWidget(QLabel("Status:"))
        self.alert_status_combo = QComboBox()
        for title, value in (
            ("Todos", None), ("Abertos", "OPEN"),
            ("Reconhecidos", "ACKNOWLEDGED"), ("Resolvidos", "RESOLVED"),
        ):
            self.alert_status_combo.addItem(title, value)
        self.alert_status_combo.currentIndexChanged.connect(self.reset_and_refresh_alerts)
        filters.addWidget(self.alert_status_combo)
        filters.addWidget(QLabel("Severidade:"))
        self.alert_severity_combo = QComboBox()
        self.alert_severity_combo.addItem("Todas", None)
        self.alert_severity_combo.addItem("Crítico", "CRITICAL")
        self.alert_severity_combo.addItem("Atenção", "ATTENTION")
        self.alert_severity_combo.currentIndexChanged.connect(self.reset_and_refresh_alerts)
        filters.addWidget(self.alert_severity_combo)
        filters.addWidget(QLabel("Métrica:"))
        self.alert_metric_combo = QComboBox()
        self.alert_metric_combo.addItem("Todas", None)
        for key in METRIC_KEYS:
            self.alert_metric_combo.addItem(METRIC_RULES[key]["title"], key)
        self.alert_metric_combo.currentIndexChanged.connect(self.reset_and_refresh_alerts)
        filters.addWidget(self.alert_metric_combo)
        filters.addWidget(QLabel("Período:"))
        self.alert_period_combo = QComboBox()
        for title, hours in (
            ("Todos", None), ("1 hora", 1), ("6 horas", 6),
            ("24 horas", 24), ("7 dias", 168),
        ):
            self.alert_period_combo.addItem(title, hours)
        self.alert_period_combo.currentIndexChanged.connect(self.reset_and_refresh_alerts)
        filters.addWidget(self.alert_period_combo)
        self.alert_count_label = QLabel("0 alerta(s)")
        filters.addWidget(self.alert_count_label)
        filters.addStretch()
        alerts_layout.addLayout(filters)

        self.alerts_table = QTableWidget(0, 8)
        self.alerts_table.setHorizontalHeaderLabels([
            "Status", "Severidade", "Métrica", "Valor atual",
            "Primeiro visto", "Último visto", "Reconhecimento", "Ações",
        ])
        self._configure_table(self.alerts_table, 230)
        self.alerts_table.itemSelectionChanged.connect(self._alert_selection_changed)
        alerts_layout.addWidget(self.alerts_table)
        self.more_alerts_button = QPushButton("Carregar mais alertas")
        self.more_alerts_button.setProperty("class", "MenuButton")
        self.more_alerts_button.clicked.connect(self.load_more_alerts)
        alerts_layout.addWidget(self.more_alerts_button)
        layout.addWidget(alerts)

    def _build_trends(self, layout):
        trends = self.host._card("Tendências")
        trends_layout = QVBoxLayout(trends)
        note = QLabel(
            "Direção descritiva pela diferença entre as médias das duas metades do período. "
            "Tendência não é previsão nem diagnóstico."
        )
        note.setWordWrap(True)
        trends_layout.addWidget(note)
        controls = FlowRow()
        controls.addWidget(QLabel("Período:"))
        self.trend_period_combo = QComboBox()
        for key, title in (("1h", "1 hora"), ("6h", "6 horas"),
                           ("24h", "24 horas"), ("7d", "7 dias")):
            self.trend_period_combo.addItem(title, key)
        controls.addWidget(self.trend_period_combo)
        controls.addWidget(QLabel("Métrica:"))
        self.trend_metric_combo = QComboBox()
        for key in METRIC_KEYS:
            self.trend_metric_combo.addItem(METRIC_RULES[key]["title"], key)
        controls.addWidget(self.trend_metric_combo)
        self.trend_update_button = QPushButton("Atualizar tendência")
        self.trend_update_button.setProperty("class", "MenuButton")
        self.trend_update_button.clicked.connect(self.refresh)
        controls.addWidget(self.trend_update_button)
        controls.addStretch()
        trends_layout.addLayout(controls)
        self.trend_table = QTableWidget(0, 7)
        self.trend_table.setHorizontalHeaderLabels([
            "Atual", "Mínimo", "Máximo", "Média", "Amostras", "Direção", "Intervalo coberto",
        ])
        self._configure_table(self.trend_table, 100)
        trends_layout.addWidget(self.trend_table)
        self.trend_criterion_label = QLabel("Aguardando dados locais.")
        self.trend_criterion_label.setWordWrap(True)
        trends_layout.addWidget(self.trend_criterion_label)
        layout.addWidget(trends)

    def _build_alert_context(self, layout):
        self.alert_context_group = QGroupBox("Contexto relacionado")
        self.alert_context_group.setCheckable(True)
        self.alert_context_group.setChecked(True)
        context_layout = QVBoxLayout(self.alert_context_group)
        self.alert_context_note = QLabel(
            "Selecione um alerta. Relações são contexto do mesmo equipamento e não provam causalidade."
        )
        self.alert_context_note.setWordWrap(True)
        context_layout.addWidget(self.alert_context_note)
        self.alert_context_table = QTableWidget(0, 4)
        self.alert_context_table.setHorizontalHeaderLabels([
            "Relação", "Tipo", "Hora", "Resumo",
        ])
        self._configure_table(self.alert_context_table, 170)
        context_layout.addWidget(self.alert_context_table)
        layout.addWidget(self.alert_context_group)

    @staticmethod
    def _configure_table(table, minimum_height):
        table.setMinimumHeight(minimum_height)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setDefaultSectionSize(32)

    @staticmethod
    def _monitor_text(status):
        return {
            "STOPPED": "Parado", "RUNNING": "Executando",
            "PAUSED": "Pausado", "ERROR": "Erro",
        }.get(status, "Parado")

    def _sync_controls(self, status):
        self.status_label.setText(self._monitor_text(status))
        self.start_button.setEnabled(status == "STOPPED")
        self.pause_button.setEnabled(status in ("RUNNING", "PAUSED", "ERROR"))
        self.pause_button.setText("Retomar" if status == "PAUSED" else "Pausar")
        self.stop_button.setEnabled(status != "STOPPED")
        self.update_button.setEnabled(status in ("RUNNING", "ERROR"))
        self.host._monitoramento_ativo = status in ("RUNNING", "ERROR")

    def start(self):
        service = self.host._get_monitoring_service()
        if service is None:
            self._sync_controls("ERROR")
            self.info_label.setText("Não foi possível iniciar a persistência local do monitoramento.")
            return
        run = service.start(service.interval_seconds)
        if not run:
            return
        self.host._timer_monitoramento.setInterval(service.interval_seconds * 1000)
        self.host._timer_monitoramento.start()
        self._sync_controls(service.status)
        self.interval_label.setText(f"Intervalo: {service.interval_seconds} s")
        self.info_label.setText("Monitoramento local em execução; a primeira coleta foi solicitada.")
        self._set_next_cycle()
        self.request_collection()

    def pause_or_resume(self):
        service = self.host._get_monitoring_service()
        if service is None:
            return
        if service.status == "PAUSED":
            service.resume()
            self.host._timer_monitoramento.start(service.interval_seconds * 1000)
            self.info_label.setText("Monitoramento retomado.")
            self._set_next_cycle()
        else:
            service.pause()
            self.host._timer_monitoramento.stop()
            self._request_worker_interruption()
            self.info_label.setText("Monitoramento pausado; nenhuma nova coleta será iniciada.")
            self.next_cycle_label.setText("Próximo ciclo: pausado")
        self._sync_controls(service.status)
        self.refresh()

    def stop(self, reason="Solicitação do técnico"):
        service = self.host._get_monitoring_service()
        self.host._timer_monitoramento.stop()
        self._request_worker_interruption()
        if service is not None:
            service.stop(reason)
            self._sync_controls(service.status)
        else:
            self._sync_controls("STOPPED")
        self.info_label.setText("Monitoramento parado. O histórico persistente permanece disponível.")
        self.next_cycle_label.setText("Próximo ciclo: —")
        self.refresh()

    def _request_worker_interruption(self):
        worker = self.host._monitoramento_worker
        if worker is not None and worker in self.host._workers:
            try:
                worker.requestInterruption()
            except Exception:
                pass

    def change_interval(self, _index=None):
        seconds = int(self.interval_combo.currentData())
        self.interval_label.setText(f"Intervalo: {seconds} s")

    def open_interval_assist(self):
        service = self.host._get_monitoring_service()
        self.host._abrir_assist_contexto(
            "MONITORING_SETTINGS", "monitoring_configuration:1",
            monitoring_state=getattr(service, "status", "INDISPONÍVEL"),
            monitoring_run_id=getattr(service, "run_id", None),
        )

    def apply_transactional_interval(self, seconds):
        """Sincroniza widgets/timer após uma transação já validada."""
        seconds = int(seconds)
        self.interval_combo.blockSignals(True)
        try:
            self.interval_combo.setCurrentIndex(self.interval_combo.findData(seconds))
        finally:
            self.interval_combo.blockSignals(False)
        self.interval_label.setText(f"Intervalo: {seconds} s")
        service = self.host._monitoring_service
        if service is not None and service.status in ("RUNNING", "ERROR"):
            self.host._timer_monitoramento.start(seconds * 1000)
            self._set_next_cycle()

    def apply_transactional_retention(self, days):
        """Reflete a política validada; não executa purge ou coleta."""
        self.retention_label.setText(f"Retenção de amostras: {int(days)} dias.")

    def _set_next_cycle(self):
        seconds = int(self.interval_combo.currentData())
        next_cycle = datetime.now().astimezone() + timedelta(seconds=seconds)
        self.next_cycle_label.setText("Próximo ciclo: " + next_cycle.strftime("%d/%m/%Y %H:%M:%S"))

    def request_collection(self):
        service = self.host._get_monitoring_service()
        if service is None or service.status not in ("RUNNING", "ERROR"):
            return
        if self.host._monitoramento_coleta_em_andamento or self.host._operacao_ativa("monitoramento"):
            self.info_label.setText("Uma coleta já está em andamento; não foi iniciado ciclo paralelo.")
            return
        worker = self.host._run(
            service.collect_once,
            label="Coletando sinais locais de monitoramento",
            progress=None,
            on_done=self.present_result,
            operation_key="monitoramento",
            blocks_navigation=False,
            on_finally=self.collection_finished,
            silent_if_busy=True,
        )
        if worker:
            self.host._monitoramento_coleta_em_andamento = True
            self.host._monitoramento_worker = worker
            self.status_label.setText("Coletando")

    def collection_finished(self, state):
        self.host._monitoramento_coleta_em_andamento = False
        self.host._monitoramento_worker = None
        service = self.host._monitoring_service
        status = service.status if service else "STOPPED"
        self._sync_controls(status)
        if status in ("RUNNING", "ERROR") and self.host._timer_monitoramento.isActive():
            self._set_next_cycle()
        if state in ("failure", "error"):
            self.info_label.setText("Falha controlada; o próximo ciclo seguro poderá tentar novamente.")

    def present_result(self, result):
        if isinstance(result, tuple):
            self._present_legacy(result)
            return
        if not isinstance(result, dict):
            return
        if result.get("cancelled"):
            self.info_label.setText("Coleta cancelada de forma cooperativa.")
            return
        if not result.get("ok"):
            if result.get("skipped") == "overlap":
                self.info_label.setText("Ciclo ignorado para evitar sobreposição.")
            else:
                self.info_label.setText(
                    "Falha controlada na coleta; sinais sem evidência suficiente permanecem indeterminados."
                )
            self._sync_controls(result.get("status") or "ERROR")
            return
        cycle = result.get("cycle") or {}
        observed = cycle.get("observed_at_utc")
        if observed:
            self.last_cycle_label.setText("Último ciclo: " + format_local_timestamp(observed))
        for observation in cycle.get("observations") or []:
            self._present_observation(observation)
        self.info_label.setText(
            "Coleta concluída. Estados exibidos usam confirmação conservadora; um pico isolado não confirma piora."
        )
        self._sync_controls(result.get("status") or "RUNNING")
        self.refresh()

    def _present_observation(self, observation):
        key = observation.get("metric_key")
        if key not in self.metric_value_labels:
            return
        value = observation.get("value_num")
        unit = observation.get("unit") or "%"
        self.metric_value_labels[key].setText("—" if value is None else f"{float(value):.1f}{unit}")
        state = observation.get("confirmed_state") or "INDETERMINATE"
        self.metric_state_labels[key].setText(f"{state} — {STATE_TEXT.get(state, STATE_TEXT['INDETERMINATE'])}")

    def _load_payload(self, days, metric, sample_offset, alert_status,
                      alert_severity, alert_metric, alert_hours, alert_offset,
                      trend_period, trend_metric):
        store = self.host._get_monitoring_store()
        if store is None:
            return {"ok": False}
        hostname = socket.gethostname() or "Não disponível"
        since = datetime.now(timezone.utc) - timedelta(days=int(days)) if days else None
        alert_since = (
            datetime.now(timezone.utc) - timedelta(hours=int(alert_hours))
            if alert_hours else None
        )
        return {
            "ok": True,
            "states": store.list_metric_states(hostname=hostname),
            "transitions": store.list_transitions(hostname=hostname, limit=30),
            "alert_summary": store.alert_summary(hostname=hostname),
            "alerts": store.list_alerts(
                hostname=hostname, status=alert_status, severity=alert_severity,
                metric_key=alert_metric, since_utc=alert_since,
                limit=PAGE_SIZE, offset=alert_offset,
            ),
            "alert_total": store.count_alerts(
                hostname=hostname, status=alert_status, severity=alert_severity,
                metric_key=alert_metric, since_utc=alert_since,
            ),
            "alert_offset": alert_offset,
            "trend": store.trend_summary(
                hostname=hostname, metric_key=trend_metric, period=trend_period,
            ),
            "samples": store.list_observations(
                hostname=hostname, metric_key=metric, since_utc=since,
                limit=PAGE_SIZE, offset=sample_offset,
            ),
            "sample_total": store.count_observations(
                hostname=hostname, metric_key=metric, since_utc=since,
            ),
            "sample_offset": sample_offset,
        }

    def refresh(self):
        days = self.period_combo.currentData()
        metric = self.metric_combo.currentData()
        sample_offset = self._sample_offset
        alert_status = self.alert_status_combo.currentData()
        alert_severity = self.alert_severity_combo.currentData()
        alert_metric = self.alert_metric_combo.currentData()
        alert_hours = self.alert_period_combo.currentData()
        alert_offset = self._alert_offset
        trend_period = self.trend_period_combo.currentData()
        trend_metric = self.trend_metric_combo.currentData()
        self.host._run(
            self._load_payload, days, metric, sample_offset,
            alert_status, alert_severity, alert_metric, alert_hours,
            alert_offset, trend_period, trend_metric,
            label="Atualizando histórico de monitoramento",
            progress=None, on_done=self._present_payload,
            operation_key="monitoring_history", blocks_navigation=False,
            silent_if_busy=True,
        )

    def _present_payload(self, payload):
        if not isinstance(payload, dict) or not payload.get("ok"):
            return
        for state in payload.get("states") or []:
            key = state.get("metric_key")
            if key not in self.metric_value_labels:
                continue
            value = state.get("last_value")
            self.metric_value_labels[key].setText("—" if value is None else f"{float(value):.1f}%")
            current = state.get("current_state") or "INDETERMINATE"
            self.metric_state_labels[key].setText(
                f"{current} — {STATE_TEXT.get(current, STATE_TEXT['INDETERMINATE'])}"
            )
            try:
                since = format_local_timestamp(state.get("state_since_utc"))
            except Exception:
                since = "—"
            self.metric_since_labels[key].setText("Desde: " + since)
        for key, label in self.alert_summary_labels.items():
            label.setText(str((payload.get("alert_summary") or {}).get(key, 0)))
        self._fill_alerts(
            payload.get("alerts") or [], int(payload.get("alert_offset") or 0),
            int(payload.get("alert_total") or 0),
        )
        self._fill_trend(payload.get("trend") or {})
        self._fill_transitions(payload.get("transitions") or [])
        self._fill_samples(
            payload.get("samples") or [], int(payload.get("sample_offset") or 0),
            int(payload.get("sample_total") or 0),
        )

    @staticmethod
    def _shown_time(value):
        try:
            return format_local_timestamp(value)
        except Exception:
            return "—"

    @staticmethod
    def _shown_value(value, unit="%"):
        try:
            return f"{float(value):.1f}{unit}"
        except (TypeError, ValueError):
            return "—"

    def _fill_alerts(self, alerts, offset, total):
        table = self.alerts_table
        table.blockSignals(True)
        try:
            if offset == 0:
                table.setRowCount(0)
                self._alert_rows = []
            for alert in alerts:
                row = table.rowCount()
                table.insertRow(row)
                self._alert_rows.append(alert)
                recognition = "—"
                if alert.get("acknowledged_by"):
                    recognition = (
                        f"{alert['acknowledged_by']} — "
                        f"{self._shown_time(alert.get('acknowledged_at_utc'))}"
                    )
                values = (
                    alert.get("status") or "—",
                    alert.get("severity") or "—",
                    METRIC_RULES.get(alert.get("metric_key"), {}).get(
                        "title", alert.get("metric_key") or "—"
                    ),
                    self._shown_value(alert.get("current_value"), alert.get("unit") or "%"),
                    self._shown_time(alert.get("first_seen_utc")),
                    self._shown_time(alert.get("last_seen_utc")),
                    recognition,
                )
                for column, value in enumerate(values):
                    table.setItem(row, column, QTableWidgetItem(str(value)))
                actions = QWidget()
                actions_layout = QHBoxLayout(actions)
                actions_layout.setContentsMargins(0, 0, 0, 0)
                actions_layout.setSpacing(4)
                acknowledge = QPushButton("Reconhecer")
                acknowledge.setProperty("class", "MenuButton")
                acknowledge.setEnabled(alert.get("status") == "OPEN")
                acknowledge.clicked.connect(
                    lambda _checked=False, alert_id=alert.get("alert_id"):
                    self.acknowledge_alert(alert_id)
                )
                investigate = QPushButton("Investigar")
                investigate.setProperty("class", "MenuButton")
                investigate.clicked.connect(
                    lambda _checked=False, alert_id=alert.get("alert_id"):
                    self.host._criar_investigacao_alerta(alert_id)
                )
                assist = QPushButton("Assist")
                assist.setProperty("class", "MenuButton")
                assist.clicked.connect(
                    lambda _checked=False, alert_id=alert.get("alert_id"):
                    self.host._abrir_assist_contexto("ALERT", alert_id)
                )
                actions_layout.addWidget(acknowledge)
                actions_layout.addWidget(investigate)
                actions_layout.addWidget(assist)
                table.setCellWidget(row, 7, actions)
            if self._selected_alert_id:
                for row, alert in enumerate(self._alert_rows):
                    if alert.get("alert_id") == self._selected_alert_id:
                        table.selectRow(row)
                        break
        finally:
            table.blockSignals(False)
        self._alert_total = total
        self._alert_offset = offset + len(alerts)
        self.alert_count_label.setText(
            f"{total} alerta(s) — {self._alert_offset} carregado(s)"
        )
        self.more_alerts_button.setEnabled(self._alert_offset < total)

    def _fill_trend(self, trend):
        self.trend_table.setRowCount(0)
        if not trend:
            self.trend_criterion_label.setText("Tendência indisponível.")
            return
        self.trend_table.insertRow(0)
        unit = METRIC_RULES.get(trend.get("metric_key"), {}).get("unit", "%")
        first = self._shown_time(trend.get("first_observed_at"))
        last = self._shown_time(trend.get("last_observed_at"))
        values = (
            self._shown_value(trend.get("current"), unit),
            self._shown_value(trend.get("minimum"), unit),
            self._shown_value(trend.get("maximum"), unit),
            self._shown_value(trend.get("average"), unit),
            trend.get("sample_count", 0),
            trend.get("trend_direction") or "INSUFFICIENT_DATA",
            f"{first} → {last}" if first != "—" else "—",
        )
        for column, value in enumerate(values):
            self.trend_table.setItem(0, column, QTableWidgetItem(str(value)))
        self.trend_criterion_label.setText(str(trend.get("criterion") or ""))

    def focus_alert(self, alert_id):
        self._selected_alert_id = str(alert_id or "").strip()[:64] or None
        self._alert_offset = 0
        self.refresh()

    def acknowledge_alert(self, alert_id):
        if not alert_id:
            return
        self.host._run(
            lambda: self.host._get_monitoring_store().acknowledge_alert(alert_id),
            label="Reconhecendo alerta local", progress=None,
            on_done=self._alert_action_done,
            operation_key="monitoring_alert_action", blocks_navigation=False,
            silent_if_busy=True,
        )

    def _alert_action_done(self, result):
        if result:
            self.info_label.setText(
                "Alerta reconhecido. A condição permanece ativa até retorno confirmado a NORMAL."
            )
            self._alert_offset = 0
            self.refresh()

    def reset_and_refresh_alerts(self, _index=None):
        self._alert_offset = 0
        self.refresh()

    def load_more_alerts(self):
        self.refresh()

    def _alert_selection_changed(self):
        row = self.alerts_table.currentRow()
        if not 0 <= row < len(self._alert_rows):
            return
        self._selected_alert_id = self._alert_rows[row].get("alert_id")
        if self._selected_alert_id:
            self.host._run(
                lambda: self.host._get_monitoring_store().alert_context(
                    self._selected_alert_id, window_minutes=10, limit=50
                ),
                label="Carregando contexto do alerta", progress=None,
                on_done=self._fill_alert_context,
                operation_key="monitoring_alert_context", blocks_navigation=False,
                silent_if_busy=True,
            )

    def _fill_alert_context(self, context):
        if not isinstance(context, dict):
            return
        self.alert_context_note.setText(
            str(context.get("causality") or "Nenhuma causalidade foi inferida.")
        )
        self.alert_context_table.setRowCount(0)
        for item in context.get("items") or []:
            row = self.alert_context_table.rowCount()
            self.alert_context_table.insertRow(row)
            values = (
                item.get("relation") or "TEMPORAL_CONTEXT",
                item.get("item_type") or "—",
                self._shown_time(item.get("observed_at_utc")),
                item.get("summary") or "—",
            )
            for column, value in enumerate(values):
                self.alert_context_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _fill_transitions(self, transitions):
        self._transition_rows = list(transitions)
        self.transitions_table.setRowCount(0)
        for transition in transitions:
            row = self.transitions_table.rowCount()
            self.transitions_table.insertRow(row)
            try:
                shown_time = format_local_timestamp(transition["observed_at_utc"])
            except Exception:
                shown_time = "—"
            key = transition.get("metric_key")
            value = transition.get("value_num")
            values = (
                shown_time, METRIC_RULES.get(key, {}).get("title", key or "—"),
                transition.get("previous_confirmed_state") or "—",
                transition.get("confirmed_state") or "—",
                "—" if value is None else f"{float(value):.1f}{transition.get('unit') or '%'}",
                f"{transition.get('debounce_count') or 0} amostra(s) de confirmação",
            )
            for column, value_text in enumerate(values):
                self.transitions_table.setItem(row, column, QTableWidgetItem(str(value_text)))
            button = QPushButton("Abrir investigação")
            button.setProperty("class", "MenuButton")
            enabled = bool(
                transition.get("transition_event_id")
                and transition.get("confirmed_state") in ("ATTENTION", "CRITICAL")
            )
            button.setEnabled(enabled)
            button.setToolTip(
                "Cria ou reabre uma sessão usando o evento da Timeline como evidência inicial."
                if enabled else "Disponível para transições de atenção/crítico persistidas na Timeline."
            )
            button.clicked.connect(
                lambda _checked=False, observation_id=transition.get("observation_id"):
                self.host._criar_investigacao_monitoramento(observation_id)
            )
            self.transitions_table.setCellWidget(row, 6, button)

    def _fill_samples(self, samples, offset, total):
        if offset == 0:
            self.samples_table.setRowCount(0)
        for observation in samples:
            row = self.samples_table.rowCount()
            self.samples_table.insertRow(row)
            try:
                shown_time = format_local_timestamp(observation["observed_at_utc"])
            except Exception:
                shown_time = "—"
            key = observation.get("metric_key")
            value = observation.get("value_num")
            values = (
                shown_time, METRIC_RULES.get(key, {}).get("title", key or "—"),
                "—" if value is None else f"{float(value):.1f}{observation.get('unit') or '%'}",
                observation.get("derived_state") or "INDETERMINATE",
                observation.get("confirmed_state") or "INDETERMINATE",
                observation.get("source") or "—",
            )
            for column, value_text in enumerate(values):
                self.samples_table.setItem(row, column, QTableWidgetItem(str(value_text)))
        self._sample_total = total
        self._sample_offset = offset + len(samples)
        self.samples_count_label.setText(f"{total} amostra(s) — {self._sample_offset} carregada(s)")
        self.more_samples_button.setEnabled(self._sample_offset < total)

    def reset_and_refresh_samples(self, _index=None):
        self._sample_offset = 0
        self.refresh()

    def load_more_samples(self):
        self.refresh()

    @staticmethod
    def _result_text(value, positive="OK", negative="Falha"):
        if value is True:
            return positive
        if value is False:
            return negative
        return "—"

    @staticmethod
    def _latency_text(value):
        return f"{value} ms" if isinstance(value, (int, float)) else "—"

    def _present_legacy(self, result):
        """Mantém apenas contratos de apresentação; a coleta ativa não usa rede."""
        ok, data, message = result if len(result) == 3 else (False, {}, "")
        data = data if isinstance(data, dict) else {}
        status = str(data.get("Status") or "Offline")
        self.status_label.setText(status)
        self.info_label.setText(("Atualizado" if ok else "Falha controlada") + ": " + str(message or "Sem detalhes."))
        self.monitor_interface.setText(str(data.get("Interface") or "—"))
        self.monitor_ipv4.setText(str(data.get("IPv4") or "—"))
        gateway = str(data.get("Gateway") or "—")
        gateway_status = self._result_text(data.get("GatewayOk"), "OK", "sem resposta")
        self.monitor_gateway.setText(gateway if gateway_status == "—" else f"{gateway} ({gateway_status})")
        self.monitor_latencia_gateway.setText(self._latency_text(data.get("GatewayLatencia_ms")))
        servers = data.get("DNS") or []
        if isinstance(servers, str):
            servers = [servers]
        dns = "\n".join(dict.fromkeys(str(item) for item in servers if str(item).strip())) or "Não disponível"
        dns_status = self._result_text(data.get("DNSOk"), "OK", "falha")
        self.monitor_dns.setText(dns)
        self.monitor_dns_validacao.setText(
            "Falha" if dns_status == "falha" else dns_status if dns_status != "—" else "Não disponível"
        )
        internet_status = self._result_text(data.get("InternetOk"), "Online", "indisponível")
        internet_latency = self._latency_text(data.get("InternetLatencia_ms"))
        self.monitor_internet.setText(
            internet_status if internet_latency == "—" else f"{internet_status} ({internet_latency})"
        )
        self.monitor_falhas.setText("0" if status == "Online" else "1")
        timestamp = str(data.get("AtualizadoEm") or "—")
        self.monitor_ultima_atualizacao.setText(local_timestamp(timestamp)[0])
        self.monitor_ultima_atualizacao.setToolTip(local_timestamp(timestamp)[1])
        for key, legacy_key in (
            ("cpu_usage", "CPU"), ("memory_usage", "RAM"), ("system_disk_free", "DISCO"),
        ):
            value = data.get(legacy_key)
            self.metric_value_labels[key].setText("—" if value is None else f"{float(value):.1f}%")
