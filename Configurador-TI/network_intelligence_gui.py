from operational_ui import local_timestamp, RawDataSection, ConsolidatedSections
from hostname_identification import identification
from html import escape
"""Apresentação Network Intelligence dentro do Inventário, sem nova página."""
from PyQt6.QtCore import Qt, QTimer, QEvent
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QHeaderView, QTextEdit, QMenu, QInputDialog, QApplication, QTabWidget)
from network_intelligence import (NetworkEngine, STATES, clean, consolidate,
                                  technical_summary, age_days)


from ui_components import FlowRow, UxTable, section, network_detail_html
QTableWidget = UxTable


class NetworkPanel(QWidget):
    def __init__(self, host, core):
        super().__init__(host)
        self.host = host
        self.engine = NetworkEngine(core.PASTA_REDE, core.executar_powershell, core.logger, core.ARQUIVO_INVENTARIO)
        self.result = {}
        self.records = {}
        self.rows = {}
        self.search_cache = {}
        self.interface_key = None
        layout = QVBoxLayout(self)
        title = QLabel("Configurador TI Network Intelligence")
        title.setObjectName("TituloSecao")
        layout.addWidget(title)
        label = QLabel("Identifique a rede/cliente de forma exclusiva. Não reutilize o mesmo identificador entre clientes. Falta de resposta não significa IP livre.")
        label.setWordWrap(True)
        layout.addWidget(label)
        bar = FlowRow()
        self.site = QLineEdit()
        self.site.setMaxLength(100)
        self.site.setPlaceholderText("Rede/cliente — exemplo: Empresa A / matriz / LAN")
        self.site.textEdited.connect(self.clear_context)
        bar.addWidget(self.site, 1)
        self.history = QPushButton("Carregar histórico desta rede")
        self.history.clicked.connect(lambda: self.start(history_only=True))
        bar.addWidget(self.history)
        layout.addLayout(bar)
        bar = FlowRow()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar IP, MAC, hostname, tipo ou observação")
        self.filter = QComboBox()
        self.filter.addItems(["Todos", *STATES, "Possível conflito", "Vistos hoje", "Vistos recentemente", "Sem hostname", "Impressoras", "Com alerta", "Identificação divergente"])
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(275)
        self.timer.timeout.connect(self.apply_filter)
        self.search.textChanged.connect(lambda: self.timer.start())
        self.filter.currentTextChanged.connect(self.apply_filter)
        self.reset_filters = QPushButton("Limpar filtros")
        self.reset_filters.clicked.connect(self.clear_filters)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.filter)
        bar.addWidget(self.reset_filters)
        layout.addLayout(bar)
        bar = FlowRow()
        self.verify = QPushButton("Verificar este IP antes de usar")
        self.verify.clicked.connect(self.verify_selected)
        self.reserve = QPushButton("Reservar / editar reserva local")
        self.reserve.clicked.connect(lambda: self.local_action("reserve"))
        self.copy = QPushButton("Copiar resumo técnico")
        self.copy.clicked.connect(self.copy_summary)
        self.cancel = QPushButton("Cancelar coleta")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.cancel_scan)
        for widget in (self.verify, self.reserve, self.copy, self.cancel):
            bar.addWidget(widget)
        layout.addLayout(bar)
        self.status = QLabel("Informe a rede e use Varredura detalhada /24 ou carregue o histórico.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setObjectName("ResultBanner")
        layout.addWidget(self.status)
        self.summary = QLabel("Nenhuma varredura carregada.")
        self.summary.setObjectName("ScanSummary")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.summary)
        self.matches = QLabel("Correspondências: 0")
        layout.addWidget(self.matches)
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(["IP", "Estado", "Confiança", "MAC atual/último", "Hostname atual/último", "Tipo", "Último visto", "Fontes", "Reserva local", "Alerta"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.setWordWrap(False)
        self.table.setMinimumHeight(290)
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for index, width in enumerate((115, 230, 90, 155, 190, 160, 190, 170, 180, 230)):
            self.table.setColumnWidth(index, width)
        self.table.itemSelectionChanged.connect(self.details)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.menu)
        layout.addWidget(section("IPs — evidências e estado operacional", self.table), 1)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMinimumHeight(190)
        self.detail.setMinimumHeight(310)
        self.raw_section = RawDataSection("Dados brutos / resumo completo", "IP selecionado", "Network Intelligence")
        self.raw_detail = self.raw_section.editor
        self.detail_tabs = ConsolidatedSections()
        self.detail_tabs.addTab(self.detail, "Leitura técnica")
        self.detail_tabs.addTab(self.raw_section, "Dados brutos / resumo completo")
        self.detail_tabs.setMinimumHeight(370)
        layout.addWidget(section("Detalhe do IP selecionado", self.detail_tabs))
        self.device_context = QLabel("Nenhum IP selecionado.")
        self.device_context.setWordWrap(True)
        self.device_context.setTextFormat(Qt.TextFormat.PlainText)
        self.device_context.setObjectName("ContextHeader")
        self.view_mode = QComboBox()
        self.view_mode.addItems(["Operacional", "Técnica"])
        self.view_mode.setAccessibleName("Visão da tabela de IPs")
        self.view_mode.currentIndexChanged.connect(self.apply_view)
        layout.insertWidget(layout.count()-3, self.view_mode)
        self._column_layouts = {}
        self._last_view_mode = None
        self._sizing_columns = False
        self._manual_operational_width = False
        self.apply_view()
        self.table.horizontalHeader().sectionResized.connect(self._remember_width)
        self.table.viewport().installEventFilter(self)
        self.details()

    def apply_view(self, *_):
        self._sizing_columns = True
        technical = self.view_mode.currentIndex() == 1
        mode = int(technical)
        header = self.table.horizontalHeader()
        vertical = self.table.verticalScrollBar().value()
        if self._last_view_mode is not None:
            self._column_layouts[self._last_view_mode] = [self.table.columnWidth(c) for c in range(10)]
        for col in (3, 7, 8):
            self.table.setColumnHidden(col, not technical)
        for col in range(10):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        header.setMinimumSectionSize(60)
        defaults = [110, 170, 88, 155, 210, 112, 128, 170, 180, 95] if not technical else [115, 230, 95, 155, 220, 160, 150, 170, 180, 230]
        widths = self._column_layouts.get(mode, defaults)
        for col, width in enumerate(widths):
            if not self.table.isColumnHidden(col):
                self.table.setColumnWidth(col, width or defaults[col])
        order = list(range(10)) if technical else [0, 4, 1, 5, 2, 6, 9, 3, 7, 8]
        for visual, logical in enumerate(order):
            header.moveSection(header.visualIndex(logical), visual)
        self.table.horizontalHeaderItem(6).setText("Último online")
        self.table.horizontalHeaderItem(4).setText("Hostname / identificação")
        self.table.verticalScrollBar().setValue(vertical)
        self._last_view_mode = mode
        self._sizing_columns = False
        self._fit_operational_columns()

    def _remember_width(self, logical, old, new):
        if not self._sizing_columns and self.view_mode.currentIndex() == 0:
            self._manual_operational_width = True

    def _fit_operational_columns(self):
        if self._sizing_columns or self.view_mode.currentIndex() != 0 or self._manual_operational_width:
            return
        # Distribuição aritmética por viewport, sem inspeção do conteúdo das células.
        widths = {0: 110, 4: 210, 1: 170, 5: 112, 2: 88, 6: 128, 9: 95}
        spare = max(0, self.table.viewport().width() - sum(widths.values()))
        state_extra = min(80, spare);widths[1] += state_extra;spare -= state_extra
        type_extra = min(38, spare);widths[5] += type_extra;spare -= type_extra
        widths[4] += spare
        self._sizing_columns = True
        try:
            for col, width in widths.items():
                if self.table.columnWidth(col) != width:
                    self.table.setColumnWidth(col, width)
        finally:
            self._sizing_columns = False

    def eventFilter(self, watched, event):
        if watched is self.table.viewport() and event.type() == QEvent.Type.Resize:
            self._fit_operational_columns()
        return super().eventFilter(watched, event)

    @staticmethod
    def display_name(record):
        name, alert, values = identification(record)
        if name == "Não identificado":
            return "Hostname não identificado"
        # O backend preserva nomes antigos; não os apresentar como consulta atual.
        checked = record.get("identification_checked")
        current = any(v.get("observed_at") == checked for v in values) if checked else any(e.get("hostname") for e in record.get("evidence", []))
        return name if current else "Último nome conhecido: " + name

    def clear_context(self, *_):
        self.result, self.records, self.rows, self.search_cache = {}, {}, {}, {}
        self.table.setRowCount(0)
        self.summary.setText("Nenhuma varredura carregada neste contexto.")
        self.matches.setText("Correspondências: 0")
        self.status.setText("Contexto alterado. Carregue o histórico ou execute nova varredura.")
        self.details()
        self.host._limpar_ips_disponiveis()

    def interface_changed(self, interface):
        key = tuple(interface.get(k) for k in ("InterfaceIndex", "IPv4", "Rede", "Gateway")) if interface else None
        if key != self.interface_key:
            self.interface_key = key
            self.clear_context()

    def start(self, focused_ip=None, history_only=False):
        if self.host._operacao_ativa("inventario_rede") or self.host._closing:
            return
        interface = self.host._interface_scan_selecionada
        if not interface or not clean(self.site.text(), 100):
            self.status.setText("Selecione uma interface ativa e informe a identificação exclusiva da rede/cliente.")
            return
        worker = self.host._run(self.engine.run, dict(interface), clean(self.site.text(), 100),
            focused_ip=focused_ip, history_only=history_only,
            operation_key="inventario_rede", blocks_navigation=False,
            label="Network Intelligence — histórico" if history_only else "Network Intelligence — verificação",
            progress=self.host.progress_inventario, indeterminate=False,
            on_done=self.receive, on_finally=self.finished)
        if worker:
            self.host._definir_estado_scan_inventario(True, "Network Intelligence em background; navegação disponível.")
            self.site.setEnabled(False)
            self.history.setEnabled(False)
            self.cancel.setEnabled(True)
            self.verify.setEnabled(False)
            self.reserve.setEnabled(False)
            self.status.setText("Carregando histórico..." if history_only else "Verificando evidências e histórico... Não atribua um IP durante a coleta.")

    def cancel_scan(self):
        worker = self.host._operation_workers.get("inventario_rede")
        if worker:
            worker.requestInterruption()
            self.cancel.setEnabled(False)
            self.status.setText("Cancelamento solicitado; aguardando consultas com timeout.")

    def finished(self, state):
        message = {"success": "Network Intelligence concluída. Consulte os resultados e evidências abaixo.",
                   "cancelled": "Network Intelligence cancelada; os resultados anteriores foram preservados.",
                   "failure": "Falha na Network Intelligence. Consulte o status e os detalhes do erro.",
                   "error": "Falha na Network Intelligence. Consulte o status e os detalhes do erro."}.get(state, "Operação encerrada. Consulte o status abaixo.")
        self.host._definir_estado_scan_inventario(False, message)
        self.site.setEnabled(True)
        self.history.setEnabled(True)
        self.cancel.setEnabled(False)
        if state == "cancelled":
            self.status.setText("Cancelado. Os resultados anteriores conservam seus timestamps.")
        elif state in ("failure", "error"):
            self.status.setText("Falha na operação. Os resultados anteriores conservam seus timestamps. Consulte os detalhes do erro e o log.")
        self.details()

    def receive(self, result):
        if not isinstance(result, dict) or result.get("Sucesso") is not True:
            self.status.setText(clean(result.get("message") if isinstance(result, dict) else result))
            return
        old_ip = self.selected_ip()
        same = self.result.get("scope") == result["scope"]
        if not result.get("focused") or not same:
            self.records = {}
        for record in result["records"]:
            self.records[record["ip"]] = record
        self.result = result
        self.status.setText(result["message"] + " | Escopo: " + result["scope"][:12])
        # Uma materialização por resultado; filtros apenas hide/show.
        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        try:
            self.table.setRowCount(len(self.records))
            self.rows = {}
            for row, (ip, record) in enumerate(sorted(self.records.items(), key=lambda kv: tuple(map(int, kv[0].split('.'))))):
                self.rows[ip] = row
                self.fill_row(row, record)
        finally:
            self.table.blockSignals(False)
            self.table.setUpdatesEnabled(True)
        self.apply_filter()
        if old_ip in self.rows and not self.table.isRowHidden(self.rows[old_ip]):
            self.table.selectRow(self.rows[old_ip])
        self.details()
        self.host._preencher_hosts([{"IP": r["ip"], "Nome": r.get("hostname", ""), "MAC": r.get("mac", ""),
            "Tipo": r.get("type", ""), "Estado": r["state"], "Servicos": ", ".join(map(str, r.get("ports", [])))}
            for r in self.records.values() if r["state"] == "Em uso agora"])
        self.host._carregar_ips_disponiveis_da_varredura()

    def fill_row(self, row, record):
        reservation = record.get("active_reservation") or {}
        values = [record["ip"], record["state"], record["confidence"], record.get("mac", ""),
                  self.display_name(record), record.get("type", ""), record.get("last_online", ""),
                  ", ".join(dict.fromkeys(e["provider"] for e in record.get("evidence", []) if e.get("responded") or e.get("mac") or e.get("hostname"))),
                  reservation.get("description", ""), " • ".join(filter(None,(record.get("identity_alert", ""),identification(record)[1])))]
        self.search_cache[record["ip"]] = " ".join(clean(v, 1000) for v in [*values, record.get("note"), record.get("manufacturer"), *record.get("macs", []), *record.get("hostnames", []), *[v.get("name", "") for v in record.get("identifications", [])], record.get("alias"), record.get("sector")]).casefold()
        for col, value in enumerate(values):
            item = QTableWidgetItem(clean(value, 500) or "—")
            item.setToolTip(clean(value, 1000) or "Não disponível")
            if col == 6:
                shown, full = local_timestamp(value)
                if not value:
                    shown = "Não registrado"
                item.setText(shown)
                item.setToolTip(("Último online: evidência ativa. " + full) if value else "Sem evidência ativa registrada. Último visto (qualquer evidência): " + local_timestamp(record.get("last_seen"))[1])
            if col == 9 and value:
                item.setText("Ver alerta")
            item.setData(Qt.ItemDataRole.UserRole, record["ip"])
            self.table.setItem(row, col, item)

    def apply_filter(self, *_):
        if self.host._closing:
            return
        self.timer.stop()
        query, state = clean(self.search.text()).casefold(), self.filter.currentText()
        previous = self.selected_ip()
        visible = []
        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        try:
            for ip, row in self.rows.items():
                record = consolidate(self.records[ip], history_ok=self.result.get("history_ok", False))
                self.records[ip] = record
                # Reavalia validade/recência sem timer de reserva, sem recriar células.
                for col, text in ((1, record["state"]), (2, record["confidence"]), (8, (record.get("active_reservation") or {}).get("description", "") or "—")):
                    cell = self.table.item(row, col)
                    if cell is not None and cell.text() != text:
                        cell.setText(clean(text, 500))
                        cell.setToolTip(clean(text, 1000))
                match = (state == "Todos" or state == record["state"]
                    or state == "Possível conflito" and bool(record.get("identity_alert"))
                    or state == "Sem hostname" and identification(record)[0] == "Não identificado"
                    or state == "Impressoras" and record.get("type", "").startswith("Impressora")
                    or state == "Com alerta" and bool(record.get("identity_alert") or identification(record)[1])
                    or state == "Identificação divergente" and bool(identification(record)[1])
                    or state == "Vistos hoje" and self.seen_today(record.get("last_seen"))
                    or state == "Vistos recentemente" and age_days(record.get("last_seen")) <= 30)
                shown = bool(match and query in self.search_cache[ip])
                if self.table.isRowHidden(row) == shown:
                    self.table.setRowHidden(row, not shown)
                if shown:
                    visible.append(ip)
            selected = previous if previous in visible else visible[0] if visible else None
            if selected:
                row = self.rows[selected]
                self.table.setCurrentCell(row, 0)
                self.table.selectRow(row)
            else:
                self.table.clearSelection()
                self.table.setCurrentCell(-1, -1)
        finally:
            self.table.blockSignals(False)
            self.table.setUpdatesEnabled(True)
        from collections import Counter
        counts = Counter(r["state"] for r in self.records.values())
        self.summary.setText("Total: " + str(len(self.records)) + "  •  " +
            "  •  ".join(state + ": " + str(counts[state]) for state in STATES) +
            "  •  Possível conflito: " + str(sum(bool(r.get("identity_alert")) for r in self.records.values())))
        self.matches.setText(f"Correspondências: {len(visible)} de {len(self.records)}" +
                             (" • Filtros ativos" if query or state != "Todos" else ""))
        self.details()

    def clear_filters(self):
        self.search.clear()
        self.filter.setCurrentIndex(0)
        self.apply_filter()

    @staticmethod
    def seen_today(stamp):
        from datetime import datetime
        try:
            return datetime.fromisoformat(stamp).astimezone().date() == datetime.now().astimezone().date()
        except (ValueError, TypeError):
            return False

    def selected_ip(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item and not self.table.isRowHidden(row) else None

    def details(self):
        ip = self.selected_ip()
        record = self.records.get(ip)
        busy = self.host._operacao_ativa("inventario_rede")
        self.verify.setEnabled(bool(record) and not busy)
        self.reserve.setEnabled(bool(record) and bool(self.result.get("history_ok")) and not busy)
        self.copy.setEnabled(bool(record))
        if record:
            shown = consolidate(record, history_ok=self.result.get("history_ok", False))
            context, unavailable = self.result.get("context", {}), self.result.get("unavailable", [])
            name, alert, identities = identification(shown)
            if hasattr(self,"device_context"):
                self.device_context.setText(f"{ip}  |  {self.display_name(shown)}  |  {shown['state']}  |  Confiança: {shown['confidence']}  |  {shown['type']}  |  Último online: {local_timestamp(shown.get('last_online'))[0] if shown.get('last_online') else 'Não registrado'}")
                self.device_context.setToolTip(local_timestamp(shown.get("last_online"))[1])
            self.raw_section.set_metadata(ip + " • " + self.display_name(shown), "Network Intelligence • evidências existentes", shown.get("checked"))
            html = network_detail_html(shown, context, unavailable, clean)
            extra = "<h3>Identificação adicional — não é confiança de disponibilidade</h3>"
            extra += "<p>NetBIOS: "+escape(clean(shown.get("identification_status") or "Não consultado"))+". Identificação não autenticada.</p>"
            if alert:extra += "<p>"+escape(alert)+"</p>"
            for value in identities:
                when,full=local_timestamp(value.get("observed_at"))
                extra += "<p>"+escape(clean(value.get("name")))+" • Fonte: "+escape(clean(value.get("source")))+" • Confiança da identificação: "+escape(clean(value.get("confidence")))+" • "+"<span title=\""+escape(full,quote=True)+"\">"+escape(when)+"</span></p>"
            self.detail.setHtml(html.replace("</body>",extra+"</body>"))
            self.raw_detail.setPlainText(technical_summary(shown, context, unavailable))
        else:
            message = ("Nenhum IP corresponde aos filtros atuais. Limpe ou ajuste os filtros."
                       if self.records else "Nenhuma varredura carregada. Selecione a interface e inicie a coleta ou carregue o histórico.")
            if hasattr(self,"device_context"):self.device_context.setText("Nenhum IP selecionado.")
            self.detail.setPlainText(message)
            self.raw_section.set_metadata("Nenhum IP selecionado", "Network Intelligence")
            self.raw_detail.setPlainText(message)

    def verify_selected(self):
        ip = self.selected_ip()
        if ip:
            self.start(focused_ip=ip)

    def copy_summary(self):
        self.details()
        if self.selected_ip():
            QApplication.clipboard().setText(self.raw_detail.toPlainText())
            self.status.setText("Resumo técnico completo copiado.")

    def local_action(self, action):
        ip = self.selected_ip()
        if not ip or not self.result.get("history_ok") or self.host._operacao_ativa("inventario_rede"):
            return
        record = self.records[ip]
        text, hours = "", 0
        if action != "remove":
            title = {"reserve": "Reserva Configurador TI local — não altera DHCP", "note": "Observação técnica — sem credenciais", "replacement": "Confirmar substituição/reutilização — preservar evidências"}[action]
            initial = (record.get("active_reservation") or {}).get("description", "") if action == "reserve" else record.get("note", "")
            text, ok = QInputDialog.getText(self, title, "Descrição (não inclua segredos):", text=initial)
            if not ok or not clean(text):
                return
        if action == "reserve":
            options = {"Sem expiração": 0, "1 hora": 1, "4 horas": 4, "1 dia": 24, "7 dias": 168}
            expiry, ok = QInputDialog.getItem(self, "Validade da reserva local", "Expira em:", list(options), editable=False)
            if not ok:
                return
            hours = options[expiry]
        worker = self.host._run(self.engine.edit, self.result["scope"], ip, action, text, hours,
            operation_key="inventario_rede", blocks_navigation=False, label="Registrando ação local de rede",
            on_done=self.edited, on_finally=self.finished)
        if worker:
            self.host._definir_estado_scan_inventario(True)
            self.site.setEnabled(False)
            self.history.setEnabled(False)
            self.details()

    def edited(self, record):
        ip = record["ip"]
        if ip in self.rows:
            self.records[ip] = record
            self.fill_row(self.rows[ip], record)
            self.apply_filter()
            self.host._carregar_ips_disponiveis_da_varredura()
            self.status.setText("Registro local salvo. Nenhuma alteração realizada no DHCP ou no dispositivo.")

    def menu(self, position):
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        ip = self.selected_ip()
        if not ip:
            return
        menu = QMenu(self)
        menu.addAction("Verificar este IP antes de usar", self.verify_selected)
        for label, action in (("Reservar / editar descrição", "reserve"), ("Remover reserva local", "remove"), ("Editar observação", "note"), ("Confirmar substituição/reutilização", "replacement")):
            item = menu.addAction(label, lambda _checked=False, a=action: self.local_action(a))
            item.setEnabled(bool(self.result.get("history_ok")) and (action != "replacement" or bool(self.records[ip].get("identity_alert"))))
        menu.addSeparator()
        for label, key in (("Copiar IP", "ip"), ("Copiar MAC", "mac"), ("Copiar hostname", "hostname")):
            menu.addAction(label, lambda _checked=False, k=key: QApplication.clipboard().setText(clean(self.records[ip].get(k))))
        menu.addAction("Copiar detalhes / resumo técnico", self.copy_summary)
        menu.addAction("Ver histórico", lambda: self.detail.setFocus())
        menu.exec(self.table.viewport().mapToGlobal(position))
