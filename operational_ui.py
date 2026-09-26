"""Apresentação operacional; não consulta hardware, rede ou disco."""
from datetime import datetime, timedelta
from html import escape
import re
import json
from PyQt6.QtWidgets import QTextEdit, QTabWidget, QWidget, QVBoxLayout, QPushButton, QApplication, QScrollArea, QGroupBox, QFormLayout, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QGridLayout, QSizePolicy, QFrame, QProgressBar
from PyQt6.QtGui import QFontDatabase


def local_timestamp(value, now=None):
    """Não presume UTC para valores sem timezone; original fica no tooltip/raw."""
    if not value:
        return "—", "Não disponível"
    raw = str(value)
    try:
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            stamp = datetime.strptime(raw, "%d/%m/%Y %H:%M:%S")
        local = stamp.astimezone()
        today = (now or datetime.now().astimezone()).astimezone().date()
        prefix = "Hoje" if local.date() == today else "Ontem" if local.date() == today - timedelta(days=1) else local.strftime("%d/%m/%Y")
        note = " (origem sem timezone; interpretada como horário local)" if stamp.tzinfo is None else ""
        return prefix + ", " + local.strftime("%H:%M"), local.strftime("%d/%m/%Y %H:%M:%S %Z %z") + note + " | Original: " + raw
    except (ValueError, TypeError, OverflowError, OSError):
        return raw, "Formato original: " + raw


def structured_html(text):
    """Reorganiza rótulos existentes, sem interpretar saúde ou produzir diagnóstico."""
    rows=[]
    for line in str(text).splitlines():
        line=line.strip()
        if not line or all(ch in "═─=-_ " for ch in line):
            continue
        line=re.sub(r"[█░]+", "", line)
        if ":" in line and not line.startswith("["):
            key,value=line.split(":",1)
            if not value.strip():
                rows.append("<tr><td colspan='2'><h3>"+escape(key)+"</h3></td></tr>")
            else:
                shown,tooltip=local_timestamp(value.strip()) if re.match(r"^(\d{4}-\d{2}-\d{2}[T ]|\d{2}/\d{2}/\d{4} )",value.strip()) else (value.strip(),value.strip())
                rows.append("<tr><td valign='top' width='30%'><b>"+escape(key)+"</b></td><td title='"+escape(tooltip,quote=True)+"'>"+escape(shown)+"</td></tr>")
        else:
            rows.append("<tr><td colspan='2'>"+escape(line)+"</td></tr>")
    return "<table width='100%' cellspacing='8'>"+"".join(rows)+"</table>"


class StructuredReadout(QTextEdit):
    """Conserva o texto integral/copiável e permite raw via menu de contexto."""
    def __init__(self, *args):
        super().__init__(*args)
        self._raw=""
        self._raw_mode=False
        self.setReadOnly(True)
    def setPlainText(self, text):
        self._raw=str(text)
        if self._raw_mode:
            super().setPlainText(self._raw)
        else:
            super().setHtml(structured_html(self._raw))
    def toPlainText(self):
        return self._raw
    def contextMenuEvent(self,event):
        menu=self.createStandardContextMenu()
        action=menu.addAction("Leitura estruturada" if self._raw_mode else "Ver dados brutos completos")
        chosen=menu.exec(event.globalPos())
        if chosen==action:
            self._raw_mode=not self._raw_mode
            self.setPlainText(self._raw)


class DiagnosticPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout=QVBoxLayout(self)
        self.status=QLabel("Nenhum diagnóstico completo executado. Use Diagnóstico completo acima.")
        self.status.setWordWrap(True);layout.addWidget(self.status)
        self.tabs=ConsolidatedSections();layout.addWidget(self.tabs)
        self.views={}
        for title in ("Resumo","Hardware","Rede","Armazenamento","Detalhes técnicos","Texto técnico"):
            view=QTextEdit() if title=="Texto técnico" else ReadoutPanel(include_raw=False)
            view.setReadOnly(True);self.views[title]=view
            if title=="Texto técnico":
                view.setObjectName("ConsoleVisual");view.setMinimumHeight(220)
                view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
            if title == "Texto técnico":
                body = QWidget();raw_layout = QVBoxLayout(body)
                raw_layout.addWidget(plain_label("Diagnóstico completo • Fonte: coleta original do sistema • Horário da coleta não informado"))
                raw_layout.addWidget(view)
                self.tabs.addTab(body,"Dados brutos")
            else:
                self.tabs.addTab(view,"Resumo operacional" if title=="Resumo" else title)
        self.copy=QPushButton("Copiar diagnóstico completo")
        self.copy.clicked.connect(self.copy_text);layout.insertWidget(1,self.copy)
        self.tabs.hide();self.copy.setEnabled(False)
    def copy_text(self):
        QApplication.clipboard().setText(self.views["Texto técnico"].toPlainText())
        self.copy.setText("Diagnóstico copiado")
    def show_result(self,text,network_text=""):
        self.tabs.show();self.copy.setEnabled(True);self.copy.setText("Copiar diagnóstico completo")
        raw=str(text);self.views["Texto técnico"].setPlainText(raw)
        self.views["Detalhes técnicos"].setPlainText(raw)
        groups={"Resumo":[],"Hardware":[],"Armazenamento":[]};section="Hardware"
        for line in raw.splitlines():
            if line.strip() in ("Armazenamento Físico:","Volumes / Partições:"):
                section="Armazenamento"
            groups[section].append(line)
            if any(line.strip().startswith(k) for k in ("Computador:","Sistema Operacional:","Processador:","Total:")):
                groups["Resumo"].append(line)
        for name,lines in groups.items():self.views[name].setPlainText("\n".join(lines) or raw)
        self.views["Rede"].setPlainText(("Última consulta independente de Rede & DNS (não recoletada pelo diagnóstico):\n"+network_text) if network_text else "A coleta atual do diagnóstico não inclui dados de rede. Consulte Rede & DNS → Atualizar informações; nenhum dado foi inventado.")
        self.status.setText("Diagnóstico completo • " + next((line.split(":",1)[1].strip() for line in raw.splitlines() if line.startswith("Computador:")), "Equipamento não informado") + " • Rede: consulta independente")
        self.tabs.setCurrentIndex(0)


def sensor_summary(groups):
    scroll=QScrollArea();scroll.setWidgetResizable(True)
    page=QWidget();layout=QVBoxLayout(page)
    for group in ("CPU","Memória RAM","GPU","Armazenamento","Bateria","Hardware térmico"):
        box=QGroupBox(group);box.setObjectName("Card");form=QFormLayout(box)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        count=0
        for component,items in groups.get(group,{}).items():
            for item in items:
                name=str(item.get("Medida") or "")
                if not any(k in name.casefold() for k in ("uso","frequência","temperatura","disponível","livre","atividade","carga","energia","saúde","ventoinha","rpm","memória","clock","espaço","smart","confiabilidade")):
                    continue
                value=item.get("Valor");state=str(item.get("Estado") or "Não disponível")
                value="—" if value is None or str(value).casefold() in ("não disponível","indeterminado","") else str(value)
                label=QLabel(value+" • "+state);label.setWordWrap(True)
                label.setToolTip(str(item.get("Origem") or "")+"\n"+str(item.get("Limitacao") or ""))
                label.setTextFormat(Qt.TextFormat.PlainText)
                key=QLabel(component+" — "+name);key.setTextFormat(Qt.TextFormat.PlainText);key.setWordWrap(True)
                form.addRow(key,label);count+=1
        if not count:form.addRow(QLabel("Dados de resumo não disponíveis na coleta atual."))
        layout.addWidget(box)
    layout.addStretch();scroll.setWidget(page);return scroll


class CollapsibleSection(QWidget):
    """Detalhe acessível por teclado; conserva o widget e seus dados ao recolher."""
    def __init__(self, title, content, expanded=False):
        super().__init__()
        self.content = content
        self.title = title
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.toggle = QPushButton()
        self.toggle.setObjectName("SectionToggle")
        self.toggle.setCheckable(True)
        self.toggle.toggled.connect(self.set_expanded)
        layout.addWidget(self.toggle)
        layout.addWidget(content)
        self.set_expanded(expanded)

    def set_expanded(self, expanded):
        self.toggle.blockSignals(True)
        self.toggle.setChecked(expanded)
        self.toggle.blockSignals(False)
        self.toggle.setText(("▾ " if expanded else "▸ ") + self.title)
        self.toggle.setAccessibleName(self.title + (" — expandido" if expanded else " — recolhido"))
        self.content.setVisible(expanded)
        self.updateGeometry()


class ResponsiveGrid(QWidget):
    """Distribui widgets já criados; resize não consulta fontes nem recria dados."""
    def __init__(self, widgets=(), cell_width=320):
        super().__init__()
        self.cells = list(widgets)
        self.cell_width = cell_width
        self.columns = 0
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(8)
        self.reflow()

    def reflow(self):
        columns = max(1, min(3, self.width() // self.cell_width))
        if columns == self.columns:
            return
        while self.grid.count():
            self.grid.takeAt(0)
        for col in range(3):
            self.grid.setColumnStretch(col, 1 if col < columns else 0)
        for i, widget in enumerate(self.cells):
            self.grid.addWidget(widget, i // columns, i % columns)
        self.columns = columns
        self.updateGeometry()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.reflow()


def plain_label(value, name=""):
    label = QLabel(str(value))
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setWordWrap(True)
    label.setMinimumWidth(0)
    if name:
        label.setObjectName(name)
    return label


class MetricCard(QFrame):
    def __init__(self, key, value, state="", tooltip=""):
        super().__init__()
        self.setObjectName("MetricCard")
        self.setMinimumWidth(0)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(plain_label(key, "MetricKey"))
        self.value_label = plain_label(presentation_value(value), "MetricValue")
        self.value_label.setToolTip(tooltip or str(value))
        layout.addWidget(self.value_label)
        if state:
            shown_state = presentation_value(state)
            marker = {"Disponível": "● ", "Não disponível": "— ", "Falha na coleta": "× ",
                      "Não suportado": "⊘ ", "Indeterminado": "? "}.get(shown_state, "")
            badge = plain_label(marker + shown_state, "StatusBadge")
            # Somente estados recebidos; nenhum limiar ou diagnóstico visual novo.
            badge.setProperty("tone", "attention" if state in ("Atenção", "Requer análise", "Crítico") else "neutral")
            badge.setProperty("collectionState", presentation_value(state))
            layout.addWidget(badge)
        self.setToolTip(tooltip)


class RawDataSection(CollapsibleSection):
    def __init__(self, title="Dados brutos", context="", source="", stamp=""):
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 0, 0)
        self.metadata = plain_label("")
        layout.addWidget(self.metadata)
        self.editor = QTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setObjectName("ConsoleVisual")
        self.editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.editor.setMinimumHeight(180)
        self.editor.setMaximumHeight(300)
        layout.addWidget(self.editor)
        self.copy = QPushButton("Copiar dados brutos")
        self.copy.clicked.connect(lambda: QApplication.clipboard().setText(self.editor.toPlainText()))
        layout.addWidget(self.copy)
        super().__init__(title, body)
        self.set_metadata(context, source, stamp)

    def set_metadata(self, context, source, stamp=""):
        shown, tip = local_timestamp(stamp)
        self.metadata.setText(f"{context or 'Objeto não informado'} • Fonte: {source or 'Resultado recebido'} • " + (shown if stamp else "Horário da coleta não informado"))
        self.metadata.setToolTip(tip)

    def setPlainText(self, text):
        self.editor.setPlainText(str(text))

    def toPlainText(self):
        return self.editor.toPlainText()


class ConsolidatedSections(QWidget):
    """Seções verticais. API de acesso legada mantida, sem QTabWidget interno."""
    def __init__(self):
        super().__init__()
        self.sections = []
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(0, 0, 0, 0)
        self.box.setSpacing(12)

    def addTab(self, widget, title):
        expanded = title not in ("Texto técnico", "Detalhes técnicos", "Dados brutos", "Dados brutos / resumo completo")
        section = widget if isinstance(widget, RawDataSection) else CollapsibleSection(title, widget, expanded)
        if isinstance(widget, RawDataSection):
            section.set_expanded(expanded)
        self.sections.append(section)
        self.box.addWidget(section)
        return len(self.sections) - 1

    def clear(self):
        for section in self.sections:
            self.box.removeWidget(section)
            section.hide()
            section.deleteLater()
        self.sections = []

    def count(self):
        return len(self.sections)

    def tabText(self, index):
        return self.sections[index].title

    def widget(self, index):
        return self.sections[index].content

    def setCurrentIndex(self, index):
        if 0 <= index < len(self.sections):
            self.sections[index].set_expanded(True)


class ReadoutPanel(QWidget):
    """Texto técnico existente em grade; raw original intacto, sem IO."""
    def __init__(self, include_raw=True):
        super().__init__()
        self._raw = ""
        self.layout_box = QVBoxLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.layout_box.setSpacing(8)
        self.content = QWidget()
        self.layout_box.addWidget(self.content)
        self.raw = RawDataSection() if include_raw else None
        if self.raw:
            self.layout_box.addWidget(self.raw)

    def setReadOnly(self, value):
        pass  # Labels selecionáveis; nenhuma edição é oferecida.

    def setPlainText(self, text):
        self._raw = str(text)
        old = self.content
        self.content = QWidget()
        layout = QVBoxLayout(self.content)
        layout.setContentsMargins(0, 0, 0, 0)
        cards = []
        for line in self._raw.splitlines():
            line = line.strip()
            if not line or all(c in "═─=-_ " for c in line):
                continue
            native = native_readout_line(line)
            if isinstance(native, DiskReadout):
                cards.append(native)
                continue
            if native is not None:
                if cards:
                    layout.addWidget(ResponsiveGrid(cards));cards = []
                layout.addWidget(native)
                continue
            if " | " in line and all(": " in part for part in line.split(" | ")):
                for part in line.split(" | "):
                    key, value = part.split(": ", 1)
                    cards.append(MetricCard(key, value))
                continue
            if ":" in line and not line.startswith("["):
                key, value = line.split(":", 1)
                value = value.strip()
                if value:
                    shown, tip = local_timestamp(value) if re.match(r"^(\d{4}-\d{2}-\d{2}[T ]|\d{2}/\d{2}/\d{4} )", value) else (value, value)
                    cards.append(MetricCard(key, shown, tooltip=tip))
                    continue
            if cards:
                layout.addWidget(ResponsiveGrid(cards));cards = []
            layout.addWidget(plain_label(line, "ReadoutHeading"))
        if cards:
            layout.addWidget(ResponsiveGrid(cards))
        self.layout_box.replaceWidget(old, self.content)
        old.hide();old.deleteLater()
        if self.raw:
            self.raw.setPlainText(self._raw)
        self.updateGeometry()

    def toPlainText(self):
        return self._raw

    def toHtml(self):
        return structured_html(self._raw)


class NetworkReadout(ReadoutPanel):
    def setPlainText(self, text):
        super().setPlainText(text)
        fields = dict(line.split(": ", 1) for line in str(text).splitlines() if ": " in line)
        groups = (
            ("Resumo operacional", ("Adaptador", "Status", "IPv4", "Gateway", "DNS IPv4", "Velocidade do link", "DHCP")),
            ("Identificação", ("Descrição", "Índice da interface", "MAC", "Tipo / mídia")),
            ("Endereçamento e DNS", ("Máscara / prefixo", "Rede", "Servidor DHCP", "IPv6", "DNS IPv6")),
            ("Informações adicionais", ("Perfil de rede", "Métrica efetiva", "Última atualização")),
        )
        # Reordenar apenas campos conhecidos; campos futuros continuam acessíveis.
        if fields:
            arranged = [];used = set()
            for title, keys in groups:
                lines = [f"{key}: {fields[key]}" for key in keys if key in fields]
                if lines:
                    arranged.extend([title, *lines]);used.update(keys)
            arranged.extend(f"{key}: {value}" for key, value in fields.items() if key not in used)
            super().setPlainText("\n".join(arranged))
            self._raw = str(text);self.raw.setPlainText(text)
        self.raw.set_metadata(fields.get("Adaptador", "Interface selecionada"), "Rede & DNS • consulta independente", fields.get("Última atualização", ""))


def consolidated_sensors(groups, result, label_for, state_for):
    page = QWidget();layout = QVBoxLayout(page)
    layout.setContentsMargins(0, 0, 0, 0)
    summary = [];attention = []
    for group in ("CPU", "Memória RAM", "GPU", "Armazenamento", "Hardware térmico", "Bateria"):
        items = [i for values in groups.get(group, {}).values() for i in values]
        primary = [i for i in items if any(k in str(i.get("Medida", "")).casefold() for k in ("uso", "clock", "frequência", "temperatura", "disponível", "carga", "núcleo", "lógico", "atividade", "energia", "rpm", "ventoinha"))]
        lines = [label_for(i) + ": " + str(i.get("Valor") if i.get("Valor") is not None else "Não disponível") for i in primary[:6]]
        summary.append(MetricCard(group, "\n".join(lines) or "Dados não disponíveis nesta coleta"))
        attention.extend(f"{group} • {i.get('Medida')}: {i.get('Estado')}" for i in items if i.get("Estado") in ("Atenção", "Requer análise", "Crítico"))
    layout.addWidget(ResponsiveGrid(summary, 360))
    if attention:
        layout.addWidget(plain_label("Pontos que exigem atenção • " + " | ".join(dict.fromkeys(attention)), "ResultBanner"))
    for group, components in groups.items():
        layout.addWidget(plain_label(group, "TituloSecao"))
        cards=[]
        for component, items in components.items():
            for item in items:
                value = item.get("Valor")
                value = "Não disponível" if value is None or value == "" else str(value)
                tooltip = "Origem: " + str(item.get("Origem") or "Não informada") + "\nLimitação: " + str(item.get("Limitacao") or "Não informada")
                cards.append(MetricCard(component + " • " + label_for(item), value, state_for(item), tooltip))
        layout.addWidget(ResponsiveGrid(cards, 320))
    raw = RawDataSection("Dados brutos completos dos sensores", "Sensores de hardware", "Consulta nativa recebida", result.get("ColetadoEm"))
    raw.setPlainText(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    layout.addWidget(raw)
    return page


_PRESENTATION_VALUES = {
    "Healthy": "Saudável", "Failed": "Falha", "Not available": "Não disponível",
    "Unknown": "Indeterminado", "N/A": "Não disponível", "None": "Não disponível",
    "Not supported": "Não suportado", "Available": "Disponível",
    "Collection failed": "Falha na coleta",
}


def presentation_value(value):
    """Traduz apenas um valor completo conhecido, nunca texto livre ou schema."""
    return _PRESENTATION_VALUES.get(str(value), str(value))


class UsageReadout(QFrame):
    """Percentual recebido, sem recalcular utilização a partir das capacidades."""
    def __init__(self, title, percent, details=""):
        super().__init__()
        self.setObjectName("MetricCard")
        layout = QVBoxLayout(self)
        layout.addWidget(plain_label(title, "MetricKey"))
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(round(float(percent.replace(",", ".")) * 10))
        self.bar.setFormat(percent + "% usado")
        self.bar.setAccessibleName(title + ": " + percent + "% usado")
        self.bar.setMinimumHeight(24)
        layout.addWidget(self.bar)
        if details:
            layout.addWidget(plain_label(details))


class DiskReadout(QFrame):
    """Registro de uma fonte; não associa discos/volumes por semelhança de nome."""
    def __init__(self, model, kind, capacity, health, interface="Não disponível", source="Sistema"):
        super().__init__()
        self.setObjectName("MetricCard")
        layout = QVBoxLayout(self)
        layout.addWidget(plain_label(model, "MetricValue"))
        layout.addWidget(plain_label("Fonte: " + source, "MetricKey"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        for key, value in (("Tipo", kind), ("Interface", interface), ("Capacidade", capacity),
                           ("Saúde", health), ("Temperatura", "Não disponível"),
                           ("Unidades relacionadas", "Não disponível")):
            key_label = plain_label(key)
            key_label.setWordWrap(False)
            form.addRow(key_label, plain_label(presentation_value(value)))
        layout.addLayout(form)
        self.setToolTip("Campos ausentes não são inferidos. Registros de fontes distintas são mantidos separados.")


def native_readout_line(line):
    """Reconhece somente formatos emitidos pelo diagnóstico atual; fallback integral."""
    ram = re.fullmatch(r"\[[█░]+\]\s+([0-9]+(?:[.,][0-9]+)?)%", line)
    volume = re.fullmatch(r"\[([^\]]+)\]\s+(?:\[[█░]+\]\s+)?([0-9]+(?:[.,][0-9]+)?)%\s*\|\s*(.+?)\s*/\s*(.+?)\s*\|\s*Livre:\s*(.+)", line)
    if ram and 0 <= float(ram[1].replace(",", ".")) <= 100:
        return UsageReadout("Memória RAM", ram[1])
    if volume and 0 <= float(volume[2].replace(",", ".")) <= 100:
        return UsageReadout("Unidade " + volume[1], volume[2],
                            f"Usado: {volume[3]} • Total: {volume[4]} • Livre: {volume[5]}")
    disk = re.fullmatch(r"• (.+) \((.+)\) - (.+ GB) \[(.+)\]", line)
    if disk:
        return DiskReadout(disk[1], disk[2], disk[3], disk[4])
    detail = re.fullmatch(r"Detalhe: (.+) \| Interface: (.+) \| Tipo: (.+) \| (.+ GB) \| Saúde: (.+)", line)
    if detail:
        return DiskReadout(detail[1], detail[3], detail[4], detail[5], detail[2], "Hardware detalhado")
    return None
