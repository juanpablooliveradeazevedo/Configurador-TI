from operational_ui import local_timestamp
"""Componentes exclusivamente visuais; sem coleta, persistência ou timers."""
from html import escape
from PyQt6.QtCore import Qt, QRect, QSize
from PyQt6.QtGui import QPainter, QColor
from PyQt6.QtWidgets import (QLayout, QWidget, QVBoxLayout, QGroupBox, QScrollArea,
    QFrame, QTableWidget, QStyledItemDelegate, QToolTip, QLineEdit, QComboBox,
    QPushButton, QLabel, QFormLayout, QSizePolicy, QMessageBox, QApplication)


class FlowRow(QLayout):
    """Linha de controles que quebra por largura disponível, sem timer."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items = []
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(8)

    def addItem(self, item):
        self._items.append(item)

    def addWidget(self, widget, stretch=0, alignment=Qt.AlignmentFlag(0)):
        widget.setProperty("flowExpand", bool(stretch))
        super().addWidget(widget)

    def addStretch(self, stretch=0):
        pass  # O espaço remanescente é distribuído somente a campos expansíveis.

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation.Horizontal

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._arrange(QRect(0, 0, width, 0), False)

    def minimumSize(self):
        size = QSize(0, 0)
        for item in self._items:
            if not item.isEmpty():
                size = size.expandedTo(QSize(min(240, item.minimumSize().width()), item.minimumSize().height()))
        return size

    def sizeHint(self):
        return QSize(640, self.heightForWidth(640))

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._arrange(rect, True)

    def _arrange(self, rect, apply):
        width = max(1, rect.width())
        rows, row, used = [], [], 0
        for item in self._items:
            if item.isEmpty():
                continue
            w = item.widget()
            flexible = bool(w and w.property("flowExpand"))
            desired = min(width, max(item.minimumSize().width(), min(item.sizeHint().width(), 300) if isinstance(w, (QLineEdit, QComboBox)) else item.sizeHint().width()))
            if row and used + self.spacing() + desired > width:
                rows.append(row)
                row, used = [], 0
            row.append((item, desired, flexible))
            used += desired + (self.spacing() if len(row) > 1 else 0)
        if row:
            rows.append(row)
        y = rect.y()
        for row in rows:
            spare = max(0, width - sum(w for _, w, _ in row) - self.spacing() * (len(row)-1))
            flex = sum(f for _, _, f in row)
            heights = []
            for item, w, f in row:
                actual = w + (spare // flex if f and flex else 0)
                heights.append(item.heightForWidth(actual) if item.hasHeightForWidth() else item.sizeHint().height())
            height = max(heights, default=0)
            x = rect.x()
            for item, w, f in row:
                actual = w + (spare // flex if f and flex else 0)
                if apply:
                    item.setGeometry(QRect(x, y, actual, height))
                x += actual + self.spacing()
            y += height + self.spacing()
        return max(0, y - rect.y() - (self.spacing() if rows else 0))


class CellTooltip(QStyledItemDelegate):
    """Tooltip sob demanda, sem percorrer/formartar todas as células."""
    def helpEvent(self, event, view, option, index):
        if event.type() == event.Type.ToolTip and index.isValid():
            value = index.data(Qt.ItemDataRole.ToolTipRole) or index.data(Qt.ItemDataRole.DisplayRole)
            if value is not None:
                QToolTip.showText(event.globalPos(), escape(str(value)), view)
                return True
        return super().helpEvent(event, view, option, index)


class UxTable(QTableWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self.setItemDelegate(CellTooltip(self))
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(32)
        self.setMinimumWidth(0)
        self.horizontalHeader().setMinimumSectionSize(90)
        self.setAccessibleDescription("Tabela. Use as setas para navegar e consulte os detalhes do item selecionado.")

    def setItem(self, row, column, item):
        header = self.horizontalHeaderItem(column)
        if header and header.text() in ("CPU", "Memória", "Handles", "Capacidade", "Temperatura", "Latência"):
            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        super().setItem(row, column, item)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.rowCount() == 0:
            painter = QPainter(self.viewport())
            painter.setPen(QColor("#b7c5d9"))
            painter.drawText(self.viewport().rect().adjusted(24, 16, -24, -16),
                             Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                             self.property("emptyMessage") or
                             "Nenhuma linha para exibir. Consulte o estado da operação acima e use a ação de atualização ou análise.")
            painter.end()


def section(title, widget):
    box = QGroupBox(title)
    box.setObjectName("Card")
    layout = QVBoxLayout(box)
    layout.setSpacing(12)
    layout.addWidget(widget)
    return box


def scroll_content(widgets):
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.setSpacing(16)
    layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
    for item in widgets:
        if isinstance(item, QLayout):
            layout.addLayout(item)
        else:
            layout.addWidget(item)
    layout.addStretch()
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setWidget(page)
    return scroll


def polish_accessibility(window):
    """Configuração única após montagem; não altera conteúdo nem callbacks."""
    for name, widget in vars(window).items():
        if isinstance(widget, (QLineEdit, QComboBox, QTableWidget)):
            if not widget.accessibleName():
                widget.setAccessibleName(name.replace("_", " "))
    for form in window.findChildren(QFormLayout):
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setVerticalSpacing(10)
        for row in range(form.rowCount()):
            label, field = form.itemAt(row, QFormLayout.ItemRole.LabelRole), form.itemAt(row, QFormLayout.ItemRole.FieldRole)
            if label and field and isinstance(label.widget(), QLabel) and field.widget():
                label.widget().setBuddy(field.widget())
                field.widget().setAccessibleName(label.widget().text())
    for field in window.findChildren(QLineEdit):
        if field.echoMode() == QLineEdit.EchoMode.Normal:
            field.setClearButtonEnabled(True)
        if not field.accessibleName():
            field.setAccessibleName(field.placeholderText() or "Campo de texto")
        if field.placeholderText() and not field.toolTip():
            field.setToolTip(field.placeholderText())
    for combo in window.findChildren(QComboBox):
        combo.setMinimumContentsLength(12)
        combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
    for label in window.findChildren(QLabel):
        if label.property("noWrap"):
            label.setWordWrap(False)
        elif label.objectName() not in ("Marca",):
            label.setWordWrap(True)
        if not label.property("preserveMinimumWidth"):
            label.setMinimumWidth(0)
    # Uma ação principal por grupo; demais ações preservam identidade/sinais.
    for group in window.findChildren(QGroupBox):
        actions = [b for b in group.findChildren(QPushButton)
                   if b.property("class") == "ActionButton"
                   and b.parentWidget() is group]
        for i, button in enumerate(actions):
            button.setProperty("actionRole", "primary" if i == 0 else "secondary")
            button.style().unpolish(button)
            button.style().polish(button)


def error_dialog(parent, title, summary, detail):
    dialog = QMessageBox(parent)
    dialog.setIcon(QMessageBox.Icon.Critical)
    dialog.setWindowTitle(title)
    dialog.setTextFormat(Qt.TextFormat.PlainText)
    dialog.setText(summary)
    dialog.setInformativeText("Consulte os detalhes e o configurador_ti.log. Nenhum erro foi ocultado.")
    dialog.setDetailedText(str(detail))
    copy = dialog.addButton("Copiar detalhes", QMessageBox.ButtonRole.ActionRole)
    copy.clicked.connect(lambda: (QApplication.clipboard().setText(str(detail)), copy.setText("Detalhes copiados")))
    dialog.addButton(QMessageBox.StandardButton.Close)
    dialog.exec()


def network_detail_html(record, context, providers, clean):
    """Renderiza somente dados existentes, escapados após a sanitização legada."""
    def text(value):
        if isinstance(value, (list, tuple)):
            value = ", ".join(map(str, value))
        if isinstance(value,str) and len(value)>10 and value[4:5]=="-" and "T" in value:
            shown, tooltip = local_timestamp(value)
            return '<span title="'+escape(tooltip, quote=True)+'">'+escape(clean(shown, 1200))+'</span>'
        return escape(clean(value, 1200) or "Não disponível")
    def pairs(values):
        return "".join("<p><b>"+escape(label)+":</b> "+text(value)+"</p>" for label,value in values)
    def heading(title):
        return "<h3>"+title+"</h3>"
    from hostname_identification import identification
    identity_name, identity_alert, _ = identification(record)
    body = heading("Decisão operacional") + pairs([
        ("IP",record.get("ip")),("Estado",record.get("state")),
        ("Confiança",record.get("confidence")),("Peso de evidência (não é probabilidade)",record.get("score")),
        ("Recomendação",record.get("recommendation")),("Alerta", " • ".join(filter(None, (record.get("identity_alert"), identity_alert))) or "Nenhum alerta registrado")])
    body += heading("Identificação") + pairs([
        ("Rede",context.get("Rede")),("Interface",context.get("Alias")),("Gateway",context.get("Gateway")),
        ("Escopo",context.get("network_scope_id")),("MAC atual/último",record.get("mac")),
        ("Hostname atual/último",record.get("hostname")),("Tipo",record.get("type")),
        ("Fabricante",record.get("manufacturer"))])
    body += heading("Evidências")
    for evidence in record.get("evidence", []):
        body += "<h4>"+text(evidence.get("provider"))+"</h4>"
        labels = {"status":"Status","strength":"Força","responded":"Resposta",
                  "ports":"Portas","mac":"MAC","hostname":"Hostname","neighbor_state":"Estado Neighbor",
                  "at":"Observado em","error":"Motivo","source":"Origem"}
        body += pairs([(labels.get(key,key),value) for key,value in evidence.items() if key != "provider"])
    body += heading("Histórico e reserva") + "<p>Último visto = qualquer evidência; último online = evidência real de atividade.</p>" + pairs([
        ("Primeiro visto",record.get("first_seen")),("Último visto",record.get("last_seen")),
        ("Último online",record.get("last_online")),("Verificado em",record.get("checked")),
        ("MACs históricos",record.get("macs")),("Hostnames históricos",record.get("hostnames")),
        ("Observação",record.get("note"))])
    reservation = record.get("active_reservation") or {}
    body += pairs([("Reserva local",reservation.get("description")),("Criada em",reservation.get("created")),
                   ("Expira em",reservation.get("expires") or ("Sem expiração" if reservation else ""))])
    for event in reversed(record.get("events", [])):
        body += pairs([(str(key),value) for key,value in event.items()])
    body += heading("Limitações") + pairs([("Limitação",v) for v in record.get("limitations",[])])
    body += pairs([("Fonte indisponível",p.get("provider")) for p in providers])
    return "<html><body>"+body+"</body></html>"
