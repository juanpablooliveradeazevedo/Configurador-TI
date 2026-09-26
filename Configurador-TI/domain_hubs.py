"""Páginas-hub operacionais construídas a partir do registry interno."""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGridLayout, QGroupBox, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from navigation_registry import DOMAIN_BY_ID, modules_for_domain


class DomainHub(QWidget):
    def __init__(self, host, domain_id):
        super().__init__(host)
        self.host = host
        self.domain_id = domain_id
        self.definition = DOMAIN_BY_ID[domain_id]
        self.module_definitions = modules_for_domain(domain_id)
        self.module_buttons = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(16)
        layout.addLayout(host._header(self.definition.title, self.definition.description))

        summary = QLabel(
            f"Resumo operacional: {len(self.module_definitions)} módulo(s) disponível(is) "
            "neste domínio. Abrir um módulo não inicia coleta automaticamente pelo Hub."
        )
        summary.setWordWrap(True)
        summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(summary)
        self.summary = summary

        actions = QLabel("Funções disponíveis")
        actions.setObjectName("SubtituloTela")
        layout.addWidget(actions)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        for index, module in enumerate(self.module_definitions):
            card = QGroupBox(module.title)
            card.setObjectName("Card")
            card_layout = QVBoxLayout(card)
            description = QLabel(module.description)
            description.setWordWrap(True)
            description.setTextFormat(Qt.TextFormat.PlainText)
            card_layout.addWidget(description)
            button = QPushButton(f"Abrir {module.title}")
            button.setProperty("class", "ActionButton")
            button.setAccessibleName(f"Abrir {module.title}")
            button.clicked.connect(
                lambda _checked=False, module_id=module.module_id: host._open_module(module_id)
            )
            card_layout.addWidget(button)
            self.module_buttons[module.module_id] = button
            grid.addWidget(card, index // 2, index % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)

        notice = QLabel(
            "Atenções e mudanças recentes permanecem nas visões detalhadas que já possuem esses dados."
        )
        notice.setWordWrap(True)
        notice.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(notice)
        layout.addStretch()
