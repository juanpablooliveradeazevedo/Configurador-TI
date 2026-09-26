#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configurador TI v5.0 — Interface Gráfica Aprimorada

Base:
    core_logic.py = backend integral recebido e preservado.

Objetivos desta versão:
- Interface mais profissional e organizada.
- Não exige psutil.
- Operações demoradas rodam em QThread.
- Barras de progresso reais quando o backend consegue informar progresso.
- Barras indeterminadas quando não existe porcentagem confiável.
- Painel de diagnóstico rápido.
- Rede/DNS + IP fixo.
- Inventário/varredura da rede.
- Manutenção: limpeza, spooler, CHKDSK, otimização e Windows Update.
- Relatório HTML.
- Monitoramento local observa CPU, memória e disco sem bloquear a GUI.
- Logs da sessão e log real.

O EXE gerado pelo BAT não precisa de Python/VS Code na máquina de destino.
"""

import sys
import os
import ipaddress
import ctypes
import ntpath
import re
import traceback
import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QGridLayout, QFormLayout, QPushButton, QLabel, QStackedWidget,
    QFrame, QTextEdit, QMessageBox, QComboBox, QLineEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QGroupBox, QSplitter, QSpinBox, QCheckBox, QInputDialog, QDialog,
    QScrollArea, QSizePolicy, QLayout, QTabWidget, QMenu, QStyle
)

# Identifica esta entrada como a GUI para que uma eventual elevação iniciada
# por uma operação do backend escolha pythonw.exe. O console/CLI continua sem
# essa marca e preserva seu comportamento interativo para desenvolvimento.
if os.name == "nt":
    os.environ.setdefault("CONFIGURADOR_TI_GUI_MODE", "1")

import core_logic
import app_paths
import app_status
import release_metadata
from audit_timeline import AuditTimelineStore, new_operation_id, record_event_safe
from audit_timeline_gui import AuditTimelinePanel
from change_intelligence import ChangeIntelligenceStore
from change_intelligence_gui import ChangeIntelligencePanel
from incident_replay import IncidentReplayStore, investigation_action_safe
from monitoring_foundation import (
    MonitoringService, monitoring_action_safe,
)
from monitoring_gui import MonitoringPanel
from endpoint_posture import EndpointPostureService, EndpointPostureStore, posture_action_safe
from endpoint_posture_gui import EndpointPosturePanel
from assist import AssistStore
from assist_gui import AssistPanel
from domain_hubs import DomainHub
from navigation_registry import (
    DOMAIN_BY_ID, MODULES, default_domain_for_view, domains as navigation_domains,
    module as navigation_module,
)
from baseline_defensivo_gui import BaselinePanel
from operational_ui import StructuredReadout, DiagnosticPanel, sensor_summary, local_timestamp, ConsolidatedSections, ReadoutPanel, NetworkReadout, RawDataSection, consolidated_sensors, ResponsiveGrid
import triagem_interativa as triagem
from network_intelligence_gui import NetworkPanel
from ui_components import (FlowRow, UxTable, section, scroll_content,
                           polish_accessibility, error_dialog)

# Mantém os contratos de QTableWidget; padroniza apenas apresentação.
QTableWidget = UxTable


BASE_DIR = Path(__file__).resolve().parent

# Workers que receberam solicitação de interrupção durante o fechamento. A
# referência de módulo evita que um QThread ainda ativo seja destruído junto com
# a janela principal. Eles são removidos assim que terminam.
WORKERS_EM_ENCERRAMENTO = []


def _tratar_excecao_global(exc_type, exc_value, exc_traceback):
    """Registra exceções não tratadas da GUI sem encerrar silenciosamente."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    detalhe = "".join(
        traceback.format_exception(exc_type, exc_value, exc_traceback)
    )
    try:
        core_logic.logger.critical(
            "Exceção não tratada na GUI:\n%s", detalhe
        )
    except Exception:
        pass

    try:
        if QApplication.instance() is not None:
            error_dialog(
                None, "Erro inesperado",
                "O Configurador encontrou um erro inesperado. O detalhe foi registrado no log.",
                detalhe,
            )
            return
    except Exception:
        pass

    # Antes de QApplication existir, pythonw.exe não oferece stderr visível.
    # Uma caixa nativa mantém a falha perceptível mesmo quando a GUI não pôde
    # ser criada; o detalhe completo já foi enviado ao log acima.
    try:
        if sys.platform.startswith("win"):
            ctypes.windll.user32.MessageBoxW(
                None,
                "O Configurador não pôde iniciar a interface. "
                "O detalhe foi registrado no log.\n\n"
                f"{exc_type.__name__}: {exc_value}",
                "Configurador TI — erro de inicialização",
                0x10,
            )
            return
    except Exception:
        pass

    sys.__excepthook__(exc_type, exc_value, exc_traceback)


class Worker(QThread):
    """Thread de operação.

    progress_callback é convertido em sinal Qt pelo próprio Worker.
    Assim o backend continua independente da GUI.
    """
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()
    progress = pyqtSignal(int, str)
    output = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            if self.isInterruptionRequested():
                self.cancelled.emit()
                return

            kwargs = dict(self.kwargs)

            # Injeta callbacks somente quando a função os declara. Assim o
            # backend permanece independente da GUI e consultas que puderem
            # cooperar com o fechamento recebem um sinal de cancelamento.
            try:
                import inspect
                sig = inspect.signature(self.fn)
                if "progress_callback" in sig.parameters and "progress_callback" not in kwargs:
                    kwargs["progress_callback"] = self._progress
                if "cancel_callback" in sig.parameters and "cancel_callback" not in kwargs:
                    kwargs["cancel_callback"] = self.isInterruptionRequested
            except Exception:
                pass

            result = self.fn(*self.args, **kwargs)
            if self.isInterruptionRequested():
                self.cancelled.emit()
            else:
                self.finished_ok.emit(result)
        except Exception as exc:
            if self.isInterruptionRequested():
                self.cancelled.emit()
            else:
                self.failed.emit(str(exc))

    def _progress(self, percent, message):
        if not self.isInterruptionRequested():
            self.progress.emit(int(percent), str(message))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Configurador TI v5.0 — Technician Desktop")
        self.resize(1260, 780)
        self.setMinimumSize(880, 440)

        self._workers = []
        self._busy_count = 0
        self._operation_workers = {}
        self._progress_owners = {}
        self._progress_generations = {}
        self._audit_store = None
        self._audit_store_failure_logged = False
        self._change_store = None
        self._change_store_failure_logged = False
        self._incident_store = None
        self._incident_store_failure_logged = False
        self._monitoring_store = None
        self._monitoring_store_failure_logged = False
        self._monitoring_service = None
        self._posture_store = None
        self._posture_store_failure_logged = False
        self._posture_service = None
        self._assist_store = None
        self._assist_store_failure_logged = False
        self._closing = False
        self._dados_processos_cache = []
        self._resultado_analise_defensiva = {}
        self._dados_analise_defensiva = []
        self._caminhos_analise_defensiva = []
        self._cache_pesquisa_analise_defensiva = {}
        self._cache_relevancia_analise_defensiva = {}
        self._linha_por_id_analise_defensiva = {}
        self._visibilidade_linhas_analise_defensiva = {}
        self._ultimo_filtro_analise_defensiva = None
        self._item_analise_defensiva_id = None
        self._item_analise_defensiva_antes_busca = None
        self._melhor_correspondencia_analise_defensiva_id = None
        self._revisoes_tecnicas = triagem.RevisoesLocais(
            core_logic.PASTA_TRIAGEM,
            core_logic.ModuloSistema._sanitizar_comando_analise_defensiva,
            core_logic.logger,
        )
        self._interface_scan_selecionada = None
        self._interface_scan_preferida = None
        self._preenchendo_interfaces_scan = False
        self._detalhes_rede_atual = None
        self._diagnostico_rede_atual = None
        self._monitoramento_ativo = False
        self._monitoramento_coleta_em_andamento = False
        self._monitoramento_worker = None
        self._timer_monitoramento = QTimer(self)
        self._timer_monitoramento.setInterval(60000)
        self._timer_monitoramento.timeout.connect(
            self._solicitar_coleta_monitoramento
        )

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("BarraLateral")
        self.sidebar.setFixedWidth(220)
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(14, 20, 14, 18)
        side.setSpacing(6)

        brand = QLabel("Configurador TI")
        brand.setWordWrap(True)
        brand.setToolTip("Configurador TI — Technician Desktop")
        brand.setObjectName("Marca")
        side.addWidget(brand)

        self.admin_label = QLabel()
        self.admin_label.setObjectName("StatusAdmin")
        side.addWidget(self.admin_label)
        self.restart_admin_button = QPushButton("Reiniciar como administrador")
        self.restart_admin_button.setAccessibleName("Reiniciar como administrador")
        self.restart_admin_button.setToolTip(
            "Relança o Configurador TI inteiro pelo UAC. As funções isoladas continuam "
            "solicitando elevação somente quando necessário."
        )
        self.restart_admin_button.clicked.connect(self._reiniciar_como_administrador)
        side.addWidget(self.restart_admin_button)
        from licensing.runtime import get_runtime
        self.license_gate = get_runtime()
        self.license_status = QLabel("Licença: " + self.license_gate.snapshot()["state"])
        self.license_status.setWordWrap(True)
        side.addWidget(self.license_status)
        self.license_button = QPushButton("Licença && Conta")
        self.license_button.clicked.connect(self._open_licensing_account)
        side.addWidget(self.license_button)
        if not self.license_gate.dev:
            self._license_timer = QTimer(self)
            self._license_timer.setInterval(60000)
            self._license_timer.timeout.connect(self._licensing_tick)
            self._license_timer.start()
            QTimer.singleShot(0, self._licensing_tick)
        self._atualizar_status_admin()

        side.addSpacing(12)

        self.nav_buttons = []
        for domain in navigation_domains():
            text = domain.title
            btn = QPushButton(text.replace(chr(38), chr(38)*2))
            btn.setIcon(self.style().standardIcon(
                getattr(QStyle.StandardPixmap, domain.icon)
            ))
            btn.setAccessibleName(text)
            btn.setToolTip("")
            btn.setProperty("class", "MenuButton")
            btn.setProperty("domain_id", domain.domain_id)
            btn.setCheckable(True)
            btn.clicked.connect(
                lambda _checked=False, domain_id=domain.domain_id: self._open_domain(domain_id)
            )
            self.nav_buttons.append(btn)
            side.addWidget(btn)

        side.addStretch()

        self.version_label = QLabel(release_metadata.VERSION)
        self.version_label.setObjectName("Versao")
        side.addWidget(self.version_label)
        self.version_label.setWordWrap(True)
        self.about_button = QPushButton("Sobre / Status")
        self.about_button.setAccessibleName("Sobre / Status do Configurador TI")
        self.about_button.clicked.connect(self._mostrar_sobre_configurador_ti)
        side.addWidget(self.about_button)
        self.environment_notice = QLabel()
        self.environment_notice.setWordWrap(True)
        self.environment_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.environment_notice.hide()
        side.addWidget(self.environment_notice)

        side.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        side_scroll = QScrollArea()
        side_scroll.setObjectName("NavegacaoRolavel")
        side_scroll.setFrameShape(QFrame.Shape.NoFrame)
        side_scroll.setWidgetResizable(True)
        side_scroll.setFixedWidth(238)
        side_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        side_scroll.setWidget(self.sidebar)
        root.addWidget(side_scroll)

        self.pages = QStackedWidget()
        self.pages.setObjectName("PainelConteudo")
        self.pages.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        self.navigation_context = QWidget()
        context_layout = QHBoxLayout(self.navigation_context)
        context_layout.setContentsMargins(18, 8, 18, 8)
        self.navigation_context_label = QLabel("")
        self.navigation_context_label.setTextFormat(Qt.TextFormat.PlainText)
        self.return_hub_button = QPushButton("Voltar ao Hub")
        self.return_hub_button.setProperty("class", "MenuButton")
        self.return_hub_button.clicked.connect(self._return_to_domain_hub)
        context_layout.addWidget(self.navigation_context_label)
        context_layout.addStretch()
        context_layout.addWidget(self.return_hub_button)
        self.navigation_context.hide()
        content_layout.addWidget(self.navigation_context)
        content_layout.addWidget(self.pages, 1)
        root.addWidget(content, 1)

        self._build_dashboard()
        self._build_rede()
        self._build_manutencao()
        self._build_inventario()
        self._build_relatorios()
        self._build_monitoramento()
        self._build_processos()
        self._build_central()
        self._build_implantacao()
        self._build_logs()
        self._build_auditoria()
        self._build_investigacao()
        self._build_postura_endpoint()
        self._build_assist()
        self._build_domain_hubs()

        self._atualizar_ambiente_configurador_ti()
        polish_accessibility(self)
        self._pagina_dashboard()
        self._carregar_adaptadores()
        self._carregar_unidades()

    # ---------------------------------------------------------
    # Helpers visuais
    # ---------------------------------------------------------
    def _atualizar_ambiente_configurador_ti(self):
        # Somente caminhos resolvidos; não consultar nem serializar configurações.
        data_paths = [path.parent for name, path in core_logic.CAMINHOS.files.items()
                      if name != "configurador_ti.log"]
        if self._revisoes_tecnicas.caminho is not None:
            data_paths.append(self._revisoes_tecnicas.caminho.parent)
        log_path, log_active = app_status.active_log_file(
            core_logic.logger, core_logic.ARQUIVO_LOG)
        app = QApplication.instance()
        qss_loaded = bool(app.property("configurador_ti_qss_loaded")) if app is not None else False
        state = app_status.environment_status(
            root=core_logic.DIRETORIO_BASE, data_paths=data_paths,
            log_path=log_path, report_path=core_logic.PASTA_RELATORIOS,
            collection_path=core_logic.PASTA_COLETAS, qss_loaded=qss_loaded,
            administrator=core_logic.verificar_admin(), log_active=log_active)
        self._configurador_ti_environment = state
        self.version_label.setText(
            f"{release_metadata.status_label(state['mode'])}\n"
            f"Dados: {'OK' if state['data_ok'] else 'Atenção'} | "
            f"Logs: {'OK' if state['logs']['ok'] else 'Atenção'}")
        self.environment_notice.setText("Ambiente requer atenção. Consulte Sobre / Status.")
        self.environment_notice.setToolTip("\n".join(state['warnings']))
        self.environment_notice.setVisible(bool(state['warnings']))
        # Mensagens fixas: não registrar conteúdo de configurações ou exceções brutas.
        if state['warnings'] != getattr(self, '_configurador_ti_last_warnings', None):
            for message in state['warnings']:
                core_logic.logger.warning("AMBIENTE_CONFIGURADOR_TI | %s", message)
        self._configurador_ti_last_warnings = list(state['warnings'])
        return state

    def _mostrar_sobre_configurador_ti(self):
        state = self._atualizar_ambiente_configurador_ti()
        if getattr(self, '_configurador_ti_about', None) is not None:
            self._configurador_ti_about.close()
        dialog = QDialog(self)
        self._configurador_ti_about = dialog
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.finished.connect(lambda: setattr(self, '_configurador_ti_about', None))
        dialog.setWindowTitle("Sobre / Status do Configurador TI")
        available = self.screen().availableGeometry()
        dialog.resize(min(660, max(320, available.width() - 48)),
                      min(550, max(240, available.height() - 48)))
        layout = QVBoxLayout(dialog)
        content = QWidget()
        form = QFormLayout(content)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        def row(title, value):
            label = QLabel(str(value))
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            form.addRow(title, label)
        row("Produto", state['product'])
        row("Versão / fase", state['version'])
        row("Data da edição", state['build'])
        row("Execução", state['mode'] + " • " + state['architecture'])
        row("Perfil de build", state['build_profile'])
        row("Backend", state['build_backend'])
        row("Administrador", state['administrator'])
        row("Dados", "\n".join(item['message'] + " — " + item['path'] for item in state['data']))
        row("Logs", state['logs']['message'] + " — " + state['log_file'])
        row("Relatórios", state['reports']['message'] + " — " + state['reports']['path'])
        row("Coletas", state['collections']['message'] + " — " + state['collections']['path'])
        row("Tema style.qss", "Carregado" if state['qss_ok'] else "Não carregado")
        row("Ambiente Configurador TI", "\n".join(state['warnings']) or "Diretórios locais disponíveis.")
        row("Verificação local", "Retrato deste momento. Não verifica conteúdo de dados nem "
            "permissões de cada arquivo. Algumas funções podem usar uma pasta alternativa. "
            "Se houver falha, use uma pasta local gravável e consulte o log efetivo acima.")
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        close = QPushButton("Fechar")
        close.clicked.connect(dialog.close)
        layout.addWidget(close)
        dialog.show()

    def _atualizar_status_admin(self):
        try:
            admin = bool(core_logic.verificar_admin())
        except Exception:
            admin = False
        self.admin_label.setText(
            "● Administrador" if admin else "● Usuário padrão — UAC sob demanda"
        )
        self.admin_label.setProperty("admin", "true" if admin else "false")
        self.admin_label.style().unpolish(self.admin_label)
        self.admin_label.style().polish(self.admin_label)
        if hasattr(self, "restart_admin_button"):
            self.restart_admin_button.setVisible(not admin)
            self.restart_admin_button.setEnabled(not admin)

    def _open_licensing_account(self):
        from licensing.gui import AccountDialog
        if not hasattr(self, "_account_dialog"):
            self._account_dialog = AccountDialog(self, self.license_gate)
        self._account_dialog.render(self.license_gate.snapshot())
        self._account_dialog.show()
        self._account_dialog.raise_()

    def _licensing_tick(self):
        if self._closing:
            return
        self._run(self.license_gate.renew, label="Atualizando licença", progress=None,
                  on_done=lambda value: self.license_status.setText("Licença: " + value["state"]),
                  operation_key="licensing_account", blocks_navigation=False, silent_if_busy=True)

    def _reiniciar_como_administrador(self):
        if core_logic.verificar_admin():
            self._atualizar_status_admin()
            return
        if self._workers:
            QMessageBox.information(
                self,
                "Operações em andamento",
                "Aguarde as operações atuais terminarem antes de reiniciar o Configurador TI.",
            )
            return
        resposta = QMessageBox.warning(
            self,
            "Reiniciar como administrador",
            "O Configurador TI será relançado pelo UAC com privilégios administrativos.\n\n"
            "Esse modo aumenta o impacto potencial das ações. A elevação sob demanda "
            "das funções existentes continuará disponível quando o Configurador TI for aberto "
            "normalmente.\n\nDeseja continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resposta != QMessageBox.StandardButton.Yes:
            core_logic.logger.info("RELANCAMENTO_ADMIN_EXPLICITO | status=cancelado_confirmacao")
            return
        resultado = core_logic.reiniciar_gui_como_administrador()
        status = resultado.get("Status")
        if status == "iniciado":
            core_logic.registrar_instancia_encerrando("RELANCAMENTO_ADMIN_EXPLICITO")
            QApplication.instance().quit()
            return
        if status == "ja_administrador":
            self._atualizar_status_admin()
            return
        if status == "nao_suportado":
            mensagem = "O relançamento administrativo está disponível somente no Windows."
        elif status == "uac_cancelado_ou_falhou":
            mensagem = "O UAC foi cancelado ou não pôde iniciar a nova instância."
        else:
            mensagem = "Não foi possível iniciar a nova instância administrativa. Consulte o log."
        QMessageBox.warning(self, "Reiniciar como administrador", mensagem)

    def _header(self, title, subtitle):
        box = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("TituloTela")
        sub = QLabel(subtitle)
        sub.setObjectName("SubtituloTela")
        sub.setWordWrap(True)
        box.addWidget(title_label)
        box.addWidget(sub)
        return box

    def _card(self, title):
        group = QGroupBox(title)
        group.setObjectName("Card")
        group.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        return group

    def _adicionar_pagina_rolavel(self, page, context_header=None):
        """Inclui uma página com rolagem vertical quando o espaço for menor.

        As telas preservam sua largura disponível; em janelas pequenas ou com
        DPI alto, a rolagem evita que layouts e tabelas sejam comprimidos pelo
        QStackedWidget.
        """
        layout = page.layout()
        if layout is not None:
            layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        page.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )
        scroll = QScrollArea()
        scroll.setObjectName("PaginaRolavel")
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        scroll.setWidget(page)
        if context_header is None:
            self.pages.addWidget(scroll)
        else:
            wrapper = QWidget()
            wrapper_layout = QVBoxLayout(wrapper)
            wrapper_layout.setContentsMargins(12, 8, 12, 0)
            wrapper_layout.addWidget(context_header)
            wrapper_layout.addWidget(scroll, 1)
            self.pages.addWidget(wrapper)

    @staticmethod
    def _configurar_tabela_legivel(tabela, altura_minima=220):
        """Define limites mínimos sem fixar alturas que reduzam legibilidade."""
        tabela.setMinimumHeight(int(altura_minima))
        tabela.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        tabela.verticalHeader().setDefaultSectionSize(32)
        tabela.verticalHeader().setMinimumSectionSize(28)

    def _log(self, message):
        if hasattr(self, "console_visual"):
            self.console_visual.append(message)
        # Resumo inline da sessão; o texto completo permanece na página Logs.
        self.statusBar().showMessage(str(message).splitlines()[0][:180] if message else "")

    def _get_audit_store(self):
        """Inicialização tardia: uma falha da timeline nunca impede a GUI."""
        if self._audit_store is not None:
            return self._audit_store
        try:
            self._audit_store = AuditTimelineStore(
                core_logic.DIRETORIO_BASE, logger=core_logic.logger, timeout=0.25
            )
            self._audit_store_failure_logged = False
            return self._audit_store
        except Exception:
            if not self._audit_store_failure_logged:
                self._audit_store_failure_logged = True
                try:
                    core_logic.logger.exception("Falha ao inicializar Audit & Timeline")
                except Exception:
                    pass
            return None

    def _audit_record(self, **event):
        return record_event_safe(
            self._get_audit_store(), logger=core_logic.logger, **event
        )

    def _get_change_store(self):
        """Inicialização tardia; falha de histórico não bloqueia o baseline."""
        if self._change_store is not None:
            return self._change_store
        try:
            self._change_store = ChangeIntelligenceStore(
                core_logic.DIRETORIO_BASE, logger=core_logic.logger, timeout=0.25
            )
            self._change_store_failure_logged = False
            return self._change_store
        except Exception:
            if not self._change_store_failure_logged:
                self._change_store_failure_logged = True
                try:
                    core_logic.logger.exception("Falha ao inicializar Change Intelligence")
                except Exception:
                    pass
            return None

    def _get_incident_store(self):
        """Store tardio e isolado; falha não invalida Timeline/Change Intelligence."""
        if self._incident_store is not None:
            return self._incident_store
        try:
            self._incident_store = IncidentReplayStore(
                core_logic.DIRETORIO_BASE, logger=core_logic.logger, timeout=0.25
            )
            self._incident_store_failure_logged = False
            return self._incident_store
        except Exception:
            if not self._incident_store_failure_logged:
                self._incident_store_failure_logged = True
                try:
                    core_logic.logger.exception("Falha ao inicializar Incident Replay")
                except Exception:
                    pass
            return None

    def _get_monitoring_store(self):
        """Inicialização tardia; a camada de monitoramento é best-effort."""
        if self._monitoring_store is not None:
            return self._monitoring_store
        try:
            self._monitoring_store = AssistStore(
                core_logic.DIRETORIO_BASE, logger=core_logic.logger, timeout=0.25
            )
            # O store mais novo também satisfaz as APIs herdadas e evita que
            # outra camada tente reabrir o schema 4 como se fosse desconhecido.
            self._audit_store = self._monitoring_store
            self._change_store = self._monitoring_store
            self._incident_store = self._monitoring_store
            self._posture_store = self._monitoring_store
            self._assist_store = self._monitoring_store
            self._monitoring_store_failure_logged = False
            return self._monitoring_store
        except Exception:
            if not self._monitoring_store_failure_logged:
                self._monitoring_store_failure_logged = True
                try:
                    core_logic.logger.exception("Falha ao inicializar Monitoring & Correlation")
                except Exception:
                    pass
            return None

    def _get_posture_store(self):
        """Store mais novo; compartilha timeline.db e mantém compatibilidade herdada."""
        if self._posture_store is not None:
            return self._posture_store
        store = self._get_monitoring_store()
        if isinstance(store, EndpointPostureStore):
            self._posture_store = store
            self._posture_store_failure_logged = False
            return store
        return None

    def _get_assist_store(self):
        """Store schema 8; mantém todas as APIs herdadas no mesmo timeline.db."""
        if self._assist_store is not None:
            return self._assist_store
        store = self._get_monitoring_store()
        if isinstance(store, AssistStore):
            self._assist_store = store
            self._assist_store_failure_logged = False
            return store
        return None

    def _get_posture_service(self):
        if self._posture_service is not None:
            return self._posture_service
        store = self._get_posture_store()
        if store is None:
            return None
        self._posture_service = EndpointPostureService(store, logger=core_logic.logger)
        return self._posture_service

    def _get_monitoring_service(self):
        if self._monitoring_service is not None:
            return self._monitoring_service
        store = self._get_monitoring_store()
        if store is None:
            return None
        self._monitoring_service = MonitoringService(store, logger=core_logic.logger)
        try:
            configured = store.get_monitoring_configuration()
            self._monitoring_service.set_interval(configured["interval_seconds"])
            self._monitoring_service.set_retention_days(configured["retention_days"])
        except Exception:
            core_logic.logger.exception("Falha ao aplicar configuração persistida de Monitoring")
        return self._monitoring_service

    def _audit_finish_worker(self, worker, status, severity, result=None):
        context = getattr(worker, "_audit_context", None)
        if not context:
            return
        details = {"result_type": type(result).__name__} if result is not None else None
        self._audit_record(
            source=context["source"], category=context["category"],
            severity=severity, status=status,
            summary=context["summary"] + {
                "COMPLETED": " — concluída", "FAILED": " — falhou",
                "CANCELLED": " — cancelada",
            }.get(status, ""),
            details=details, operation_id=context["operation_id"],
        )

    def _set_nav(self, index, domain_id=None):
        # O refresh automático pertence somente à tela de Processos. Ao trocar
        # de página, nenhum QTimer fica disparando consultas CIM em segundo
        # plano sem que o usuário esteja vendo o resultado.
        if hasattr(self, "_timer_processos") and index != 6:
            self._timer_processos.stop()
            if hasattr(self, "_timer_filtro_processos"):
                self._timer_filtro_processos.stop()
            if hasattr(self, "_timer_filtro_analise_defensiva"):
                self._timer_filtro_analise_defensiva.stop()

        domain_id = domain_id or self._domain_for_page(index)
        for b in self.nav_buttons:
            b.setChecked(b.property("domain_id") == domain_id)
        self.pages.setCurrentIndex(index)
        self._active_domain_id = domain_id
        self._update_navigation_context(index, domain_id)

        if (
            index == 6
            and hasattr(self, "chk_auto_proc")
            and self.chk_auto_proc.isChecked()
        ):
            self._timer_processos.start()

    def _domain_for_page(self, index):
        for domain_id, page_index in getattr(self, "domain_page_indexes", {}).items():
            if page_index == index:
                return domain_id
        return default_domain_for_view(index) or "overview"

    def _update_navigation_context(self, index, domain_id):
        hub_index = getattr(self, "domain_page_indexes", {}).get(domain_id)
        is_hub = index == hub_index or (domain_id == "overview" and index == 0)
        if is_hub:
            self.navigation_context.hide()
            return
        module = next((item for item in MODULES if item.view_index == index and item.domain == domain_id), None)
        if module is None:
            module = next((item for item in MODULES if item.view_index == index), None)
        domain = DOMAIN_BY_ID.get(domain_id)
        self.navigation_context_label.setText(
            f"{domain.title if domain else 'Configurador TI'}  ›  {module.title if module else 'Detalhes'}"
        )
        self.return_hub_button.setProperty("domain_id", domain_id)
        self.navigation_context.show()

    def _open_domain(self, domain_id):
        if domain_id == "overview":
            self._pagina_dashboard()
            return
        index = self.domain_page_indexes.get(domain_id)
        if index is not None:
            self._set_nav(index, domain_id=domain_id)

    def _return_to_domain_hub(self, _checked=False):
        self._open_domain(self.return_hub_button.property("domain_id") or self._active_domain_id)

    def _open_module(self, module_id):
        definition = navigation_module(module_id)
        route = getattr(self, definition.route, None)
        if not callable(route):
            raise RuntimeError("Rota interna do módulo não foi resolvida.")
        route()

    def _build_domain_hubs(self):
        self.domain_hubs = {}
        self.domain_page_indexes = {}
        for domain in navigation_domains():
            if domain.domain_id == "overview":
                self.domain_page_indexes[domain.domain_id] = 0
                continue
            hub = DomainHub(self, domain.domain_id)
            self.domain_hubs[domain.domain_id] = hub
            before = self.pages.count()
            self._adicionar_pagina_rolavel(hub)
            self.domain_page_indexes[domain.domain_id] = before

    def _busy(self, busy):
        self._busy_count = max(0, self._busy_count + (1 if busy else -1))
        locked = self._busy_count > 0
        for b in self.nav_buttons:
            b.setEnabled(not locked or b.isChecked())

    def _operacao_ativa(self, operation_key):
        """Indica se uma operação identificada ainda possui Worker ativo."""
        if not operation_key:
            return False
        worker = self._operation_workers.get(operation_key)
        return worker is not None and worker in self._workers

    def _run(self, fn, *args, label="", admin_reason=None, progress=None,
             on_done=None, indeterminate=True, operation_key=None,
             blocks_navigation=True, on_finally=None, silent_if_busy=False,
             audit_source=None, audit_category=None, audit_summary=None,
             audit_details=None, audit_operation_id=None,
             **kwargs):
        if self._closing:
            return None

        if operation_key and self._operacao_ativa(operation_key):
            if not silent_if_busy:
                QMessageBox.information(
                    self,
                    "Operação em andamento",
                    "Já existe uma atualização desta operação em andamento. "
                    "Aguarde a conclusão antes de iniciar outra.",
                )
            return None

        if admin_reason and not self._exigir_admin(admin_reason):
            return None

        progress_key = None
        progress_generation = None
        if progress is not None:
            progress_key = id(progress)
            owner = self._progress_owners.get(progress_key)
            if owner is not None and owner in self._workers:
                if not silent_if_busy:
                    QMessageBox.information(
                        self,
                        "Operação em andamento",
                        "Aguarde a conclusão da operação que já usa esta barra de progresso.",
                    )
                return None
            progress_generation = self._progress_generations.get(progress_key, 0) + 1
            self._progress_generations[progress_key] = progress_generation
            progress.show()
            if indeterminate:
                progress.setRange(0, 0)
            else:
                progress.setRange(0, 100)
                progress.setValue(0)

        audit_context = None
        if audit_category:
            audit_context = {
                "operation_id": audit_operation_id or new_operation_id(),
                "source": audit_source or "Configurador TI",
                "category": audit_category,
                "summary": audit_summary or label or getattr(fn, "__name__", "Operação"),
            }
            self._audit_record(
                source=audit_context["source"], category=audit_context["category"],
                severity="INFO", status="STARTED",
                summary=audit_context["summary"] + " — iniciada",
                details=audit_details, operation_id=audit_context["operation_id"],
            )

        self._log(f">> {label or fn.__name__}...")

        worker = Worker(fn, *args, **kwargs)
        worker._operation_key = operation_key
        worker._progress_key = progress_key
        worker._progress_generation = progress_generation
        worker._blocks_navigation = bool(blocks_navigation)
        worker._on_finally = on_finally
        worker._audit_context = audit_context
        self._workers.append(worker)
        if operation_key:
            self._operation_workers[operation_key] = worker
        if progress_key is not None:
            self._progress_owners[progress_key] = worker
        if blocks_navigation:
            self._busy(True)

        if progress is not None:
            worker.progress.connect(
                lambda p, m, w=worker: self._on_progress(w, progress, p, m),
                Qt.ConnectionType.QueuedConnection,
            )
        
        worker.finished_ok.connect(
            lambda result: self._worker_done(
                worker, progress, result, on_done
            ),
            Qt.ConnectionType.QueuedConnection,
        )
        worker.failed.connect(
            lambda err: self._worker_error(worker, progress, err),
            Qt.ConnectionType.QueuedConnection,
        )
        worker.cancelled.connect(
            lambda: self._worker_cancelled(worker, progress),
            Qt.ConnectionType.QueuedConnection,
        )
        try:
            worker.start()
        except Exception:
            self._concluir_worker(worker)
            self._audit_finish_worker(worker, "FAILED", "ERROR")
            raise
        return worker

    def _on_progress(self, worker, widget, percent, message):
        if self._closing or self._progress_owners.get(id(widget)) is not worker:
            return
        widget.show()
        widget.setRange(0, 100)
        widget.setValue(max(0, min(100, percent)))
        widget.setFormat(f"{percent}% — {message}")
        if (
            getattr(worker, "_operation_key", None) == "benchmark_configurador_ti"
            and hasattr(self, "lbl_etapa_benchmark_configurador_ti")
        ):
            self.lbl_etapa_benchmark_configurador_ti.setText(f"Etapa atual: {message}")

    def _concluir_worker(self, worker):
        """Libera referências, chaves e barras pertencentes a um Worker."""
        try:
            self._workers.remove(worker)
        except ValueError:
            pass

        operation_key = getattr(worker, "_operation_key", None)
        if operation_key and self._operation_workers.get(operation_key) is worker:
            self._operation_workers.pop(operation_key, None)

        progress_key = getattr(worker, "_progress_key", None)
        if progress_key is not None and self._progress_owners.get(progress_key) is worker:
            self._progress_owners.pop(progress_key, None)

        if getattr(worker, "_blocks_navigation", False) and not self._closing:
            self._busy(False)

        try:
            WORKERS_EM_ENCERRAMENTO.remove(worker)
        except ValueError:
            pass

    def _executar_finalizacao_worker(self, worker, state):
        callback = getattr(worker, "_on_finally", None)
        if not callback or self._closing:
            return
        try:
            callback(state)
        except Exception as exc:
            self._log(f">> [ERRO] Falha na finalização do Worker: {exc}")
            try:
                core_logic.logger.exception("Falha na finalização de Worker da GUI")
            except Exception:
                pass

    def _agendar_ocultacao_progresso(self, worker, progress, delay_ms):
        if progress is None or self._closing:
            return

        progress_key = getattr(worker, "_progress_key", None)
        generation = getattr(worker, "_progress_generation", None)

        def ocultar_se_ainda_for_atual():
            if self._closing:
                return
            if (
                self._progress_generations.get(progress_key) == generation
                and self._progress_owners.get(progress_key) is None
            ):
                progress.hide()

        QTimer.singleShot(delay_ms, ocultar_se_ainda_for_atual)

    def _worker_done(self, worker, progress, result, callback):
        if self._closing:
            audit_failure = (
                isinstance(result, tuple) and result and result[0] is False
            ) or (isinstance(result, dict) and (
                result.get("Sucesso") is False or bool(result.get("error"))
            ))
            self._audit_finish_worker(
                worker, "FAILED" if audit_failure else "COMPLETED",
                "ERROR" if audit_failure else "INFO", result,
            )
            self._concluir_worker(worker)
            return

        sucesso = not (
            isinstance(result, tuple)
            and result
            and isinstance(result[0], bool)
            and result[0] is False
        )
        if isinstance(result, dict) and result.get("Sucesso") is False:
            sucesso = False

        if progress is not None:
            progress.setRange(0, 100)
            if sucesso:
                progress.setValue(100)
                progress.setFormat("100% — Concluído")
            else:
                progress.setValue(0)
                progress.setFormat("Falha — operação não concluída")

        self._concluir_worker(worker)

        audit_failure = not sucesso or (
            isinstance(result, dict) and bool(result.get("error"))
        )
        self._audit_finish_worker(
            worker, "FAILED" if audit_failure else "COMPLETED",
            "ERROR" if audit_failure else "INFO", result,
        )

        callback_ok = True
        if callback:
            try:
                callback(result)
            except Exception as exc:
                callback_ok = False
                if progress is not None:
                    progress.setRange(0, 100)
                    progress.setValue(0)
                    progress.setFormat("Falha ao processar o resultado")
                self._log(f">> [ERRO] Falha no callback: {exc}")
                try:
                    core_logic.logger.exception(
                        "Falha ao processar callback de conclusão da GUI"
                    )
                except Exception:
                    pass
                error_dialog(
                    self, "Erro ao apresentar resultado",
                    "A operação terminou, mas a interface não conseguiu apresentar o resultado.",
                    str(exc),
                )

        self._executar_finalizacao_worker(worker, "success" if sucesso else "failure")
        if progress is not None:
            if sucesso and callback_ok:
                self._agendar_ocultacao_progresso(worker, progress, 700)
            else:
                self._agendar_ocultacao_progresso(worker, progress, 1800)

    def _worker_error(self, worker, progress, message):
        if self._closing:
            self._audit_finish_worker(worker, "FAILED", "ERROR")
            self._concluir_worker(worker)
            return

        if progress is not None:
            progress.setRange(0, 100)
            progress.setValue(0)
            progress.setFormat("Falha — consulte os detalhes e o log")
            progress.show()
        self._concluir_worker(worker)
        self._audit_finish_worker(worker, "FAILED", "ERROR")
        self._executar_finalizacao_worker(worker, "error")
        if progress is getattr(self, "progress_dashboard", None):
            self.dashboard_status.setText("Falha na consulta. Consulte os detalhes do erro e tente atualizar novamente.")
        elif progress is getattr(self, "progress_relatorio", None):
            self.report_status.setText("Falha ao gerar o relatório. Consulte os detalhes do erro.")
        self._log(f">> [ERRO] {message}")
        try:
            core_logic.logger.error("Falha em Worker da GUI: %s", message)
        except Exception:
            pass
        error_dialog(self, "Erro na operação", "Não foi possível concluir a operação solicitada.", message)

    def _worker_cancelled(self, worker, progress):
        if self._closing:
            self._audit_finish_worker(worker, "CANCELLED", "NOTICE")
            self._concluir_worker(worker)
            return

        if progress is not None:
            progress.setRange(0, 100)
            progress.setValue(0)
            progress.setFormat("Cancelada — operação não concluída")
        self._concluir_worker(worker)
        self._audit_finish_worker(worker, "CANCELLED", "NOTICE")
        self._executar_finalizacao_worker(worker, "cancelled")
        self._log(">> [CANCELADA] Operação interrompida antes de apresentar resultado.")
        self._agendar_ocultacao_progresso(worker, progress, 1800)

    def _exigir_admin(self, motivo):
        try:
            if core_logic.verificar_admin():
                return True
        except Exception:
            pass

        resposta = QMessageBox.question(
            self,
            "Privilégio de administrador",
            f"A ação abaixo exige administrador:\n\n{motivo}\n\n"
            "Deseja reiniciar o Configurador com UAC?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if resposta != QMessageBox.StandardButton.Yes:
            core_logic.registrar_evento_instancia(
                "RELANCAMENTO_UAC_CANCELADO",
                motivo=f"GUI:{motivo}",
            )
            return False

        try:
            resultado = core_logic.reiniciar_gui_como_administrador(
                motivo=f"GUI_FUNCAO_ISOLADA:{motivo}"
            )
            if resultado.get("Status") != "iniciado":
                if resultado.get("Status") != "uac_cancelado_ou_falhou":
                    QMessageBox.warning(
                        self,
                        "UAC",
                        "Não foi possível solicitar elevação. Consulte o log técnico.",
                    )
                return False
            core_logic.registrar_instancia_encerrando(
                f"RELANCAMENTO_UAC_GUI:{motivo};workers_ativos={len(self._workers)}"
            )
            QApplication.instance().quit()
            return False
        except Exception as exc:
            core_logic.registrar_evento_instancia(
                "RELANCAMENTO_UAC_FALHOU",
                motivo=f"GUI:{motivo}:{type(exc).__name__}",
            )
            try:
                core_logic.logger.exception("Falha ao solicitar UAC na GUI")
            except Exception:
                pass
            QMessageBox.critical(
                self, "UAC", f"Não foi possível solicitar elevação:\n{exc}"
            )
            return False

    # ---------------------------------------------------------
    # Dashboard
    # ---------------------------------------------------------
    def _build_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)

        layout.addLayout(self._header(
            "Visão Geral",
            "Resumo rápido da estação e acesso às operações mais utilizadas."
        ))

        cards = QGridLayout()
        cards.setSpacing(12)

        self.card_host = QLabel("—")
        self.card_os = QLabel("—")
        self.card_cpu = QLabel("—")
        self.card_ram = QLabel("—")

        for col, (title, label) in enumerate([
            ("🖥 Computador", self.card_host),
            ("🪟 Windows", self.card_os),
            ("⚙ Processador", self.card_cpu),
            ("🧠 Memória", self.card_ram),
        ]):
            box = self._card(title)
            b = QVBoxLayout(box)
            label.setObjectName("ValorCard")
            label.setWordWrap(True)
            b.addWidget(label)
            cards.addWidget(box, col // 2, col % 2)

        layout.addLayout(cards)

        quick = self._card("Ações rápidas")
        ql = FlowRow(quick)

        self.btn_diag = QPushButton("🔍 Diagnóstico completo")
        self.btn_diag.setProperty("class", "ActionButton")
        self.btn_diag.clicked.connect(self._diagnostico)

        self.btn_report_quick = QPushButton("📊 Gerar relatório")
        self.btn_report_quick.setProperty("class", "ActionButton")
        self.btn_report_quick.clicked.connect(self._gerar_relatorio)

        self.btn_monitor_quick = QPushButton("📈 Abrir Monitoramento")
        self.btn_monitor_quick.setProperty("class", "ActionButton")
        self.btn_monitor_quick.clicked.connect(self._abrir_monitoramento)

        for b in (self.btn_diag, self.btn_report_quick, self.btn_monitor_quick):
            ql.addWidget(b)

        layout.addWidget(quick)

        status = self._card("Status da estação")
        sl = QVBoxLayout(status)
        self.dashboard_status = QLabel(
            "Clique em Atualizar para coletar informações atuais."
        )
        self.dashboard_status.setWordWrap(True)
        sl.addWidget(self.dashboard_status)

        self.btn_refresh_dashboard = QPushButton("🔄 Atualizar diagnóstico")
        self.btn_refresh_dashboard.setProperty("class", "MenuButton")
        self.btn_refresh_dashboard.clicked.connect(self._atualizar_dashboard)
        sl.addWidget(self.btn_refresh_dashboard)

        self.progress_dashboard = QProgressBar()
        self.progress_dashboard.hide()
        sl.addWidget(self.progress_dashboard)

        layout.addWidget(status)
        self.diagnostico_integrado = DiagnosticPanel()
        layout.addWidget(section("Diagnóstico completo", self.diagnostico_integrado))
        layout.addStretch()

        self._adicionar_pagina_rolavel(page)

    def _pagina_dashboard(self):
        self._set_nav(0)
        self._atualizar_dashboard()

    def _atualizar_dashboard(self):
        self.dashboard_status.setText("Coletando informações...")
        self._run(
            self._coletar_dashboard,
            label="Coletando diagnóstico rápido",
            progress=self.progress_dashboard,
            on_done=self._mostrar_dashboard,
            indeterminate=True,
            operation_key="dashboard_refresh",
            blocks_navigation=False,
            silent_if_busy=True,
        )

    def _coletar_dashboard(self):
        info = core_logic.ModuloSistema.obter_informacoes_sistema() or {}
        versao = core_logic.ModuloSistema.obter_versao_windows() or {}
        hw = core_logic.ModuloSistema.obter_hardware_detalhado() or {}
        return info, versao, hw

    def _mostrar_dashboard(self, result):
        info, versao, hw = result
        host = info.get("HostName") or os.environ.get("COMPUTERNAME", "N/A")
        os_name = (
            versao.get("Nome")
            or info.get("OS")
            or "Windows"
        )
        display = versao.get("DisplayVersion") or versao.get("BuildCompleta")
        cpu = hw.get("CPU") or info.get("CPU") or "N/A"
        ram = info.get("RAMTotalGB") or hw.get("RAMTotalGB") or "N/A"

        self.card_host.setText(str(host))
        self.card_os.setText(f"{os_name}\n{display or ''}".strip())
        self.card_cpu.setText(str(cpu))
        self.card_ram.setText(f"{ram} GB")
        self.dashboard_status.setText(
            f"Hostname: {host}  •  Windows: {display or 'N/A'}  •  "
            f"Administrador: {'Sim' if core_logic.verificar_admin() else 'Não'}"
        )

    def _diagnostico(self):
        self._log(">> Executando diagnóstico completo...")
        self._run(
            core_logic.ModuloSistema.gerar_diagnostico_completo_texto,
            label="Diagnóstico completo",
            progress=self.progress_dashboard,
            indeterminate=True,
            on_done=self._mostrar_diagnostico_integrado,
        )

    def _mostrar_diagnostico_integrado(self, resultado):
        self.diagnostico_integrado.show_result(resultado, self.texto_detalhes_rede.toPlainText())
        self._set_nav(0)

    def _mostrar_texto_dialogo(self, titulo: str):
        """Devolve um callback pronto para on_done que abre o resultado (uma
        string) numa janela própria, com fonte monoespaçada e rolagem — em
        vez de a informação só "desaparecer" depois de coletada (o que
        acontecia com funções que antes só faziam print() para um console
        que não existe no app compilado)."""
        def _callback(resultado):
            texto = resultado if isinstance(resultado, str) else str(resultado)
            dlg = QDialog(self)
            dlg.setWindowTitle(titulo)
            dlg.resize(700, 560)
            lay = QVBoxLayout(dlg)
            visor = QTextEdit()
            visor.setObjectName("ConsoleVisual")
            visor.setReadOnly(True)
            visor.setFontFamily("Consolas")
            visor.setPlainText(texto)
            lay.addWidget(visor)
            botoes = FlowRow()
            btn_copiar = QPushButton("📋 Copiar")
            btn_copiar.setProperty("class", "MenuButton")
            btn_copiar.clicked.connect(lambda: (
                QApplication.clipboard().setText(texto), btn_copiar.setText("Copiado")))
            btn_fechar = QPushButton("Fechar")
            btn_fechar.setProperty("class", "ActionButton")
            btn_fechar.clicked.connect(dlg.accept)
            botoes.addWidget(btn_copiar)
            botoes.addStretch()
            botoes.addWidget(btn_fechar)
            lay.addLayout(botoes)
            self._log(f">> {titulo}: pronto.")
            dlg.exec()
        return _callback

    # ---------------------------------------------------------
    # Rede & DNS
    # ---------------------------------------------------------
    def _build_rede(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Rede & DNS",
            "Configuração segura de DNS, DHCP, renovação e IP fixo."
        ))

        form_card = self._card("Interface selecionada")
        form = QFormLayout(form_card)

        self.combo_adaptador = QComboBox()
        self.combo_adaptador.setMinimumWidth(200)
        self.combo_adaptador.currentIndexChanged.connect(
            self._adaptador_rede_mudou
        )
        form.addRow("Adaptador:", self.combo_adaptador)

        self.campo_dns = QLineEdit()
        self.campo_dns.setPlaceholderText("Ex.: 1.1.1.1, 8.8.8.8")
        form.addRow("DNS:", self.campo_dns)

        self.campo_ip = QLineEdit()
        self.campo_ip.setPlaceholderText("Ex.: 192.168.1.50")
        form.addRow("IP fixo:", self.campo_ip)

        self.campo_mascara = QLineEdit()
        self.campo_mascara.setPlaceholderText("Ex.: 255.255.255.0")
        form.addRow("Máscara:", self.campo_mascara)

        self.campo_gateway = QLineEdit()
        self.campo_gateway.setPlaceholderText("Ex.: 192.168.1.1")
        form.addRow("Gateway:", self.campo_gateway)

        layout.addWidget(form_card)

        perfis_card = self._card("Perfis de DNS salvos")
        pf = FlowRow(perfis_card)
        self.combo_perfil_dns = QComboBox()
        self.combo_perfil_dns.setMinimumWidth(180)
        pf.addWidget(self.combo_perfil_dns)
        btn_usar_perfil = QPushButton("✅ Usar perfil")
        btn_usar_perfil.setProperty("class", "MenuButton")
        btn_usar_perfil.clicked.connect(self._usar_perfil_dns)
        btn_salvar_perfil = QPushButton("💾 Salvar atual como perfil")
        btn_salvar_perfil.setProperty("class", "MenuButton")
        btn_salvar_perfil.clicked.connect(self._salvar_perfil_dns)
        btn_excluir_perfil = QPushButton("🗑 Excluir perfil")
        btn_excluir_perfil.setProperty("class", "DangerButton")
        btn_excluir_perfil.clicked.connect(self._excluir_perfil_dns)
        pf.addWidget(btn_usar_perfil)
        pf.addWidget(btn_salvar_perfil)
        pf.addWidget(btn_excluir_perfil)
        pf.addStretch()
        layout.addWidget(perfis_card)

        actions = self._card("Operações")
        al = QGridLayout(actions)

        buttons = [
            ("🔄 Atualizar adaptadores", self._carregar_adaptadores, False),
            ("🌐 Aplicar DNS manual", self._aplicar_dns, False),
            ("↩ Restaurar DHCP", self._restaurar_dhcp, False),
            ("♻ Renovar conexão", self._renovar_conexao, False),
            ("📌 Aplicar IP fixo", self._aplicar_ip_fixo, True),
            ("🔎 Detalhes da interface", self._detalhes_interface, False),
        ]
        for i, (text, fn, _) in enumerate(buttons):
            b = QPushButton(text)
            b.setProperty("class", "ActionButton")
            b.clicked.connect(fn)
            al.addWidget(b, i // 2, i % 2)

        detalhes_card = self._card("Informações detalhadas da rede")
        detalhes_layout = QVBoxLayout(detalhes_card)
        self.lbl_detalhes_rede_status = QLabel(
            "Selecione uma interface e clique em ‘Atualizar informações’."
        )
        self.lbl_detalhes_rede_status.setWordWrap(True)
        self.texto_detalhes_rede = NetworkReadout()
        self.texto_detalhes_rede.setReadOnly(True)
        self.texto_detalhes_rede.setMinimumHeight(285)
        self.texto_detalhes_rede.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        detalhes_botoes = FlowRow()
        self.btn_atualizar_informacoes_rede = QPushButton("🔄 Atualizar informações")
        self.btn_atualizar_informacoes_rede.setProperty("class", "ActionButton")
        self.btn_atualizar_informacoes_rede.clicked.connect(self._atualizar_informacoes_rede)
        self.btn_copiar_informacoes_rede = QPushButton("📋 Copiar informações")
        self.btn_copiar_informacoes_rede.setProperty("class", "MenuButton")
        self.btn_copiar_informacoes_rede.setEnabled(False)
        self.btn_copiar_informacoes_rede.clicked.connect(self._copiar_informacoes_rede)
        detalhes_botoes.addWidget(self.btn_atualizar_informacoes_rede)
        detalhes_botoes.addWidget(self.btn_copiar_informacoes_rede)
        detalhes_botoes.addStretch()
        detalhes_layout.addWidget(self.lbl_detalhes_rede_status)
        detalhes_layout.addWidget(self.texto_detalhes_rede)
        detalhes_layout.addLayout(detalhes_botoes)

        diagnostico_card = self._card("Diagnóstico rápido de conectividade")
        diagnostico_layout = QVBoxLayout(diagnostico_card)
        diagnostico_topo = FlowRow()
        self.btn_diagnostico_rede = QPushButton("🩺 Executar diagnóstico rápido")
        self.btn_diagnostico_rede.setProperty("class", "ActionButton")
        self.btn_diagnostico_rede.clicked.connect(self._executar_diagnostico_rede_rapido)
        self.lbl_diagnostico_rede = QLabel(
            "Diagnóstico sob demanda; não altera configurações de rede."
        )
        self.lbl_diagnostico_rede.setWordWrap(True)
        diagnostico_topo.addWidget(self.btn_diagnostico_rede)
        diagnostico_topo.addWidget(self.lbl_diagnostico_rede, 1)
        self.tabela_diagnostico_rede = QTableWidget(0, 3)
        self.tabela_diagnostico_rede.setHorizontalHeaderLabels(
            ["Verificação", "Resultado", "Detalhe"]
        )
        self.tabela_diagnostico_rede.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_diagnostico_rede.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        for coluna in (0, 1):
            self.tabela_diagnostico_rede.horizontalHeader().setSectionResizeMode(
                coluna, QHeaderView.ResizeMode.ResizeToContents
            )
        self.tabela_diagnostico_rede.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self._configurar_tabela_legivel(self.tabela_diagnostico_rede, 190)
        diagnostico_layout.addLayout(diagnostico_topo)
        diagnostico_layout.addWidget(self.tabela_diagnostico_rede)

        self.progress_rede = QProgressBar()
        self.progress_rede.hide()
        layout.addWidget(actions)
        layout.addWidget(detalhes_card)
        layout.addWidget(diagnostico_card)
        layout.addWidget(self.progress_rede)
        layout.addStretch()

        self._adicionar_pagina_rolavel(page)
        self._carregar_perfis_dns()

    def _carregar_perfis_dns(self):
        self.combo_perfil_dns.clear()
        try:
            perfis = core_logic.gerenciador_perfis.listar()
        except Exception as e:
            self._log(f">> [ERRO] Não foi possível carregar perfis de DNS: {e}")
            return
        for perfil in perfis:
            self.combo_perfil_dns.addItem(
                f"{perfil.nome} ({', '.join(perfil.servidores)})", perfil
            )

    def _usar_perfil_dns(self):
        idx = self.combo_perfil_dns.currentIndex()
        if idx < 0:
            QMessageBox.information(self, "Perfis de DNS", "Nenhum perfil salvo ainda.")
            return
        perfil = self.combo_perfil_dns.itemData(idx)
        self.campo_dns.setText(", ".join(perfil.servidores))
        self._log(f">> Perfil '{perfil.nome}' carregado no campo DNS. Clique em 'Aplicar DNS manual' para efetivar.")

    def _salvar_perfil_dns(self):
        servidores = [x.strip() for x in self.campo_dns.text().split(",") if x.strip()]
        if not servidores:
            QMessageBox.warning(self, "Salvar perfil", "Preencha o campo DNS com um ou mais IPs antes de salvar como perfil.")
            return
        for ip in servidores:
            if not self._validar_ip(ip):
                QMessageBox.warning(self, "Salvar perfil", f"'{ip}' não é um IP válido.")
                return
        nome, ok = QInputDialog.getText(self, "Salvar perfil de DNS", "Nome do perfil:")
        if not ok or not nome.strip():
            return
        nome = nome.strip()
        try:
            if core_logic.gerenciador_perfis.obter(nome) is not None:
                if QMessageBox.question(self, "Perfil existente", f"Já existe um perfil chamado '{nome}'. Sobrescrever?") != QMessageBox.StandardButton.Yes:
                    return
            perfil = core_logic.PerfilDNS(nome=nome, servidores=servidores)
            core_logic.gerenciador_perfis.adicionar(perfil)
            self._carregar_perfis_dns()
            self._log(f">> [OK] Perfil '{nome}' salvo.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))

    def _excluir_perfil_dns(self):
        idx = self.combo_perfil_dns.currentIndex()
        if idx < 0:
            return
        perfil = self.combo_perfil_dns.itemData(idx)
        if QMessageBox.question(self, "Excluir perfil", f"Excluir o perfil '{perfil.nome}'?") != QMessageBox.StandardButton.Yes:
            return
        try:
            core_logic.gerenciador_perfis.remover(perfil.nome)
            self._carregar_perfis_dns()
            self._log(f">> Perfil '{perfil.nome}' removido.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))

    def _pagina_rede(self):
        self._set_nav(1)

    def _carregar_adaptadores(self):
        self._run(
            core_logic.ModuloRede.listar_adaptadores_detalhados,
            label="Consultando adaptadores",
            progress=getattr(self, "progress_rede", None),
            on_done=self._mostrar_adaptadores,
        )

    @staticmethod
    def _indice_adaptador_recomendado(adaptadores):
        """Retorna o índice da interface elegível pela política já aprovada.

        A lista detalhada usada pela página Rede & DNS não deve depender da
        ordem devolvida pelo Windows. Os campos disponíveis são adaptados para
        o avaliador único do backend; métricas só são encaminhadas quando a
        própria estrutura as fornece, sem fabricar preferência por tipo.
        """
        adaptadores = list(adaptadores or [])
        avaliaveis = []
        for ad in adaptadores:
            nome = str(getattr(ad, "nome", "") or "").strip()
            alias = str(getattr(ad, "interface_alias", "") or nome).strip()
            item = {
                "InterfaceAlias": alias,
                "Descricao": nome,
                "Status": getattr(ad, "status", ""),
                "IPv4": getattr(ad, "ip", "") or "",
                "Gateway": getattr(ad, "gateway", "") or "",
                "DNS": getattr(ad, "dns", "") or "",
            }
            prefixo = getattr(ad, "prefix_length", None)
            metrica = getattr(ad, "route_metric", None)
            if prefixo is not None:
                item["PrefixLength"] = prefixo
            if metrica is not None:
                item["RouteMetric"] = metrica
            avaliaveis.append(item)

        avaliacao = core_logic.ModuloEmpresa._avaliar_interfaces_varredura(
            avaliaveis
        )
        selecionada = avaliacao.get("Selecionada") or {}
        alvo = str(
            selecionada.get("InterfaceAlias") or selecionada.get("Alias") or ""
        ).strip().casefold()
        if not alvo:
            return -1
        for indice, ad in enumerate(adaptadores):
            nome = str(getattr(ad, "nome", "") or "").strip().casefold()
            alias = str(
                getattr(ad, "interface_alias", "") or getattr(ad, "nome", "") or ""
            ).strip().casefold()
            if alvo in {alias, nome}:
                return indice
        return -1

    def _mostrar_adaptadores(self, adapters):
        adaptadores = list(adapters or [])
        role_alias = int(Qt.ItemDataRole.UserRole) + 1
        alias_anterior = str(
            self.combo_adaptador.currentData(role_alias) or ""
        ).strip().casefold()
        nome_anterior = str(
            self.combo_adaptador.currentData() or ""
        ).strip().casefold()

        self.combo_adaptador.blockSignals(True)
        try:
            self.combo_adaptador.clear()
            for ad in adaptadores:
                status = "Ativo" if ad.esta_ativo() else "Inativo"
                self.combo_adaptador.addItem(
                    f"{ad.nome} — {status} — {ad.ip or 'sem IP'}",
                    ad.nome,
                )
                self.combo_adaptador.setItemData(
                    self.combo_adaptador.count() - 1,
                    str(getattr(ad, "interface_alias", "") or ad.nome),
                    role_alias,
                )

            indice = -1
            for posicao, ad in enumerate(adaptadores):
                alias = str(
                    getattr(ad, "interface_alias", "") or ad.nome
                ).strip().casefold()
                nome = str(ad.nome or "").strip().casefold()
                if alias_anterior and alias == alias_anterior:
                    indice = posicao
                    break
                if not alias_anterior and nome_anterior and nome == nome_anterior:
                    indice = posicao
                    break
            if indice < 0:
                indice = self._indice_adaptador_recomendado(adaptadores)
            self.combo_adaptador.setCurrentIndex(indice)
        finally:
            self.combo_adaptador.blockSignals(False)

        self._adaptador_rede_mudou(self.combo_adaptador.currentIndex())
        self._log(f">> {len(adaptadores)} adaptador(es) encontrado(s).")

    @staticmethod
    def _texto_detalhe_rede(valor):
        if valor is None or valor == "":
            return "—"
        if isinstance(valor, (list, tuple, set)):
            valores = [str(item).strip() for item in valor if str(item).strip()]
            return ", ".join(valores) if valores else "—"
        return str(valor)

    def _limpar_painel_detalhes_rede(self, mensagem=None):
        self._detalhes_rede_atual = None
        self.texto_detalhes_rede.setPlainText("")
        self.lbl_detalhes_rede_status.setText(
            mensagem or "Selecione uma interface e clique em ‘Atualizar informações’."
        )
        self.btn_copiar_informacoes_rede.setEnabled(False)

    def _limpar_diagnostico_rede(self, mensagem=None):
        self._diagnostico_rede_atual = None
        self.tabela_diagnostico_rede.setRowCount(0)
        self.lbl_diagnostico_rede.setText(
            mensagem or "Diagnóstico sob demanda; não altera configurações de rede."
        )

    def _adaptador_rede_mudou(self, _indice):
        if not self._closing:
            self._limpar_painel_detalhes_rede()
            self._limpar_diagnostico_rede()

    def _resultado_rede_corresponde_ao_selecionado(self, resultado):
        if not isinstance(resultado, dict):
            return False
        interface = resultado.get("Interface") or {}
        selecionado = str(self.combo_adaptador.itemData(
            self.combo_adaptador.currentIndex()
        ) or "").strip().casefold()
        return bool(selecionado and selecionado in {
            str(interface.get("Nome") or "").strip().casefold(),
            str(interface.get("Alias") or "").strip().casefold(),
        })

    def _formatar_detalhes_rede(self, resultado):
        d = resultado.get("Interface") or {}
        mascara = self._texto_detalhe_rede(d.get("Mascara"))
        if d.get("PrefixLength") is not None:
            mascara = f"{mascara} (/{d['PrefixLength']})"
        status = self._texto_detalhe_rede(d.get("StatusNormalizado"))
        if d.get("Status") and str(d["Status"]).casefold() != status.casefold():
            status = f"{status} ({d['Status']})"
        campos = [
            ("Adaptador", d.get("Alias") or d.get("Nome")),
            ("Descrição", d.get("Descricao")), ("Índice da interface", d.get("InterfaceIndex")),
            ("Status", status), ("Tipo / mídia", d.get("TipoMidia")),
            ("IPv4", d.get("IPv4")), ("Máscara / prefixo", mascara), ("Rede", d.get("Rede")),
            ("Gateway", d.get("Gateway")), ("Métrica efetiva", d.get("MetricaEfetiva")),
            ("MAC", d.get("MAC")), ("Velocidade do link", d.get("VelocidadeLink")),
            ("DNS IPv4", d.get("DNSIPv4")), ("DNS IPv6", d.get("DNSIPv6")),
            ("DHCP", d.get("DHCPHabilitado")), ("Servidor DHCP", d.get("ServidorDHCP")),
            ("IPv6", d.get("IPv6")), ("Perfil de rede", d.get("PerfilRede")),
            ("Última atualização", d.get("AtualizadoEm")),
        ]
        return chr(10).join(f"{rotulo}: {self._texto_detalhe_rede(valor)}"
                            for rotulo, valor in campos)

    def _atualizar_informacoes_rede(self):
        adaptador = self._adaptador()
        if not adaptador:
            return
        if self._operacao_ativa("detalhes_rede"):
            self.lbl_detalhes_rede_status.setText(
                "Atualização das informações de rede já está em andamento."
            )
            return
        self.lbl_detalhes_rede_status.setText(
            "Atualizando informações da interface selecionada..."
        )
        worker = self._run(
            core_logic.ModuloRede.obter_detalhes_rede, adaptador,
            label=f"Atualizando informações de rede: {adaptador}",
            progress=self.progress_rede, indeterminate=True,
            operation_key="detalhes_rede", blocks_navigation=False,
            on_done=self._mostrar_detalhes_rede,
            on_finally=self._finalizar_atualizacao_detalhes_rede,
            silent_if_busy=True,
        )
        if worker is not None:
            self.btn_atualizar_informacoes_rede.setEnabled(False)
        elif not self._closing:
            self.lbl_detalhes_rede_status.setText(
                "A atualização não pôde iniciar porque outra operação usa a rede."
            )

    def _mostrar_detalhes_rede(self, resultado):
        if not isinstance(resultado, dict) or resultado.get("Cancelada"):
            self._limpar_painel_detalhes_rede("Atualização das informações cancelada.")
            self._log(">> [CANCELADA] Atualização das informações de rede.")
            return
        if not resultado.get("Sucesso"):
            mensagem = resultado.get("Mensagem") or "Não foi possível atualizar as informações de rede."
            self._limpar_painel_detalhes_rede(mensagem)
            self._log(f">> [ERRO] {mensagem}")
            return
        if not self._resultado_rede_corresponde_ao_selecionado(resultado):
            self._limpar_painel_detalhes_rede(
                "A seleção mudou durante a atualização; o resultado foi descartado."
            )
            self._log(">> [AVISO] Resultado de rede descartado após troca de interface.")
            return
        self._detalhes_rede_atual = resultado
        self.texto_detalhes_rede.setPlainText(self._formatar_detalhes_rede(resultado))
        self.btn_copiar_informacoes_rede.setEnabled(True)
        self.lbl_detalhes_rede_status.setText(
            resultado.get("Mensagem") or "Informações de rede atualizadas."
        )
        self._limpar_diagnostico_rede()
        self._log(f">> [OK] {self.lbl_detalhes_rede_status.text()}")

    def _finalizar_atualizacao_detalhes_rede(self, estado):
        if not self._closing:
            self.btn_atualizar_informacoes_rede.setEnabled(True)
            if estado == "cancelled":
                self.lbl_detalhes_rede_status.setText(
                    "Atualização das informações cancelada."
                )

    def _executar_diagnostico_rede_rapido(self):
        adaptador = self._adaptador()
        if not adaptador:
            return
        if self._operacao_ativa("diagnostico_rede"):
            self.lbl_diagnostico_rede.setText("Diagnóstico rápido já está em andamento.")
            return
        detalhes = self._detalhes_rede_atual
        if not self._resultado_rede_corresponde_ao_selecionado(detalhes):
            detalhes = None
        self.lbl_diagnostico_rede.setText(
            "Executando verificações curtas de conectividade..."
        )
        worker = self._run(
            core_logic.ModuloRede.executar_diagnostico_rede_rapido, adaptador,
            detalhes_precoletados=detalhes,
            label=f"Executando diagnóstico rápido: {adaptador}",
            progress=self.progress_rede, indeterminate=True,
            operation_key="diagnostico_rede", blocks_navigation=False,
            on_done=self._mostrar_diagnostico_rede,
            on_finally=self._finalizar_diagnostico_rede,
            silent_if_busy=True,
        )
        if worker is not None:
            self.btn_diagnostico_rede.setEnabled(False)
        elif not self._closing:
            self.lbl_diagnostico_rede.setText(
                "O diagnóstico não pôde iniciar porque outra operação usa a rede."
            )

    def _mostrar_diagnostico_rede(self, resultado):
        if not isinstance(resultado, dict) or resultado.get("Cancelada"):
            self._limpar_diagnostico_rede("Diagnóstico rápido cancelado.")
            self._log(">> [CANCELADA] Diagnóstico rápido de rede.")
            return
        if not resultado.get("Sucesso"):
            mensagem = resultado.get("Mensagem") or "Não foi possível executar o diagnóstico rápido."
            self._limpar_diagnostico_rede(mensagem)
            self._log(f">> [ERRO] {mensagem}")
            return
        detalhes = resultado.get("Detalhes") or {}
        if not self._resultado_rede_corresponde_ao_selecionado(detalhes):
            self._limpar_diagnostico_rede("A seleção mudou; diagnóstico descartado. Execute novamente para a interface atual.")
            self._log(">> [AVISO] Diagnóstico descartado após troca de interface.")
            return
        if detalhes.get("Sucesso") and self._resultado_rede_corresponde_ao_selecionado(detalhes):
            self._detalhes_rede_atual = detalhes
            self.texto_detalhes_rede.setPlainText(self._formatar_detalhes_rede(detalhes))
            self.btn_copiar_informacoes_rede.setEnabled(True)
            self.lbl_detalhes_rede_status.setText(
                detalhes.get("Mensagem") or "Informações de rede atualizadas."
            )
        self.tabela_diagnostico_rede.setRowCount(0)
        for linha in resultado.get("Linhas") or []:
            if not isinstance(linha, dict):
                continue
            row = self.tabela_diagnostico_rede.rowCount()
            self.tabela_diagnostico_rede.insertRow(row)
            for coluna, chave in enumerate(("Verificacao", "Estado", "Detalhe")):
                self.tabela_diagnostico_rede.setItem(
                    row, coluna, QTableWidgetItem(str(linha.get(chave) or "—"))
                )
        self._diagnostico_rede_atual = resultado
        geral = resultado.get("ResultadoGeral") or "Concluído"
        mensagem = resultado.get("Mensagem") or "Diagnóstico rápido concluído."
        self.lbl_diagnostico_rede.setText(f"{geral}: {mensagem}")
        self._log(f">> [OK] Diagnóstico de rede: {geral}. {mensagem}")

    def _finalizar_diagnostico_rede(self, estado):
        if not self._closing:
            self.btn_diagnostico_rede.setEnabled(True)
            if estado == "cancelled":
                self.lbl_diagnostico_rede.setText("Diagnóstico rápido cancelado.")

    def _copiar_informacoes_rede(self):
        if not isinstance(self._detalhes_rede_atual, dict):
            self.lbl_detalhes_rede_status.setText("Não há informações atualizadas para copiar.")
            return
        texto = self._formatar_detalhes_rede(self._detalhes_rede_atual)
        if isinstance(self._diagnostico_rede_atual, dict) and self._diagnostico_rede_atual.get("Sucesso"):
            linhas = ["", "DIAGNÓSTICO RÁPIDO",
                      "Resultado: " + str(self._diagnostico_rede_atual.get("ResultadoGeral") or "—")]
            for item in self._diagnostico_rede_atual.get("Linhas") or []:
                if isinstance(item, dict):
                    linhas.append("%s: %s — %s" % (
                        item.get("Verificacao") or "—", item.get("Estado") or "—",
                        item.get("Detalhe") or "—"))
            texto += chr(10) + chr(10).join(linhas)
        try:
            QApplication.clipboard().setText(
                "CONFIGURADOR TI — INFORMAÇÕES DE REDE" + chr(10) + chr(10) + texto
            )
            self.lbl_detalhes_rede_status.setText(
                "Informações de rede copiadas para a área de transferência."
            )
            self._log(">> [OK] Informações de rede copiadas.")
        except Exception as exc:
            self.lbl_detalhes_rede_status.setText(
                "Não foi possível copiar as informações de rede."
            )
            self._log(f">> [ERRO] Falha ao copiar informações de rede: {exc}")
            try:
                core_logic.logger.exception("Falha ao copiar informações de rede")
            except Exception:
                pass

    def _adaptador(self):
        idx = self.combo_adaptador.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "Rede", "Selecione um adaptador.")
            return None
        return self.combo_adaptador.itemData(idx)

    @staticmethod
    def _validar_ip(text):
        try:
            return str(ipaddress.ip_address(text.strip()))
        except ValueError:
            return None

    def _aplicar_dns(self):
        ad = self._adaptador()
        if not ad:
            return
        raw = self.campo_dns.text().strip()
        ips = [x.strip() for x in raw.split(",") if x.strip()]
        if not ips or any(not self._validar_ip(x) for x in ips):
            QMessageBox.warning(self, "DNS", "Informe IP(s) válidos.")
            return
        self._run(
            core_logic.ModuloRede.aplicar_dns,
            ad, ips,
            label=f"Aplicando DNS em {ad}",
            admin_reason="alterar DNS",
            progress=self.progress_rede,
            indeterminate=True,
            on_done=self._resultado_generico,
        )

    def _restaurar_dhcp(self):
        ad = self._adaptador()
        if not ad:
            return
        self._run(
            core_logic.ModuloRede.restaurar_dhcp,
            ad,
            label=f"Restaurando DHCP em {ad}",
            admin_reason="restaurar DNS via DHCP",
            progress=self.progress_rede,
            on_done=lambda ok: self._resultado_generico(
                (ok, "DHCP restaurado." if ok else "Falha ao restaurar DHCP.")
            ),
        )

    def _renovar_conexao(self):
        self._run(
            core_logic.ModuloRede.renovar_ip_e_flush_dns,
            label="Renovando conexão",
            admin_reason="renovar IP e limpar cache DNS",
            progress=self.progress_rede,
            on_done=self._resultado_generico,
        )

    def _aplicar_ip_fixo(self):
        ad = self._adaptador()
        if not ad:
            return
        ip = self._validar_ip(self.campo_ip.text())
        mascara = self._validar_ip(self.campo_mascara.text())
        gateway = self._validar_ip(self.campo_gateway.text())
        if not ip or not mascara or not gateway:
            QMessageBox.warning(
                self, "IP fixo",
                "IP, máscara e gateway precisam ser endereços IPv4 válidos."
            )
            return

        # O core atual recebe exatamente estes argumentos; mantém a API existente.
        self._run(
            core_logic.ModuloRede.configurar_ip_fixo,
            ad, ip, mascara, gateway,
            label=f"Configurando IP fixo em {ad}",
            admin_reason="configurar IP, máscara e gateway",
            progress=self.progress_rede,
            indeterminate=True,
            on_done=self._resultado_generico,
        )

    def _detalhes_interface(self):
        ad = self._adaptador()
        if not ad:
            return
        self._run(
            core_logic.ModuloRede.consultar_detalhes_interface_texto,
            ad,
            label=f"Consultando detalhes de {ad}",
            progress=self.progress_rede,
            on_done=self._mostrar_texto_dialogo(f"Detalhes da interface — {ad}"),
        )

    def _resultado_generico(self, result):
        if isinstance(result, tuple):
            ok, msg = result[0], result[1] if len(result) > 1 else ""
        else:
            ok, msg = bool(result), str(result)

        self._log((">> [OK] " if ok else ">> [ERRO] ") + str(msg))
        if ok:
            QMessageBox.information(self, "Concluído", str(msg) or "Operação concluída.")
        else:
            QMessageBox.critical(self, "Falha", str(msg) or "Operação falhou.")

    # ---------------------------------------------------------
    # Manutenção
    # ---------------------------------------------------------
    def _build_manutencao(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Manutenção & Diagnóstico",
            "Operações de manutenção com confirmação e progresso visual."
        ))

        quick = self._card("Manutenção rápida")
        ql = QGridLayout(quick)

        actions = [
            ("🧹 Analisar limpeza segura", self._analisar_limpeza_segura),
            ("🖨 Reiniciar spooler", self._spooler),
            ("🔄 Windows Update", self._windows_update),
            ("🪟 Versão do Windows", self._versao_windows),
            ("🔋 Planos de energia", self._planos_energia),
            ("🖥 Renomear computador", self._renomear),
        ]
        for i, (text, fn) in enumerate(actions):
            b = QPushButton(text)
            b.setProperty("class", "ActionButton")
            b.clicked.connect(fn)
            ql.addWidget(b, i // 3, i % 3)
        layout.addWidget(quick)

        limpeza_rapida = self._card("Limpeza rápida segura")
        lr = QVBoxLayout(limpeza_rapida)
        lbl_limpeza_rapida = QLabel(
            "Analise antes de apagar. As categorias rápidas não incluem "
            "Downloads, Documentos, Área de Trabalho, navegador, e-mail, "
            "OneDrive ou dados do Configurador TI."
        )
        lbl_limpeza_rapida.setWordWrap(True)
        lr.addWidget(lbl_limpeza_rapida)
        self.tabela_limpeza_rapida = QTableWidget(0, 5)
        self._configurar_tabela_limpeza_segura(self.tabela_limpeza_rapida, 155)
        lr.addWidget(self.tabela_limpeza_rapida)

        acoes_limpeza = FlowRow()
        self.btn_analisar_limpeza_segura = QPushButton(
            "🔎 Analisar espaço recuperável"
        )
        self.btn_analisar_limpeza_segura.setProperty("class", "ActionButton")
        self.btn_analisar_limpeza_segura.clicked.connect(
            self._analisar_limpeza_segura
        )
        self.btn_executar_limpeza_segura = QPushButton("🧹 Limpar selecionados")
        self.btn_executar_limpeza_segura.setProperty("class", "MenuButton")
        self.btn_executar_limpeza_segura.setEnabled(False)
        self.btn_executar_limpeza_segura.clicked.connect(
            self._executar_limpeza_segura
        )
        acoes_limpeza.addWidget(self.btn_analisar_limpeza_segura)
        acoes_limpeza.addWidget(self.btn_executar_limpeza_segura)
        acoes_limpeza.addStretch()
        lr.addLayout(acoes_limpeza)

        self.progress_limpeza_segura = QProgressBar()
        self.progress_limpeza_segura.hide()
        lr.addWidget(self.progress_limpeza_segura)
        self.lbl_resultado_limpeza_segura = QLabel(
            "Execute a análise para estimar o espaço recuperável."
        )
        self.lbl_resultado_limpeza_segura.setObjectName("SubtituloTela")
        self.lbl_resultado_limpeza_segura.setWordWrap(True)
        lr.addWidget(self.lbl_resultado_limpeza_segura)
        self._analise_limpeza_segura_atual = None
        layout.addWidget(limpeza_rapida)

        limpeza_avancada = self._card("Limpeza avançada controlada")
        la = QVBoxLayout(limpeza_avancada)
        lbl_limpeza_avancada = QLabel(
            "Categorias de maior impacto permanecem desmarcadas. Leia a "
            "descrição, selecione conscientemente e confirme antes de limpar."
        )
        lbl_limpeza_avancada.setWordWrap(True)
        la.addWidget(lbl_limpeza_avancada)
        self.tabela_limpeza_avancada = QTableWidget(0, 5)
        self._configurar_tabela_limpeza_segura(
            self.tabela_limpeza_avancada, 150
        )
        la.addWidget(self.tabela_limpeza_avancada)
        layout.addWidget(limpeza_avancada)

        saude_sistema = self._card("Saúde do sistema")
        ss = QVBoxLayout(saude_sistema)
        self.lbl_saude_sistema = QLabel(
            "Leitura consolidada e somente informativa. Nenhuma recomendação "
            "é executada automaticamente."
        )
        self.lbl_saude_sistema.setWordWrap(True)
        ss.addWidget(self.lbl_saude_sistema)
        acoes_saude_sistema = FlowRow()
        self.btn_atualizar_saude_sistema = QPushButton(
            "🩺 Atualizar saúde do sistema"
        )
        self.btn_atualizar_saude_sistema.setProperty("class", "ActionButton")
        self.btn_atualizar_saude_sistema.clicked.connect(
            self._atualizar_saude_sistema
        )
        acoes_saude_sistema.addWidget(self.btn_atualizar_saude_sistema)
        acoes_saude_sistema.addStretch()
        ss.addLayout(acoes_saude_sistema)
        self.progress_saude_sistema = QProgressBar()
        self.progress_saude_sistema.hide()
        ss.addWidget(self.progress_saude_sistema)
        self.tabela_saude_sistema = QTableWidget(0, 4)
        self.tabela_saude_sistema.setHorizontalHeaderLabels(
            ["Item", "Estado", "Detalhe", "Recomendação"]
        )
        self.tabela_saude_sistema.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_saude_sistema.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tabela_saude_sistema.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_saude_sistema.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_saude_sistema.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.tabela_saude_sistema.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._configurar_tabela_legivel(self.tabela_saude_sistema, 180)
        ss.addWidget(self.tabela_saude_sistema)
        self.lbl_recomendacoes_saude_sistema = QLabel(
            "Atualize para consultar recomendações informativas."
        )
        self.lbl_recomendacoes_saude_sistema.setObjectName("SubtituloTela")
        self.lbl_recomendacoes_saude_sistema.setWordWrap(True)
        ss.addWidget(self.lbl_recomendacoes_saude_sistema)
        layout.addWidget(saude_sistema)

        disk = self._card("Discos")
        dl = QGridLayout(disk)

        self.combo_unidade = QComboBox()
        self.btn_unidades = QPushButton("🔄 Atualizar unidades")
        self.btn_chkdsk = QPushButton("🔍 Verificar erros (CHKDSK)")
        self.btn_otimizar = QPushButton("⚡ Otimizar / Desfragmentar")

        for b in (self.btn_unidades, self.btn_chkdsk, self.btn_otimizar):
            b.setProperty("class", "ActionButton")

        self.btn_unidades.clicked.connect(self._carregar_unidades)
        self.btn_chkdsk.clicked.connect(self._chkdsk)
        self.btn_otimizar.clicked.connect(self._otimizar)

        dl.addWidget(QLabel("Unidade:"), 0, 0)
        dl.addWidget(self.combo_unidade, 0, 1)
        dl.addWidget(self.btn_unidades, 0, 2)
        dl.addWidget(self.btn_chkdsk, 1, 1)
        dl.addWidget(self.btn_otimizar, 1, 2)

        self.lbl_status_unidades = QLabel("")
        self.lbl_status_unidades.setObjectName("SubtituloTela")
        dl.addWidget(self.lbl_status_unidades, 2, 0, 1, 3)

        self.progress_manutencao = QProgressBar()
        self.progress_manutencao.hide()
        dl.addWidget(self.progress_manutencao, 3, 0, 1, 3)

        layout.addWidget(disk)

        # A saúde de armazenamento é uma leitura técnica sob demanda. Ela fica
        # próxima de CHKDSK/Otimização por tratar do mesmo domínio, mas em
        # card separado para não sugerir que execute reparo, desfragmentação ou
        # qualquer alteração automática no disco.
        saude = self._card("Saúde de armazenamento")
        sl = QVBoxLayout(saude)
        self._dados_saude_armazenamento = None
        self._resumo_saude_armazenamento = ""

        self.lbl_saude_armazenamento = QLabel(
            "Consulta sob demanda e somente leitura. SMART/confiabilidade "
            "indica o que o Windows e o driver expõem; CHKDSK verifica a "
            "integridade do sistema de arquivos."
        )
        self.lbl_saude_armazenamento.setWordWrap(True)
        sl.addWidget(self.lbl_saude_armazenamento)

        acoes_saude = FlowRow()
        self.btn_analisar_saude_armazenamento = QPushButton(
            "🩺 Analisar saúde dos discos"
        )
        self.btn_analisar_saude_armazenamento.setProperty("class", "ActionButton")
        self.btn_analisar_saude_armazenamento.clicked.connect(
            self._analisar_saude_armazenamento
        )
        self.btn_saude_armazenamento_admin = QPushButton(
            "🔐 Obter dados avançados (Admin)"
        )
        self.btn_saude_armazenamento_admin.setProperty("class", "ActionButton")
        self.btn_saude_armazenamento_admin.setEnabled(False)
        self.btn_saude_armazenamento_admin.hide()
        self.btn_saude_armazenamento_admin.clicked.connect(
            self._analisar_saude_armazenamento_elevada
        )
        self.btn_copiar_saude_armazenamento = QPushButton(
            "📋 Copiar informações"
        )
        self.btn_copiar_saude_armazenamento.setProperty("class", "MenuButton")
        self.btn_copiar_saude_armazenamento.setEnabled(False)
        self.btn_copiar_saude_armazenamento.clicked.connect(
            self._copiar_saude_armazenamento
        )
        acoes_saude.addWidget(self.btn_analisar_saude_armazenamento)
        acoes_saude.addWidget(self.btn_saude_armazenamento_admin)
        acoes_saude.addWidget(self.btn_copiar_saude_armazenamento)
        acoes_saude.addStretch()
        sl.addLayout(acoes_saude)

        self.progress_saude_armazenamento = QProgressBar()
        self.progress_saude_armazenamento.hide()
        sl.addWidget(self.progress_saude_armazenamento)

        self.tabela_saude_armazenamento = QTableWidget(0, 8)
        self.tabela_saude_armazenamento.setHorizontalHeaderLabels(
            [
                "Disco",
                "Modelo",
                "Tipo / interface",
                "Capacidade",
                "Saúde",
                "Temperatura",
                "SMART / confiabilidade",
                "Unidades",
            ]
        )
        self.tabela_saude_armazenamento.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_saude_armazenamento.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        for coluna in (0, 3, 4, 5, 6, 7):
            self.tabela_saude_armazenamento.horizontalHeader().setSectionResizeMode(
                coluna, QHeaderView.ResizeMode.ResizeToContents
            )
        self.tabela_saude_armazenamento.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.tabela_saude_armazenamento.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self._configurar_tabela_legivel(self.tabela_saude_armazenamento, 210)
        sl.addWidget(self.tabela_saude_armazenamento)

        # R2: seções por assunto na mesma visão, com raw integral recolhível.
        # O resumo completo para copiar permanece separado em memória.
        self.abas_saude_armazenamento = ConsolidatedSections()
        self.abas_saude_armazenamento.setMinimumHeight(235)
        self.abas_saude_armazenamento.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.texto_saude_resumo = ReadoutPanel(include_raw=False)
        self.texto_saude_identificacao = ReadoutPanel(include_raw=False)
        self.texto_saude_smart = ReadoutPanel(include_raw=False)
        self.texto_saude_contadores = ReadoutPanel(include_raw=False)
        self._textos_detalhes_saude_armazenamento = (
            self.texto_saude_resumo,
            self.texto_saude_identificacao,
            self.texto_saude_smart,
            self.texto_saude_contadores,
        )
        for texto in self._textos_detalhes_saude_armazenamento:
            texto.setReadOnly(True)
            texto.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
            )
            texto.setPlainText(
                "Nenhuma análise de saúde de armazenamento foi executada."
            )
        self.abas_saude_armazenamento.addTab(self.texto_saude_resumo, "Resumo")
        self.abas_saude_armazenamento.addTab(
            self.texto_saude_identificacao, "Identificação"
        )
        self.abas_saude_armazenamento.addTab(self.texto_saude_smart, "SMART / Saúde")
        self.abas_saude_armazenamento.addTab(
            self.texto_saude_contadores, "Contadores"
        )
        # Mantém o atributo legado para não alterar os fluxos visuais já
        # existentes; ele agora representa a aba de resumo.
        self.texto_saude_armazenamento = self.texto_saude_resumo
        sl.addWidget(self.abas_saude_armazenamento)
        self.raw_saude_armazenamento = RawDataSection("Dados brutos completos de armazenamento", "Discos / unidades", "Saúde de armazenamento")
        sl.addWidget(self.raw_saude_armazenamento)

        layout.addWidget(saude)
        self.abas_manutencao = QTabWidget()
        self.abas_manutencao.setMinimumHeight(280)
        for widget in (quick, limpeza_rapida, limpeza_avancada, saude_sistema, disk, saude):
            layout.removeWidget(widget)
        for title, widgets in (
            ("Saúde do sistema", [saude_sistema, quick]),
            ("Limpeza segura", [limpeza_rapida, limpeza_avancada]),
            ("Armazenamento", [saude, disk]),
            ("Sensores", [self._criar_card_sensores_hardware()]),
            ("Benchmark", [self._criar_card_benchmark_configurador_ti()]),
        ):
            self.abas_manutencao.addTab(scroll_content(widgets), title)
        # A ação rápida mantém o resultado no campo de visão, sem outra coleta.
        for button in quick.findChildren(QPushButton):
            if "Analisar limpeza" in button.text():
                button.clicked.connect(lambda: self.abas_manutencao.setCurrentIndex(1))
        layout.addWidget(self.abas_manutencao)
        self._adicionar_pagina_rolavel(page)

    def _criar_card_sensores_hardware(self):
        """Monta a telemetria sob demanda no domínio de Manutenção."""
        sensores = self._card("Sensores de hardware")
        sensores_layout = QVBoxLayout(sensores)
        sensores_intro = QLabel(
            "Consulta manual e somente leitura com fontes nativas do Windows. "
            "Temperaturas, RPM e contadores que o firmware não expuser aparecem "
            "como não disponíveis — nunca são estimados."
        )
        sensores_intro.setObjectName("SubtituloTela")
        sensores_intro.setWordWrap(True)
        sensores_layout.addWidget(sensores_intro)

        sensores_controles = FlowRow()
        self.btn_atualizar_sensores = QPushButton("↻ Atualizar sensores")
        self.btn_atualizar_sensores.setProperty("class", "ActionButton")
        self.btn_atualizar_sensores.clicked.connect(
            self._atualizar_sensores_hardware
        )
        sensores_controles.addWidget(self.btn_atualizar_sensores)
        sensores_controles.addStretch()
        sensores_layout.addLayout(sensores_controles)

        self.lbl_sensores_hardware = QLabel(
            "Ainda não consultado. A atualização não solicita UAC e pode ser feita a qualquer momento."
        )
        self.lbl_sensores_hardware.setObjectName("SubtituloTela")
        self.lbl_sensores_hardware.setWordWrap(True)
        sensores_layout.addWidget(self.lbl_sensores_hardware)

        self.progress_sensores_hardware = QProgressBar()
        self.progress_sensores_hardware.setTextVisible(True)
        self.progress_sensores_hardware.hide()
        sensores_layout.addWidget(self.progress_sensores_hardware)

        # R2: resumo e componentes na mesma visão. Fonte/limitação em tooltip
        # e no payload bruto completo copiável, sem nova coleta.
        self.abas_sensores_hardware = ConsolidatedSections()
        self.abas_sensores_hardware.setMinimumHeight(270)
        self.abas_sensores_hardware.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        sensores_layout.addWidget(self.abas_sensores_hardware)
        return sensores

    def _criar_card_benchmark_configurador_ti(self):
        """Monta o benchmark próprio sem criar uma nova página principal."""
        benchmark = self._card("Benchmark Configurador TI")
        bl = QVBoxLayout(benchmark)

        introducao = QLabel(
            "Teste técnico próprio, limitado e comparável somente com execuções "
            "desta mesma máquina. CPU, RAM e armazenamento são medidos em segundo "
            "plano; não há alteração de plano de energia, UAC automático, acesso "
            "a arquivos pessoais ou benchmark de GPU nesta fase."
        )
        introducao.setObjectName("SubtituloTela")
        introducao.setWordWrap(True)
        bl.addWidget(introducao)

        controles = FlowRow()
        controles.addWidget(QLabel("Modo:"))
        self.combo_modo_benchmark_configurador_ti = QComboBox()
        self.combo_modo_benchmark_configurador_ti.addItem(
            "Rápido — baixo impacto (aprox. 30–90 s)", "rapido"
        )
        self.combo_modo_benchmark_configurador_ti.addItem(
            "Completo — controlado (aprox. 2–5 min)", "completo"
        )
        controles.addWidget(self.combo_modo_benchmark_configurador_ti, 1)

        self.btn_executar_benchmark_configurador_ti = QPushButton("▶ Executar benchmark")
        self.btn_executar_benchmark_configurador_ti.setProperty("class", "ActionButton")
        self.btn_executar_benchmark_configurador_ti.clicked.connect(
            self._executar_benchmark_configurador_ti
        )
        controles.addWidget(self.btn_executar_benchmark_configurador_ti)

        self.btn_cancelar_benchmark_configurador_ti = QPushButton("■ Cancelar")
        self.btn_cancelar_benchmark_configurador_ti.setProperty("class", "DangerButton")
        self.btn_cancelar_benchmark_configurador_ti.setEnabled(False)
        self.btn_cancelar_benchmark_configurador_ti.clicked.connect(
            self._cancelar_benchmark_configurador_ti
        )
        controles.addWidget(self.btn_cancelar_benchmark_configurador_ti)
        bl.addLayout(controles)

        self.lbl_benchmark_configurador_ti = QLabel(
            "Selecione o modo e execute quando a máquina estiver sem tarefas pesadas."
        )
        self.lbl_benchmark_configurador_ti.setObjectName("SubtituloTela")
        self.lbl_benchmark_configurador_ti.setWordWrap(True)
        bl.addWidget(self.lbl_benchmark_configurador_ti)

        self.lbl_etapa_benchmark_configurador_ti = QLabel("Etapa atual: aguardando.")
        self.lbl_etapa_benchmark_configurador_ti.setObjectName("SubtituloTela")
        self.lbl_etapa_benchmark_configurador_ti.setWordWrap(True)
        bl.addWidget(self.lbl_etapa_benchmark_configurador_ti)

        self.progress_benchmark_configurador_ti = QProgressBar()
        self.progress_benchmark_configurador_ti.setTextVisible(True)
        self.progress_benchmark_configurador_ti.hide()
        bl.addWidget(self.progress_benchmark_configurador_ti)

        resultados = QGridLayout()
        componentes = (
            ("CPU", "lbl_benchmark_cpu_configurador_ti"),
            ("Memória RAM", "lbl_benchmark_ram_configurador_ti"),
            ("Armazenamento", "lbl_benchmark_armazenamento_configurador_ti"),
            ("Configurador TI Geral", "lbl_benchmark_geral_configurador_ti"),
        )
        for indice, (titulo, atributo) in enumerate(componentes):
            card = self._card(titulo)
            card_layout = QVBoxLayout(card)
            label = QLabel("Ainda não executado.")
            label.setObjectName("SubtituloTela")
            label.setWordWrap(True)
            label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            card_layout.addWidget(label)
            setattr(self, atributo, label)
            resultados.addWidget(card, indice // 2, indice % 2)
        bl.addLayout(resultados)

        self.lbl_benchmark_gpu_configurador_ti = QLabel(
            "GPU: Benchmark de GPU não disponível nesta fase; nenhum score será estimado."
        )
        self.lbl_benchmark_gpu_configurador_ti.setObjectName("SubtituloTela")
        self.lbl_benchmark_gpu_configurador_ti.setWordWrap(True)
        bl.addWidget(self.lbl_benchmark_gpu_configurador_ti)

        comparacao = self._card("Histórico local e comparação")
        cl = QVBoxLayout(comparacao)
        self.lbl_comparacao_benchmark_configurador_ti = QLabel(
            "Ainda não há comparação. As variações serão apenas informativas."
        )
        self.lbl_comparacao_benchmark_configurador_ti.setObjectName("SubtituloTela")
        self.lbl_comparacao_benchmark_configurador_ti.setWordWrap(True)
        cl.addWidget(self.lbl_comparacao_benchmark_configurador_ti)
        self.texto_historico_benchmark_configurador_ti = QTextEdit()
        self.texto_historico_benchmark_configurador_ti.setReadOnly(True)
        self.texto_historico_benchmark_configurador_ti.setMinimumHeight(120)
        self.texto_historico_benchmark_configurador_ti.setPlainText(
            "Nenhum histórico carregado nesta sessão."
        )
        cl.addWidget(self.texto_historico_benchmark_configurador_ti)
        acoes_historico = FlowRow()
        self.btn_historico_benchmark_configurador_ti = QPushButton("↻ Ver último resultado")
        self.btn_historico_benchmark_configurador_ti.setProperty("class", "MenuButton")
        self.btn_historico_benchmark_configurador_ti.clicked.connect(
            self._carregar_historico_benchmark_configurador_ti
        )
        acoes_historico.addWidget(self.btn_historico_benchmark_configurador_ti)
        self.btn_copiar_benchmark_configurador_ti = QPushButton("📋 Copiar resultado")
        self.btn_copiar_benchmark_configurador_ti.setProperty("class", "MenuButton")
        self.btn_copiar_benchmark_configurador_ti.setEnabled(False)
        self.btn_copiar_benchmark_configurador_ti.clicked.connect(
            self._copiar_resultado_benchmark_configurador_ti
        )
        acoes_historico.addWidget(self.btn_copiar_benchmark_configurador_ti)
        acoes_historico.addStretch()
        cl.addLayout(acoes_historico)
        bl.addWidget(comparacao)

        self._ultimo_benchmark_configurador_ti = None
        return benchmark

    @staticmethod
    def _formatar_bytes_benchmark_configurador_ti(valor):
        try:
            tamanho = max(0, int(valor))
        except (TypeError, ValueError):
            return "Não disponível"
        unidades = ("B", "KiB", "MiB", "GiB", "TiB")
        indice = 0
        while tamanho >= 1024 and indice < len(unidades) - 1:
            tamanho /= 1024.0
            indice += 1
        return f"{tamanho:.1f} {unidades[indice]}" if indice else f"{tamanho:.0f} B"

    @staticmethod
    def _formatar_score_benchmark_configurador_ti(valor):
        if isinstance(valor, bool) or valor is None:
            return "Não disponível"
        try:
            return str(int(round(float(valor))))
        except (TypeError, ValueError):
            return "Não disponível"

    def _texto_historico_benchmark_configurador_ti(self, resultados):
        linhas = []
        for resultado in (resultados or [])[:5]:
            if not isinstance(resultado, dict):
                continue
            scores = resultado.get("Scores") if isinstance(resultado.get("Scores"), dict) else {}
            linhas.append(
                "{quando} — {modo} | Geral: {geral} | CPU: {cpu} | RAM: {ram} | Disco: {disco}".format(
                    quando=local_timestamp(resultado.get("Timestamp"))[0] if resultado.get("Timestamp") else "Data não disponível",
                    modo=resultado.get("Modo") or "Modo não disponível",
                    geral=self._formatar_score_benchmark_configurador_ti(scores.get("Geral")),
                    cpu=self._formatar_score_benchmark_configurador_ti(scores.get("CPU")),
                    ram=self._formatar_score_benchmark_configurador_ti(scores.get("RAM")),
                    disco=self._formatar_score_benchmark_configurador_ti(scores.get("Armazenamento")),
                )
            )
        return "\n".join(linhas) if linhas else "Nenhum resultado local encontrado nesta máquina."

    def _operacao_conflitante_benchmark_configurador_ti(self):
        conflitos = (
            ("limpeza_segura", "Limpeza segura"),
            ("saude_sistema", "Saúde do sistema"),
            ("saude_armazenamento", "Saúde de armazenamento"),
            ("chkdsk_unidade", "CHKDSK"),
            ("otimizacao_unidade", "Otimização de unidade"),
        )
        for chave, titulo in conflitos:
            if self._operacao_ativa(chave):
                return titulo
        return None

    @staticmethod
    def _aviso_energia_benchmark_configurador_ti(modo):
        """Obtém um aviso leve antes do modo Completo, sem PowerShell/UAC.

        ``GetSystemPowerStatus`` é uma consulta nativa imediata. A verificação
        também é repetida no Worker para manter o backend correto quando ele
        for chamado sem a GUI.
        """
        if str(modo or "").casefold() != "completo":
            return ""
        try:
            energia = core_logic.ModuloSistema._energia_nativa_benchmark_configurador_ti()
        except Exception:
            return ""
        if isinstance(energia, dict) and energia.get("EmBateria") is True:
            return (
                "Aviso: o notebook está em bateria. Conecte-o à energia quando "
                "possível para um resultado mais comparável; o plano de energia "
                "não será alterado."
            )
        return ""

    def _executar_benchmark_configurador_ti(self):
        if self._closing or not hasattr(self, "combo_modo_benchmark_configurador_ti"):
            return
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_benchmark_configurador_ti.setText("Já existe um Benchmark Configurador TI em andamento.")
            return
        conflito = self._operacao_conflitante_benchmark_configurador_ti()
        if conflito:
            self.lbl_benchmark_configurador_ti.setText(
                f"{conflito} está em andamento. Aguarde antes de medir armazenamento."
            )
            return

        modo = str(self.combo_modo_benchmark_configurador_ti.currentData() or "rapido")
        nome_modo = "Completo" if modo == "completo" else "Rápido"
        aviso_energia = self._aviso_energia_benchmark_configurador_ti(modo)
        self._ultimo_benchmark_configurador_ti = None
        self.btn_executar_benchmark_configurador_ti.setEnabled(False)
        self.btn_cancelar_benchmark_configurador_ti.setEnabled(True)
        self.btn_copiar_benchmark_configurador_ti.setEnabled(False)
        texto_inicio = (
            f"Benchmark Configurador TI {nome_modo} em andamento em segundo plano; "
            "você pode navegar pela interface."
        )
        if aviso_energia:
            texto_inicio += f"\n{aviso_energia}"
        self.lbl_benchmark_configurador_ti.setText(texto_inicio)
        self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: preparando pré-condições.")
        for label in (
            self.lbl_benchmark_cpu_configurador_ti,
            self.lbl_benchmark_ram_configurador_ti,
            self.lbl_benchmark_armazenamento_configurador_ti,
            self.lbl_benchmark_geral_configurador_ti,
        ):
            label.setText("Aguardando etapa do benchmark…")

        snapshot_armazenamento = (
            self._dados_saude_armazenamento
            if isinstance(getattr(self, "_dados_saude_armazenamento", None), dict)
            else None
        )
        worker = self._run(
            core_logic.ModuloSistema.executar_benchmark_configurador_ti,
            modo,
            snapshot_armazenamento,
            label=f"Benchmark Configurador TI {nome_modo}",
            progress=self.progress_benchmark_configurador_ti,
            indeterminate=False,
            operation_key="benchmark_configurador_ti",
            blocks_navigation=False,
            on_done=self._mostrar_resultado_benchmark_configurador_ti,
            on_finally=self._finalizar_benchmark_configurador_ti,
            silent_if_busy=True,
        )
        if worker is None and not self._closing:
            self.btn_executar_benchmark_configurador_ti.setEnabled(True)
            self.btn_cancelar_benchmark_configurador_ti.setEnabled(False)
            self.lbl_benchmark_configurador_ti.setText("Não foi possível iniciar o Benchmark Configurador TI.")

    def _cancelar_benchmark_configurador_ti(self):
        worker = self._operation_workers.get("benchmark_configurador_ti")
        if worker is None or worker not in self._workers:
            self.lbl_benchmark_configurador_ti.setText("Nenhum Benchmark Configurador TI ativo para cancelar.")
            return
        try:
            worker.requestInterruption()
            self.btn_cancelar_benchmark_configurador_ti.setEnabled(False)
            self.lbl_benchmark_configurador_ti.setText(
                "Cancelamento solicitado. A etapa atual será interrompida de forma cooperativa e o arquivo temporário será removido."
            )
            self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: cancelando com segurança…")
        except Exception as exc:
            self._log(f">> [ERRO] Falha ao solicitar cancelamento do Benchmark Configurador TI: {exc}")

    def _mostrar_resultado_benchmark_configurador_ti(self, resultado):
        if not isinstance(resultado, dict):
            raise ValueError("Retorno inválido do Benchmark Configurador TI.")
        if resultado.get("Cancelada"):
            self.lbl_benchmark_configurador_ti.setText(
                resultado.get("Mensagem") or "Benchmark Configurador TI cancelado. Nenhum resultado foi salvo."
            )
            self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: cancelada.")
            self._log(">> [CANCELADA] BENCHMARK_CONFIGURADOR_TI.")
            return
        if not resultado.get("Sucesso"):
            mensagem = resultado.get("Mensagem") or "Benchmark Configurador TI não foi concluído."
            self.lbl_benchmark_configurador_ti.setText(mensagem)
            self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: falha controlada.")
            self._log(f">> [ERRO] BENCHMARK_CONFIGURADOR_TI: {mensagem}")
            return

        componentes = resultado.get("Componentes") if isinstance(resultado.get("Componentes"), dict) else {}
        scores = resultado.get("Scores") if isinstance(resultado.get("Scores"), dict) else {}
        contexto = resultado.get("Contexto") if isinstance(resultado.get("Contexto"), dict) else {}
        cpu = componentes.get("CPU") if isinstance(componentes.get("CPU"), dict) else {}
        ram = componentes.get("RAM") if isinstance(componentes.get("RAM"), dict) else {}
        armazenamento = (
            componentes.get("Armazenamento")
            if isinstance(componentes.get("Armazenamento"), dict) else {}
        )
        metricas_cpu = cpu.get("Metricas") if isinstance(cpu.get("Metricas"), dict) else {}
        metricas_ram = ram.get("Metricas") if isinstance(ram.get("Metricas"), dict) else {}
        metricas_disco = (
            armazenamento.get("Metricas")
            if isinstance(armazenamento.get("Metricas"), dict) else {}
        )
        contexto_cpu = contexto.get("CPU") if isinstance(contexto.get("CPU"), dict) else {}
        contexto_ram = contexto.get("RAM") if isinstance(contexto.get("RAM"), dict) else {}

        self.lbl_benchmark_cpu_configurador_ti.setText(
            "Modelo: {modelo}\nNúcleos / threads: {nucleos} / {threads}\n"
            "Clock reportado: {clock}\nCiclos/s: {ciclos}\nCONFIGURADOR_TI CPU: {score}".format(
                modelo=contexto_cpu.get("Modelo") or "Não disponível",
                nucleos=contexto_cpu.get("Nucleos") or "Não disponível",
                threads=contexto_cpu.get("Threads") or "Não disponível",
                clock=(
                    f"{contexto_cpu.get('ClockReportadoMHz')} MHz"
                    if contexto_cpu.get("ClockReportadoMHz") else "Não disponível"
                ),
                ciclos=metricas_cpu.get("CiclosPorSegundo", "Não disponível"),
                score=self._formatar_score_benchmark_configurador_ti(scores.get("CPU")),
            )
        )

        if ram.get("Status") == "OK":
            self.lbl_benchmark_ram_configurador_ti.setText(
                "RAM total: {total}\nDisponível antes: {livre}\nBuffer: {buffer}\n"
                "Leitura: {leitura} MB/s | Cópia: {copia} MB/s | Escrita: {escrita} MB/s\n"
                "Configurador TI RAM: {score}".format(
                    total=self._formatar_bytes_benchmark_configurador_ti(contexto_ram.get("TotalBytes")),
                    livre=self._formatar_bytes_benchmark_configurador_ti(metricas_ram.get("DisponivelAntesBytes")),
                    buffer=self._formatar_bytes_benchmark_configurador_ti(metricas_ram.get("BufferBytes")),
                    leitura=metricas_ram.get("LeituraMBps", "—"),
                    copia=metricas_ram.get("CopiaMBps", "—"),
                    escrita=metricas_ram.get("EscritaMBps", "—"),
                    score=self._formatar_score_benchmark_configurador_ti(scores.get("RAM")),
                )
            )
        else:
            self.lbl_benchmark_ram_configurador_ti.setText(
                f"RAM: {ram.get('Status') or 'Não disponível'}\n"
                f"{ram.get('Mensagem') or 'Nenhum score foi atribuído.'}"
            )

        if armazenamento.get("Status") == "OK":
            temperaturas = contexto.get("TemperaturasArmazenamentoSnapshot") or []
            texto_temperatura = (
                "\nTemperatura(s) do último snapshot: " + "; ".join(map(str, temperaturas))
                if temperaturas else ""
            )
            self.lbl_benchmark_armazenamento_configurador_ti.setText(
                "Volume: {volume}\nLivre antes: {livre}\nEscrita: {escrita} MB/s | Leitura: {leitura} MB/s\n"
                "Latência da primeira leitura: {latencia} ms\nEscrita máxima: {maximo}\n"
                "Configurador TI Armazenamento: {score}{temperatura}".format(
                    volume=metricas_disco.get("Volume", "Não disponível"),
                    livre=self._formatar_bytes_benchmark_configurador_ti(metricas_disco.get("EspacoLivreAntesBytes")),
                    escrita=metricas_disco.get("EscritaMBps", "—"),
                    leitura=metricas_disco.get("LeituraMBps", "—"),
                    latencia=metricas_disco.get("LatenciaPrimeiraLeituraMs", "—"),
                    maximo=self._formatar_bytes_benchmark_configurador_ti(metricas_disco.get("EscritaMaximaBytes")),
                    score=self._formatar_score_benchmark_configurador_ti(scores.get("Armazenamento")),
                    temperatura=texto_temperatura,
                )
            )
        else:
            self.lbl_benchmark_armazenamento_configurador_ti.setText(
                f"Armazenamento: {armazenamento.get('Status') or 'Não disponível'}\n"
                f"{armazenamento.get('Mensagem') or 'Nenhum score foi atribuído.'}"
            )

        pesos = resultado.get("PesosScoreGeral") if isinstance(resultado.get("PesosScoreGeral"), dict) else {}
        pesos_texto = ", ".join(
            f"{nome}: {valor * 100:.0f}%" for nome, valor in pesos.items()
        ) or "Nenhum componente elegível."
        self.lbl_benchmark_geral_configurador_ti.setText(
            "Configurador TI Geral: {score}\nComponentes usados: {pesos}\n"
            "Duração: {duracao} s\nBenchmarkVersion: {versao}".format(
                score=self._formatar_score_benchmark_configurador_ti(scores.get("Geral")),
                pesos=pesos_texto,
                duracao=resultado.get("DuracaoSegundos", "—"),
                versao=resultado.get("BenchmarkVersion", "—"),
            )
        )
        self.lbl_benchmark_gpu_configurador_ti.setText(
            "GPU: Benchmark de GPU não disponível nesta fase; nenhum score foi estimado."
        )

        comparacao = resultado.get("ComparacaoAnterior") if isinstance(resultado.get("ComparacaoAnterior"), dict) else {}
        itens_comparacao = comparacao.get("Itens") if isinstance(comparacao.get("Itens"), list) else []
        if itens_comparacao:
            linhas = []
            for item in itens_comparacao:
                try:
                    variacao = float(item.get("VariacaoPercentual"))
                except (TypeError, ValueError):
                    continue
                sinal = "+" if variacao >= 0 else ""
                linhas.append(
                    f"{item.get('Componente', 'Componente')}: {sinal}{variacao:.1f}% vs teste anterior"
                )
            self.lbl_comparacao_benchmark_configurador_ti.setText(
                "\n".join(linhas) + "\nVariação informativa; não confirma defeito automaticamente."
            )
        else:
            self.lbl_comparacao_benchmark_configurador_ti.setText(
                comparacao.get("Mensagem") or "Sem execução anterior comparável."
            )

        status = resultado.get("Mensagem") or "Benchmark Configurador TI concluído."
        avisos = [
            str(aviso).strip()
            for aviso in (resultado.get("Avisos") or [])
            if str(aviso).strip()
        ]
        if avisos:
            status += "\nAvisos: " + " ".join(avisos)
        if not resultado.get("HistoricoSalvo"):
            status += " " + str(resultado.get("MensagemHistorico") or "Histórico não salvo.")
        self.lbl_benchmark_configurador_ti.setText(status)
        self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: consolidação concluída.")
        self._ultimo_benchmark_configurador_ti = resultado
        self.btn_copiar_benchmark_configurador_ti.setEnabled(True)
        marcador = "[PARCIAL]" if resultado.get("Parcial") else "[OK]"
        self._log(
            f">> {marcador} BENCHMARK_CONFIGURADOR_TI: geral={scores.get('Geral')}; "
            f"duração={resultado.get('DuracaoSegundos')}s."
        )

    def _finalizar_benchmark_configurador_ti(self, estado):
        if self._closing:
            return
        if hasattr(self, "btn_executar_benchmark_configurador_ti"):
            self.btn_executar_benchmark_configurador_ti.setEnabled(True)
        if hasattr(self, "btn_cancelar_benchmark_configurador_ti"):
            self.btn_cancelar_benchmark_configurador_ti.setEnabled(False)
        if estado == "cancelled" and hasattr(self, "lbl_benchmark_configurador_ti"):
            self.lbl_benchmark_configurador_ti.setText(
                "Benchmark Configurador TI cancelado. Nenhum resultado parcial foi salvo como concluído."
            )
            self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: cancelada.")
        elif estado in {"error", "failure"} and hasattr(self, "lbl_etapa_benchmark_configurador_ti"):
            self.lbl_etapa_benchmark_configurador_ti.setText("Etapa atual: falha controlada.")

    def _mostrar_historico_benchmark_configurador_ti(self, resultado):
        if not isinstance(resultado, dict) or not resultado.get("Sucesso"):
            mensagem = (
                resultado.get("Mensagem")
                if isinstance(resultado, dict) else "Retorno inválido do histórico."
            )
            self.texto_historico_benchmark_configurador_ti.setPlainText(str(mensagem))
            return
        resultados = resultado.get("Resultados") or []
        self.texto_historico_benchmark_configurador_ti.setPlainText(
            self._texto_historico_benchmark_configurador_ti(resultados)
        )
        self.texto_historico_benchmark_configurador_ti.setToolTip("\n".join(local_timestamp(r.get("Timestamp"))[1] for r in (resultados or [])[:5] if isinstance(r, dict)))
        self.lbl_benchmark_configurador_ti.setText(resultado.get("Mensagem") or "Histórico atualizado.")

    def _carregar_historico_benchmark_configurador_ti(self):
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_benchmark_configurador_ti.setText(
                "Aguarde o benchmark atual terminar antes de abrir o histórico."
            )
            return
        self.lbl_benchmark_configurador_ti.setText("Carregando histórico local em segundo plano...")
        self._run(
            core_logic.ModuloSistema.obter_historico_benchmark_configurador_ti,
            label="Carregando histórico do Benchmark Configurador TI",
            operation_key="historico_benchmark_configurador_ti",
            blocks_navigation=False,
            on_done=self._mostrar_historico_benchmark_configurador_ti,
            silent_if_busy=True,
        )

    def _formatar_resultado_benchmark_configurador_ti(self, resultado):
        if not isinstance(resultado, dict):
            return ""
        scores = resultado.get("Scores") if isinstance(resultado.get("Scores"), dict) else {}
        contexto = resultado.get("Contexto") if isinstance(resultado.get("Contexto"), dict) else {}
        cpu = contexto.get("CPU") if isinstance(contexto.get("CPU"), dict) else {}
        linhas = [
            "CONFIGURADOR TI — BENCHMARK Configurador TI",
            f"Modo: {resultado.get('Modo', '—')}",
            f"BenchmarkVersion: {resultado.get('BenchmarkVersion', '—')}",
            f"Host: {contexto.get('Hostname', '—')}",
            f"CPU: {cpu.get('Modelo', '—')}",
            f"Duração: {resultado.get('DuracaoSegundos', '—')} s",
            f"Configurador TI CPU: {self._formatar_score_benchmark_configurador_ti(scores.get('CPU'))}",
            f"Configurador TI RAM: {self._formatar_score_benchmark_configurador_ti(scores.get('RAM'))}",
            f"Configurador TI Armazenamento: {self._formatar_score_benchmark_configurador_ti(scores.get('Armazenamento'))}",
            "Configurador TI GPU: não disponível nesta fase",
            f"Configurador TI Geral: {self._formatar_score_benchmark_configurador_ti(scores.get('Geral'))}",
            "Observação: scores Configurador TI são próprios e comparáveis apenas com esta máquina.",
        ]
        return "\n".join(linhas)

    def _copiar_resultado_benchmark_configurador_ti(self):
        texto = self._formatar_resultado_benchmark_configurador_ti(self._ultimo_benchmark_configurador_ti)
        if not texto:
            self.lbl_benchmark_configurador_ti.setText("Não há resultado de benchmark para copiar.")
            return
        try:
            QApplication.clipboard().setText(texto)
            self.lbl_benchmark_configurador_ti.setText(
                "Resultado do Benchmark Configurador TI copiado para a área de transferência."
            )
            self._log(">> [OK] Resultado do Benchmark Configurador TI copiado.")
        except Exception as exc:
            self.lbl_benchmark_configurador_ti.setText(
                "Não foi possível copiar o resultado do Benchmark Configurador TI."
            )
            self._log(f">> [ERRO] Falha ao copiar Benchmark Configurador TI: {exc}")
            try:
                core_logic.logger.exception("Falha ao copiar resultado do Benchmark Configurador TI")
            except Exception:
                pass

    def _pagina_manutencao(self):
        self._set_nav(2)

    def _configurar_tabela_limpeza_segura(self, tabela, altura_minima):
        tabela.setHorizontalHeaderLabels(
            ["Selecionar", "Categoria", "Estimativa", "Itens", "Descrição"]
        )
        tabela.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tabela.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        tabela.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        tabela.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        tabela.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        tabela.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        tabela.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self._configurar_tabela_legivel(tabela, altura_minima)

    def _categorias_selecionadas_limpeza_segura(self):
        selecionadas = []
        for tabela in (
            getattr(self, "tabela_limpeza_rapida", None),
            getattr(self, "tabela_limpeza_avancada", None),
        ):
            if tabela is None:
                continue
            for linha in range(tabela.rowCount()):
                item = tabela.item(linha, 0)
                if (
                    item is not None
                    and item.checkState() == Qt.CheckState.Checked
                ):
                    codigo = item.data(Qt.ItemDataRole.UserRole)
                    if codigo:
                        selecionadas.append(str(codigo))
        return selecionadas

    def _preencher_tabela_limpeza_segura(self, tabela, categorias, selecionadas):
        tabela.setRowCount(0)
        for categoria in categorias:
            if not isinstance(categoria, dict):
                continue
            linha = tabela.rowCount()
            tabela.insertRow(linha)
            codigo = str(categoria.get("Codigo") or "")
            elegivel = bool(categoria.get("Elegivel"))
            marcado = (
                codigo in selecionadas if selecionadas
                else bool(categoria.get("SelecionadaPadrao"))
            )
            selecionar = QTableWidgetItem()
            selecionar.setData(Qt.ItemDataRole.UserRole, codigo)
            selecionar.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | (Qt.ItemFlag.ItemIsUserCheckable if elegivel else Qt.ItemFlag.NoItemFlags)
            )
            selecionar.setCheckState(
                Qt.CheckState.Checked
                if marcado and elegivel else Qt.CheckState.Unchecked
            )
            tabela.setItem(linha, 0, selecionar)
            descricao = str(categoria.get("Descricao") or "—")
            status = str(categoria.get("Status") or "Não disponível")
            if status != "OK":
                descricao = f"{descricao} ({status})"
            valores = (
                categoria.get("Categoria") or "—",
                (
                    categoria.get("TamanhoLegivel")
                    if categoria.get("EstimativaDisponivel", True)
                    else "Não disponível"
                ),
                categoria.get("Quantidade", 0),
                descricao,
            )
            for coluna, valor in enumerate(valores, start=1):
                tabela.setItem(linha, coluna, QTableWidgetItem(str(valor)))

    def _mostrar_analise_limpeza_segura(self, resultado):
        if not isinstance(resultado, dict) or resultado.get("Cancelada"):
            self._analise_limpeza_segura_atual = None
            self.lbl_resultado_limpeza_segura.setText(
                "Análise de limpeza cancelada. Nenhum arquivo foi removido."
            )
            return
        if not resultado.get("Sucesso"):
            self._analise_limpeza_segura_atual = None
            mensagem = resultado.get("Mensagem") or "Não foi possível analisar a limpeza."
            self.lbl_resultado_limpeza_segura.setText(mensagem)
            self._log(f">> [ERRO] Limpeza analisada: {mensagem}")
            return

        selecao_anterior = set(self._categorias_selecionadas_limpeza_segura())
        categorias = resultado.get("Categorias") or []
        rapidas = [
            categoria for categoria in categorias
            if isinstance(categoria, dict) and not categoria.get("Avancada")
        ]
        avancadas = [
            categoria for categoria in categorias
            if isinstance(categoria, dict) and categoria.get("Avancada")
        ]
        self._preencher_tabela_limpeza_segura(
            self.tabela_limpeza_rapida, rapidas, selecao_anterior
        )
        self._preencher_tabela_limpeza_segura(
            self.tabela_limpeza_avancada, avancadas, selecao_anterior
        )
        self._analise_limpeza_segura_atual = resultado
        total = resultado.get("TotalEncontradoLegivel", "0 B")
        quantidade = resultado.get("TotalEncontradoQuantidade", 0)
        falhas = resultado.get("TotalFalhas", 0)
        texto = (
            f"Encontrado: {total} em {quantidade} item(ns). "
            "Nenhum arquivo foi removido; selecione as categorias desejadas "
            "e confirme a limpeza."
        )
        if falhas:
            texto += f" {falhas} item(ns) não puderam ser analisados."
        self.lbl_resultado_limpeza_segura.setText(texto)
        self.btn_executar_limpeza_segura.setEnabled(True)
        self._log(
            f">> [OK] LIMPEZA_ANALISADA: {total} em {quantidade} item(ns)."
        )

    def _analisar_limpeza_segura(self):
        if self._operacao_ativa("limpeza_segura"):
            self.lbl_resultado_limpeza_segura.setText(
                "Já existe uma análise ou limpeza em andamento."
            )
            return
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_resultado_limpeza_segura.setText(
                "O Benchmark Configurador TI está usando arquivo temporário controlado. Aguarde antes de analisar a limpeza."
            )
            return
        if self._operacao_ativa("saude_sistema"):
            self.lbl_resultado_limpeza_segura.setText(
                "A Saúde do sistema está estimando temporários. Aguarde a conclusão "
                "antes de iniciar outra análise de limpeza."
            )
            return
        self._analise_limpeza_segura_atual = None
        self.lbl_resultado_limpeza_segura.setText(
            "Analisando categorias seguras em segundo plano; você pode navegar."
        )
        worker = self._run(
            core_logic.ModuloSistema.analisar_limpeza_segura,
            label="Analisando espaço recuperável",
            progress=self.progress_limpeza_segura,
            indeterminate=True,
            operation_key="limpeza_segura",
            blocks_navigation=False,
            on_done=self._mostrar_analise_limpeza_segura,
            on_finally=self._finalizar_limpeza_segura,
            silent_if_busy=True,
        )
        if worker is not None:
            self.btn_analisar_limpeza_segura.setEnabled(False)
            self.btn_executar_limpeza_segura.setEnabled(False)

    def _executar_limpeza_segura(self):
        if self._operacao_ativa("limpeza_segura"):
            self.lbl_resultado_limpeza_segura.setText(
                "Já existe uma análise ou limpeza em andamento."
            )
            return
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_resultado_limpeza_segura.setText(
                "O Benchmark Configurador TI está usando arquivo temporário controlado. Aguarde antes de limpar."
            )
            return
        if self._operacao_ativa("saude_sistema"):
            self.lbl_resultado_limpeza_segura.setText(
                "A Saúde do sistema está estimando temporários. Aguarde a conclusão "
                "antes de iniciar a limpeza."
            )
            return
        if not self._analise_limpeza_segura_atual:
            self.lbl_resultado_limpeza_segura.setText(
                "Analise as categorias antes de executar a limpeza."
            )
            return
        categorias = self._categorias_selecionadas_limpeza_segura()
        if not categorias:
            self.lbl_resultado_limpeza_segura.setText(
                "Selecione ao menos uma categoria antes de limpar."
            )
            return
        resumo = []
        por_codigo = {
            item.get("Codigo"): item
            for item in self._analise_limpeza_segura_atual.get("Categorias", [])
            if isinstance(item, dict)
        }
        for codigo in categorias:
            categoria = por_codigo.get(codigo, {})
            resumo.append(
                f"• {categoria.get('Categoria', codigo)} — "
                f"{categoria.get('TamanhoLegivel', 'Não disponível')}"
            )
        aviso_lixeira = ""
        if "lixeira" in categorias:
            aviso_lixeira = (
                "\n\nA Lixeira foi selecionada e será esvaziada para o usuário atual."
            )
        resposta = QMessageBox.question(
            self,
            "Confirmar limpeza segura",
            "A limpeza fará uma nova análise antes de excluir arquivos.\n\n"
            + "\n".join(resumo)
            + aviso_lixeira
            + "\n\nDeseja continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resposta != QMessageBox.StandardButton.Yes:
            return
        self.lbl_resultado_limpeza_segura.setText(
            "Limpando categorias selecionadas em segundo plano..."
        )
        worker = self._run(
            core_logic.ModuloSistema.executar_limpeza_segura,
            categorias,
            label="Executando limpeza segura",
            progress=self.progress_limpeza_segura,
            indeterminate=True,
            operation_key="limpeza_segura",
            blocks_navigation=False,
            on_done=self._mostrar_resultado_limpeza_segura,
            on_finally=self._finalizar_limpeza_segura,
            silent_if_busy=True,
            audit_source="Manutenção",
            audit_category="MAINTENANCE",
            audit_summary="Limpeza segura",
            audit_details={"categorias_selecionadas": len(categorias)},
        )
        if worker is not None:
            self.btn_analisar_limpeza_segura.setEnabled(False)
            self.btn_executar_limpeza_segura.setEnabled(False)

    @staticmethod
    def _formatar_bytes_limpeza_gui(valor):
        try:
            tamanho = max(0, int(valor or 0))
        except (TypeError, ValueError):
            return "Não disponível"
        unidades = ("B", "KB", "MB", "GB", "TB")
        convertido = float(tamanho)
        for unidade in unidades:
            if convertido < 1024 or unidade == unidades[-1]:
                return (
                    f"{int(convertido)} {unidade}"
                    if unidade == "B" else f"{convertido:.1f} {unidade}"
                )
            convertido /= 1024
        return f"{tamanho} B"

    def _mostrar_resultado_limpeza_segura(self, resultado):
        if not isinstance(resultado, dict) or resultado.get("Cancelada"):
            self.lbl_resultado_limpeza_segura.setText(
                "Limpeza cancelada. O resultado parcial não foi apresentado como sucesso."
            )
            self._log(">> [CANCELADA] LIMPEZA_EXECUTADA.")
            return
        encontrado = self._formatar_bytes_limpeza_gui(
            resultado.get("EncontradoBytes")
        )
        removido = self._formatar_bytes_limpeza_gui(
            resultado.get("RemovidoBytes")
        )
        nao_removido = self._formatar_bytes_limpeza_gui(
            resultado.get("NaoRemovidoBytes")
        )
        quantidade_encontrada = resultado.get("EncontradoQuantidade", 0)
        quantidade_removida = resultado.get("RemovidoQuantidade", 0)
        quantidade_nao_removida = resultado.get("NaoRemovidoQuantidade", 0)
        if not resultado.get("Sucesso"):
            mensagem = resultado.get("Mensagem") or "Limpeza não concluída."
            self.lbl_resultado_limpeza_segura.setText(
                f"{mensagem}\nEncontrado: {encontrado} ({quantidade_encontrada} item(ns))\n"
                f"Removido: {removido} ({quantidade_removida} item(ns))\n"
                f"Não removido: {nao_removido} ({quantidade_nao_removida} item(ns))"
            )
            self._log(f">> [ERRO] LIMPEZA_EXECUTADA: {mensagem}")
            return
        titulo = (
            "Limpeza concluída parcialmente."
            if resultado.get("Parcial") else "Limpeza concluída."
        )
        mensagem = resultado.get("Mensagem") or titulo
        self.lbl_resultado_limpeza_segura.setText(
            f"{titulo} {mensagem}\n"
            f"Encontrado: {encontrado} ({quantidade_encontrada} item(ns))\n"
            f"Removido: {removido} ({quantidade_removida} item(ns))\n"
            f"Não removido: {nao_removido} ({quantidade_nao_removida} item(ns))"
        )
        marcador = "[PARCIAL]" if resultado.get("Parcial") else "[OK]"
        self._log(
            f">> {marcador} LIMPEZA_EXECUTADA: removido {removido}; "
            f"não removido {nao_removido}."
        )
        # A análise anterior não representa mais o estado atual dos arquivos.
        self._analise_limpeza_segura_atual = None

    def _finalizar_limpeza_segura(self, estado):
        if self._closing:
            return
        if hasattr(self, "btn_analisar_limpeza_segura"):
            self.btn_analisar_limpeza_segura.setEnabled(True)
        if hasattr(self, "btn_executar_limpeza_segura"):
            self.btn_executar_limpeza_segura.setEnabled(
                bool(self._analise_limpeza_segura_atual) and estado == "success"
            )
        if estado == "cancelled" and hasattr(self, "lbl_resultado_limpeza_segura"):
            self.lbl_resultado_limpeza_segura.setText(
                "Operação de limpeza cancelada. Nenhum resultado foi tratado como sucesso."
            )

    def _atualizar_saude_sistema(self):
        if self._operacao_ativa("saude_sistema"):
            self.lbl_saude_sistema.setText(
                "Já existe uma atualização de Saúde do sistema em andamento."
            )
            return
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_saude_sistema.setText(
                "O Benchmark Configurador TI está em andamento. Aguarde antes de consultar o armazenamento pela Saúde do sistema."
            )
            return
        if self._operacao_ativa("limpeza_segura"):
            self.lbl_saude_sistema.setText(
                "A análise ou limpeza segura está em andamento. Aguarde para evitar "
                "duas leituras simultâneas dos temporários."
            )
            return
        if self._operacao_ativa("saude_armazenamento"):
            self.lbl_saude_sistema.setText(
                "A Saúde de armazenamento está em andamento. Aguarde para evitar "
                "duas consultas Storage simultâneas."
            )
            return
        self.lbl_saude_sistema.setText(
            "Consultando dados nativos em segundo plano; você pode navegar."
        )
        worker = self._run(
            core_logic.ModuloSistema.obter_saude_sistema,
            label="Atualizando saúde do sistema",
            progress=self.progress_saude_sistema,
            indeterminate=True,
            operation_key="saude_sistema",
            blocks_navigation=False,
            on_done=self._mostrar_saude_sistema,
            on_finally=self._finalizar_saude_sistema,
            silent_if_busy=True,
        )
        if worker is not None:
            self.btn_atualizar_saude_sistema.setEnabled(False)

    def _mostrar_saude_sistema(self, resultado):
        if not isinstance(resultado, dict) or resultado.get("Cancelada"):
            self.lbl_saude_sistema.setText("Atualização de Saúde do sistema cancelada.")
            self.lbl_recomendacoes_saude_sistema.setText(
                "Nenhuma recomendação nova foi aplicada automaticamente."
            )
            self._log(">> [CANCELADA] SAUDE_SISTEMA_ATUALIZADA.")
            return
        if not resultado.get("Sucesso"):
            mensagem = resultado.get("Mensagem") or "Não foi possível atualizar a Saúde do sistema."
            self.lbl_saude_sistema.setText(mensagem)
            self._log(f">> [ERRO] SAUDE_SISTEMA_ATUALIZADA: {mensagem}")
            return
        self.tabela_saude_sistema.setRowCount(0)
        for item in resultado.get("Itens") or []:
            if not isinstance(item, dict):
                continue
            linha = self.tabela_saude_sistema.rowCount()
            self.tabela_saude_sistema.insertRow(linha)
            valores = (
                item.get("Item", "—"),
                item.get("Estado", "Não disponível"),
                item.get("Detalhe", "—"),
                item.get("Recomendacao", "—") or "—",
            )
            for coluna, valor in enumerate(valores):
                self.tabela_saude_sistema.setItem(
                    linha, coluna, QTableWidgetItem(str(valor))
                )
        recomendacoes = [
            str(item).strip() for item in (resultado.get("Recomendacoes") or [])
            if str(item).strip()
        ]
        if recomendacoes:
            self.lbl_recomendacoes_saude_sistema.setText(
                "Recomendações informativas:\n• " + "\n• ".join(recomendacoes)
            )
        else:
            self.lbl_recomendacoes_saude_sistema.setText(
                "Nenhuma ação é recomendada com os dados atualmente disponíveis."
            )
        mensagem = resultado.get("Mensagem") or "Saúde do sistema atualizada."
        self.lbl_saude_sistema.setText(mensagem)
        self._log(f">> [OK] SAUDE_SISTEMA_ATUALIZADA: {mensagem}")

    def _finalizar_saude_sistema(self, estado):
        if self._closing:
            return
        if hasattr(self, "btn_atualizar_saude_sistema"):
            self.btn_atualizar_saude_sistema.setEnabled(True)
        if estado == "cancelled" and hasattr(self, "lbl_saude_sistema"):
            self.lbl_saude_sistema.setText("Atualização de Saúde do sistema cancelada.")

    def _limpar_temp(self):
        """Compatibilidade do atalho antigo: agora inicia somente a análise."""
        self._analisar_limpeza_segura()

    def _resultado_limpeza(self, result):
        if isinstance(result, tuple):
            msg = result[1] if len(result) > 1 else str(result)
            self._resultado_generico((True, msg))
        else:
            self._resultado_generico((True, str(result)))

    def _spooler(self):
        self._run(
            core_logic.ModuloSistema.reiniciar_spooler_impressao,
            label="Reiniciando spooler",
            admin_reason="reiniciar spooler de impressão",
            progress=self.progress_manutencao,
            on_done=lambda ok: self._resultado_generico(
                (ok, "Spooler reiniciado." if ok else "Falha no spooler.")
            ),
        )

    def _windows_update(self):
        if QMessageBox.question(
            self,
            "Windows Update",
            "Pesquisar, baixar e instalar atualizações disponíveis?\n\n"
            "As atualizações serão processadas individualmente para evitar "
            "que uma falha bloqueie todo o lote.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        ) != QMessageBox.StandardButton.Yes:
            return

        self.progress_manutencao.show()
        self.progress_manutencao.setRange(0, 100)
        self.progress_manutencao.setValue(0)
        self._run(
            core_logic.ModuloSistema.executar_windows_update,
            label="Windows Update — processando atualizações individualmente",
            progress=self.progress_manutencao,
            indeterminate=False,
            operation_key="windows_update",
            on_done=self._resultado_generico,
        )

    def _versao_windows(self):
        self._run(
            core_logic.ModuloSistema.obter_versao_windows,
            label="Consultando versão do Windows",
            progress=self.progress_manutencao,
            on_done=self._mostrar_versao,
        )

    def _mostrar_versao(self, data):
        if not data:
            self._resultado_generico((False, "Não foi possível obter a versão do Windows."))
            return
        msg = (
            f"{data.get('Nome', 'Windows')}\n"
            f"Edição: {data.get('Edicao', 'N/A')}\n"
            f"Versão: {data.get('DisplayVersion', 'N/A')}\n"
            f"Build: {data.get('BuildCompleta', 'N/A')}\n"
            f"Arquitetura: {data.get('Arquitetura', 'N/A')}"
        )
        self._log(">> " + msg.replace("\n", " | "))
        QMessageBox.information(self, "Versão do Windows", msg)

    def _planos_energia(self):
        self._run(
            core_logic.ModuloSistema.obter_planos_energia,
            label="Consultando planos de energia",
            progress=self.progress_manutencao,
            on_done=self._mostrar_planos,
        )

    def _mostrar_planos(self, data):
        mensagem = ""
        if isinstance(data, tuple):
            ok = bool(data[0]) if data else False
            planos = data[1] if len(data) > 1 else []
            mensagem = str(data[2]) if len(data) > 2 else ""
            if not ok:
                self._resultado_generico((
                    False,
                    mensagem or "Não foi possível consultar os planos de energia."
                ))
                return
        else:
            planos = data or []

        if isinstance(planos, dict):
            planos = [planos]
        # Defesa adicional na fronteira visual: resultados antigos, testes ou
        # fontes externas recebem a mesma consolidação semântica do backend.
        # Ela não remove planos do Windows; apenas escolhe um representante
        # para clones padrão inequívocos no texto exibido.
        planos_unicos = core_logic.ModuloSistema.consolidar_planos_energia_visual(
            planos
        )
        msg = "\n".join(
            f"• {p.get('nome', p.get('Nome', p.get('name', 'Plano')))} "
            f"{'(ATIVO)' if p.get('ativo') or p.get('Ativo') or p.get('active') else ''}"
            for p in planos_unicos
        ) or "Nenhum plano encontrado."
        self._log(">> Planos de energia consultados com sucesso.")
        QMessageBox.information(self, "Planos de energia", msg)

    def _renomear(self):
        atual = os.environ.get("COMPUTERNAME", "")
        nome, ok = self._input_dialog(
            "Novo nome",
            f"Nome atual: {atual}\n\nNovo nome (até 15 caracteres):"
        )
        if not ok:
            return
        self._run(
            core_logic.ModuloSistema.renomear_computador,
            nome,
            label=f"Renomeando computador para {nome}",
            admin_reason="renomear o computador",
            progress=self.progress_manutencao,
            on_done=self._resultado_generico,
        )

    def _input_dialog(self, title, prompt):
        from PyQt6.QtWidgets import QInputDialog
        return QInputDialog.getText(self, title, prompt)

    def _carregar_unidades(self):
        if not hasattr(self, "combo_unidade"):
            return
        self.lbl_status_unidades.setText("Atualizando unidades...")
        self.btn_unidades.setEnabled(False)
        worker = self._run(
            core_logic.ModuloSistema.listar_unidades,
            label="Atualizando unidades",
            on_done=self._mostrar_unidades,
            operation_key="unidades_refresh",
            blocks_navigation=False,
            silent_if_busy=True,
            on_finally=self._finalizar_atualizacao_unidades,
        )
        if worker is None and not self._operacao_ativa("unidades_refresh"):
            self.btn_unidades.setEnabled(True)

    def _mostrar_unidades(self, unidades):
        if not hasattr(self, "combo_unidade"):
            return
        if not isinstance(unidades, (list, tuple)):
            self._log(">> [ERRO] Unidades: retorno inválido da consulta.")
            self.lbl_status_unidades.setText("Falha ao atualizar unidades.")
            return
        self.combo_unidade.clear()
        for u in unidades:
            if not isinstance(u, dict):
                continue
            letra = u.get("DriveLetter")
            if not letra:
                continue
            self.combo_unidade.addItem(
                f"{letra}: — {u.get('FreeGB', 0)} GB livres / {u.get('SizeGB', 0)} GB",
                letra,
            )
        self.lbl_status_unidades.setText("Unidades atualizadas.")

    def _finalizar_atualizacao_unidades(self, estado):
        if hasattr(self, "btn_unidades"):
            self.btn_unidades.setEnabled(True)
        if not hasattr(self, "lbl_status_unidades"):
            return
        if estado == "error":
            self.lbl_status_unidades.setText("Falha ao atualizar unidades.")
        elif estado == "cancelled":
            self.lbl_status_unidades.setText("Atualização de unidades cancelada.")

    def _limpar_saude_armazenamento(self, mensagem):
        """Limpa resultado anterior para não apresentar leitura antiga como atual."""
        self.raw_saude_armazenamento.setPlainText(str(mensagem))
        self.raw_saude_armazenamento.set_metadata("Discos / unidades", "Saúde de armazenamento")
        self._dados_saude_armazenamento = None
        self._resumo_saude_armazenamento = ""
        if hasattr(self, "tabela_saude_armazenamento"):
            self.tabela_saude_armazenamento.setRowCount(0)
        textos = getattr(self, "_textos_detalhes_saude_armazenamento", ())
        if textos:
            for texto in textos:
                texto.setPlainText(str(mensagem))
        elif hasattr(self, "texto_saude_armazenamento"):
            self.texto_saude_armazenamento.setPlainText(str(mensagem))
        if hasattr(self, "btn_copiar_saude_armazenamento"):
            self.btn_copiar_saude_armazenamento.setEnabled(False)
        if hasattr(self, "btn_saude_armazenamento_admin"):
            self.btn_saude_armazenamento_admin.setEnabled(False)
            self.btn_saude_armazenamento_admin.hide()

    def _preencher_detalhes_saude_armazenamento(self, resultado):
        """Distribui a mesma leitura em seções consolidadas, sem alterar diagnóstico."""
        import json
        self.raw_saude_armazenamento.setPlainText(json.dumps(resultado, ensure_ascii=False, indent=2, default=str))
        self.raw_saude_armazenamento.set_metadata("Discos / unidades", "Saúde de armazenamento", resultado.get("ColetadoEm", ""))
        discos = resultado.get("Discos") if isinstance(resultado, dict) else []
        secoes = {
            "resumo": [],
            "identificacao": [],
            "smart": [],
            "contadores": [],
        }

        for disco in discos if isinstance(discos, list) else []:
            if not isinstance(disco, dict):
                continue
            titulo = f"DISCO {disco.get('Numero', '—')}"
            observacoes = [
                str(motivo).strip()
                for motivo in (disco.get("Motivos") or [])
                if str(motivo).strip()
            ]
            limitacoes = [
                str(limite).strip()
                for limite in (disco.get("Limitacoes") or [])
                if str(limite).strip()
            ]
            secoes["resumo"].extend(
                [
                    titulo,
                    f"Modelo: {disco.get('Modelo', '—')}",
                    f"Tipo: {disco.get('Tipo', '—')}",
                    f"Interface: {disco.get('BusType', '—')}",
                    f"Capacidade: {disco.get('Capacidade', '—')}",
                    f"Unidades: {disco.get('Unidades', '—')}",
                    f"Saúde: {disco.get('Saude', '—')}",
                    f"Temperatura: {disco.get('Temperatura', '—')}",
                    f"SMART / confiabilidade: {disco.get('SMART', '—')}",
                    (
                        "Observações: " + " ".join(observacoes)
                        if observacoes else "Observações: —"
                    ),
                    "",
                ]
            )
            secoes["identificacao"].extend(
                [
                    titulo,
                    f"Modelo: {disco.get('Modelo', '—')}",
                    f"Fabricante: {disco.get('Fabricante', '—')}",
                    f"Serial: {disco.get('Serial', '—')}",
                    f"Firmware: {disco.get('Firmware', '—')}",
                    f"Capacidade: {disco.get('Capacidade', '—')}",
                    f"Tipo: {disco.get('Tipo', '—')}",
                    f"Interface: {disco.get('BusType', '—')}",
                    f"Mídia reportada: {disco.get('MediaType', '—')}",
                    f"Unidades: {disco.get('Unidades', '—')}",
                    "",
                ]
            )
            secoes["smart"].extend(
                [
                    titulo,
                    f"Saúde normalizada: {disco.get('Saude', '—')}",
                    f"HealthStatus (Windows): {disco.get('HealthStatus', '—')}",
                    (
                        "OperationalStatus (Windows): "
                        f"{disco.get('OperationalStatus', '—')}"
                    ),
                    f"Temperatura: {disco.get('Temperatura', '—')}",
                    f"SMART / confiabilidade: {disco.get('SMART', '—')}",
                    (
                        "Falha preditiva: "
                        f"{disco.get('PredictiveFailure', 'Não disponível')}"
                    ),
                    (
                        "Observações: " + " ".join(observacoes)
                        if observacoes else "Observações: —"
                    ),
                    (
                        "Limitações: " + " ".join(limitacoes)
                        if limitacoes else "Limitações: —"
                    ),
                    "",
                ]
            )
            secoes["contadores"].extend(
                [
                    titulo,
                    f"Horas ligado: {disco.get('HorasLigado', '—')}",
                    f"Power cycles: {disco.get('PowerCycles', '—')}",
                    f"Desgaste reportado: {disco.get('Wear', '—')}",
                    f"Erros de leitura: {disco.get('ReadErrors', '—')}",
                    (
                        "Erros de leitura não corrigidos: "
                        f"{disco.get('ReadErrorsUncorrected', '—')}"
                    ),
                    f"Erros de gravação: {disco.get('WriteErrors', '—')}",
                    (
                        "Erros de gravação não corrigidos: "
                        f"{disco.get('WriteErrorsUncorrected', '—')}"
                    ),
                    (
                        "Desligamentos não seguros: "
                        f"{disco.get('UnsafeShutdowns', '—')}"
                    ),
                    f"Erros de mídia/dados: {disco.get('MediaErrors', '—')}",
                    "",
                ]
            )

        limitacoes_globais = [
            str(limite).strip()
            for limite in (resultado.get("Limitacoes") or [])
            if str(limite).strip()
        ] if isinstance(resultado, dict) else []
        if limitacoes_globais:
            secoes["smart"].extend(
                [
                    "Limitações das fontes nativas:",
                    "; ".join(limitacoes_globais),
                ]
            )
        if not any(secoes.values()):
            mensagem = "Nenhum disco físico foi retornado pelo Windows."
            secoes = {chave: [mensagem] for chave in secoes}

        campos = (
            ("resumo", "texto_saude_resumo"),
            ("identificacao", "texto_saude_identificacao"),
            ("smart", "texto_saude_smart"),
            ("contadores", "texto_saude_contadores"),
        )
        for secao, atributo in campos:
            texto = getattr(self, atributo, None)
            if texto is not None:
                texto.setPlainText("\n".join(secoes[secao]).strip())

    def _formatar_saude_armazenamento(self, resultado):
        """Monta um resumo copiável sem logs, segredos ou dados SMART brutos."""
        discos = resultado.get("Discos") if isinstance(resultado, dict) else []
        linhas = [
            "CONFIGURADOR TI — SAÚDE DE ARMAZENAMENTO",
            "",
            "Consulta somente leitura com mecanismos nativos do Windows.",
            "SMART/confiabilidade depende do disco, driver e controladora; "
            "CHKDSK é uma verificação diferente, do sistema de arquivos.",
        ]
        if not discos:
            linhas.extend(["", "Nenhum disco físico foi retornado pelo Windows."])
            return "\n".join(linhas)

        for disco in discos:
            if not isinstance(disco, dict):
                continue
            linhas.extend(
                [
                    "",
                    f"DISCO {disco.get('Numero', '—')}",
                    f"Modelo: {disco.get('Modelo', '—')}",
                    f"Fabricante: {disco.get('Fabricante', '—')}",
                    f"Serial: {disco.get('Serial', '—')}",
                    f"Firmware: {disco.get('Firmware', '—')}",
                    f"Capacidade: {disco.get('Capacidade', '—')}",
                    f"Tipo: {disco.get('Tipo', '—')}",
                    f"Interface: {disco.get('BusType', '—')}",
                    f"Mídia reportada: {disco.get('MediaType', '—')}",
                    f"Unidades: {disco.get('Unidades', '—')}",
                    f"Saúde: {disco.get('Saude', '—')}",
                    f"HealthStatus (Windows): {disco.get('HealthStatus', '—')}",
                    (
                        "OperationalStatus (Windows): "
                        f"{disco.get('OperationalStatus', '—')}"
                    ),
                    f"Temperatura: {disco.get('Temperatura', '—')}",
                    f"Horas ligado: {disco.get('HorasLigado', '—')}",
                    f"Power cycles: {disco.get('PowerCycles', '—')}",
                    f"Desgaste reportado: {disco.get('Wear', '—')}",
                    f"Erros de leitura: {disco.get('ReadErrors', '—')}",
                    (
                        "Erros de leitura não corrigidos: "
                        f"{disco.get('ReadErrorsUncorrected', '—')}"
                    ),
                    f"Erros de gravação: {disco.get('WriteErrors', '—')}",
                    (
                        "Erros de gravação não corrigidos: "
                        f"{disco.get('WriteErrorsUncorrected', '—')}"
                    ),
                    (
                        "Desligamentos não seguros: "
                        f"{disco.get('UnsafeShutdowns', '—')}"
                    ),
                    f"Erros de mídia/dados: {disco.get('MediaErrors', '—')}",
                    f"SMART / confiabilidade: {disco.get('SMART', '—')}",
                    (
                        "Falha preditiva: "
                        f"{disco.get('PredictiveFailure', 'Não disponível')}"
                    ),
                ]
            )
            motivos = [
                str(motivo).strip()
                for motivo in (disco.get("Motivos") or [])
                if str(motivo).strip()
            ]
            if motivos:
                linhas.append("Observações: " + " ".join(motivos))
            limitacoes = [
                str(limite).strip()
                for limite in (disco.get("Limitacoes") or [])
                if str(limite).strip()
            ]
            if limitacoes:
                linhas.append("Limitações: " + " ".join(limitacoes))

        limitacoes_globais = [
            str(limite).strip()
            for limite in (resultado.get("Limitacoes") or [])
            if str(limite).strip()
        ]
        if limitacoes_globais:
            linhas.extend(
                [
                    "",
                    "Limitações das fontes nativas: "
                    + "; ".join(limitacoes_globais),
                ]
            )
        return "\n".join(linhas)

    @staticmethod
    def _resultado_requer_admin_reliability(resultado):
        if not isinstance(resultado, dict):
            return False
        if resultado.get("RequerAdminReliability") is True:
            return True
        discos = resultado.get("Discos") or []
        return any(
            isinstance(disco, dict)
            and (
                disco.get("RequerAdminReliability") is True
                or disco.get("ReliabilityStatus") == "acesso_negado"
            )
            for disco in discos
        )

    def _analisar_saude_armazenamento_elevada(self):
        if self._operacao_ativa("saude_armazenamento"):
            self.lbl_saude_armazenamento.setText(
                "Já existe uma análise de saúde de armazenamento em andamento."
            )
            return
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_saude_armazenamento.setText(
                "O Benchmark Configurador TI está em andamento. Aguarde antes da coleta avançada de armazenamento."
            )
            return
        if self._operacao_ativa("saude_sistema"):
            self.lbl_saude_armazenamento.setText(
                "A Saúde do sistema está consultando o armazenamento. "
                "Aguarde a conclusão antes da coleta avançada."
            )
            return
        if not self._resultado_requer_admin_reliability(
            self._dados_saude_armazenamento
        ):
            self.lbl_saude_armazenamento.setText(
                "A coleta atual não indicou bloqueio administrativo dos "
                "contadores avançados."
            )
            return

        resposta = QMessageBox.question(
            self,
            "Dados avançados de armazenamento",
            "O Windows permitiu os dados básicos, mas bloqueou temperatura, "
            "desgaste e outros contadores de reliability.\n\n"
            "Deseja iniciar somente essa coleta auxiliar com privilégio "
            "administrativo? A aplicação principal continuará em modo normal.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resposta != QMessageBox.StandardButton.Yes:
            try:
                core_logic.registrar_log(
                    "SISTEMA",
                    "SAUDE_ARMAZENAMENTO_ELEVADA_CANCELADA",
                    "etapa=confirmacao_gui",
                )
            except Exception:
                pass
            self.lbl_saude_armazenamento.setText(
                "Coleta avançada não iniciada. Os dados básicos foram preservados."
            )
            return

        self.lbl_saude_armazenamento.setText(
            "Aguardando autorização UAC para a coleta avançada; "
            "a aplicação principal permanece em modo normal."
        )
        worker = self._run(
            core_logic.ModuloSistema.obter_saude_armazenamento_elevada,
            label="Obtendo dados avançados de armazenamento",
            progress=self.progress_saude_armazenamento,
            indeterminate=True,
            operation_key="saude_armazenamento",
            blocks_navigation=False,
            on_done=self._mostrar_saude_armazenamento_elevada,
            on_finally=self._finalizar_saude_armazenamento_elevada,
            silent_if_busy=True,
        )
        if worker is not None:
            self.btn_analisar_saude_armazenamento.setEnabled(False)
            self.btn_saude_armazenamento_admin.setEnabled(False)
        elif not self._closing:
            self.lbl_saude_armazenamento.setText(
                "Não foi possível iniciar a coleta avançada. "
                "Os dados básicos foram preservados."
            )

    def _mostrar_saude_armazenamento_elevada(self, resultado):
        if not isinstance(resultado, dict):
            self.lbl_saude_armazenamento.setText(
                "A coleta avançada retornou formato inválido. "
                "Os dados básicos foram preservados."
            )
            self._log(">> [ERRO] Coleta avançada de armazenamento inválida.")
            return
        if resultado.get("Cancelada"):
            mensagem = resultado.get("Mensagem") or (
                "Coleta avançada cancelada. Os dados básicos foram preservados."
            )
            self.lbl_saude_armazenamento.setText(mensagem)
            self._log(">> [CANCELADA] Coleta avançada de armazenamento.")
            return
        if not resultado.get("Sucesso") or not (resultado.get("Discos") or []):
            mensagem = resultado.get("Mensagem") or (
                "A coleta avançada falhou. Os dados básicos foram preservados."
            )
            self.lbl_saude_armazenamento.setText(mensagem)
            self._log(f">> [ERRO] Coleta avançada de armazenamento: {mensagem}")
            return

        self._mostrar_saude_armazenamento(resultado)

    def _finalizar_saude_armazenamento_elevada(self, estado):
        if self._closing:
            return
        self.btn_analisar_saude_armazenamento.setEnabled(True)
        requer_admin = self._resultado_requer_admin_reliability(
            self._dados_saude_armazenamento
        )
        self.btn_saude_armazenamento_admin.setVisible(requer_admin)
        self.btn_saude_armazenamento_admin.setEnabled(requer_admin)

    def _analisar_saude_armazenamento(self):
        if not hasattr(self, "btn_analisar_saude_armazenamento"):
            return
        if self._operacao_ativa("saude_armazenamento"):
            self.lbl_saude_armazenamento.setText(
                "Já existe uma análise de saúde de armazenamento em andamento."
            )
            return
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_saude_armazenamento.setText(
                "O Benchmark Configurador TI está em andamento. Aguarde antes de iniciar outra consulta de armazenamento."
            )
            return

        self._limpar_saude_armazenamento(
            "Analisando saúde dos discos com mecanismos nativos do Windows..."
        )
        self.lbl_saude_armazenamento.setText(
            "Analisando saúde dos discos em segundo plano; você pode navegar "
            "para outras páginas."
        )
        worker = self._run(
            core_logic.ModuloSistema.obter_saude_armazenamento,
            label="Analisando saúde de armazenamento",
            progress=self.progress_saude_armazenamento,
            indeterminate=True,
            operation_key="saude_armazenamento",
            blocks_navigation=False,
            on_done=self._mostrar_saude_armazenamento,
            on_finally=self._finalizar_analise_saude_armazenamento,
            silent_if_busy=True,
        )
        if worker is not None:
            self.btn_analisar_saude_armazenamento.setEnabled(False)
        elif not self._closing:
            self.lbl_saude_armazenamento.setText(
                "Não foi possível iniciar a análise de saúde de armazenamento."
            )

    def _mostrar_saude_armazenamento(self, resultado):
        if not isinstance(resultado, dict) or resultado.get("Cancelada"):
            self._limpar_saude_armazenamento(
                "Análise de saúde de armazenamento cancelada."
            )
            self.lbl_saude_armazenamento.setText(
                "Análise de saúde de armazenamento cancelada."
            )
            self._log(">> [CANCELADA] Saúde de armazenamento.")
            return

        if not resultado.get("Sucesso"):
            mensagem = (
                resultado.get("Mensagem")
                or "Não foi possível analisar a saúde de armazenamento."
            )
            self._limpar_saude_armazenamento(mensagem)
            self.lbl_saude_armazenamento.setText(mensagem)
            self._log(f">> [ERRO] Saúde de armazenamento: {mensagem}")
            return

        discos = resultado.get("Discos") or []
        if not isinstance(discos, list):
            self._limpar_saude_armazenamento(
                "A consulta retornou dados de saúde em formato inválido."
            )
            self.lbl_saude_armazenamento.setText(
                "A consulta retornou dados de saúde em formato inválido."
            )
            self._log(">> [ERRO] Saúde de armazenamento: retorno inválido.")
            return

        self.tabela_saude_armazenamento.setRowCount(0)
        for disco in discos:
            if not isinstance(disco, dict):
                continue
            linha = self.tabela_saude_armazenamento.rowCount()
            self.tabela_saude_armazenamento.insertRow(linha)
            valores = (
                f"Disco {disco.get('Numero', '—')}",
                disco.get("Modelo", "—"),
                f"{disco.get('Tipo', '—')} / {disco.get('BusType', '—')}",
                disco.get("Capacidade", "—"),
                disco.get("Saude", "—"),
                disco.get("Temperatura", "—"),
                disco.get("SMART", "—"),
                disco.get("Unidades", "—"),
            )
            for coluna, valor in enumerate(valores):
                self.tabela_saude_armazenamento.setItem(
                    linha, coluna, QTableWidgetItem(str(valor or "—"))
                )

        self._dados_saude_armazenamento = resultado
        self._resumo_saude_armazenamento = self._formatar_saude_armazenamento(
            resultado
        )
        self._preencher_detalhes_saude_armazenamento(resultado)
        self.btn_copiar_saude_armazenamento.setEnabled(bool(discos))
        requer_admin = self._resultado_requer_admin_reliability(resultado)
        self.btn_saude_armazenamento_admin.setVisible(requer_admin)
        self.btn_saude_armazenamento_admin.setEnabled(requer_admin)
        mensagem = resultado.get("Mensagem") or "Análise de saúde concluída."
        self.lbl_saude_armazenamento.setText(mensagem)
        self._log(f">> [OK] Saúde de armazenamento: {mensagem}")

    def _finalizar_analise_saude_armazenamento(self, estado):
        if self._closing:
            return
        if hasattr(self, "btn_analisar_saude_armazenamento"):
            self.btn_analisar_saude_armazenamento.setEnabled(True)
        if estado == "cancelled":
            self._limpar_saude_armazenamento(
                "Análise de saúde de armazenamento cancelada."
            )
            self.lbl_saude_armazenamento.setText(
                "Análise de saúde de armazenamento cancelada."
            )

    def _copiar_saude_armazenamento(self):
        if not self._resumo_saude_armazenamento:
            self.lbl_saude_armazenamento.setText(
                "Não há análise de saúde de armazenamento para copiar."
            )
            return
        try:
            QApplication.clipboard().setText(self._resumo_saude_armazenamento)
            self.lbl_saude_armazenamento.setText(
                "Informações de saúde de armazenamento copiadas para a área "
                "de transferência."
            )
            self._log(">> [OK] Informações de saúde de armazenamento copiadas.")
        except Exception as exc:
            self.lbl_saude_armazenamento.setText(
                "Não foi possível copiar as informações de saúde de armazenamento."
            )
            self._log(
                ">> [ERRO] Falha ao copiar saúde de armazenamento: "
                f"{exc}"
            )
            try:
                core_logic.logger.exception(
                    "Falha ao copiar informações de saúde de armazenamento"
                )
            except Exception:
                pass

    @staticmethod
    def _detectar_midia_e_otimizar(letra, cancel_callback=None):
        """Executa a descoberta de mídia e a otimização no mesmo Worker."""
        if callable(cancel_callback) and cancel_callback():
            return False, "Otimização cancelada", "Operação cancelada antes da coleta."

        tipo = "Unknown"
        try:
            hardware = core_logic.ModuloSistema.obter_hardware_detalhado() or {}
            for disco in hardware.get("Discos", []) or []:
                if str(disco.get("Nome", "")).strip():
                    tipo = str(disco.get("Tipo") or "Unknown")
                    break
        except Exception as exc:
            try:
                core_logic.logger.warning("Não foi possível identificar a mídia: %s", exc)
            except Exception:
                pass

        if callable(cancel_callback) and cancel_callback():
            return False, "Otimização cancelada", "Operação cancelada antes da otimização."
        return core_logic.ModuloSistema.otimizar_unidade(letra, tipo)

    def _chkdsk(self):
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_status_unidades.setText(
                "O Benchmark Configurador TI está em andamento. Aguarde antes de executar CHKDSK."
            )
            return
        idx = self.combo_unidade.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "CHKDSK", "Selecione uma unidade.")
            return
        letra = self.combo_unidade.itemData(idx)
        self._run(
            core_logic.ModuloSistema.verificar_erros_disco,
            letra,
            label=f"CHKDSK /scan em {letra}:",
            admin_reason="verificar erros de disco",
            progress=self.progress_manutencao,
            indeterminate=False,
            operation_key="chkdsk_unidade",
            on_done=self._resultado_chkdsk,
        )

    def _resultado_chkdsk(self, result):
        ok, msg = result if isinstance(result, tuple) else (bool(result), str(result))
        self._log(">> [CHKDSK] " + str(msg))
        if ok:
            # Mostra o resumo final sem transformar todo o output em uma janela gigante.
            linhas = str(msg).splitlines()
            resumo = "\n".join(linhas[-18:]) if linhas else "Concluído."
            QMessageBox.information(self, "CHKDSK concluído", resumo)
        else:
            QMessageBox.critical(self, "CHKDSK", str(msg))

    def _otimizar(self):
        if self._operacao_ativa("benchmark_configurador_ti"):
            self.lbl_status_unidades.setText(
                "O Benchmark Configurador TI está em andamento. Aguarde antes de otimizar a unidade."
            )
            return
        idx = self.combo_unidade.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "Otimização", "Selecione uma unidade.")
            return
        letra = self.combo_unidade.itemData(idx)

        self._run(
            self._detectar_midia_e_otimizar,
            letra,
            label=f"Otimizando {letra}:",
            admin_reason="otimizar a unidade",
            progress=self.progress_manutencao,
            indeterminate=True,
            operation_key="otimizacao_unidade",
            on_done=lambda result, unidade=letra: self._resultado_otimizacao(
                result, unidade
            ),
        )

    def _resultado_otimizacao(self, result, unidade=None):
        if isinstance(result, tuple):
            ok = bool(result[0]) if result else False
            acao = str(result[1]) if len(result) > 1 else "Otimização"
            saida = str(result[2]) if len(result) > 2 else ""
        else:
            ok, acao, saida = bool(result), "Otimização", str(result)

        unidade_txt = f"{unidade}:" if unidade else "não identificada"
        msg = (
            f"Unidade: {unidade_txt}\n"
            f"Procedimento: {acao}\n\n"
            f"{saida or ('Operação concluída.' if ok else 'Operação não concluída.')}"
        )
        self._log((">> [OK] " if ok else ">> [ERRO] ") + msg.replace("\n", " | "))
        if ok:
            QMessageBox.information(self, "Otimização", msg)
        else:
            QMessageBox.critical(self, "Falha na otimização", msg)

    # ---------------------------------------------------------
    # Inventário / rede
    # ---------------------------------------------------------
    def _build_inventario(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Inventário de Rede",
            "Descoberta de hosts ativos, hostname, MAC, possíveis impressoras e serviços expostos."
        ))

        seletor = FlowRow()
        seletor.addWidget(QLabel("Interface:"))
        self.combo_interface_scan = QComboBox()
        self.combo_interface_scan.setMinimumWidth(200)
        self.combo_interface_scan.currentIndexChanged.connect(
            self._atualizar_interface_scan
        )
        seletor.addWidget(self.combo_interface_scan, 1)
        self.btn_atualizar_interfaces_scan = QPushButton("↻ Atualizar interfaces")
        self.btn_atualizar_interfaces_scan.setProperty("class", "MenuButton")
        self.btn_atualizar_interfaces_scan.clicked.connect(
            self._carregar_interfaces_varredura
        )
        seletor.addWidget(self.btn_atualizar_interfaces_scan)
        layout.addLayout(seletor)

        self.info_interface_scan = QLabel(
            "As interfaces serão consultadas ao abrir esta página."
        )
        self.info_interface_scan.setObjectName("SubtituloTela")
        self.info_interface_scan.setWordWrap(True)
        layout.addWidget(self.info_interface_scan)

        bar = FlowRow()
        self.btn_scan_passivo = QPushButton("📡 Atualizar inventário passivo")
        self.btn_scan_completo = QPushButton("🔎 Varredura detalhada /24")
        for b in (self.btn_scan_passivo, self.btn_scan_completo):
            b.setProperty("class", "ActionButton")
        self.btn_scan_passivo.clicked.connect(self._scan_passivo)
        self.btn_scan_completo.clicked.connect(self._scan_completo)
        self.btn_ips_disponiveis = QPushButton("📋 IPs provavelmente disponíveis")
        self.btn_ips_disponiveis.setProperty("class", "MenuButton")
        self.btn_ips_disponiveis.setEnabled(False)
        self.btn_ips_disponiveis.clicked.connect(self._alternar_ips_disponiveis)
        # A varredura detalhada só pode começar após a seleção assíncrona de uma
        # interface IPv4 elegível; evita uma janela curta com botão acionável.
        self.btn_scan_completo.setEnabled(False)
        bar.addWidget(self.btn_scan_passivo)
        bar.addWidget(self.btn_scan_completo)
        bar.addWidget(self.btn_ips_disponiveis)
        bar.addStretch()
        layout.addLayout(bar)

        self.progress_inventario = QProgressBar()
        self.progress_inventario.hide()
        layout.addWidget(self.progress_inventario)

        self.status_inventario = QLabel(
            "Pronto para atualizar o inventário ou iniciar uma varredura detalhada."
        )
        self.status_inventario.setObjectName("SubtituloTela")
        self.status_inventario.setWordWrap(True)
        layout.addWidget(self.status_inventario)

        self.network_panel = NetworkPanel(self, core_logic)
        layout.addWidget(self.network_panel)

        self.tabela_hosts = QTableWidget(0, 7)
        self.tabela_hosts.setHorizontalHeaderLabels([
            "Tipo", "Hostname", "IP", "MAC", "Estado", "Latência", "Serviços"
        ])
        self.tabela_hosts.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tabela_hosts.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tabela_hosts.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_hosts.horizontalHeader().setStretchLastSection(True)
        self._configurar_tabela_legivel(self.tabela_hosts, 260)
        layout.addWidget(section("Inventário passivo / hosts e serviços observados", self.tabela_hosts))

        self.painel_ips_disponiveis = self._card(
            "IPs provavelmente disponíveis"
        )
        ips_layout = QVBoxLayout(self.painel_ips_disponiveis)
        self.lbl_ips_disponiveis = QLabel(
            "Disponibilidade estimada pela varredura local. Confirme "
            "DHCP/reservas antes de configurar um IP manualmente."
        )
        self.lbl_ips_disponiveis.setObjectName("SubtituloTela")
        self.lbl_ips_disponiveis.setWordWrap(True)
        ips_layout.addWidget(self.lbl_ips_disponiveis)
        self.tabela_ips_disponiveis = QTableWidget(0, 3)
        self.tabela_ips_disponiveis.setHorizontalHeaderLabels(
            ["IPv4", "Estado", "Resumo"]
        )
        self.tabela_ips_disponiveis.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_ips_disponiveis.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tabela_ips_disponiveis.horizontalHeader().setStretchLastSection(True)
        self._configurar_tabela_legivel(self.tabela_ips_disponiveis, 190)
        ips_layout.addWidget(self.tabela_ips_disponiveis)
        self.painel_ips_disponiveis.hide()
        self._ips_disponiveis = []
        layout.addWidget(self.painel_ips_disponiveis)

        self._adicionar_pagina_rolavel(page, self.network_panel.device_context)

    def _pagina_inventario(self):
        self._set_nav(3)
        self._carregar_interfaces_varredura(automatico=True)

    def _carregar_interfaces_varredura(self, automatico=False):
        """Consulta em Worker as interfaces permitidas para a varredura."""
        worker = self._run(
            core_logic.ModuloEmpresa.obter_interfaces_varredura,
            label="Consultando interfaces para varredura",
            progress=self.progress_inventario,
            indeterminate=True,
            on_done=self._mostrar_interfaces_varredura,
            operation_key="inventario_rede",
            blocks_navigation=False,
            on_finally=self._finalizar_atualizacao_interfaces_scan,
            silent_if_busy=automatico,
        )
        if worker:
            self.combo_interface_scan.setEnabled(False)
            self.btn_atualizar_interfaces_scan.setEnabled(False)
            self.btn_scan_completo.setEnabled(False)
            self.info_interface_scan.setText("Consultando interfaces IPv4 ativas...")

    @staticmethod
    def _descricao_interface_scan(interface):
        alias = str(interface.get("Alias") or "Interface sem nome")
        ipv4 = str(interface.get("IPv4") or "sem IPv4")
        rede = str(interface.get("Rede") or "rede não disponível")
        gateway = str(interface.get("Gateway") or "").strip()
        texto = f"{alias} — {ipv4} — {rede}"
        return f"{texto} — GW {gateway}" if gateway else texto

    def _mostrar_interfaces_varredura(self, result):
        ok, dados, msg = result if isinstance(result, tuple) else (False, {}, str(result))
        candidatos = dados.get("Candidatas", []) if isinstance(dados, dict) else []
        selecionada_auto = dados.get("Selecionada") if isinstance(dados, dict) else None
        # Interfaces virtuais continuam selecionáveis explicitamente. Não são
        # sugeridas como rede física só por possuírem a menor métrica.
        fisicas = [item for item in candidatos if not item.get("Virtual")]
        selecionada_auto = fisicas[0] if fisicas else None
        preferida = self._interface_scan_preferida

        self._preenchendo_interfaces_scan = True
        self.combo_interface_scan.blockSignals(True)
        try:
            self.combo_interface_scan.clear()
            self._interface_scan_selecionada = None
            indice_escolhido = -1
            for indice, interface in enumerate(candidatos):
                if not isinstance(interface, dict):
                    continue
                item = dict(interface)
                self.combo_interface_scan.addItem(
                    self._descricao_interface_scan(item), item
                )
                chave = (item.get("Alias"), item.get("IPv4"), item.get("Rede"))
                if preferida and chave == preferida:
                    indice_escolhido = self.combo_interface_scan.count() - 1
                elif (
                    indice_escolhido < 0
                    and selecionada_auto
                    and chave == (
                        selecionada_auto.get("Alias"),
                        selecionada_auto.get("IPv4"),
                        selecionada_auto.get("Rede"),
                    )
                ):
                    indice_escolhido = self.combo_interface_scan.count() - 1
            self.combo_interface_scan.setCurrentIndex(indice_escolhido)
        finally:
            self.combo_interface_scan.blockSignals(False)
            self._preenchendo_interfaces_scan = False

        if self.combo_interface_scan.currentIndex() >= 0:
            self._atualizar_interface_scan(
                self.combo_interface_scan.currentIndex(), registrar=False
            )
            self.status_inventario.setText(
                "Interface selecionada. A varredura detalhada usará somente a rede exibida acima."
            )
        else:
            self.info_interface_scan.setText(
                msg or "Nenhuma interface IPv4 adequada foi encontrada para a varredura /24."
            )
            self.status_inventario.setText(
                "Varredura detalhada indisponível até que exista uma interface IPv4 ativa adequada."
            )
        self.btn_scan_completo.setEnabled(bool(self._interface_scan_selecionada))
        self.combo_interface_scan.setEnabled(bool(candidatos))
        self.btn_atualizar_interfaces_scan.setEnabled(True)
        self._log(
            f">> Interfaces de varredura: {len(candidatos)} elegível(is). {msg or ''}".strip()
        )

    def _atualizar_interface_scan(self, indice=None, registrar=True):
        if indice is None:
            indice = self.combo_interface_scan.currentIndex()
        if indice is None or indice < 0:
            self._interface_scan_selecionada = None
            self.network_panel.interface_changed(None)
            self.btn_scan_completo.setEnabled(False)
            return
        interface = self.combo_interface_scan.itemData(indice)
        if not isinstance(interface, dict):
            self._interface_scan_selecionada = None
            self.btn_scan_completo.setEnabled(False)
            return
        interface = dict(interface)
        if registrar and not self._preenchendo_interfaces_scan:
            interface["MotivoSelecao"] = "escolha_usuario"
            try:
                core_logic.registrar_log(
                    "EMPRESA",
                    "INTERFACE_SCAN_SELECIONADA",
                    "Alias: {0}; IPv4: {1}; Rede: {2}; Gateway: {3}; Motivo: escolha_usuario".format(
                        interface.get("Alias"), interface.get("IPv4"),
                        interface.get("Rede"), interface.get("Gateway") or "—",
                    ),
                )
            except Exception:
                pass
        self._interface_scan_selecionada = interface
        self.network_panel.interface_changed(interface)
        self._interface_scan_preferida = (
            interface.get("Alias"), interface.get("IPv4"), interface.get("Rede")
        )
        self.info_interface_scan.setText(
            "Rede selecionada para a varredura: {0} (máscara {1}).".format(
                interface.get("Rede"), interface.get("Mascara") or "não informada"
            )
        )
        if not self._operacao_ativa("inventario_rede"):
            self.btn_scan_completo.setEnabled(True)

    def _scan_passivo(self):
        self._limpar_ips_disponiveis()
        worker = self._run(
            core_logic.ModuloEmpresa.coletar_inventario_rede,
            label="Atualizando inventário passivo",
            progress=self.progress_inventario,
            indeterminate=True,
            blocks_navigation=False,
            on_done=self._mostrar_inventario_passivo,
            operation_key="inventario_rede",
            on_finally=self._finalizar_scan_inventario,
        )
        if worker:
            self._definir_estado_scan_inventario(
                True, "Atualizando inventário passivo..."
            )

    def _mostrar_inventario_passivo(self, result):
        ok, data, msg = result if isinstance(result, tuple) else (False, {}, str(result))
        if not ok:
            self.status_inventario.setText(
                f"Inventário passivo não concluído: {msg or 'falha controlada.'}"
            )
            self._resultado_generico((False, msg))
            return
        self._preencher_hosts(data.get("Hosts", []))
        self.status_inventario.setText(
            f"{msg} {len(data.get('Hosts', []))} host(s) recebido(s)."
        )
        self._log(f">> Inventário passivo: {len(data.get('Hosts', []))} host(s).")

    def _scan_completo(self):
        interface = self._interface_scan_selecionada
        if not isinstance(interface, dict):
            QMessageBox.warning(
                self,
                "Varredura detalhada",
                "Aguarde a consulta das interfaces ou selecione uma interface IPv4 adequada.",
            )
            return
        self.network_panel.start()

    def _mostrar_scan_completo(self, result):
        ok, hosts, msg = result if isinstance(result, tuple) else (False, [], str(result))
        if not ok:
            self.status_inventario.setText(
                f"Varredura detalhada não concluída: {msg or 'falha controlada.'}"
            )
            self._resultado_generico((False, msg))
            return
        self._preencher_hosts(hosts)
        self._carregar_ips_disponiveis_da_varredura()
        self.status_inventario.setText(msg or "Varredura detalhada concluída.")
        self._log(f">> {msg}")

    def _limpar_ips_disponiveis(self):
        """Limpa resultados de disponibilidade quando uma nova coleta começa."""
        self._ips_disponiveis = []
        if hasattr(self, "tabela_ips_disponiveis"):
            self.tabela_ips_disponiveis.setRowCount(0)
        if hasattr(self, "painel_ips_disponiveis"):
            self.painel_ips_disponiveis.hide()
        if hasattr(self, "btn_ips_disponiveis"):
            self.btn_ips_disponiveis.setEnabled(False)
            self.btn_ips_disponiveis.setText("📋 IPs provavelmente disponíveis")

    def _carregar_ips_disponiveis_da_varredura(self):
        """Exibe somente a estimativa produzida pela varredura já concluída."""
        try:
            # Não usa mais a estimativa legada baseada em uma única varredura.
            from network_intelligence import consolidate
            itens = []
            for registro in self.network_panel.records.values():
                atual = consolidate(registro, history_ok=self.network_panel.result.get("history_ok", False))
                if atual["state"] == "Candidato a livre":
                    itens.append({"IP": atual["ip"], "Estado": atual["state"], "Resumo": atual["recommendation"]})
        except Exception as exc:
            self._log(f">> [ERRO] Não foi possível ler a estimativa de IPs: {exc}")
            itens = []

        unicos = {}
        for item in itens if isinstance(itens, list) else []:
            if not isinstance(item, dict):
                continue
            ip = str(item.get("IP") or "").strip()
            try:
                endereco = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if endereco.version == 4:
                unicos[str(endereco)] = {
                    "IP": str(endereco),
                    "Estado": str(item.get("Estado") or "Provavelmente disponível"),
                    "Resumo": str(item.get("Resumo") or "Sem resposta ICMP/TCP observada na varredura."),
                }
        self._ips_disponiveis = sorted(
            unicos.values(), key=lambda item: int(ipaddress.ip_address(item["IP"]))
        )

        self.tabela_ips_disponiveis.setUpdatesEnabled(False)
        try:
            self.tabela_ips_disponiveis.setRowCount(0)
            for item in self._ips_disponiveis:
                row = self.tabela_ips_disponiveis.rowCount()
                self.tabela_ips_disponiveis.insertRow(row)
                for coluna, chave in enumerate(("IP", "Estado", "Resumo")):
                    self.tabela_ips_disponiveis.setItem(
                        row, coluna, QTableWidgetItem(item[chave])
                    )
        finally:
            self.tabela_ips_disponiveis.setUpdatesEnabled(True)

        quantidade = len(self._ips_disponiveis)
        self.btn_ips_disponiveis.setEnabled(True)
        self.btn_ips_disponiveis.setText(
            f"📋 Candidatos a livre ({quantidade})"
        )
        self.lbl_ips_disponiveis.setText(
            f"{quantidade} IP(s) sem evidência de uso na varredura concluída. "
            "Disponibilidade estimada pela varredura local. Confirme "
            "DHCP/reservas antes de configurar um IP manualmente."
        )

    def _alternar_ips_disponiveis(self):
        """Mantém a estimativa no Inventário sem iniciar nova varredura."""
        self._carregar_ips_disponiveis_da_varredura()
        self.network_panel.filter.setCurrentText("Candidato a livre")
        visivel = self.painel_ips_disponiveis.isVisible()
        self.painel_ips_disponiveis.setVisible(not visivel)
        self.btn_ips_disponiveis.setText(
            "📋 Ocultar IPs provavelmente disponíveis"
            if not visivel
            else f"📋 IPs provavelmente disponíveis ({len(self._ips_disponiveis)})"
        )

    def _definir_estado_scan_inventario(self, em_andamento, mensagem=""):
        """Mantém os controles do inventário coerentes durante uma única coleta."""
        if not hasattr(self, "btn_scan_completo"):
            return
        self.btn_scan_passivo.setEnabled(not em_andamento)
        self.btn_scan_completo.setEnabled(
            not em_andamento and bool(self._interface_scan_selecionada)
        )
        if hasattr(self, "combo_interface_scan"):
            self.combo_interface_scan.setEnabled(not em_andamento)
        if hasattr(self, "btn_atualizar_interfaces_scan"):
            self.btn_atualizar_interfaces_scan.setEnabled(not em_andamento)
        self.btn_scan_completo.setText(
            "🔎 Varredura detalhada em andamento..."
            if em_andamento else "🔎 Varredura detalhada /24"
        )
        if mensagem:
            self.status_inventario.setText(mensagem)

    def _finalizar_scan_inventario(self, state):
        self._definir_estado_scan_inventario(False)
        if state == "cancelled":
            self.status_inventario.setText(
                "Varredura cancelada — nenhum resultado parcial foi aplicado à tabela."
            )
        elif state in ("failure", "error"):
            # O callback pode já ter apresentado uma causa específica; este é
            # apenas o estado seguro para erros sem resultado retornado.
            if "não concluída" not in self.status_inventario.text().lower():
                self.status_inventario.setText("Varredura não concluída. Consulte a mensagem e o log.")

    def _finalizar_atualizacao_interfaces_scan(self, state):
        if hasattr(self, "btn_atualizar_interfaces_scan"):
            self.btn_atualizar_interfaces_scan.setEnabled(True)
        if hasattr(self, "combo_interface_scan"):
            self.combo_interface_scan.setEnabled(self.combo_interface_scan.count() > 0)
        if hasattr(self, "btn_scan_completo"):
            self.btn_scan_completo.setEnabled(bool(self._interface_scan_selecionada))
        if state == "cancelled":
            self.info_interface_scan.setText("Consulta de interfaces cancelada.")
        elif state == "error" and not self._interface_scan_selecionada:
            self.info_interface_scan.setText("Não foi possível consultar interfaces. Consulte o log.")

    def _preencher_hosts(self, hosts):
        # O backend já produz IPs únicos, mas a GUI também protege a tabela
        # contra respostas duplicadas/parciais de qualquer origem futura.
        por_ip = {}
        for indice, item in enumerate(hosts or []):
            if not isinstance(item, dict):
                continue
            ip = str(item.get("IP") or "").strip()
            chave = ip or f"__sem_ip_{indice}"
            if chave not in por_ip:
                por_ip[chave] = item

        def chave_ordenacao(item):
            ip = str(item.get("IP") or "").strip()
            try:
                endereco = ipaddress.ip_address(ip)
                return (0 if endereco.version == 4 else 1, int(endereco))
            except ValueError:
                return (2, ip.lower())

        itens = sorted(por_ip.values(), key=chave_ordenacao)
        self.tabela_hosts.setUpdatesEnabled(False)
        try:
            self.tabela_hosts.setRowCount(0)
            for item in itens:
                nome = str(item.get("Nome") or "").strip()
                if not nome or nome.lower() in {"não identificado", "nao identificado"}:
                    nome = "Não disponível"
                mac = str(item.get("MAC") or "").strip()
                if not mac or mac.lower() in {"não identificado", "nao identificado"}:
                    mac = "—"
                latencia = item.get("Latencia_ms")
                latencia_txt = f"{latencia} ms" if isinstance(latencia, (int, float)) else "—"
                servicos = item.get("Servicos") or item.get("Detalhes")
                if isinstance(servicos, (list, tuple, set)):
                    servicos = "; ".join(str(valor) for valor in servicos if str(valor).strip())
                servicos = str(servicos or "Nenhum serviço TCP identificado")
                row = self.tabela_hosts.rowCount()
                self.tabela_hosts.insertRow(row)
                values = [
                    item.get("Tipo") or "Host",
                    nome,
                    item.get("IP") or "—",
                    mac,
                    item.get("Estado") or "—",
                    latencia_txt,
                    servicos,
                ]
                for col, value in enumerate(values):
                    self.tabela_hosts.setItem(row, col, QTableWidgetItem(str(value)))
        finally:
            self.tabela_hosts.setUpdatesEnabled(True)

    # ---------------------------------------------------------
    # Relatórios
    # ---------------------------------------------------------
    def _build_relatorios(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Relatórios",
            "Gere o relatório completo da estação com hardware, discos, rede e histórico desta sessão."
        ))

        card = self._card("Relatório da máquina")
        cl = QVBoxLayout(card)

        self.report_status = QLabel(
            "Nenhum relatório gerado nesta sessão. Gere o HTML para consultar os dados completos.")
        destino = QLabel("Pasta de relatórios: " + str(core_logic.PASTA_RELATORIOS))
        destino.setWordWrap(True)
        cl.addWidget(destino)
        self.report_status.setObjectName("SubtituloTela")
        cl.addWidget(self.report_status)

        self.progress_relatorio = QProgressBar()
        self.progress_relatorio.hide()
        cl.addWidget(self.progress_relatorio)

        row = FlowRow()
        b = QPushButton("📊 Gerar Relatório HTML completo")
        b.setProperty("class", "ActionButton")
        b.clicked.connect(self._gerar_relatorio)
        row.addWidget(b)

        self.btn_open_reports = QPushButton("📁 Abrir pasta de relatórios")
        self.btn_open_reports.setProperty("class", "MenuButton")
        self.btn_open_reports.clicked.connect(self._abrir_pasta_relatorios)
        row.addWidget(self.btn_open_reports)
        row.addStretch()
        cl.addLayout(row)

        layout.addWidget(card)
        layout.addStretch()
        self._adicionar_pagina_rolavel(page)

    def _pagina_relatorios(self):
        self._set_nav(4)

    def _gerar_relatorio(self):
        self.report_status.setText("Coletando dados e montando relatório...")
        self._run(
            core_logic.gerar_relatorio,
            False,
            label="Gerando relatório HTML completo",
            progress=self.progress_relatorio,
            indeterminate=True,
            on_done=self._resultado_relatorio,
            audit_source="Relatórios",
            audit_category="REPORT",
            audit_summary="Geração de relatório HTML completo",
        )

    def _resultado_relatorio(self, result):
        if isinstance(result, tuple):
            ok = bool(result[0]) if result else False
            msg = str(result[1]) if len(result) > 1 else ""
        else:
            ok, msg = bool(result), str(result)

        if ok:
            self.report_status.setText("Relatório concluído. " + msg)
            self._log(">> [OK] Relatório gerado: " + msg)
        else:
            self.report_status.setText("Falha ao gerar o relatório.")
            self._log(">> [ERRO] Relatório: " + msg)
            QMessageBox.critical(
                self, "Falha no relatório", msg or "Não foi possível gerar o relatório."
            )

    def _abrir_pasta_relatorios(self):
        caminho = Path(core_logic.PASTA_RELATORIOS)
        try:
            os.startfile(str(caminho))
        except Exception as exc:
            QMessageBox.critical(self, "Pasta", str(exc))

    # ---------------------------------------------------------
    # Monitoramento
    # ---------------------------------------------------------
    def _build_monitoramento(self):
        self.monitoring_panel = MonitoringPanel(self, core_logic)
        self._adicionar_pagina_rolavel(self.monitoring_panel)
        # Alias de compatibilidade para automações e testes das versões
        # anteriores; a coleta ativa desta fase usa somente CPU/RAM/disco.
        self.monitoramento_status = self.monitoring_panel.status_label
        self.monitoramento_info = self.monitoring_panel.info_label
        self.btn_monitor_toggle = self.monitoring_panel.start_button
        self.combo_intervalo_monitoramento = self.monitoring_panel.interval_combo
        self.monitor_cpu = self.monitoring_panel.metric_value_labels["cpu_usage"]
        self.monitor_ram = self.monitoring_panel.metric_value_labels["memory_usage"]
        self.monitor_disco = self.monitoring_panel.metric_value_labels["system_disk_free"]
        self.tabela_historico_monitoramento = self.monitoring_panel.transitions_table
        for name in (
            "monitor_interface", "monitor_ipv4", "monitor_gateway",
            "monitor_latencia_gateway", "monitor_dns", "monitor_dns_validacao",
            "monitor_internet", "monitor_falhas", "monitor_ultima_atualizacao",
        ):
            setattr(self, name, getattr(self.monitoring_panel, name))
        return

    def _pagina_monitoramento(self):
        self._set_nav(5)
        if hasattr(self, "monitoring_panel"):
            self.monitoring_panel.refresh()

    def _abrir_monitoramento(self):
        """Atalho da Visão Geral: navega sem abrir monitor externo legado."""
        self._pagina_monitoramento()

    def _alternar_monitoramento(self):
        service = self._get_monitoring_service()
        if service is None or service.status == "STOPPED":
            return self.monitoring_panel.start()
        return self.monitoring_panel.stop()

    def _iniciar_monitoramento(self):
        return self.monitoring_panel.start()

    def _parar_monitoramento(self, motivo="usuario"):
        return self.monitoring_panel.stop(str(motivo))

    def _intervalo_monitoramento_segundos(self):
        return int(self.monitoring_panel.interval_combo.currentData())

    def _alterar_intervalo_monitoramento(self, _indice=None):
        return self.monitoring_panel.change_interval(_indice)

    def _solicitar_coleta_monitoramento(self):
        """Dispara no máximo uma coleta local de monitoramento por vez."""
        return self.monitoring_panel.request_collection()

    def _aplicar_snapshot_monitoramento(self, result):
        return self.monitoring_panel.present_result(result)

    def _limpar_historico_monitoramento(self):
        self.monitoring_panel._sample_offset = 0
        self.monitoring_panel.refresh()

    def _atualizar_sensores_hardware(self):
        """Atualiza sensores em Worker sem interferir no monitoramento local."""
        if self._closing or not hasattr(self, "btn_atualizar_sensores"):
            return
        if self._operacao_ativa("sensores_hardware"):
            self.lbl_sensores_hardware.setText(
                "Já existe uma atualização de sensores em andamento."
            )
            return

        # A temperatura de disco é apenas reaproveitada da última análise de
        # Saúde de Armazenamento; não executamos SMART/reliability novamente
        # nem alteramos a elevação isolada já aprovada para essa operação.
        snapshot_armazenamento = (
            self._dados_saude_armazenamento
            if isinstance(getattr(self, "_dados_saude_armazenamento", None), dict)
            else None
        )
        self.btn_atualizar_sensores.setEnabled(False)
        self.lbl_sensores_hardware.setText(
            "Coletando telemetria nativa em segundo plano; você pode navegar pela interface."
        )
        worker = self._run(
            core_logic.ModuloSistema.obter_sensores_hardware,
            snapshot_armazenamento,
            label="Atualizando sensores de hardware",
            progress=self.progress_sensores_hardware,
            indeterminate=True,
            operation_key="sensores_hardware",
            blocks_navigation=False,
            on_done=self._mostrar_sensores_hardware,
            on_finally=self._finalizar_atualizacao_sensores_hardware,
            silent_if_busy=True,
        )
        if worker is None and not self._closing:
            self.btn_atualizar_sensores.setEnabled(True)
            self.lbl_sensores_hardware.setText(
                "Não foi possível iniciar a atualização dos sensores."
            )

    def _mostrar_sensores_hardware(self, resultado):
        """Apresenta a telemetria por componente, sem alterar a coleta."""
        if not isinstance(resultado, dict):
            raise ValueError("Retorno inválido da telemetria de hardware.")
        if resultado.get("Cancelada"):
            self.lbl_sensores_hardware.setText(
                resultado.get("Mensagem") or "Atualização de sensores cancelada."
            )
            self._log(">> [CANCELADA] Atualização de sensores de hardware.")
            return
        if not resultado.get("Sucesso"):
            mensagem = (
                resultado.get("Mensagem")
                or "Não foi possível atualizar a telemetria de hardware."
            )
            self.abas_sensores_hardware.clear()
            self.lbl_sensores_hardware.setText(mensagem)
            self._log(f">> [ERRO] Sensores de hardware: {mensagem}")
            return

        medidas = resultado.get("Componentes") or []
        if not isinstance(medidas, list):
            raise ValueError("Lista de sensores em formato inválido.")

        # Uma GPU é identificada pela própria origem nativa, e não pelo nome.
        # Assim somente adaptadores explicitamente reconhecidos como virtuais
        # são separados da GPU física; os demais mantêm o nome do driver.
        componentes_gpu = {
            str(medida.get("Componente") or "")
            for medida in medidas
            if isinstance(medida, dict)
            and str(medida.get("Medida") or "") == "Adaptador"
            and str(medida.get("Origem") or "") == "Win32_VideoController"
        }
        marcadores_gpu_virtual = (
            "ms idd device",
            "microsoft basic render driver",
            "microsoft remote display adapter",
            "indirect display",
        )

        def nome_componente(item):
            bruto = str(item.get("Componente") or "—")
            if bruto.casefold() == "primary":
                return "Bateria principal"
            return bruto

        def eh_gpu_virtual(componente):
            normalizado = componente.casefold()
            return any(marcador in normalizado for marcador in marcadores_gpu_virtual)

        def consolidar_instancias_virtuais(itens):
            """Consolida somente blocos virtuais idênticos já devolvidos.

            O backend não recebe identificador individual para cada instância
            de Win32_VideoController. Por isso a consolidação só ocorre quando
            todos os blocos, delimitados por `Adaptador`, possuem as mesmas
            medidas, valores, estados, origem e limitação.
            """
            blocos = []
            bloco_atual = []
            for item in itens:
                if str(item.get("Medida") or "") == "Adaptador" and bloco_atual:
                    blocos.append(bloco_atual)
                    bloco_atual = []
                bloco_atual.append(item)
            if bloco_atual:
                blocos.append(bloco_atual)
            if len(blocos) < 2 or any(
                not bloco or str(bloco[0].get("Medida") or "") != "Adaptador"
                for bloco in blocos
            ):
                return itens, 1, None

            def assinatura(bloco):
                return tuple(
                    (
                        str(item.get("Medida") or "").casefold(),
                        str(item.get("Valor") or ""),
                        str(item.get("Estado") or ""),
                        str(item.get("Origem") or ""),
                        str(item.get("Limitacao") or ""),
                    )
                    for item in bloco
                )

            primeira_assinatura = assinatura(blocos[0])
            if not all(assinatura(bloco) == primeira_assinatura for bloco in blocos[1:]):
                return itens, 1, blocos

            representante = list(blocos[0])
            origem = str(representante[0].get("Origem") or "Win32_VideoController")
            representante.insert(0, {
                "Componente": representante[0].get("Componente") or "—",
                "Medida": "Instâncias detectadas",
                "Valor": str(len(blocos)),
                "Estado": "Informativo",
                "Origem": origem,
                "Limitacao": (
                    "Instâncias virtuais equivalentes foram consolidadas somente na apresentação; "
                    "nenhum adaptador foi removido ou associado a uma GPU física."
                ),
            })
            return representante, len(blocos), None

        def grupo_para(item):
            componente = str(item.get("Componente") or "")
            componente_normalizado = componente.casefold()
            origem = str(item.get("Origem") or "").casefold()
            if componente_normalizado.startswith("cpu"):
                return "CPU"
            if "memória ram" in componente_normalizado:
                return "Memória RAM"
            if componente in componentes_gpu or componente_normalizado == "gpu (agregada)":
                return (
                    "Adaptadores virtuais"
                    if componente in componentes_gpu and eh_gpu_virtual(componente)
                    else "GPU"
                )
            if componente_normalizado.startswith("disco") or componente_normalizado == "discos":
                return "Armazenamento"
            if (
                componente_normalizado.startswith("placa-mãe")
                or componente_normalizado.startswith("chassis")
                or componente_normalizado.startswith("ventoinha")
            ):
                return "Hardware térmico"
            if "win32_battery" in origem or componente_normalizado.startswith("bateria") or componente_normalizado == "primary":
                return "Bateria"
            return "Outros dados nativos"

        def titulo_componente(item):
            componente = nome_componente(item)
            if str(item.get("Componente") or "") in componentes_gpu:
                if eh_gpu_virtual(str(item.get("Componente") or "")):
                    return f"Adaptador de vídeo virtual — {componente}"
                return f"GPU — {componente}"
            if componente.casefold() == "gpu (agregada)":
                return "Atividade agregada de GPU"
            return componente

        def rotulo_medida(item):
            medida = str(item.get("Medida") or "—")
            nomes = {
                "Uso total": "Uso atual",
                "Frequência máxima conhecida": "Frequência máxima reportada pelo Windows",
                "Memória dedicada informada": "Memória reportada pelo driver",
            }
            return nomes.get(medida, medida)

        def estado_visual(item):
            estado = str(item.get("Estado") or "Não disponível")
            if estado != "Indeterminado":
                return estado
            # Leituras de inventário e amostras sem limiar de saúde são
            # informativas. Temperaturas genéricas e de disco continuam
            # indeterminadas porque não há limite universal seguro.
            medida = str(item.get("Medida") or "").casefold()
            origem = str(item.get("Origem") or "").casefold()
            if "temperatura" in medida or "zona térmica acpi" in medida or "msacpi_thermalzonetemperature" in origem:
                return "Indeterminado"
            return "Informativo"

        grupos = {}
        for medida in medidas:
            if not isinstance(medida, dict):
                continue
            grupo = grupo_para(medida)
            titulo = titulo_componente(medida)
            grupos.setdefault(grupo, {}).setdefault(titulo, []).append(medida)

        for titulo, itens in list(grupos.get("Adaptadores virtuais", {}).items()):
            itens_consolidados, quantidade, subitens_distintos = consolidar_instancias_virtuais(itens)
            if quantidade > 1:
                grupos["Adaptadores virtuais"][titulo] = itens_consolidados
            elif subitens_distintos:
                # A mesma identificação não prova que as instâncias são
                # equivalentes. Quando qualquer medida diverge, cada bloco é
                # preservado em subcard próprio, sem misturar métricas.
                del grupos["Adaptadores virtuais"][titulo]
                for indice, subitens in enumerate(subitens_distintos, start=1):
                    grupos["Adaptadores virtuais"][
                        f"{titulo} — instância {indice}"
                    ] = subitens

        abas = self.abas_sensores_hardware
        abas.setUpdatesEnabled(False)
        try:
            abas.clear()
            abas.addTab(consolidated_sensors(grupos, resultado, rotulo_medida, estado_visual), "Resumo")
        finally:
            abas.setUpdatesEnabled(True)

        mensagem = resultado.get("Mensagem") or "Telemetria atualizada."
        coletado_em = str(resultado.get("ColetadoEm") or "")
        if coletado_em:
            mensagem = f"{mensagem} Atualizado em {local_timestamp(coletado_em)[0]}."
            self.lbl_sensores_hardware.setToolTip(local_timestamp(coletado_em)[1])
        self.lbl_sensores_hardware.setText(mensagem)
        self._log(f">> [OK] Sensores de hardware: {mensagem}")

    def _finalizar_atualizacao_sensores_hardware(self, estado):
        if self._closing:
            return
        if hasattr(self, "btn_atualizar_sensores"):
            self.btn_atualizar_sensores.setEnabled(True)
        if estado == "cancelled":
            self.lbl_sensores_hardware.setText(
                "Atualização de sensores cancelada de forma cooperativa."
            )
        elif estado == "error":
            self.lbl_sensores_hardware.setText(
                "Falha controlada ao coletar sensores. Consulte o log para detalhes."
            )

    def _finalizar_coleta_monitoramento(self, state):
        return self.monitoring_panel.collection_finished(state)

    # ---------------------------------------------------------
    # Implantação
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # Processos & Serviços — versão nativa Qt
    # ---------------------------------------------------------
    def _build_processos(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Processos & Serviços",
            "Painel nativo do configurador para visualizar processos, consumo e serviços."
        ))

        top = FlowRow()
        self.filtro_processo = QLineEdit()
        self.filtro_processo.setPlaceholderText("Filtrar por nome ou PID...")
        self.filtro_processo.textChanged.connect(self._agendar_filtro_processos)
        top.addWidget(self.filtro_processo)

        self.btn_refresh_proc = QPushButton("🔄 Atualizar")
        self.btn_refresh_proc.setProperty("class", "ActionButton")
        self.btn_refresh_proc.clicked.connect(self._atualizar_processos)
        top.addWidget(self.btn_refresh_proc)

        self.chk_auto_proc = QCheckBox("Atualização automática (3s)")
        self.chk_auto_proc.toggled.connect(self._alternar_auto_processos)
        top.addWidget(self.chk_auto_proc)
        layout.addLayout(top)

        cards = QHBoxLayout()
        self.proc_cpu = QLabel("CPU: —")
        self.proc_ram = QLabel("RAM: —")
        self.proc_disk = QLabel("Discos: —")
        for title, label in (("Processador", self.proc_cpu), ("Memória RAM", self.proc_ram), ("Armazenamento", self.proc_disk)):
            label.setObjectName("ValorCard")
            box = self._card(title)
            bl = QVBoxLayout(box)
            bl.addWidget(label)
            cards.addWidget(box)
        layout.addLayout(cards)

        self.tabela_processos = QTableWidget(0, 5)
        self.tabela_processos.setHorizontalHeaderLabels(
            ["PID", "Processo", "CPU", "Memória", "Handles"]
        )
        self.tabela_processos.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_processos.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tabela_processos.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_processos.horizontalHeader().setStretchLastSection(False)
        self.tabela_processos.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._configurar_tabela_legivel(self.tabela_processos, 260)
        layout.addWidget(self.tabela_processos, 1)

        actions = FlowRow()
        self.btn_proc_finalizar = QPushButton("⛔ Encerrar processo")
        self.btn_proc_finalizar.setProperty("class", "DangerButton")
        self.btn_proc_finalizar.clicked.connect(self._finalizar_processo)
        actions.addWidget(self.btn_proc_finalizar)
        self.btn_proc_detalhes = QPushButton("🔎 Detalhes")
        self.btn_proc_detalhes.setProperty("class", "MenuButton")
        self.btn_proc_detalhes.clicked.connect(self._detalhes_processo)
        actions.addWidget(self.btn_proc_detalhes)
        actions.addStretch()
        layout.addLayout(actions)

        services = self._card("Serviços do Windows")
        sl = QVBoxLayout(services)
        self.tabela_servicos = QTableWidget(0, 4)
        self.tabela_servicos.setHorizontalHeaderLabels(
            ["Nome", "Nome de exibição", "Estado", "Inicialização"]
        )
        self.tabela_servicos.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_servicos.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tabela_servicos.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_servicos.horizontalHeader().setStretchLastSection(False)
        self.tabela_servicos.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._configurar_tabela_legivel(self.tabela_servicos, 190)
        sl.addWidget(self.tabela_servicos)
        sa = FlowRow()
        for text, action in [
            ("▶ Iniciar", "start"), ("⏹ Parar", "stop"), ("🔄 Reiniciar", "restart")
        ]:
            b = QPushButton(text)
            b.setProperty("class", "MenuButton")
            b.clicked.connect(lambda checked=False, a=action: self._servico(a))
            sa.addWidget(b)
        sa.addStretch()
        sl.addLayout(sa)
        layout.addWidget(services)

        analise = self._card("Análise defensiva")
        analise_layout = QVBoxLayout(analise)
        aviso_analise = QLabel(
            "Triagem local e somente leitura de processos, executáveis, "
            "assinaturas e persistências. Os sinais ajudam a investigação "
            "humana e não confirmam malware."
        )
        aviso_analise.setObjectName("SubtituloTela")
        aviso_analise.setWordWrap(True)
        analise_layout.addWidget(aviso_analise)

        botoes_analise = FlowRow()
        self.btn_iniciar_analise_defensiva = QPushButton(
            "🛡 Analisar processos e persistências"
        )
        self.btn_iniciar_analise_defensiva.setProperty("class", "ActionButton")
        self.btn_iniciar_analise_defensiva.clicked.connect(
            self._iniciar_analise_defensiva
        )
        botoes_analise.addWidget(self.btn_iniciar_analise_defensiva)

        self.btn_cancelar_analise_defensiva = QPushButton("Cancelar")
        self.btn_cancelar_analise_defensiva.setProperty("class", "MenuButton")
        self.btn_cancelar_analise_defensiva.setEnabled(False)
        self.btn_cancelar_analise_defensiva.clicked.connect(
            self._cancelar_analise_defensiva
        )
        botoes_analise.addWidget(self.btn_cancelar_analise_defensiva)

        self.btn_atualizar_analise_defensiva = QPushButton("🔄 Atualizar")
        self.btn_atualizar_analise_defensiva.setProperty("class", "MenuButton")
        self.btn_atualizar_analise_defensiva.clicked.connect(
            self._iniciar_analise_defensiva
        )
        botoes_analise.addWidget(self.btn_atualizar_analise_defensiva)

        self.btn_copiar_analise_defensiva = QPushButton("Copiar resumo")
        self.btn_copiar_analise_defensiva.setProperty("class", "MenuButton")
        self.btn_copiar_analise_defensiva.clicked.connect(
            self._copiar_resumo_analise_defensiva
        )
        botoes_analise.addWidget(self.btn_copiar_analise_defensiva)

        self.btn_hash_analise_defensiva = QPushButton("Calcular SHA-256")
        self.btn_hash_analise_defensiva.setProperty("class", "MenuButton")
        self.btn_hash_analise_defensiva.setEnabled(False)
        self.btn_hash_analise_defensiva.clicked.connect(
            self._calcular_hash_analise_defensiva
        )
        botoes_analise.addWidget(self.btn_hash_analise_defensiva)
        botoes_analise.addStretch()
        analise_layout.addLayout(botoes_analise)

        self.lbl_analise_defensiva = QLabel(
            "Pronto para uma análise explícita. Nenhuma ação corretiva será executada."
        )
        self.lbl_analise_defensiva.setWordWrap(True)
        analise_layout.addWidget(self.lbl_analise_defensiva)
        self.lbl_defender_analise_defensiva = QLabel(
            "Microsoft Defender: status ainda não consultado."
        )
        self.lbl_defender_analise_defensiva.setWordWrap(True)
        analise_layout.addWidget(self.lbl_defender_analise_defensiva)

        self.progresso_analise_defensiva = QProgressBar()
        self.progresso_analise_defensiva.setRange(0, 100)
        self.progresso_analise_defensiva.hide()
        analise_layout.addWidget(self.progresso_analise_defensiva)

        resumo_analise = QGridLayout()
        self.contador_normal_analise = QPushButton("Normal: 0")
        self.contador_informativo_analise = QPushButton("Informativo: 0")
        self.contador_atencao_analise = QPushButton("Atenção: 0")
        self.contador_suspeito_analise = QPushButton("Suspeito: 0")
        self.contador_requer_analise = QPushButton("Requer análise: 0")
        self.contador_nao_disponivel_analise = QPushButton("Não disponível: 0")
        for indice, contador in enumerate((
            self.contador_normal_analise,
            self.contador_informativo_analise,
            self.contador_atencao_analise,
            self.contador_suspeito_analise,
            self.contador_requer_analise,
            self.contador_nao_disponivel_analise,
        )):
            classe = contador.text().rsplit(":", 1)[0]
            contador.setProperty("class", "MenuButton")
            contador.setToolTip("Filtrar por " + classe + "; clicar novamente volta a Todos.")
            contador.clicked.connect(
                lambda _checked=False, valor=classe: self._filtrar_card_triagem(valor)
            )
            resumo_analise.addWidget(contador, indice // 3, indice % 3)
        analise_layout.addLayout(resumo_analise)
        self.baseline_panel = BaselinePanel(self, core_logic)
        analise_layout.addWidget(self.baseline_panel)

        filtros_analise = FlowRow()
        filtros_analise.addWidget(QLabel("Classificação:"))
        self.filtro_classificacao_analise = QComboBox()
        self.filtro_classificacao_analise.addItems([
            "Todos", "Normal", "Informativo", "Atenção", "Suspeito",
            "Requer análise", "Não disponível",
        ])
        self.filtro_classificacao_analise.currentTextChanged.connect(
            self._renderizar_analise_defensiva
        )
        filtros_analise.addWidget(self.filtro_classificacao_analise)
        self.filtro_texto_analise = QLineEdit()
        self.filtro_texto_analise.setPlaceholderText(
            "Filtrar por tipo, nome, PID, caminho ou motivo..."
        )
        self.filtro_texto_analise.textChanged.connect(
            self._agendar_filtro_analise_defensiva
        )
        filtros_analise.addWidget(self.filtro_texto_analise, 1)
        self.lbl_correspondencias_analise = QLabel("Correspondências: 0")
        filtros_analise.addWidget(self.lbl_correspondencias_analise)
        analise_layout.addLayout(filtros_analise)

        filtros_triagem = QGridLayout()
        filtros_triagem.addWidget(QLabel("Revisão:"), 0, 0)
        self.filtro_revisao_triagem = QComboBox()
        self.filtro_revisao_triagem.addItems(triagem.FILTROS)
        self.filtro_revisao_triagem.currentTextChanged.connect(self._renderizar_analise_defensiva)
        filtros_triagem.addWidget(self.filtro_revisao_triagem, 0, 1)
        filtros_triagem.addWidget(QLabel("Focar por:"), 0, 2)
        self.foco_triagem = QComboBox()
        self.foco_triagem.addItems(triagem.FOCOS)
        self.foco_triagem.setToolTip("Seleciona e rola para o primeiro candidato; não reordena linhas. Nova busca textual prioriza relevância.")
        self.foco_triagem.currentTextChanged.connect(self._renderizar_analise_defensiva)
        filtros_triagem.addWidget(self.foco_triagem, 0, 3)
        self.somente_relevantes_triagem = QCheckBox("Somente itens relevantes")
        self.somente_relevantes_triagem.setToolTip("Atenção, Suspeito ou Requer análise; combinado com os demais filtros por E lógico.")
        self.somente_relevantes_triagem.toggled.connect(self._renderizar_analise_defensiva)
        filtros_triagem.addWidget(self.somente_relevantes_triagem, 1, 0, 1, 4)
        filtros_triagem.setColumnStretch(3, 1)
        analise_layout.addLayout(filtros_triagem)
        self.lbl_filtros_ativos_triagem = QLabel("")
        analise_layout.addWidget(self.lbl_filtros_ativos_triagem)
        limpar_filtros = QPushButton("Limpar filtros")
        limpar_filtros.clicked.connect(self._limpar_filtros_triagem)
        analise_layout.addWidget(limpar_filtros, alignment=Qt.AlignmentFlag.AlignLeft)

        self.tabela_analise_defensiva = QTableWidget(0, 7)
        self.tabela_analise_defensiva.setHorizontalHeaderLabels([
            "Tipo", "Nome", "PID", "Caminho / alvo", "Assinatura",
            "Classificação", "Motivo principal",
        ])
        self.tabela_analise_defensiva.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.tabela_analise_defensiva.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tabela_analise_defensiva.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.tabela_analise_defensiva.setShowGrid(False)
        self.tabela_analise_defensiva.setWordWrap(False)
        self.tabela_analise_defensiva.setTextElideMode(
            Qt.TextElideMode.ElideRight
        )
        cabecalho_analise = self.tabela_analise_defensiva.horizontalHeader()
        cabecalho_analise.setMinimumSectionSize(86)
        cabecalho_analise.setStretchLastSection(False)
        cabecalho_analise.setSectionResizeMode(
            0, QHeaderView.ResizeMode.Interactive
        )
        cabecalho_analise.resizeSection(0, 115)
        cabecalho_analise.setSectionResizeMode(
            1, QHeaderView.ResizeMode.Interactive
        )
        cabecalho_analise.resizeSection(1, 190)
        cabecalho_analise.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        cabecalho_analise.resizeSection(2, 86)
        cabecalho_analise.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        cabecalho_analise.setSectionResizeMode(
            4, QHeaderView.ResizeMode.Interactive
        )
        cabecalho_analise.resizeSection(4, 150)
        cabecalho_analise.setSectionResizeMode(
            5, QHeaderView.ResizeMode.Interactive
        )
        cabecalho_analise.resizeSection(5, 160)
        cabecalho_analise.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        dicas_cabecalho = (
            "Origem do item analisado.",
            "Nome sanitizado do processo, arquivo ou persistência.",
            "Identificador do processo, quando aplicável.",
            "Caminho ou alvo sem argumentos de linha de comando.",
            "Estado da assinatura digital disponível na coleta.",
            "Classificação conservadora da análise defensiva.",
            "Principal razão objetiva para a classificação.",
        )
        for coluna, dica in enumerate(dicas_cabecalho):
            item_cabecalho = self.tabela_analise_defensiva.horizontalHeaderItem(
                coluna
            )
            if item_cabecalho is not None:
                item_cabecalho.setToolTip(dica)
        self.tabela_analise_defensiva.itemSelectionChanged.connect(
            self._mostrar_detalhes_analise_defensiva
        )
        self.tabela_analise_defensiva.itemClicked.connect(
            self._mostrar_detalhes_analise_defensiva
        )
        self.tabela_analise_defensiva.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabela_analise_defensiva.customContextMenuRequested.connect(self._menu_triagem)
        self._configurar_tabela_legivel(self.tabela_analise_defensiva, 250)
        analise_layout.addWidget(self.tabela_analise_defensiva)

        self.detalhes_analise_defensiva = QTextEdit()
        self.detalhes_analise_defensiva.setReadOnly(True)
        self.detalhes_analise_defensiva.setMinimumHeight(190)
        self.detalhes_analise_defensiva.setPlaceholderText(
            "Selecione um item para ver evidências, limitações e recomendação."
        )
        analise_layout.addWidget(section("Detalhes e evidências do item selecionado", self.detalhes_analise_defensiva))
        acoes_triagem = FlowRow()
        for texto, callback in (
            ("Revisar item…", self._menu_triagem_botao),
            ("Copiar resumo da investigação", self._copiar_resumo_investigacao),
        ):
            botao = QPushButton(texto)
            botao.setProperty("class", "MenuButton")
            botao.clicked.connect(callback)
            acoes_triagem.addWidget(botao)
        acoes_triagem.addStretch()
        analise_layout.addLayout(acoes_triagem)
        self.lbl_triagem = QLabel("Revisão humana separada da classificação automática. Botão direito para avaliar ou anotar.")
        self.lbl_triagem.setWordWrap(True)
        self.lbl_triagem.setTextFormat(Qt.TextFormat.PlainText)
        analise_layout.addWidget(self.lbl_triagem)
        layout.addWidget(analise)

        self.abas_processos = QTabWidget()
        self.abas_processos.setMinimumHeight(280)
        layout.removeWidget(services)
        layout.removeWidget(analise)
        process_items = []
        while layout.count() > 1:
            item = layout.takeAt(1)
            if item.widget() is not None:
                process_items.append(item.widget())
            elif item.layout() is not None:
                process_items.append(item.layout())
        self.abas_processos.addTab(scroll_content(process_items), "Processos")
        self.abas_processos.addTab(scroll_content([services]), "Serviços")
        self.abas_processos.addTab(scroll_content([analise]), "Análise defensiva e triagem")
        layout.addWidget(self.abas_processos)

        self._timer_processos = QTimer(self)
        self._timer_processos.setInterval(3000)
        self._timer_processos.timeout.connect(self._atualizacao_processos_automatica)
        self._timer_filtro_processos = QTimer(self)
        self._timer_filtro_processos.setSingleShot(True)
        self._timer_filtro_processos.setInterval(300)
        self._timer_filtro_processos.timeout.connect(
            self._aplicar_filtro_processos_debounced
        )
        self._timer_filtro_analise_defensiva = QTimer(self)
        self._timer_filtro_analise_defensiva.setSingleShot(True)
        self._timer_filtro_analise_defensiva.setInterval(275)
        self._timer_filtro_analise_defensiva.timeout.connect(
            self._aplicar_filtro_analise_defensiva_debounced
        )
        self._adicionar_pagina_rolavel(page)

    def _limpar_filtros_triagem(self):
        """Limpa somente controles visuais; reutiliza o filtro/cache existente."""
        self.filtro_texto_analise.clear()
        self.filtro_classificacao_analise.setCurrentIndex(0)
        self.filtro_revisao_triagem.setCurrentIndex(0)
        self.foco_triagem.setCurrentIndex(0)
        self.somente_relevantes_triagem.setChecked(False)

    def _pagina_processos(self):
        self._set_nav(6)
        self.abas_processos.setCurrentIndex(0)
        self._atualizar_processos()
        self._carregar_servicos()

    def _pagina_seguranca(self):
        """Abre a análise defensiva existente sob o domínio Segurança."""
        self._set_nav(6, domain_id="security")
        self.abas_processos.setCurrentIndex(2)

    def _alternar_auto_processos(self, ativo):
        if ativo and self.pages.currentIndex() == 6:
            self._timer_processos.start()
        else:
            self._timer_processos.stop()

    def _atualizacao_processos_automatica(self):
        if (
            self._closing
            or self.pages.currentIndex() != 6
            or not self.chk_auto_proc.isChecked()
        ):
            self._timer_processos.stop()
            return
        self._atualizar_processos(automatico=True)

    def _agendar_filtro_processos(self, _texto=""):
        if not self._closing:
            self._timer_filtro_processos.start()

    def _aplicar_filtro_processos_debounced(self):
        if self._closing or self.pages.currentIndex() != 6:
            return
        if self._dados_processos_cache:
            self._renderizar_processos(self._dados_processos_cache)
        else:
            self._atualizar_processos()

    def _agendar_filtro_analise_defensiva(self, texto=""):
        if self._closing:
            return
        if not str(texto):
            self._timer_filtro_analise_defensiva.stop()
            self._renderizar_analise_defensiva()
            return
        self._timer_filtro_analise_defensiva.start()

    def _aplicar_filtro_analise_defensiva_debounced(self):
        if self._closing or self.pages.currentIndex() != 6:
            return
        self._renderizar_analise_defensiva()

    @staticmethod
    def _powershell_json(script, timeout=30, cancel_callback=None):
        """Executa PowerShell somente a partir de Worker e devolve JSON."""
        if callable(cancel_callback) and cancel_callback():
            return []
        import subprocess
        script_utf8 = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;"
            "$OutputEncoding = [System.Text.Encoding]::UTF8;"
            + script
        )
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script_utf8],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if callable(cancel_callback) and cancel_callback():
            return []
        if r.returncode:
            bruto = r.stderr or r.stdout or b"Falha ao executar PowerShell."
            mensagem = bruto.decode("utf-8-sig", errors="replace")
            raise RuntimeError(mensagem.strip())
        raw = (r.stdout or b"").decode("utf-8-sig", errors="replace").strip()
        if not raw:
            return []
        import json
        value = json.loads(raw)
        if isinstance(value, dict):
            return [value]
        return value

    @staticmethod
    def _coletar_processos(cancel_callback=None):
        dados = MainWindow._powershell_json(
            "$ErrorActionPreference='Stop'; "
            "Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | "
            "? {$_.IDProcess -gt 0 -and $_.Name -notin @('Idle','_Total')} | "
            "% {[pscustomobject]@{PID=[int]$_.IDProcess;Nome=$_.Name;"
            "CPU=[double]$_.PercentProcessorTime;Memoria=[int64]$_.WorkingSetPrivate;"
            "Handles=[int]$_.HandleCount}} | ConvertTo-Json -Depth 3 -Compress",
            cancel_callback=cancel_callback,
        )
        if callable(cancel_callback) and cancel_callback():
            return {}

        processos = [item for item in dados if isinstance(item, dict)]
        processos.sort(
            key=lambda item: float(item.get("Memoria", 0) or 0),
            reverse=True,
        )
        resumo_lista = MainWindow._powershell_json(
            "$os=Get-CimInstance Win32_OperatingSystem;"
            "$cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor|"
            "? Name -eq '_Total'|select -First 1;"
            "$disks=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|"
            "% {$_.DeviceID+': '+[math]::Round((1-($_.FreeSpace/$_.Size))*100)+'% usado'};"
            "[pscustomobject]@{CPU=$cpu.PercentProcessorTime;"
            "Total=[int64]$os.TotalVisibleMemorySize*1KB;"
            "Livre=[int64]$os.FreePhysicalMemory*1KB;Discos=$disks}|"
            "ConvertTo-Json -Depth 4 -Compress",
            cancel_callback=cancel_callback,
        )
        if callable(cancel_callback) and cancel_callback():
            return {}
        return {
            "processos": processos,
            "resumo": resumo_lista[0] if resumo_lista else {},
        }

    def _atualizar_processos(self, automatico=False):
        if not hasattr(self, "tabela_processos"):
            return
        if self._operacao_ativa("processos_refresh"):
            return
        self._run(
            self._coletar_processos,
            label="Atualizando processos" if not automatico else "Atualização automática de processos",
            on_done=self._processos_carregados,
            operation_key="processos_refresh",
            blocks_navigation=False,
            silent_if_busy=True,
        )

    def _processos_carregados(self, resultado):
        if not isinstance(resultado, dict):
            self._log(">> [ERRO] Processos: retorno inválido da consulta.")
            return
        dados = resultado.get("processos", [])
        if not isinstance(dados, list):
            self._log(">> [ERRO] Processos: lista de processos inválida.")
            return
        self._dados_processos_cache = dados
        self._renderizar_processos(dados)

        resumo = resultado.get("resumo", {})
        if not isinstance(resumo, dict):
            resumo = {}
        total = float(resumo.get("Total", 0) or 0)
        livre = float(resumo.get("Livre", 0) or 0)
        ram = ((total - livre) / total * 100) if total else 0
        self.proc_cpu.setText(f"CPU: {float(resumo.get('CPU', 0) or 0):.1f}%")
        self.proc_ram.setText(f"RAM: {ram:.1f}%")
        discos = resumo.get("Discos", [])
        if isinstance(discos, str):
            discos = [discos]
        self.proc_disk.setText(
            "Discos: " + (" | ".join(map(str, discos)) if discos else "—")
        )

    def _renderizar_processos(self, dados):
        if self._closing or not hasattr(self, "tabela_processos"):
            return
        filtro = self.filtro_processo.text().strip().lower()
        pid_selecionado = self._selected_process_pid()
        linha_selecionada = None
        self.tabela_processos.setUpdatesEnabled(False)
        try:
            self.tabela_processos.setRowCount(0)
            for item in dados:
                if not isinstance(item, dict):
                    continue
                pid = str(item.get("PID", ""))
                nome = str(item.get("Nome", ""))
                if filtro and filtro not in pid.lower() and filtro not in nome.lower():
                    continue
                row = self.tabela_processos.rowCount()
                self.tabela_processos.insertRow(row)
                if pid_selecionado is not None and pid == str(pid_selecionado):
                    linha_selecionada = row
                valores = [
                    pid,
                    nome,
                    f"{float(item.get('CPU', 0) or 0):.1f}%",
                    f"{float(item.get('Memoria', 0) or 0) / 1048576:.1f} MB",
                    str(item.get("Handles", "")),
                ]
                for coluna, valor in enumerate(valores):
                    self.tabela_processos.setItem(
                        row, coluna, QTableWidgetItem(valor)
                    )
        finally:
            self.tabela_processos.setUpdatesEnabled(True)
        if linha_selecionada is not None:
            self.tabela_processos.selectRow(linha_selecionada)

    def _carregar_servicos(self):
        if not hasattr(self, "tabela_servicos") or self._operacao_ativa("servicos_refresh"):
            return
        self._run(
            self._coletar_servicos,
            label="Atualizando serviços",
            on_done=self._servicos_carregados,
            operation_key="servicos_refresh",
            blocks_navigation=False,
            silent_if_busy=True,
        )

    @staticmethod
    def _coletar_servicos(cancel_callback=None):
        return MainWindow._powershell_json(
            "Get-CimInstance Win32_Service | "
            "select Name,DisplayName,State,StartMode | "
            "ConvertTo-Json -Depth 3 -Compress",
            cancel_callback=cancel_callback,
        )

    def _servicos_carregados(self, dados):
        if not isinstance(dados, list) or not hasattr(self, "tabela_servicos"):
            self._log(">> [ERRO] Serviços: retorno inválido da consulta.")
            return
        self.tabela_servicos.setUpdatesEnabled(False)
        try:
            self.tabela_servicos.setRowCount(0)
            for item in dados:
                if not isinstance(item, dict):
                    continue
                row = self.tabela_servicos.rowCount()
                self.tabela_servicos.insertRow(row)
                for coluna, chave in enumerate(
                    ("Name", "DisplayName", "State", "StartMode")
                ):
                    self.tabela_servicos.setItem(
                        row, coluna, QTableWidgetItem(str(item.get(chave, "")))
                    )
        finally:
            self.tabela_servicos.setUpdatesEnabled(True)

    def _selected_process_pid(self):
        row = self.tabela_processos.currentRow()
        if row < 0:
            return None
        item = self.tabela_processos.item(row, 0)
        try:
            return int(item.text()) if item else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _finalizar_processo_worker(pid, cancel_callback=None):
        if callable(cancel_callback) and cancel_callback():
            return False, "Encerramento cancelado antes da execução."
        import subprocess
        resultado = subprocess.run(
            ["taskkill.exe", "/PID", str(pid), "/T"],
            capture_output=True,
            timeout=35,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if resultado.returncode:
            bruto = resultado.stderr or resultado.stdout or b"Falha ao encerrar processo."
            try:
                mensagem = bruto.decode("mbcs", errors="replace")
            except LookupError:
                mensagem = bruto.decode("utf-8", errors="replace")
            return False, mensagem.strip()
        return True, f"Processo {pid} encerrado."

    def _finalizar_processo(self):
        pid = self._selected_process_pid()
        if not pid:
            QMessageBox.warning(self, "Processos", "Selecione um processo.")
            return
        if pid == os.getpid():
            QMessageBox.warning(self, "Protegido", "O Configurador não pode encerrar a si próprio.")
            return
        if QMessageBox.question(self, "Confirmar",
                                f"Encerrar o processo PID {pid}?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self._run(
            self._finalizar_processo_worker,
            pid,
            label=f"Encerrando processo {pid}",
            admin_reason="encerrar processo",
            on_done=lambda resultado, processo_pid=pid: self._resultado_finalizar_processo(
                resultado, processo_pid
            ),
            operation_key=f"finalizar_processo:{pid}",
        )

    def _resultado_finalizar_processo(self, resultado, pid):
        ok, mensagem = (
            resultado if isinstance(resultado, tuple) else (bool(resultado), str(resultado))
        )
        if ok:
            self._log(f"✅ {mensagem}")
            self._atualizar_processos()
        else:
            self._log(f">> [ERRO] Processo {pid}: {mensagem}")
            QMessageBox.critical(self, "Erro ao encerrar processo", str(mensagem))

    @staticmethod
    def _coletar_detalhes_processo(pid, cancel_callback=None):
        dados = MainWindow._powershell_json(
            f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' | "
            "select ProcessId,Name,ExecutablePath,CommandLine,Priority,CreationDate | "
            "ConvertTo-Json -Compress",
            cancel_callback=cancel_callback,
        )
        return dados[0] if dados else {}

    def _detalhes_processo(self):
        pid = self._selected_process_pid()
        if not pid:
            QMessageBox.warning(self, "Processos", "Selecione um processo.")
            return
        self._run(
            self._coletar_detalhes_processo,
            pid,
            label=f"Consultando detalhes do processo {pid}",
            on_done=self._mostrar_detalhes_processo,
            operation_key="detalhes_processo",
            blocks_navigation=False,
            silent_if_busy=True,
        )

    def _mostrar_detalhes_processo(self, dados):
        import json
        QMessageBox.information(
            self,
            "Detalhes do processo",
            json.dumps(dados if isinstance(dados, dict) else {}, ensure_ascii=False, indent=2),
        )

    @staticmethod
    def _executar_servico_worker(nome, acao, cancel_callback=None):
        comandos = {
            "start": "Start-Service",
            "stop": "Stop-Service",
            "restart": "Restart-Service",
        }
        if acao not in comandos:
            return False, "Ação de serviço inválida."
        if callable(cancel_callback) and cancel_callback():
            return False, "Operação de serviço cancelada antes da execução."

        import subprocess
        comando = f"{comandos[acao]} -Name '{nome.replace(chr(39), chr(39) * 2)}' -ErrorAction Stop"
        resultado = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", comando],
            capture_output=True,
            timeout=35,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if resultado.returncode:
            bruto = resultado.stderr or resultado.stdout or "Falha na operação do serviço.".encode("utf-8")
            try:
                mensagem = bruto.decode("mbcs", errors="replace")
            except LookupError:
                mensagem = bruto.decode("utf-8", errors="replace")
            return False, mensagem.strip()
        return True, f"Serviço {nome}: {acao}."

    def _servico(self, acao):
        row = self.tabela_servicos.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Serviços", "Selecione um serviço.")
            return
        nome = self.tabela_servicos.item(row, 0).text()
        if acao != "start" and QMessageBox.question(
            self, "Confirmar", f"{acao.title()} o serviço {nome}?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self._run(
            self._executar_servico_worker,
            nome,
            acao,
            label=f"{acao.title()} serviço {nome}",
            admin_reason=f"{acao.title()} serviço",
            on_done=lambda resultado, nome_servico=nome, acao_servico=acao: self._resultado_servico(
                resultado, nome_servico, acao_servico
            ),
            operation_key=f"servico:{nome}",
        )

    def _resultado_servico(self, resultado, nome, acao):
        ok, mensagem = (
            resultado if isinstance(resultado, tuple) else (bool(resultado), str(resultado))
        )
        if ok:
            self._log(f"✅ {mensagem}")
            self._carregar_servicos()
        else:
            self._log(f">> [ERRO] Serviço {nome}: {mensagem}")
            QMessageBox.critical(self, "Erro no serviço", str(mensagem))

    # ---------------------------------------------------------
    # Análise defensiva — somente leitura
    # ---------------------------------------------------------
    def _iniciar_analise_defensiva(self, _checked=False):
        if self._closing or not hasattr(self, "tabela_analise_defensiva"):
            return
        if self._operacao_ativa("analise_defensiva"):
            return
        if self._operacao_ativa("analise_defensiva_hash"):
            self.lbl_analise_defensiva.setText(
                "Aguarde a conclusão ou cancele o cálculo de SHA-256 atual."
            )
            return

        self.baseline_panel.invalidate()
        self.btn_iniciar_analise_defensiva.setEnabled(False)
        self.btn_atualizar_analise_defensiva.setEnabled(False)
        self.btn_hash_analise_defensiva.setEnabled(False)
        self.btn_cancelar_analise_defensiva.setEnabled(True)
        self.lbl_analise_defensiva.setText(
            "Coletando informações locais em modo somente leitura..."
        )
        self._run(
            core_logic.ModuloSistema.obter_analise_defensiva,
            label="Análise defensiva de processos e persistências",
            progress=self.progresso_analise_defensiva,
            on_done=self._analise_defensiva_carregada,
            indeterminate=False,
            operation_key="analise_defensiva",
            blocks_navigation=False,
            on_finally=self._finalizar_interface_analise_defensiva,
            silent_if_busy=True,
        )

    def _cancelar_analise_defensiva(self):
        worker = self._operation_workers.get("analise_defensiva")
        if worker is None:
            worker = self._operation_workers.get("analise_defensiva_hash")
        if worker is None or worker not in self._workers:
            self.btn_cancelar_analise_defensiva.setEnabled(False)
            return
        worker.requestInterruption()
        self.btn_cancelar_analise_defensiva.setEnabled(False)
        self.lbl_analise_defensiva.setText(
            "Cancelamento solicitado. Uma consulta nativa já iniciada pode "
            "terminar antes de o Worker encerrar com segurança."
        )

    def _finalizar_interface_analise_defensiva(self, estado):
        if self._closing:
            return
        em_andamento = self._operacao_ativa("analise_defensiva") or self._operacao_ativa(
            "analise_defensiva_hash"
        )
        self.btn_iniciar_analise_defensiva.setEnabled(not em_andamento)
        self.btn_atualizar_analise_defensiva.setEnabled(not em_andamento)
        self.btn_cancelar_analise_defensiva.setEnabled(em_andamento)
        item = self._item_analise_defensiva_selecionado()
        self.btn_hash_analise_defensiva.setEnabled(
            not em_andamento and self._hash_analise_defensiva_disponivel(item)
        )
        if estado == "cancelled":
            self.lbl_analise_defensiva.setText(
                "Operação cancelada de forma cooperativa. O último resultado "
                "válido permanece visível."
            )
        elif estado == "error":
            self.lbl_analise_defensiva.setText(
                "Falha controlada na operação. Consulte configurador_ti.log."
            )

    def _analise_defensiva_carregada(self, resultado):
        if not isinstance(resultado, dict):
            self.lbl_analise_defensiva.setText(
                "Falha: a coleta retornou um formato inválido."
            )
            return
        if resultado.get("Cancelada"):
            self.lbl_analise_defensiva.setText(
                str(resultado.get("Mensagem") or "Análise defensiva cancelada.")
            )
            return
        if resultado.get("Sucesso") is not True:
            self.lbl_analise_defensiva.setText(
                str(resultado.get("Mensagem") or "A análise defensiva falhou.")
            )
            self._log(
                ">> [ERRO] Análise defensiva não foi concluída; consulte o log."
            )
            return

        itens = resultado.get("Itens")
        if not isinstance(itens, list):
            self.lbl_analise_defensiva.setText(
                "Falha: a lista de resultados é inválida."
            )
            return
        self._resultado_analise_defensiva = dict(resultado)
        self._dados_analise_defensiva = [
            item for item in itens if isinstance(item, dict)
        ]
        self._revisoes_tecnicas.reaplicar(self._dados_analise_defensiva)
        self.lbl_triagem.setText(self._revisoes_tecnicas.erro or
            "Revisões reaplicadas somente com identidade suficiente. Botão direito para revisar.")
        campos_pesquisa = (
            "Tipo", "Nome", "PID", "CaminhoExibicao",
            "Assinatura", "Classificacao", "MotivoPrincipal",
        )
        self._cache_pesquisa_analise_defensiva = {}
        self._cache_relevancia_analise_defensiva = {}
        for item in self._dados_analise_defensiva:
            campos_normalizados = {
                chave: str(
                    item.get(chave)
                    if item.get(chave) is not None
                    else ""
                ).casefold()
                for chave in campos_pesquisa
            }
            nome = campos_normalizados["Nome"]
            caminho = campos_normalizados["CaminhoExibicao"]
            self._cache_pesquisa_analise_defensiva[id(item)] = " ".join(
                campos_normalizados[chave] for chave in campos_pesquisa
            )
            self._cache_relevancia_analise_defensiva[id(item)] = {
                "nome": nome,
                "tokens_nome": tuple(re.findall(r"\w+", nome)),
                "tipo": campos_normalizados["Tipo"],
                "pid": campos_normalizados["PID"],
                "caminho": caminho,
                "basename": ntpath.basename(caminho.replace("/", "\\")),
                "assinatura": campos_normalizados["Assinatura"],
                "classificacao": campos_normalizados["Classificacao"],
                "motivo": campos_normalizados["MotivoPrincipal"],
            }
        self._ultimo_filtro_analise_defensiva = None
        self._item_analise_defensiva_id = None
        self._item_analise_defensiva_antes_busca = None
        self._melhor_correspondencia_analise_defensiva_id = None
        permitidos = resultado.get("CaminhosPermitidosHash")
        self._caminhos_analise_defensiva = (
            [str(valor) for valor in permitidos if str(valor).strip()]
            if isinstance(permitidos, list)
            else []
        )

        contagens = resultado.get("Contagens")
        contagens = contagens if isinstance(contagens, dict) else {}
        self.contador_normal_analise.setText(
            f"Normal: {int(contagens.get('Normal', 0) or 0)}"
        )
        self.contador_informativo_analise.setText(
            f"Informativo: {int(contagens.get('Informativo', 0) or 0)}"
        )
        self.contador_atencao_analise.setText(
            f"Atenção: {int(contagens.get('Atenção', 0) or 0)}"
        )
        self.contador_suspeito_analise.setText(
            f"Suspeito: {int(contagens.get('Suspeito', 0) or 0)}"
        )
        self.contador_requer_analise.setText(
            f"Requer análise: {int(contagens.get('Requer análise', 0) or 0)}"
        )
        self.contador_nao_disponivel_analise.setText(
            "Não disponível: "
            f"{int(contagens.get('Não disponível', 0) or 0)}"
        )

        defender = resultado.get("Defender")
        defender = defender if isinstance(defender, dict) else {}
        if defender.get("Disponivel"):
            estado = str(defender.get("Estado") or "Não disponível")
            tempo_real = "ativo" if defender.get("TempoRealAtivo") else "inativo"
            self.lbl_defender_analise_defensiva.setText(
                f"Microsoft Defender: {estado}; proteção em tempo real: {tempo_real}. "
                "Apenas o status foi consultado."
            )
        else:
            self.lbl_defender_analise_defensiva.setText(
                "Microsoft Defender: status não disponível nesta sessão. "
                "Nenhuma política ou exclusão foi alterada."
            )

        indisponiveis = resultado.get("FontesIndisponiveis")
        quantidade_indisponiveis = (
            len(indisponiveis) if isinstance(indisponiveis, list) else 0
        )
        mensagem = str(resultado.get("Mensagem") or "Análise concluída.")
        if quantidade_indisponiveis:
            mensagem += (
                f" {quantidade_indisponiveis} fonte(s) parcial(is) não estavam disponíveis."
            )
        self.lbl_analise_defensiva.setText(mensagem)
        self._materializar_tabela_analise_defensiva()
        self._renderizar_analise_defensiva()
        self._log(
            f">> [OK] Análise defensiva: {len(self._dados_analise_defensiva)} item(ns)."
        )
        self.baseline_panel.receive(resultado)

    def _id_item_analise_defensiva_selecionado(self):
        if not hasattr(self, "tabela_analise_defensiva"):
            return None
        linha = self.tabela_analise_defensiva.currentRow()
        if linha < 0:
            return None
        if self.tabela_analise_defensiva.isRowHidden(linha):
            return None
        celula = self.tabela_analise_defensiva.item(linha, 0)
        if celula is None:
            return None
        return celula.data(Qt.ItemDataRole.UserRole)

    def _item_analise_defensiva_selecionado(self):
        identificador = self._id_item_analise_defensiva_selecionado()
        if not identificador:
            return None
        return next(
            (
                item for item in self._dados_analise_defensiva
                if item.get("Id") == identificador
            ),
            None,
        )

    def _hash_analise_defensiva_disponivel(self, item):
        if not isinstance(item, dict) or not item.get("Caminho"):
            return False
        chave = core_logic.ModuloSistema._chave_caminho_analise_defensiva(
            item.get("Caminho")
        )
        return bool(
            chave
            and any(
                core_logic.ModuloSistema._chave_caminho_analise_defensiva(
                    caminho
                ) == chave
                for caminho in self._caminhos_analise_defensiva
            )
        )

    @staticmethod
    def _pontuar_relevancia_analise_defensiva(cache, consulta):
        """Pontua somente campos sanitizados, respeitando ordem de força."""
        if not consulta or not isinstance(cache, dict):
            return 0

        nome = cache.get("nome", "")
        if nome == consulta:
            return 1200
        if nome.startswith(consulta):
            return 1100
        if any(
            token.startswith(consulta)
            for token in cache.get("tokens_nome", ())
        ):
            return 1000
        if consulta in nome:
            return 900

        tipo = cache.get("tipo", "")
        if tipo == consulta or tipo.startswith(consulta):
            return 800

        basename = cache.get("basename", "")
        if basename == consulta:
            return 700
        if basename.startswith(consulta):
            return 650
        if consulta in basename:
            return 600

        if cache.get("pid", "") == consulta:
            return 500
        if consulta in cache.get("caminho", ""):
            return 300
        if (
            consulta in cache.get("assinatura", "")
            or consulta in cache.get("classificacao", "")
        ):
            return 200
        if consulta in cache.get("motivo", ""):
            return 100
        return 0

    def _materializar_tabela_analise_defensiva(self):
        """Materializa uma vez as células recebidas pela análise atual."""
        if self._closing or not hasattr(self, "tabela_analise_defensiva"):
            return

        tabela = self.tabela_analise_defensiva
        sinais_bloqueados = tabela.blockSignals(True)
        updates_habilitados = tabela.updatesEnabled()
        tabela.setUpdatesEnabled(False)
        try:
            tabela.setRowCount(len(self._dados_analise_defensiva))
            tabela.clearSelection()
            tabela.setCurrentItem(None)
            self._linha_por_id_analise_defensiva = {}
            self._visibilidade_linhas_analise_defensiva = {}
            for linha, item in enumerate(self._dados_analise_defensiva):
                valores = (
                    item.get("Tipo"), item.get("Nome"), item.get("PID"),
                    item.get("CaminhoExibicao"), item.get("Assinatura"),
                    item.get("Classificacao"), item.get("MotivoPrincipal"),
                )
                for coluna, valor in enumerate(valores):
                    celula = QTableWidgetItem(str(valor or "—"))
                    celula.setFlags(
                        celula.flags() & ~Qt.ItemFlag.ItemIsEditable
                    )
                    if coluna in {1, 3, 4, 5, 6}:
                        celula.setToolTip(celula.text())
                    if coluna == 0:
                        celula.setData(
                            Qt.ItemDataRole.UserRole, item.get("Id")
                        )
                    tabela.setItem(linha, coluna, celula)

                identificador = item.get("Id")
                if identificador is not None:
                    self._linha_por_id_analise_defensiva[identificador] = linha
                tabela.setRowHidden(linha, False)
                self._visibilidade_linhas_analise_defensiva[linha] = True
                self._indicador_triagem(linha, item)
        finally:
            tabela.setUpdatesEnabled(updates_habilitados)
            tabela.blockSignals(sinais_bloqueados)

        self._ultimo_filtro_analise_defensiva = None

    def _renderizar_analise_defensiva(self, _valor=None):
        if self._closing or not hasattr(self, "tabela_analise_defensiva"):
            return
        identificador_selecionado = (
            self._id_item_analise_defensiva_selecionado()
            or self._item_analise_defensiva_id
        )
        classificacao = self.filtro_classificacao_analise.currentText()
        texto = self.filtro_texto_analise.text().strip().casefold()
        revisao = self.filtro_revisao_triagem.currentText()
        foco = self.foco_triagem.currentText()
        relevantes = self.somente_relevantes_triagem.isChecked()
        estado_filtro = (classificacao, texto, revisao, foco, relevantes)
        if estado_filtro == self._ultimo_filtro_analise_defensiva:
            return

        estado_anterior = self._ultimo_filtro_analise_defensiva
        texto_anterior = estado_anterior[1] if estado_anterior else ""
        texto_mudou = estado_anterior is None or texto != texto_anterior
        foco_mudou = estado_anterior is None or foco != estado_anterior[3]
        if texto and texto_mudou and not texto_anterior:
            self._item_analise_defensiva_antes_busca = identificador_selecionado

        tabela = self.tabela_analise_defensiva
        primeira_linha_visivel = None
        melhor_linha = None
        melhor_identificador = None
        melhor_pontuacao = -1
        quantidade_correspondencias = 0
        linha_foco = None
        melhor_chave_foco = None
        sinais_bloqueados = tabela.blockSignals(True)
        updates_habilitados = tabela.updatesEnabled()
        tabela.setUpdatesEnabled(False)
        try:
            for linha, item in enumerate(self._dados_analise_defensiva):
                bate_classificacao = (
                    classificacao == "Todos"
                    or item.get("Classificacao") == classificacao
                )
                pesquisavel = self._cache_pesquisa_analise_defensiva.get(
                    id(item), ""
                )
                estado_revisao = self._revisoes_tecnicas.estado(item)
                visivel = bate_classificacao and triagem.bate_revisao(estado_revisao, revisao) and (
                    not relevantes or item.get("Classificacao") in {"Suspeito", "Requer análise", "Atenção"}
                ) and (
                    not texto or texto in pesquisavel
                )
                if visivel:
                    quantidade_correspondencias += 1
                    if foco != triagem.FOCOS[0]:
                        chave_foco = triagem.chave_foco(
                            self._cache_relevancia_analise_defensiva.get(id(item), {}),
                            estado_revisao, foco, linha,
                        )
                        if melhor_chave_foco is None or chave_foco < melhor_chave_foco:
                            melhor_chave_foco, linha_foco = chave_foco, linha
                    if primeira_linha_visivel is None:
                        primeira_linha_visivel = linha
                    if texto:
                        pontuacao = self._pontuar_relevancia_analise_defensiva(
                            self._cache_relevancia_analise_defensiva.get(
                                id(item), {}
                            ),
                            texto,
                        )
                        if pontuacao > melhor_pontuacao:
                            melhor_pontuacao = pontuacao
                            melhor_linha = linha
                            melhor_identificador = item.get("Id")
                if self._visibilidade_linhas_analise_defensiva.get(linha) != visivel:
                    tabela.setRowHidden(linha, not visivel)
                    self._visibilidade_linhas_analise_defensiva[linha] = visivel

            linha_atual = self._linha_por_id_analise_defensiva.get(
                identificador_selecionado
            )
            if texto and texto_mudou:
                linha_selecionada = melhor_linha
            elif foco_mudou and foco != triagem.FOCOS[0]:
                linha_selecionada = linha_foco
            elif not texto and texto_mudou and texto_anterior:
                linha_restaurada = self._linha_por_id_analise_defensiva.get(
                    self._item_analise_defensiva_antes_busca
                )
                linha_selecionada = (
                    linha_restaurada
                    if self._visibilidade_linhas_analise_defensiva.get(
                        linha_restaurada, False
                    )
                    else primeira_linha_visivel
                )
                self._item_analise_defensiva_antes_busca = None
            elif self._visibilidade_linhas_analise_defensiva.get(
                linha_atual, False
            ):
                linha_selecionada = linha_atual
            else:
                linha_selecionada = (
                    melhor_linha if texto else
                    linha_foco if foco != triagem.FOCOS[0] else primeira_linha_visivel
                )

            tabela.clearSelection()
            if linha_selecionada is not None:
                tabela.setCurrentCell(linha_selecionada, 0)
                tabela.selectRow(linha_selecionada)
            else:
                tabela.setCurrentItem(None)
        finally:
            tabela.setUpdatesEnabled(updates_habilitados)
            tabela.blockSignals(sinais_bloqueados)

        self._ultimo_filtro_analise_defensiva = estado_filtro
        self._melhor_correspondencia_analise_defensiva_id = (
            melhor_identificador if texto else None
        )
        self.lbl_correspondencias_analise.setText(
            f"Correspondências: {quantidade_correspondencias}"
        )
        self.lbl_filtros_ativos_triagem.setText(
            "Filtros ativos — use Limpar filtros para exibir todos os itens."
            if self.filtro_texto_analise.text() or self.filtro_classificacao_analise.currentIndex() != 0
            or self.filtro_revisao_triagem.currentIndex() != 0
            or self.somente_relevantes_triagem.isChecked() else ""
        )
        if linha_selecionada is not None:
            celula_selecionada = tabela.item(linha_selecionada, 0)
            if celula_selecionada is not None:
                tabela.scrollToItem(
                    celula_selecionada,
                    QAbstractItemView.ScrollHint.PositionAtTop,
                )
            self._mostrar_detalhes_analise_defensiva()
        else:
            self._item_analise_defensiva_id = None
            self._mostrar_detalhes_analise_defensiva()

    def _mostrar_detalhes_analise_defensiva(self, _item_clicado=None):
        item = self._item_analise_defensiva_selecionado()
        if not item:
            self._item_analise_defensiva_id = None
            self.detalhes_analise_defensiva.setPlainText(
                "Nenhum item selecionado."
            )
            self.btn_hash_analise_defensiva.setEnabled(False)
            return
        self._item_analise_defensiva_id = item.get("Id")

        def lista_texto(valor):
            if isinstance(valor, list):
                return [str(parte) for parte in valor if str(parte).strip()]
            return []

        tamanho = item.get("TamanhoBytes")
        try:
            tamanho_texto = f"{int(tamanho):,} bytes".replace(",", ".")
        except (TypeError, ValueError):
            tamanho_texto = "—"
        linhas = [
            f"Classificação automática: {item.get('Classificacao') or '—'}",
            f"Tipo: {item.get('Tipo') or '—'}",
            f"Nome: {item.get('Nome') or '—'}",
            f"PID: {item.get('PID') or '—'}",
            f"Caminho/alvo: {item.get('CaminhoExibicao') or '—'}",
            f"Usuário/contexto: {item.get('ContextoUsuario') or item.get('Usuario') or '—'}",
            f"Processo pai: {item.get('ParentNome') or '—'} (PID {item.get('ParentPID') or '—'})",
            f"Criado o processo: {item.get('CriadoProcesso') or '—'}",
            f"Fonte: {item.get('Fonte') or '—'}",
            f"Assinatura: {item.get('Assinatura') or '—'}",
            f"Publisher: {item.get('Publisher') or '—'}",
            f"Empresa/produto: {item.get('Empresa') or '—'} / {item.get('Produto') or '—'}",
            f"Tamanho: {tamanho_texto}",
            f"Criado (local): {local_timestamp(item.get('CriadoUtc'))[0]}",
            f"Modificado (local): {local_timestamp(item.get('ModificadoUtc'))[0]}",
            f"Atributos: {item.get('Atributos') or '—'}",
            f"SHA-256: {item.get('SHA256') or '—'} ({item.get('HashStatus') or 'Não calculado'})",
            "",
            "Comando sanitizado:",
            str(item.get("Comando") or "—"),
        ]
        detalhes_especificos = (
            ("Tipo de origem", "OrigemTipo"),
            ("Item de origem", "OrigemNome"),
            ("Nome técnico", "NomeTecnico"),
            ("Estado", "Estado"),
            ("Inicialização", "Inicializacao"),
            ("Tarefa", "CaminhoTarefa"),
            ("Tipo de ação", "TipoAcao"),
            ("Classe da ação", "ClasseAcao"),
            ("ClassId da ação", "ClassIdAcao"),
            ("Autor da tarefa", "AutorTarefa"),
            ("Habilitada", "Habilitada"),
            ("Gatilhos", "Gatilhos"),
            ("Nível de execução", "NivelExecucao"),
            ("Tipo de logon", "TipoLogon"),
            ("Diretório de trabalho", "DiretorioTrabalho"),
            ("Arquivo Startup", "ArquivoStartup"),
        )
        presentes = [
            (rotulo, item.get(chave))
            for rotulo, chave in detalhes_especificos
            if chave in item and item.get(chave) not in (None, "")
        ]
        if presentes:
            linhas.extend(["", "Detalhes da origem:"])
            linhas.extend(
                f"- {rotulo}: {valor}" for rotulo, valor in presentes
            )
        motivos = lista_texto(item.get("Motivos"))
        linhas.extend(["", "Motivos objetivos:"])
        linhas.extend([f"- {motivo}" for motivo in motivos] or ["- Nenhum sinal de atenção correlacionado."])
        evidencias = lista_texto(item.get("Evidencias"))
        linhas.extend(["", "Evidências e contexto:"])
        linhas.extend([f"- {evidencia}" for evidencia in evidencias] or ["- Sem evidência adicional disponível."])

        correlacoes = item.get("Correlacoes")
        correlacoes = correlacoes if isinstance(correlacoes, dict) else {}
        processos = lista_texto(correlacoes.get("Processos"))
        persistencias = lista_texto(correlacoes.get("Persistencias"))
        linhas.extend(["", "Correlações:"])
        linhas.append(
            "- Processos: " + (", ".join(processos) if processos else "nenhum")
        )
        linhas.append(
            "- Persistências: "
            + (", ".join(persistencias) if persistencias else "nenhuma")
        )
        recomendacao = str(item.get("Recomendacao") or "").strip()
        if recomendacao:
            linhas.extend(["", "Recomendação humana:", recomendacao])
        limitacoes = lista_texto(item.get("Limitacoes"))
        linhas.extend(["", "Limitações:"])
        linhas.extend([f"- {limite}" for limite in limitacoes])
        estado = self._revisoes_tecnicas.estado(item)
        linhas[1:1] = [
            "", "REVISÃO HUMANA (não altera a análise automática)",
            "Avaliação técnica: " + estado["avaliacao"],
            "Status de revisão: " + ("Revisado" if triagem.revisado(estado) else "Não revisado"),
            "Prioridade técnica: " + ("Sim" if estado["prioridade"] else "Não"),
            "Nota do técnico: " + (estado["nota"] or "—"),
            "Última revisão (local): " + local_timestamp(estado["atualizado"])[0],
            "Identidade para persistência: " + (
                "suficiente (contexto e metadados; não é prova de integridade)"
                if self._revisoes_tecnicas.identidades.get(id(item))
                else "insuficiente/ambígua; revisão apenas nesta sessão"
            ),
            "",
        ]
        self.detalhes_analise_defensiva.setPlainText("\n".join(linhas))
        self.detalhes_analise_defensiva.setToolTip("\n".join(local_timestamp(stamp)[1] for stamp in (item.get("CriadoUtc"), item.get("ModificadoUtc"), estado["atualizado"])))

        ocupado = self._operacao_ativa("analise_defensiva") or self._operacao_ativa(
            "analise_defensiva_hash"
        )
        self.btn_hash_analise_defensiva.setEnabled(
            not ocupado and self._hash_analise_defensiva_disponivel(item)
        )

    def _filtrar_card_triagem(self, classificacao):
        atual = self.filtro_classificacao_analise.currentText()
        self.filtro_classificacao_analise.setCurrentText(
            "Todos" if atual == classificacao else classificacao
        )

    def _indicador_triagem(self, linha, item):
        """Badge compacto no Nome; cache de busca permanece sem badge."""
        estado = self._revisoes_tecnicas.estado(item)
        siglas = dict(zip(triagem.AVALIACOES, ("NR", "L", "FP", "O", "I", "SC")))
        badge = siglas[estado["avaliacao"]]
        if estado["nota"]:
            badge += "·N"
        if estado["prioridade"]:
            badge = "★ " + badge
        celula = self.tabela_analise_defensiva.item(linha, 1)
        if celula is not None:
            nome = str(item.get("Nome") or "—")
            celula.setText(f"[{badge}] {nome}")
            celula.setToolTip(
                nome + "\nAvaliação técnica: " + estado["avaliacao"]
                + "\nRevisado: " + ("Sim" if triagem.revisado(estado) else "Não")
                + "\nPrioridade: " + ("Sim" if estado["prioridade"] else "Não")
                + "\nN = com nota. Automática permanece independente."
            )

    def _alterar_triagem(self, item, **mudancas):
        if id(item) not in self._cache_relevancia_analise_defensiva:
            self.lbl_triagem.setText("Item substituído por nova análise; selecione novamente.")
            return
        mensagem = self._revisoes_tecnicas.alterar(item, **mudancas)
        linha = self._linha_por_id_analise_defensiva.get(item.get("Id"))
        tabela = self.tabela_analise_defensiva
        bloqueado = tabela.blockSignals(True)
        try:
            if linha is not None:
                self._indicador_triagem(linha, item)
        finally:
            tabela.blockSignals(bloqueado)
        # Invalida apenas a chave de filtro, nunca a materialização/mapa/caches.
        anterior = self._ultimo_filtro_analise_defensiva
        if anterior:
            self._ultimo_filtro_analise_defensiva = (*anterior, "revisao_alterada")
        self._renderizar_analise_defensiva()
        self.lbl_triagem.setText(mensagem)

    def _editar_nota_triagem(self, item):
        estado = self._revisoes_tecnicas.estado(item)
        dialogo = QInputDialog(self)
        dialogo.setWindowTitle("Nota técnica — texto simples")
        dialogo.setLabelText("Nota (máximo 500 caracteres; não inclua senhas/tokens):")
        dialogo.setInputMode(QInputDialog.InputMode.TextInput)
        dialogo.setTextValue(estado["nota"])
        editor = dialogo.findChild(QLineEdit)
        if editor is not None:
            editor.setMaxLength(triagem.LIMITE_NOTA)
        if dialogo.exec() == QDialog.DialogCode.Accepted:
            self._alterar_triagem(item, nota=dialogo.textValue())

    def _menu_triagem_botao(self):
        tabela = self.tabela_analise_defensiva
        celula = tabela.currentItem()
        if celula is None:
            self.lbl_triagem.setText("Selecione uma linha para revisar.")
            return
        self._menu_triagem(tabela.visualItemRect(celula).center())

    def _menu_triagem(self, posicao):
        tabela = self.tabela_analise_defensiva
        celula = tabela.itemAt(posicao)
        if celula is None or tabela.isRowHidden(celula.row()):
            return
        tabela.setCurrentCell(celula.row(), 0)
        tabela.selectRow(celula.row())
        self._mostrar_detalhes_analise_defensiva()
        item = self._item_analise_defensiva_selecionado()
        if not item:
            return
        menu = QMenu(self)
        comandos = {}
        for avaliacao in triagem.AVALIACOES[1:]:
            acao = menu.addAction("Avaliação: " + avaliacao)
            comandos[acao] = lambda valor=avaliacao: self._alterar_triagem(item, avaliacao=valor)
        comandos[menu.addAction("Restaurar avaliação para Não revisado")] = lambda: self._alterar_triagem(item, avaliacao=triagem.AVALIACOES[0])
        estado = self._revisoes_tecnicas.estado(item)
        prioridade = estado["prioridade"]
        menu.addSeparator()
        comandos[menu.addAction("Remover prioridade" if prioridade else "Priorizar para revisão")] = lambda: self._alterar_triagem(item, prioridade=not prioridade)
        comandos[menu.addAction("Adicionar/Editar nota…")] = lambda: self._editar_nota_triagem(item)
        comandos[menu.addAction("Limpar nota")] = lambda: self._alterar_triagem(item, nota="")
        menu.addSeparator()
        comandos[menu.addAction("Copiar caminho sanitizado")] = lambda: QApplication.clipboard().setText(
            triagem.texto_seguro(item.get("CaminhoExibicao"), self._revisoes_tecnicas.sanitizar)
        )
        comandos[menu.addAction("Copiar detalhes sanitizados (sem SHA)")] = lambda: QApplication.clipboard().setText(
            triagem.detalhes_copiaveis(item, self._revisoes_tecnicas.estado(item), self._revisoes_tecnicas.sanitizar)
        )
        acao_hash = menu.addAction("Calcular SHA-256")
        acao_hash.setEnabled(self.btn_hash_analise_defensiva.isEnabled())
        comandos[acao_hash] = self._calcular_hash_analise_defensiva
        # Sem consulta de disco no menu. Validação local/existência ocorre apenas
        # na ação explícita; nunca interpreta Comando/argumentos como caminho.
        local = triagem.caminho_local(item.get("Caminho"))
        abrir = menu.addAction("Abrir local do arquivo (validar e selecionar)")
        abrir.setEnabled(os.name == "nt" and local is not None and item.get("Existe") is True)
        abrir.setToolTip("Somente arquivo local existente; UNC, argumentos, links e unidades de rede são recusados.")
        comandos[abrir] = lambda: self._abrir_local_triagem(item)
        if not abrir.isEnabled():
            menu.addAction("Local indisponível: alvo ausente, não local ou não confirmado").setEnabled(False)
        escolha = menu.exec(tabela.viewport().mapToGlobal(posicao))
        if escolha in comandos:
            if id(item) not in self._cache_relevancia_analise_defensiva or self._item_analise_defensiva_selecionado() is not item:
                self.lbl_triagem.setText("A seleção mudou durante o menu; abra-o novamente.")
                return
            comandos[escolha]()

    def _abrir_local_triagem(self, item):
        try:
            caminho = triagem.validar_local_existente(item.get("Caminho"))
            pasta_windows = ctypes.create_unicode_buffer(32768)
            if not ctypes.windll.kernel32.GetWindowsDirectoryW(pasta_windows, len(pasta_windows)):
                raise OSError("Diretório Windows indisponível.")
            subprocess.Popen(
                [str(Path(pasta_windows.value) / "explorer.exe"), "/select,", caminho],
                shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.lbl_triagem.setText("Explorer solicitado para selecionar o arquivo; o alvo não foi executado.")
        except (OSError, ValueError) as exc:
            core_logic.logger.warning("Triagem: abrir local recusado (%s)", type(exc).__name__)
            self.lbl_triagem.setText("Local indisponível ou não seguro. Nenhum arquivo foi executado.")

    def _copiar_resumo_investigacao(self):
        if not self._dados_analise_defensiva:
            self.lbl_triagem.setText("Execute a análise antes de copiar a investigação.")
            return
        QApplication.clipboard().setText(triagem.resumo_investigacao(
            self._dados_analise_defensiva, self._revisoes_tecnicas,
        ))
        self.lbl_triagem.setText("Resumo da investigação copiado; sem comandos ou hashes.")

    def _copiar_resumo_analise_defensiva(self):
        if not self._dados_analise_defensiva:
            self.lbl_analise_defensiva.setText(
                "Execute a análise antes de copiar o resumo."
            )
            return
        resultado = self._resultado_analise_defensiva
        contagens = resultado.get("Contagens")
        contagens = contagens if isinstance(contagens, dict) else {}
        linhas = [
            "CONFIGURADOR TI — RESUMO SANITIZADO DA ANÁLISE DEFENSIVA",
            f"Coletado em: {resultado.get('ColetadoEm') or '—'}",
            "Modo: somente leitura",
            (
                "Contagens: "
                + "; ".join(
                    f"{nome}={int(contagens.get(nome, 0) or 0)}"
                    for nome in (
                        "Normal", "Informativo", "Atenção", "Suspeito",
                        "Requer análise", "Não disponível",
                    )
                )
            ),
            "",
            "Itens que pedem revisão humana:",
        ]
        relevantes = [
            item for item in self._dados_analise_defensiva
            if item.get("Classificacao") in {
                "Atenção", "Suspeito", "Requer análise"
            }
        ]
        if not relevantes:
            linhas.append("- Nenhum item nessas classificações.")
        for item in relevantes:
            caminho_real = str(item.get("Caminho") or "").strip()
            caminho_resumo = (
                (item.get("CaminhoExibicao") or "—")
                if core_logic.ModuloSistema._caminho_absoluto_windows_analise_defensiva(
                    caminho_real
                )
                else "—"
            )
            linhas.append(
                "- [{classificacao}] {tipo} | {nome} | PID {pid} | {caminho} | {motivo}".format(
                    classificacao=item.get("Classificacao") or "—",
                    tipo=item.get("Tipo") or "—",
                    nome=item.get("Nome") or "—",
                    pid=item.get("PID") or "—",
                    caminho=caminho_resumo,
                    motivo=item.get("MotivoPrincipal") or "—",
                )
            )
        linhas.extend([
            "",
            "Observação: os sinais não confirmam ameaça. O resumo omite linhas "
            "de comando e hashes para reduzir exposição de dados sensíveis.",
        ])
        QApplication.clipboard().setText("\n".join(linhas))
        self.lbl_analise_defensiva.setText(
            "Resumo sanitizado copiado para a área de transferência."
        )

    def _calcular_hash_analise_defensiva(self):
        item = self._item_analise_defensiva_selecionado()
        if not self._hash_analise_defensiva_disponivel(item):
            self.lbl_analise_defensiva.setText(
                "Selecione um item com arquivo associado para calcular o SHA-256."
            )
            return
        if self._operacao_ativa("analise_defensiva") or self._operacao_ativa(
            "analise_defensiva_hash"
        ):
            return
        self.btn_iniciar_analise_defensiva.setEnabled(False)
        self.btn_atualizar_analise_defensiva.setEnabled(False)
        self.btn_hash_analise_defensiva.setEnabled(False)
        self.btn_cancelar_analise_defensiva.setEnabled(True)
        self.lbl_analise_defensiva.setText(
            "Calculando SHA-256 local do item selecionado..."
        )
        self._run(
            core_logic.ModuloSistema.calcular_sha256_analise_defensiva,
            str(item.get("Caminho")),
            list(self._caminhos_analise_defensiva),
            label="Calculando SHA-256 defensivo",
            progress=self.progresso_analise_defensiva,
            on_done=self._hash_analise_defensiva_carregado,
            indeterminate=False,
            operation_key="analise_defensiva_hash",
            blocks_navigation=False,
            on_finally=self._finalizar_interface_analise_defensiva,
            silent_if_busy=True,
        )

    def _hash_analise_defensiva_carregado(self, resultado):
        if not isinstance(resultado, dict):
            self.lbl_analise_defensiva.setText(
                "Falha: retorno inválido no cálculo de SHA-256."
            )
            return
        if resultado.get("Sucesso") is not True:
            self.lbl_analise_defensiva.setText(
                str(resultado.get("Mensagem") or "O SHA-256 não foi calculado.")
            )
            return
        caminho = str(resultado.get("Caminho") or "")
        chave = core_logic.ModuloSistema._chave_caminho_analise_defensiva(
            caminho
        )
        for item in self._dados_analise_defensiva:
            if core_logic.ModuloSistema._chave_caminho_analise_defensiva(
                item.get("Caminho")
            ) == chave:
                item["SHA256"] = str(resultado.get("SHA256") or "—")
                item["HashStatus"] = (
                    "Calculado (cache)" if resultado.get("Cache") else "Calculado"
                )
        self.lbl_analise_defensiva.setText(
            "SHA-256 calculado localmente e associado aos itens do mesmo arquivo."
        )
        self._mostrar_detalhes_analise_defensiva()

    # ---------------------------------------------------------
    # Empresa + Centralização
    # ---------------------------------------------------------
    def _build_central(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Empresa & Central",
            "Perfil corporativo, coletas centralizadas, relatório consolidado, e-mail e agendamento."
        ))

        cfg = core_logic.ModuloCentralizacao.carregar_config()
        perfil = core_logic.ModuloEmpresa.carregar_perfil()

        empresa = self._card("🏢 Perfil da empresa")
        ef = QFormLayout(empresa)
        self.campo_empresa = QLineEdit(str(perfil.get("empresa","")))
        self.campo_unidade = QLineEdit(str(perfil.get("unidade","")))
        self.campo_tecnicos = QLineEdit(", ".join(perfil.get("tecnicos",[]) or []))
        self.campo_obs_empresa = QLineEdit(str(perfil.get("observacoes","")))
        ef.addRow("Empresa:", self.campo_empresa)
        ef.addRow("Unidade:", self.campo_unidade)
        ef.addRow("Técnicos:", self.campo_tecnicos)
        ef.addRow("Observações:", self.campo_obs_empresa)
        bsave = QPushButton("💾 Salvar perfil")
        bsave.setProperty("class","ActionButton")
        bsave.clicked.connect(self._salvar_perfil_empresa)
        ef.addRow("", bsave)
        layout.addWidget(empresa)

        central = self._card("☁ Centralização")
        cf = QFormLayout(central)
        self.campo_pasta_central = QLineEdit(str(cfg.get("pasta_central","")))
        self.campo_pasta_central.setPlaceholderText(r"Ex.: \\SERVIDOR\TI\Coletas")
        self.campo_email_smtp = QLineEdit(str(cfg.get("email",{}).get("smtp","")))
        self.campo_email_usuario = QLineEdit(str(cfg.get("email",{}).get("usuario","")))
        self.campo_email_dest = QLineEdit(", ".join(cfg.get("email",{}).get("destinatarios",[]) or []))
        self.campo_email_senha = QLineEdit()
        self.campo_email_senha.setEchoMode(QLineEdit.EchoMode.Password)
        self.chk_email = QCheckBox("Ativar envio automático por e-mail")
        self.chk_email.setChecked(bool(cfg.get("email",{}).get("ativo")))
        self.campo_email_porta = QSpinBox()
        self.campo_email_porta.setRange(1,65535)
        self.campo_email_porta.setValue(int(cfg.get("email",{}).get("porta",587) or 587))
        self.campo_horario = QLineEdit(str(cfg.get("agendamento",{}).get("horario","18:00")))
        self.chk_central = QCheckBox("Esta máquina é a Central responsável pelo envio")
        self.chk_central.setChecked(bool(cfg.get("modo_central")))
        self.chk_central.toggled.connect(self._alternar_modo_central_gui)
        cf.addRow("Pasta central:", self.campo_pasta_central)
        cf.addRow("SMTP:", self.campo_email_smtp)
        cf.addRow("Usuário SMTP:", self.campo_email_usuario)
        cf.addRow("Destinatários:", self.campo_email_dest)
        cf.addRow("Senha SMTP:", self.campo_email_senha)
        cf.addRow("Porta:", self.campo_email_porta)
        cf.addRow("", self.chk_email)
        cf.addRow("Horário:", self.campo_horario)
        cf.addRow("", self.chk_central)
        self.lbl_aviso_central = QLabel(
            "Esta instalação está em modo Cliente: só coleta e envia para a pasta "
            "central — os campos de e-mail ficam bloqueados de propósito, para não "
            "duplicar a senha de e-mail em várias máquinas. Marque a caixa acima "
            "somente na única máquina de TI responsável por enviar os relatórios."
        )
        self.lbl_aviso_central.setWordWrap(True)
        self.lbl_aviso_central.setProperty("class", "Campo")
        cf.addRow(self.lbl_aviso_central)

        acts = FlowRow()
        for i,(text,fn) in enumerate([
            ("⚙ Salvar configuração", self._salvar_central),
            ("💾 Enviar coleta desta máquina", self._central_coleta),
            ("📊 Relatório consolidado do dia", self._central_relatorio),
            ("📧 Enviar último relatório", self._central_email),
            ("⏰ Agendar coleta diária", self._central_agendar),
            ("📋 Listar máquinas coletadas", self._central_listar),
        ]):
            b=QPushButton(text); b.setProperty("class","ActionButton"); b.clicked.connect(fn)
            acts.addWidget(b)
        cf.addRow(acts)
        layout.addWidget(central)

        estado = self._card("Estado operacional")
        estado_form = QFormLayout(estado)
        self.lbl_central_modo = QLabel("—")
        self.lbl_central_pasta = QLabel("—")
        self.lbl_central_acesso = QLabel("—")
        self.lbl_central_snapshot = QLabel("—")
        self.lbl_central_relatorio = QLabel("—")
        self.lbl_central_agendamento = QLabel("—")
        for rotulo in (
            self.lbl_central_pasta, self.lbl_central_snapshot,
            self.lbl_central_relatorio, self.lbl_central_agendamento,
        ):
            rotulo.setWordWrap(True)
        estado_form.addRow("Modo:", self.lbl_central_modo)
        estado_form.addRow("Pasta:", self.lbl_central_pasta)
        estado_form.addRow("Acesso:", self.lbl_central_acesso)
        estado_form.addRow("Último snapshot:", self.lbl_central_snapshot)
        estado_form.addRow("Último consolidado:", self.lbl_central_relatorio)
        estado_form.addRow("Agendamento:", self.lbl_central_agendamento)
        btn_status = QPushButton("🔄 Atualizar estado")
        btn_status.setProperty("class", "MenuButton")
        btn_status.clicked.connect(self._central_atualizar_status)
        estado_form.addRow("", btn_status)
        layout.addWidget(estado)

        self.central_status = QTextEdit()
        self.central_status.setReadOnly(True)
        self.central_status.setMinimumHeight(110)
        self.central_status.setMaximumHeight(180)
        self.central_status.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        layout.addWidget(section("Resultado das operações", self.central_status))
        layout.addStretch()
        self._adicionar_pagina_rolavel(page)
        self._atualizar_bloqueio_email_central(inicial=True)

    def _atualizar_bloqueio_email_central(self, inicial: bool = False):
        """Trava/destrava os campos de e-mail conforme o modo Cliente/Central.

        Isso é o que efetivamente impede uma máquina Cliente de acumular
        senha de e-mail sem querer — o checkbox sozinho (sem isto) só
        registrava a intenção, mas deixava os campos editáveis e salváveis
        de qualquer jeito, o que anulava a proteção pensada para o modo
        Cliente/Central (ver conversa anterior sobre isolar a senha SMTP
        numa única máquina)."""
        central = self.chk_central.isChecked()
        for campo in (self.campo_email_smtp, self.campo_email_usuario,
                      self.campo_email_dest, self.campo_email_senha,
                      self.campo_email_porta, self.chk_email):
            campo.setEnabled(central)
        self.lbl_aviso_central.setVisible(not central)
        if not inicial and not central:
            self.campo_email_smtp.clear()
            self.campo_email_usuario.clear()
            self.campo_email_dest.clear()
            self.campo_email_senha.clear()
            self.chk_email.setChecked(False)

    def _alternar_modo_central_gui(self, marcado: bool):
        if marcado:
            resposta = QMessageBox.warning(
                self, "Ativar modo Central",
                "Ativar o modo Central faz ESTA máquina guardar a senha de "
                "e-mail (criptografada com DPAPI) e ser responsável por "
                "enviar os relatórios consolidados de todas as coletas.\n\n"
                "Use isso em UMA única máquina de TI — nunca em cada máquina "
                "de usuário final que for configurada.\n\nContinuar?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resposta != QMessageBox.StandardButton.Yes:
                self.chk_central.blockSignals(True)
                self.chk_central.setChecked(False)
                self.chk_central.blockSignals(False)
                self._atualizar_bloqueio_email_central()
                return
        else:
            if QMessageBox.question(
                self, "Desativar modo Central",
                "Desativar o modo Central apaga a senha de e-mail salva "
                "nesta máquina. Continuar?",
            ) == QMessageBox.StandardButton.Yes:
                try:
                    cfg = core_logic.ModuloCentralizacao.carregar_config()
                    cfg["modo_central"] = False
                    cfg["email"] = core_logic.ModuloCentralizacao._padrao()["email"]
                    core_logic.ModuloCentralizacao.salvar_config(cfg)
                    self.central_status.append("✅ Modo Central desativado. Senha de e-mail removida desta máquina.")
                except Exception as e:
                    QMessageBox.critical(self, "Erro", str(e))
            else:
                self.chk_central.blockSignals(True)
                self.chk_central.setChecked(True)
                self.chk_central.blockSignals(False)
                self._atualizar_bloqueio_email_central()
                return
        self._atualizar_bloqueio_email_central()

    def _pagina_central(self):
        self._set_nav(7)
        self._log(">> Centralização carregada.")
        self._central_atualizar_status()

    def _salvar_perfil_empresa(self):
        d = core_logic.ModuloEmpresa.carregar_perfil()
        d.update({
            "empresa": self.campo_empresa.text().strip(),
            "unidade": self.campo_unidade.text().strip(),
            "tecnicos": [x.strip() for x in self.campo_tecnicos.text().split(",") if x.strip()],
            "observacoes": self.campo_obs_empresa.text().strip(),
        })
        try:
            core_logic.ModuloEmpresa.salvar_perfil(d)
            self.central_status.append("✅ Perfil da empresa salvo.")
        except Exception as e:
            QMessageBox.critical(self,"Erro",str(e))

    def _config_central_atual(self):
        cfg=core_logic.ModuloCentralizacao.carregar_config()
        cfg.update({
            "pasta_central": self.campo_pasta_central.text().strip(),
            "modo_central": self.chk_central.isChecked(),
        })
        cfg["email"].update({
            "smtp": self.campo_email_smtp.text().strip(),
            "usuario": self.campo_email_usuario.text().strip(),
            "destinatarios":[x.strip() for x in self.campo_email_dest.text().split(",") if x.strip()],
            "porta": self.campo_email_porta.value(),
            "ativo": self.chk_email.isChecked(),
        })
        # Senha vazia significa "manter a senha já configurada".
        if self.campo_email_senha.text():
            cfg["email"]["senha"] = self.campo_email_senha.text()
        cfg["agendamento"]["horario"]=self.campo_horario.text().strip()
        return cfg

    def _salvar_central(self):
        try:
            cfg=self._config_central_atual()
            core_logic.ModuloCentralizacao.salvar_config(cfg)
            self.central_status.append("✅ Configuração central salva.")
            self._central_atualizar_status()
        except Exception as e:
            QMessageBox.critical(self,"Erro",str(e))

    def _central_coleta(self):
        self._run(core_logic.ModuloCentralizacao.salvar_snapshot, label="Enviar coleta para central", on_done=self._resultado_central_com_status)

    def _central_relatorio(self):
        self._run(core_logic.ModuloCentralizacao.gerar_relatorio_consolidado, label="Gerar relatório consolidado", on_done=self._resultado_central_com_status)

    def _central_email(self):
        self._run(
            core_logic.ModuloCentralizacao.enviar_ultimo_relatorio,
            label="Enviar último relatório consolidado por e-mail",
            on_done=self._resultado_central_com_status,
            operation_key="central_email",
        )

    def _central_agendar(self):
        horario=self.campo_horario.text().strip()
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", horario):
            QMessageBox.warning(self,"Horário","Use o formato HH:MM.")
            return
        self._run(core_logic.ModuloCentralizacao.criar_agendamento, horario, label="Agendar coleta diária", on_done=self._resultado_central_com_status)

    def _central_listar(self):
        self._run(
            core_logic.ModuloCentralizacao.listar_maquinas_hoje,
            label="Listar máquinas coletadas hoje",
            on_done=self._central_lista_carregada,
            operation_key="central_listagem",
            blocks_navigation=False,
        )

    def _central_lista_carregada(self, coletas):
        if not isinstance(coletas,list):
            raise ValueError("Retorno inválido da listagem central.")
        texto=f"Máquinas coletadas hoje: {len(coletas)}\n"
        for item in coletas[:100]:
            texto+=(
                f"- {item.get('maquina','—')} | usuário: {item.get('usuario','—')} | "
                f"IPv4: {item.get('ipv4_principal','—')} | "
                f"coleta: {item.get('coletado_em','—')} | schema: {item.get('schema',0)}\n"
            )
        self.central_status.setPlainText(texto)

    def _central_atualizar_status(self):
        self._run(
            core_logic.ModuloCentralizacao.obter_status_centralizacao,
            label="Atualizar estado da Centralização",
            on_done=self._central_status_carregado,
            operation_key="central_status",
            blocks_navigation=False,
            silent_if_busy=True,
        )

    def _central_status_carregado(self, status):
        if not isinstance(status,dict):
            raise ValueError("Retorno inválido do estado da Centralização.")
        self.lbl_central_modo.setText(str(status.get('modo') or '—'))
        self.lbl_central_pasta.setText(str(status.get('pasta') or '—'))
        acessivel=status.get('pasta_acessivel')
        gravavel=status.get('pasta_gravavel')
        self.lbl_central_acesso.setText(
            'Disponível para gravação' if acessivel and gravavel
            else ('Disponível, sem gravação confirmada' if acessivel else 'Indisponível')
        )
        self.lbl_central_snapshot.setText(str(status.get('ultimo_snapshot') or '—'))
        self.lbl_central_relatorio.setText(str(status.get('ultimo_relatorio') or '—'))
        tarefa=status.get('agendamento') if isinstance(status.get('agendamento'),dict) else {}
        existe=tarefa.get('existe')
        if existe is True:
            texto_tarefa=f"Configurada — {tarefa.get('horario','—')}"
        elif existe is False:
            texto_tarefa="Não encontrada no Agendador de Tarefas"
        else:
            texto_tarefa=str(tarefa.get('mensagem') or 'Não consultado')
        self.lbl_central_agendamento.setText(texto_tarefa)

    def _resultado_central_com_status(self, result):
        self._mostrar_central_resultado(result)
        self._central_atualizar_status()

    def _mostrar_central_resultado(self, result):
        self.central_status.append(">> " + str(result))

    def _build_implantacao(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Implantação Corporativa",
            "Atalhos para as rotinas já existentes de implantação. Ações destrutivas exigem confirmação."
        ))

        cards = QGridLayout()
        items = [
            ("👤 Usuário local", self._impl_usuario, False),
            ("🌐 Grupo de trabalho", self._impl_workgroup, False),
            ("🏢 Domínio", self._impl_dominio, False),
            ("📦 Aplicativo via WinGet", self._impl_winget, False),
            ("💽 Unidade de rede", self._impl_unidade, False),
            ("🖨 Impressora de rede", self._impl_impressora, False),
            ("🔗 Atalho", self._impl_atalho, False),
            ("🛡 Segurança", self._impl_seguranca, False),
            ("♻ Redefinição do Windows", self._impl_reset, True),
        ]
        for i, (text, fn, perigoso) in enumerate(items):
            b = QPushButton(text)
            b.setProperty("class", "DangerButton" if perigoso else "ActionButton")
            b.clicked.connect(fn)
            if perigoso:
                layout.addWidget(section("Ação de alto impacto — confirmação obrigatória", b))
            else:
                cards.addWidget(b, i // 2, i % 2)

        layout.insertLayout(1, cards)
        layout.addStretch()
        self._adicionar_pagina_rolavel(page)

    def _pagina_implantacao(self):
        self._set_nav(8)

    def _input_many(self, title, labels):
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        form = QFormLayout(dlg)
        edits = []
        for label in labels:
            e = QLineEdit()
            if "senha" in label.lower():
                e.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow(label, e)
            edits.append(e)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None
        return [e.text() for e in edits]

    def _impl_usuario(self):
        values = self._input_many("Criar usuário", ["Usuário", "Senha"])
        if not values:
            return
        self._run(
            core_logic.ModuloImplantacao.criar_usuario,
            values[0], values[1], False,
            label=f"Criando usuário {values[0]}",
            admin_reason="criar usuário local",
            progress=self.progress_manutencao,
            on_done=self._resultado_generico,
        )

    def _impl_workgroup(self):
        values = self._input_many("Grupo de trabalho", ["Grupo"])
        if values:
            self._run(
                core_logic.ModuloImplantacao.workgroup, values[0],
                label="Alterando grupo de trabalho",
                admin_reason="alterar grupo de trabalho",
                progress=self.progress_manutencao,
                on_done=self._resultado_generico,
            )

    def _impl_dominio(self):
        values = self._input_many("Ingressar no domínio", ["Domínio", "Usuário", "Senha"])
        if values:
            self._run(
                core_logic.ModuloImplantacao.dominio, *values,
                label="Ingressando no domínio",
                admin_reason="ingressar computador no domínio",
                progress=self.progress_manutencao,
                on_done=self._resultado_generico,
            )

    def _impl_winget(self):
        values = self._input_many("Instalar aplicativo", ["Nome", "ID do WinGet"])
        if values:
            self._run(
                core_logic.ModuloImplantacao.winget, *values,
                label=f"Instalando {values[0]}",
                admin_reason="instalar aplicativo",
                progress=self.progress_manutencao,
                on_done=self._resultado_generico,
            )

    def _impl_unidade(self):
        values = self._input_many("Mapear unidade", ["Letra", "Caminho UNC"])
        if values:
            self._run(
                core_logic.ModuloImplantacao.mapear_unidade, *values,
                label="Mapeando unidade de rede",
                admin_reason="mapear unidade de rede",
                progress=self.progress_manutencao,
                on_done=self._resultado_generico,
            )

    def _impl_impressora(self):
        values = self._input_many("Mapear impressora", ["Caminho UNC"])
        if values:
            self._run(
                core_logic.ModuloImplantacao.mapear_impressora, values[0],
                label="Mapeando impressora",
                admin_reason="mapear impressora",
                progress=self.progress_manutencao,
                on_done=self._resultado_generico,
            )

    def _impl_atalho(self):
        values = self._input_many("Criar atalho", ["Nome", "Destino"])
        if values:
            self._run(
                core_logic.ModuloImplantacao.criar_atalho, *values,
                label="Criando atalho",
                admin_reason="criar atalho na Área de Trabalho Pública",
                progress=self.progress_manutencao,
                on_done=self._resultado_generico,
            )

    def _impl_seguranca(self):
        self._run(
            core_logic.ModuloImplantacao.seguranca, True,
            label="Executando rotina de segurança",
            admin_reason="executar rotina de segurança",
            progress=self.progress_manutencao,
            on_done=self._resultado_generico,
        )

    def _impl_reset(self):
        if QMessageBox.warning(
            self,
            "Redefinição do Windows",
            "Essa operação pode causar perda de dados.\n\n"
            "Deseja realmente abrir a rotina nativa de redefinição?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._run(
            core_logic.ModuloImplantacao.reset_windows,
            label="Abrindo redefinição nativa do Windows",
            admin_reason="redefinir o Windows",
            progress=self.progress_manutencao,
            on_done=self._resultado_generico,
        )

    # ---------------------------------------------------------
    # Logs
    # ---------------------------------------------------------
    def _build_logs(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)
        layout.addLayout(self._header(
            "Logs",
            "Acompanhe a sessão e abra o arquivo de log real do backend."
        ))

        self.console_visual = QTextEdit()
        self.console_visual.setReadOnly(True)
        self.console_visual.setObjectName("ConsoleVisual")
        self.console_visual.setPlainText(
            ">> Configurador TI v5.0 iniciado.\n"
            ">> Backend preservado carregado.\n"
            ">> Nenhuma operação executada ainda."
        )
        self.console_visual.setMinimumHeight(260)
        self.console_visual.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        busca = FlowRow()
        self.busca_logs = QLineEdit()
        self.busca_logs.setPlaceholderText("Localizar nos eventos da sessão — pressione Enter")
        self.busca_logs.returnPressed.connect(self._localizar_log_visual)
        busca.addWidget(self.busca_logs, 1)
        proximo_log = QPushButton("Localizar próximo")
        proximo_log.clicked.connect(self._localizar_log_visual)
        busca.addWidget(proximo_log)
        copiar_log = QPushButton("Copiar seleção")
        copiar_log.clicked.connect(lambda: (
            QApplication.clipboard().setText(self.console_visual.textCursor().selectedText()),
            self.statusBar().showMessage("Seleção copiada.")))
        busca.addWidget(copiar_log)
        layout.addLayout(busca)
        layout.addWidget(section("Eventos desta sessão", self.console_visual))

        row = FlowRow()
        openlog = QPushButton("📄 Abrir log real")
        openlog.setProperty("class", "MenuButton")
        openlog.clicked.connect(self._abrir_log)
        clear = QPushButton("🗑 Limpar visualização")
        clear.setProperty("class", "MenuButton")
        clear.clicked.connect(self.console_visual.clear)
        row.addWidget(openlog)
        row.addWidget(clear)
        row.addStretch()
        layout.addLayout(row)

        self._adicionar_pagina_rolavel(page)

    def _localizar_log_visual(self):
        termo = self.busca_logs.text()
        if not termo:
            self.statusBar().showMessage("Digite o texto que deseja localizar na sessão.")
            return
        encontrado = self.console_visual.find(termo)
        if not encontrado:
            cursor = self.console_visual.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            self.console_visual.setTextCursor(cursor)
            encontrado = self.console_visual.find(termo)
        self.statusBar().showMessage("Ocorrência selecionada." if encontrado else "Nenhuma ocorrência na sessão.")

    def _pagina_logs(self):
        self._set_nav(9)

    # ---------------------------------------------------------
    # Audit & Timeline
    # ---------------------------------------------------------
    def _build_auditoria(self):
        self.audit_panel = AuditTimelinePanel(self, core_logic)
        self.pages.addWidget(self.audit_panel)

    def _pagina_auditoria(self):
        self._set_nav(10)
        self.audit_panel.refresh()

    # ---------------------------------------------------------
    # Change Intelligence / Investigation View MVP
    # ---------------------------------------------------------
    def _build_investigacao(self):
        self.investigation_panel = ChangeIntelligencePanel(self, core_logic)
        self._adicionar_pagina_rolavel(self.investigation_panel)

    def _pagina_investigacao(self):
        self._set_nav(11)
        self.investigation_panel.refresh()
        self.investigation_panel.refresh_sessions()

    # ---------------------------------------------------------
    # Endpoint Posture & Health Intelligence
    # ---------------------------------------------------------
    def _build_postura_endpoint(self):
        self.endpoint_posture_panel = EndpointPosturePanel(self, core_logic)
        self._adicionar_pagina_rolavel(self.endpoint_posture_panel)

    def _pagina_postura_endpoint(self):
        self._set_nav(12, domain_id="security")
        self.endpoint_posture_panel.refresh()

    # ---------------------------------------------------------
    # Assistente Técnico & Safe Playbooks Foundation
    # ---------------------------------------------------------
    def _build_assist(self):
        self.assist_panel = AssistPanel(self, core_logic)
        self._adicionar_pagina_rolavel(self.assist_panel)

    def _pagina_assist(self):
        self._set_nav(13, domain_id="operations")
        self.assist_panel.refresh()

    def _abrir_assist_contexto(self, source_type, source_id=None, **values):
        self._set_nav(13, domain_id="operations")
        self.assist_panel.focus_context(source_type, source_id, **values)

    def _abrir_evidencia_assist(self, evidence_type, evidence_id):
        """Roteamento fechado para referências persistidas; não aceita rotas livres."""
        if evidence_type == "ALERT":
            self._set_nav(5, domain_id="observability")
            self.monitoring_panel.focus_alert(evidence_id)
        elif evidence_type == "POSTURE_CHANGE":
            self._set_nav(12, domain_id="security")
            self.endpoint_posture_panel.focus_change(evidence_id)
        elif evidence_type == "POSTURE_CHECK":
            self._set_nav(12, domain_id="security")
            self.endpoint_posture_panel.focus_check(evidence_id)
        elif evidence_type == "ENDPOINT_POSTURE_RUN":
            self._set_nav(12, domain_id="security")
            self.endpoint_posture_panel.refresh()
        elif evidence_type == "MONITORING_OBSERVATION":
            self._set_nav(5, domain_id="observability")
            self.monitoring_panel.refresh()
        elif evidence_type in ("MONITORING_CONFIGURATION", "MONITORING_RUN"):
            self._set_nav(5, domain_id="observability")
            self.monitoring_panel.refresh()
        elif evidence_type == "ACTION_RUN":
            self._set_nav(13, domain_id="operations")
            self.assist_panel.focus_action_run(evidence_id)
        elif evidence_type == "TIMELINE_EVENT":
            self._set_nav(10, domain_id="investigation")
            self.audit_panel.focus_event(evidence_id)
        elif evidence_type == "CHANGE_GROUP":
            self._abrir_investigacao(evidence_id)
        elif evidence_type == "INVESTIGATION_SESSION":
            self._abrir_sessao_investigacao(evidence_id)

    def _criar_investigacao_postura(self, change_id):
        session = posture_action_safe(
            self._get_posture_store(), core_logic.logger,
            lambda store, reference: store.create_investigation_from_posture_change(reference),
            change_id,
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _abrir_investigacao(self, operation_id=None):
        self._set_nav(11)
        self.investigation_panel.focus_operation(operation_id)

    def _abrir_sessao_investigacao(self, session_id):
        self._set_nav(11)
        self.investigation_panel.focus_session(session_id)

    def _criar_investigacao_evento(self, event_id):
        session = investigation_action_safe(
            self._get_incident_store(), core_logic.logger,
            lambda store, reference: (
                store.find_session_for_reference("TIMELINE_EVENT", reference)
                or store.create_from_timeline_event(reference)
            ), event_id,
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _criar_investigacao_monitoramento(self, observation_id):
        session = monitoring_action_safe(
            self._get_monitoring_store(), core_logic.logger,
            lambda store, reference: store.create_investigation_from_observation(reference),
            observation_id,
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _criar_investigacao_alerta(self, alert_id):
        session = monitoring_action_safe(
            self._get_monitoring_store(), core_logic.logger,
            lambda store, reference: store.create_investigation_from_alert(reference),
            alert_id,
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _criar_investigacao_grupo(self, operation_id):
        session = investigation_action_safe(
            self._get_incident_store(), core_logic.logger,
            lambda store, reference: (
                store.find_session_for_reference("CHANGE_GROUP", reference)
                or store.create_from_change_group(reference)
            ), operation_id,
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _criar_investigacao_mudanca(self, change_id):
        session = investigation_action_safe(
            self._get_incident_store(), core_logic.logger,
            lambda store, reference: (
                store.find_session_for_reference("CHANGE", reference)
                or store.create_from_change(reference)
            ), change_id,
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _criar_investigacao_manual(self):
        session = investigation_action_safe(
            self._get_incident_store(), core_logic.logger,
            lambda store: store.create_session(
                title="Investigação local", source="MANUAL",
                summary="Sessão criada manualmente; adicione apenas itens revisados."
            ),
        )
        if session:
            self._abrir_sessao_investigacao(session["session_id"])

    def _abrir_item_original(self, item_type, referenced_id):
        if item_type == "TIMELINE_EVENT":
            self._set_nav(10)
            self.audit_panel.focus_event(referenced_id)
        elif item_type == "CHANGE_GROUP":
            self._abrir_investigacao(referenced_id)
        elif item_type == "CHANGE":
            self._set_nav(11)
            self.investigation_panel.focus_change(referenced_id)

    def _abrir_log(self):
        caminho = Path(core_logic.ARQUIVO_LOG)
        if not caminho.exists():
            QMessageBox.information(self, "Log", "O log ainda não existe.")
            return
        try:
            os.startfile(str(caminho))
        except Exception as exc:
            QMessageBox.critical(self, "Log", str(exc))

    # ---------------------------------------------------------
    # Fechamento seguro
    # ---------------------------------------------------------
    def closeEvent(self, event):
        # Consultas de Processos/Serviços podem cooperar com a interrupção,
        # mas comandos nativos já iniciados (CHKDSK, PowerShell, domínio) não
        # devem ser terminados à força pela GUI. O aviso deixa essa diferença
        # explícita antes de o usuário confirmar o fechamento.
        if self._workers and not getattr(self, "_licensing_close_pending", False):
            resposta = QMessageBox.warning(
                self, "Operação em andamento",
                f"Há {len(self._workers)} operação(ões) ainda em andamento "
                "(ex.: Windows Update, CHKDSK, ingresso em domínio).\n\n"
                "Consultas cooperativas recebem solicitação de cancelamento. "
                "Processos do Windows já iniciados podem continuar até seu "
                "próprio término.\n\n"
                "Deseja realmente fechar mesmo assim?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if resposta != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        self._closing = True
        if hasattr(self, "_license_timer"):
            self._license_timer.stop()
        if hasattr(self, "network_panel"):
            self.network_panel.timer.stop()
        if hasattr(self, "_timer_processos"):
            self._timer_processos.stop()
        if hasattr(self, "_timer_filtro_processos"):
            self._timer_filtro_processos.stop()
        if hasattr(self, "_timer_filtro_analise_defensiva"):
            self._timer_filtro_analise_defensiva.stop()
        # O monitoramento local não possui loop próprio: interrompe somente o
        # QTimer e solicita cancelamento cooperativo da coleta atual.
        monitor_service = getattr(self, "_monitoring_service", None)
        if (monitor_service is not None and monitor_service.status != "STOPPED") or getattr(self, "_monitoramento_ativo", False):
            self._parar_monitoramento("encerramento")
        elif hasattr(self, "_timer_monitoramento"):
            self._timer_monitoramento.stop()

        # Não destrói objetos em callback pendente: preserva uma referência de
        # módulo até cada QThread terminar. A interrupção é cooperativa; ela não
        # mata à força operações administrativas que poderiam deixar o Windows
        # em estado inconsistente.
        for worker in list(self._workers):
            try:
                worker.requestInterruption()
            except Exception:
                pass
            if worker not in WORKERS_EM_ENCERRAMENTO:
                WORKERS_EM_ENCERRAMENTO.append(worker)
        if any(getattr(w, "_operation_key", None) == "licensing_account" and w.isRunning()
               for w in list(self._workers)):
            self._licensing_close_pending = True
            QTimer.singleShot(100, self.close)
            event.ignore()
            return
        # O helper 1F do Windows Update é cooperativamente cancelável e mantém
        # sua árvore em Job Object. Dá a ele uma janela curta para encerrar o
        # helper elevado antes de finalizar o event loop, sem bloquear outros
        # workers administrativos legados que não podem ser terminados à força.
        for worker in list(self._workers):
            if getattr(worker, "_operation_key", None) == "windows_update":
                try:
                    worker.wait(5000)
                except Exception:
                    pass
        core_logic.registrar_instancia_encerrando(
            f"GUI_CLOSE;workers_ativos={len(self._workers)}"
        )
        event.accept()


def main():
    sys.excepthook = _tratar_excecao_global

    codigo_headless = core_logic.despachar_modo_headless(sys.argv[1:])
    if codigo_headless is not None:
        return int(codigo_headless)

    if sys.platform.startswith("win"):
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("Configurador TI")
    app.setApplicationVersion(app_status.VERSION)
    app.aboutToQuit.connect(
        lambda: core_logic.registrar_instancia_encerrando("QT_ABOUT_TO_QUIT")
    )

    app.setProperty("configurador_ti_qss_loaded", False)
    qss = app_paths.asset_path("style.qss")
    if qss.exists():
        try:
            app.setStyleSheet(qss.read_text(encoding="utf-8"))
            app.setProperty("configurador_ti_qss_loaded", bool(app.styleSheet().strip()))
        except Exception:
            core_logic.logger.warning("AMBIENTE_CONFIGURADOR_TI | Não foi possível carregar style.qss.")

    window = MainWindow()
    window.show()
    core_logic.registrar_evento_instancia("GUI_PRONTA")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
