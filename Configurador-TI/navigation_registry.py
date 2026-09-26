"""Taxonomia declarativa interna da navegação do Configurador TI.

Não carrega código dinamicamente e não constitui uma API de plugins. Rotas são
nomes explícitos de métodos já existentes na janela principal.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DomainDefinition:
    domain_id: str
    title: str
    description: str
    order: int
    icon: str


@dataclass(frozen=True)
class ModuleDefinition:
    module_id: str
    title: str
    description: str
    domain: str
    order: int
    route: str
    view_index: int
    visible: bool = True
    badge: str | None = None
    capability: str | None = None


DOMAINS = (
    DomainDefinition("overview", "Visão Geral", "Estação, status rápido e atalhos frequentes.", 10, "SP_ComputerIcon"),
    DomainDefinition("operations", "Operações & Manutenção", "Saúde, manutenção e operação local da estação.", 20, "SP_FileDialogDetailedView"),
    DomainDefinition("network", "Rede", "Configuração, inventário e inteligência de rede.", 30, "SP_DriveNetIcon"),
    DomainDefinition("security", "Segurança", "Análise defensiva, persistências, assinaturas e evidências.", 40, "SP_MessageBoxWarning"),
    DomainDefinition("investigation", "Investigação & Auditoria", "Timeline, mudanças, sessões e replay investigativo.", 50, "SP_FileDialogInfoView"),
    DomainDefinition("observability", "Observabilidade", "Monitoramento, relatórios e logs operacionais.", 60, "SP_MediaPlay"),
    DomainDefinition("deployment", "Implantação", "Funções homologadas de preparação e implantação.", 70, "SP_ArrowUp"),
    DomainDefinition("company", "Empresa & Central", "Dados empresariais e recursos locais da Central.", 80, "SP_DirHomeIcon"),
)


MODULES = (
    ModuleDefinition("dashboard", "Painel da estação", "Resumo operacional, status rápido e ações frequentes.", "overview", 10, "_pagina_dashboard", 0),
    ModuleDefinition("maintenance", "Saúde e manutenção", "Limpeza segura, armazenamento, sensores, benchmark e manutenção.", "operations", 10, "_pagina_manutencao", 2),
    ModuleDefinition("processes_services", "Processos & Serviços", "Operação local de processos e serviços do Windows.", "operations", 20, "_pagina_processos", 6),
    ModuleDefinition("assist", "Assistente Técnico", "Orientação por evidências e Safe Playbooks sob decisão do técnico.", "operations", 30, "_pagina_assist", 13),
    ModuleDefinition("network_dns", "Rede & DNS", "Adaptadores, DNS, IP e diagnóstico detalhado da estação.", "network", 10, "_pagina_rede", 1),
    ModuleDefinition("network_inventory", "Inventário e Network Intelligence", "Varredura, contexto por IP e histórico operacional da rede.", "network", 20, "_pagina_inventario", 3),
    ModuleDefinition("defensive_analysis", "Análise defensiva", "Processos, persistências, assinaturas, hash, baseline e triagem humana.", "security", 10, "_pagina_seguranca", 6),
    ModuleDefinition("endpoint_posture", "Postura do Endpoint", "BitLocker, TPM, Secure Boot, antivírus, assinatura e Firewall em leitura local.", "security", 20, "_pagina_postura_endpoint", 12),
    ModuleDefinition("audit_timeline", "Auditoria & Timeline", "Eventos estruturados e evidências operacionais locais.", "investigation", 10, "_pagina_auditoria", 10),
    ModuleDefinition("investigation_replay", "Investigação e Incident Replay", "Change Intelligence, sessões, relações e replay cronológico.", "investigation", 20, "_pagina_investigacao", 11),
    ModuleDefinition("monitoring", "Monitoramento", "Amostras operacionais sob demanda e estado atual.", "observability", 10, "_pagina_monitoramento", 5),
    ModuleDefinition("reports", "Relatórios", "Geração e acesso aos relatórios técnicos existentes.", "observability", 20, "_pagina_relatorios", 4),
    ModuleDefinition("logs", "Logs", "Sessão visual e log técnico persistente.", "observability", 30, "_pagina_logs", 9),
    ModuleDefinition("deployment_tools", "Implantação", "Ferramentas atuais de preparação e implantação.", "deployment", 10, "_pagina_implantacao", 8),
    ModuleDefinition("company_central", "Empresa & Central", "Dados empresariais e funções locais já existentes.", "company", 10, "_pagina_central", 7),
)


DOMAIN_IDS = frozenset(domain.domain_id for domain in DOMAINS)
DOMAIN_BY_ID = {domain.domain_id: domain for domain in DOMAINS}
MODULE_BY_ID = {module.module_id: module for module in MODULES}


def domains():
    return tuple(sorted(DOMAINS, key=lambda item: (item.order, item.domain_id)))


def modules():
    return tuple(sorted(MODULES, key=lambda item: (
        DOMAIN_BY_ID[item.domain].order, item.order, item.module_id
    )))


def modules_for_domain(domain_id, *, visible_only=True):
    if domain_id not in DOMAIN_IDS:
        raise ValueError("Domínio de navegação inválido.")
    result = [item for item in MODULES if item.domain == domain_id]
    if visible_only:
        result = [item for item in result if item.visible]
    return tuple(sorted(result, key=lambda item: (item.order, item.module_id)))


def module(module_id):
    try:
        return MODULE_BY_ID[module_id]
    except KeyError as exc:
        raise ValueError("Módulo de navegação inválido.") from exc


def default_domain_for_view(view_index):
    candidates = [item for item in MODULES if item.view_index == int(view_index) and item.visible]
    if not candidates:
        return None
    # Processos/Serviços e Análise defensiva compartilham uma visão. O uso
    # operacional é o padrão; a rota de Segurança informa o domínio explicitamente.
    candidates.sort(key=lambda item: (item.domain != "operations", item.order, item.module_id))
    return candidates[0].domain


def validate_registry():
    domain_ids = [item.domain_id for item in DOMAINS]
    module_ids = [item.module_id for item in MODULES]
    if len(domain_ids) != len(set(domain_ids)) or len(module_ids) != len(set(module_ids)):
        raise ValueError("IDs duplicados no registry de navegação.")
    if any(item.domain not in DOMAIN_IDS for item in MODULES):
        raise ValueError("Módulo associado a domínio inválido.")
    if any(not item.route.startswith("_pagina_") for item in MODULES):
        raise ValueError("Rota declarativa inválida.")
    return True


validate_registry()
