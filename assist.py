"""Assistente Técnico e Safe Playbooks: orientação local, determinística e auditável.

Assist recomenda; o técnico decide. Playbooks são roteiros declarativos e não
scripts. Nenhuma conclusão de causa, remediação automática ou comando livre é
produzido por este módulo.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import socket
import sqlite3
import threading
import uuid

from audit_timeline import _clean_text, _utc_text, record_event_safe
from endpoint_posture import EndpointPostureStore
from monitoring_intelligence import local_technical_identity


DATABASE_SCHEMA_VERSION = 9
ASSIST_SCHEMA_VERSION = 2
CONTEXT_TYPES = (
    "ALERT", "POSTURE_CHANGE", "POSTURE_CHECK", "TIMELINE_EVENT", "CHANGE_GROUP",
    "INVESTIGATION_SESSION", "MONITORING_SETTINGS", "MANUAL_CONTEXT",
)
SESSION_STATUSES = ("OPEN", "COMPLETED", "ABORTED")
STEP_STATUSES = ("PENDING", "DONE", "SKIPPED")
STEP_TYPES = ("GUIDANCE", "NAVIGATE", "EXISTING_SAFE_ACTION")
MAX_QUERY_LIMIT = 100
MAX_NOTE_CHARS = 500
ACTION_STATUSES = (
    "PLANNED", "PRECHECK_FAILED", "READY", "RUNNING", "VALIDATING",
    "SUCCEEDED", "FAILED", "ROLLBACK_READY", "ROLLING_BACK",
    "ROLLED_BACK", "ROLLBACK_FAILED", "CANCELLED", "RECOVERY_REQUIRED",
)
ACTION_RESULTS = (
    "SUCCESS", "FAILURE", "INDETERMINATE", "CANCELLED", "ROLLED_BACK",
)
ACTION_EVENT_TYPES = (
    "PLANNED", "PRECHECK_FAILED", "DRY_RUN_COMPLETED", "CONFIRMED",
    "STARTED", "VALIDATION_STARTED", "SUCCEEDED", "FAILED", "CANCELLED",
    "ROLLBACK_READY", "ROLLBACK_STARTED", "ROLLED_BACK", "ROLLBACK_FAILED",
    "RECOVERY_REQUIRED", "RECOVERY_REVALIDATED",
)
MUTABLE_ACTIVE_STATUSES = (
    "PLANNED", "READY", "RUNNING", "VALIDATING", "ROLLBACK_READY",
    "ROLLING_BACK", "RECOVERY_REQUIRED",
)
_MUTATION_LOCK = threading.RLock()
_SENSITIVE_NOTE = re.compile(
    r"(?:password|passwd|senha|token|secret|segredo|credential|credencial|"
    r"recovery\s*key|chave\s*de\s*recupera|authorization|api[_ -]?key)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class StepDefinition:
    step_id: str
    title: str
    description: str
    step_type: str
    required: bool
    evidence_hint: str
    target_route: str | None = None
    action_ref: str | None = None


@dataclass(frozen=True)
class PlaybookDefinition:
    playbook_id: str
    version: int
    title: str
    description: str
    category: str
    applicable_contexts: tuple[str, ...]
    risk_level: str
    steps: tuple[StepDefinition, ...]
    visible: bool = True
    deprecated: bool = False


@dataclass(frozen=True)
class ActionDefinition:
    action_id: str
    version: int
    title: str
    description: str
    category: str
    risk_level: str
    side_effect_class: str
    requires_confirmation: bool
    requires_elevation: bool
    supports_dry_run: bool
    rollback_mode: str
    preconditions: tuple[str, ...]
    snapshotter_ref: str | None
    executor_ref: str
    validator_ref: str
    rollback_ref: str | None
    rollback_validator_ref: str | None
    parameter_schema: dict
    evidence_policy: str
    expected_effect: str
    collected_data: tuple[str, ...]
    expected_persistence: tuple[str, ...]
    limitations: tuple[str, ...]
    visible: bool = True


def _execute_refresh_endpoint_posture(runtime, *, cancel_callback=None):
    return runtime["posture_service"].collect_once(cancel_callback=cancel_callback)


def _execute_collect_monitoring_sample(runtime, *, cancel_callback=None):
    service = runtime["monitoring_service"]
    temporary_run = service.status == "STOPPED"
    if temporary_run:
        service.start()
    try:
        return service.collect_once(cancel_callback=cancel_callback)
    finally:
        if temporary_run:
            service.stop("Coleta imediata guiada concluída")


def _validate_posture_result(store, action_run, execution_result):
    snapshot = (execution_result or {}).get("snapshot") if isinstance(execution_result, dict) else None
    run = (snapshot or {}).get("run") or {}
    checks = list((snapshot or {}).get("checks") or [])
    if not (execution_result or {}).get("ok") or not run.get("run_id") or not checks:
        return "FAILURE", "A coleta não produziu um run de postura com checks persistidos.", None
    persisted = store.get_latest_snapshot(hostname=action_run["hostname"])
    if not persisted or (persisted.get("run") or {}).get("run_id") != run.get("run_id"):
        return "INDETERMINATE", "O coletor terminou, mas o novo snapshot não pôde ser comprovado no histórico.", None
    reference = {"type": "ENDPOINT_POSTURE_RUN", "id": run["run_id"]}
    partial = len(checks) < 6 or any(
        item.get("capability_state") != "AVAILABLE" or item.get("assessment") == "INDETERMINATE"
        for item in checks
    )
    if partial:
        return "INDETERMINATE", "Novo snapshot persistido; a coleta contém fontes limitadas ou indeterminadas.", reference
    return "SUCCESS", "Novo run de postura e checks persistidos para o endpoint correto.", reference


def _validate_monitoring_result(store, action_run, execution_result):
    cycle = (execution_result or {}).get("cycle") if isinstance(execution_result, dict) else None
    observations = list((cycle or {}).get("observations") or [])
    if not (execution_result or {}).get("ok") or not observations:
        return "FAILURE", "A coleta não produziu observações de monitoramento persistidas.", None
    identifiers = {item.get("observation_id") for item in observations if item.get("observation_id")}
    persisted = {
        item.get("observation_id") for item in store.list_observations(
            hostname=action_run["hostname"], limit=max(3, len(identifiers))
        )
    }
    reference_id = next(iter(identifiers), None)
    reference = {"type": "MONITORING_OBSERVATION", "id": reference_id} if reference_id else None
    if not identifiers or not identifiers.issubset(persisted):
        return "INDETERMINATE", "O coletor terminou, mas todas as novas observações não puderam ser comprovadas.", reference
    if any(item.get("value_num") is None for item in observations):
        return "INDETERMINATE", "Novas observações persistidas com ao menos uma métrica indisponível.", reference
    return "SUCCESS", "Novas observações de monitoramento persistidas e vinculadas ao run local.", reference


def _snapshot_monitoring_interval(store, runtime, action_run):
    service = runtime.get("monitoring_service")
    persisted = store.get_monitoring_configuration()
    runtime_interval = getattr(service, "interval_seconds", None)
    if service is None or runtime_interval is None:
        raise RuntimeError("MonitoringService indisponível para snapshot.")
    value = int(persisted["interval_seconds"])
    if int(runtime_interval) != value:
        # A fonte persistida é canônica; alinhar antes da proposta evitaria
        # registrar um Before ambíguo. O técnico deve revisar a divergência.
        raise RuntimeError("Configuração persistida e runtime de Monitoring divergem.")
    return {
        "old_interval_seconds": value,
        "monitoring_runtime_state": str(getattr(service, "status", "UNKNOWN")),
        "runtime_interval_seconds": int(runtime_interval),
        "config_source": "timeline.db/monitoring_configuration",
        "config_version": int(persisted["config_version"]),
    }


def _execute_set_monitoring_interval(store, runtime, action_run, *, cancel_callback=None):
    if cancel_callback and cancel_callback():
        return {"cancelled": True, "changed": False}
    service = runtime["monitoring_service"]
    before = action_run["before"]
    new_value = int(action_run["parameters"]["interval_seconds"])
    with _MUTATION_LOCK:
        persisted = store.set_monitoring_configuration(
            new_value, expected_interval=before["old_interval_seconds"]
        )
        # A persistência ocorre primeiro; qualquer falha posterior é detectada
        # como alteração parcial e encaminhada ao rollback determinístico.
        service.set_interval(new_value)
    return {
        "changed": True,
        "persisted_interval_seconds": int(persisted["interval_seconds"]),
        "runtime_interval_seconds": int(service.interval_seconds),
    }


def _observe_monitoring_interval(store, runtime, action_run, expected):
    service = runtime.get("monitoring_service")
    persisted = store.get_monitoring_configuration()
    runtime_value = getattr(service, "interval_seconds", None)
    active_run_value = None
    if service is not None and getattr(service, "run_id", None):
        current_run = store.get_run(service.run_id)
        active_run_value = (current_run or {}).get("interval_seconds")
    matches = (
        int(persisted["interval_seconds"]) == int(expected)
        and runtime_value is not None and int(runtime_value) == int(expected)
        and (active_run_value is None or int(active_run_value) == int(expected))
    )
    state = {
        "interval_seconds": int(persisted["interval_seconds"]),
        "runtime_interval_seconds": int(runtime_value) if runtime_value is not None else None,
        "active_run_interval_seconds": (
            int(active_run_value) if active_run_value is not None else None
        ),
        "monitoring_runtime_state": str(getattr(service, "status", "UNAVAILABLE")),
        "config_source": "timeline.db/monitoring_configuration",
        "config_version": int(persisted["config_version"]),
    }
    return matches, state


def _validate_set_monitoring_interval(store, runtime, action_run, execution_result):
    target = int(action_run["parameters"]["interval_seconds"])
    matches, state = _observe_monitoring_interval(store, runtime, action_run, target)
    if not matches:
        return "FAILURE", "O valor persistido/runtime não comprovou o intervalo proposto.", state
    return "SUCCESS", f"Configuração persistida e runtime usam {target} s.", state


def _rollback_set_monitoring_interval(store, runtime, action_run):
    service = runtime["monitoring_service"]
    target = int(action_run["before"]["old_interval_seconds"])
    current = store.get_monitoring_configuration()
    with _MUTATION_LOCK:
        store.set_monitoring_configuration(
            target, expected_interval=int(current["interval_seconds"])
        )
        service.set_interval(target)
    return {"rollback_target_interval_seconds": target}


def _validate_rollback_monitoring_interval(store, runtime, action_run, rollback_result):
    target = int(action_run["before"]["old_interval_seconds"])
    matches, state = _observe_monitoring_interval(store, runtime, action_run, target)
    if not matches:
        return False, "Rollback não pôde ser comprovado na persistência/runtime.", state
    return True, f"Rollback comprovado: intervalo restaurado para {target} s.", state


def _snapshot_monitoring_retention(store, runtime, action_run):
    service = runtime.get("monitoring_service")
    persisted = store.get_monitoring_configuration()
    runtime_value = getattr(service, "retention_days", None)
    if service is None or runtime_value is None:
        raise RuntimeError("MonitoringService indisponível para snapshot de retenção.")
    value = int(persisted["retention_days"])
    if int(runtime_value) != value:
        raise RuntimeError("Política persistida e runtime de retenção divergem.")
    return {
        "old_retention_days": value,
        "runtime_retention_days": int(runtime_value),
        "config_source": "timeline.db/monitoring_configuration",
        "config_version": int(persisted["config_version"]),
        "purge_executed": False,
    }


def _execute_set_monitoring_retention(store, runtime, action_run, *, cancel_callback=None):
    if cancel_callback and cancel_callback():
        return {"cancelled": True, "changed": False, "purge_executed": False}
    service = runtime["monitoring_service"]
    before = action_run["before"]
    new_value = int(action_run["parameters"]["retention_days"])
    with _MUTATION_LOCK:
        persisted = store.set_monitoring_configuration(
            retention_days=new_value,
            expected_retention=before["old_retention_days"],
        )
        service.set_retention_days(new_value)
    return {
        "changed": True,
        "persisted_retention_days": int(persisted["retention_days"]),
        "runtime_retention_days": int(service.retention_days),
        "purge_executed": False,
    }


def _observe_monitoring_retention(store, runtime, action_run, expected):
    service = runtime.get("monitoring_service")
    persisted = store.get_monitoring_configuration()
    runtime_value = getattr(service, "retention_days", None)
    matches = (
        int(persisted["retention_days"]) == int(expected)
        and runtime_value is not None and int(runtime_value) == int(expected)
    )
    return matches, {
        "retention_days": int(persisted["retention_days"]),
        "runtime_retention_days": int(runtime_value) if runtime_value is not None else None,
        "config_source": "timeline.db/monitoring_configuration",
        "config_version": int(persisted["config_version"]),
        "purge_executed": False,
    }


def _validate_set_monitoring_retention(store, runtime, action_run, execution_result):
    target = int(action_run["parameters"]["retention_days"])
    matches, state = _observe_monitoring_retention(store, runtime, action_run, target)
    if not matches:
        return "FAILURE", "Persistência/runtime não comprovaram a política de retenção.", state
    return "SUCCESS", f"Política persistida e runtime usam retenção de {target} dias; nenhum purge foi executado.", state


def _rollback_set_monitoring_retention(store, runtime, action_run):
    service = runtime["monitoring_service"]
    target = int(action_run["before"]["old_retention_days"])
    current = store.get_monitoring_configuration()
    with _MUTATION_LOCK:
        store.set_monitoring_configuration(
            retention_days=target,
            expected_retention=int(current["retention_days"]),
        )
        service.set_retention_days(target)
    return {"rollback_target_retention_days": target, "purge_executed": False}


def _validate_rollback_monitoring_retention(store, runtime, action_run, rollback_result):
    target = int(action_run["before"]["old_retention_days"])
    matches, state = _observe_monitoring_retention(store, runtime, action_run, target)
    if not matches:
        return False, "Rollback da retenção não pôde ser comprovado.", state
    return True, f"Rollback comprovado: retenção restaurada para {target} dias.", state


_ACTION_EXECUTOR_ALLOWLIST = {
    "refresh_endpoint_posture": _execute_refresh_endpoint_posture,
    "collect_monitoring_sample_now": _execute_collect_monitoring_sample,
    "set_monitoring_interval": _execute_set_monitoring_interval,
    "set_monitoring_retention": _execute_set_monitoring_retention,
}
_ACTION_VALIDATOR_ALLOWLIST = {
    "validate_endpoint_posture": _validate_posture_result,
    "validate_monitoring_sample": _validate_monitoring_result,
    "validate_monitoring_interval": _validate_set_monitoring_interval,
    "validate_monitoring_retention": _validate_set_monitoring_retention,
}
_ACTION_SNAPSHOTTER_ALLOWLIST = {
    "snapshot_monitoring_interval": _snapshot_monitoring_interval,
    "snapshot_monitoring_retention": _snapshot_monitoring_retention,
}
_ACTION_ROLLBACK_ALLOWLIST = {
    "rollback_monitoring_interval": _rollback_set_monitoring_interval,
    "rollback_monitoring_retention": _rollback_set_monitoring_retention,
}
_ACTION_ROLLBACK_VALIDATOR_ALLOWLIST = {
    "validate_rollback_monitoring_interval": _validate_rollback_monitoring_interval,
    "validate_rollback_monitoring_retention": _validate_rollback_monitoring_retention,
}

ACTION_REGISTRY = (
    ActionDefinition(
        "REFRESH_ENDPOINT_POSTURE", 1, "Atualizar Postura do Endpoint",
        "Executa a coleta local de postura já aprovada, sem alterar configurações.",
        "POSTURE", "LOW", "READ_ONLY", True, False, True, "NOT_REQUIRED",
        ("Persistência local disponível", "Nenhuma coleta de postura concorrente"),
        None, "refresh_endpoint_posture", "validate_endpoint_posture", None, None, {},
        "REFERENCE_ONLY",
        "Gravar um novo snapshot local de postura e seus checks.",
        ("BitLocker", "TPM", "Secure Boot", "Antivírus", "Assinatura Defender", "Firewall"),
        ("endpoint_posture_runs", "endpoint_posture_checks", "estado e mudanças significativas"),
        ("Fontes podem permanecer limitadas ou indeterminadas.",),
    ),
    ActionDefinition(
        "COLLECT_MONITORING_SAMPLE_NOW", 1, "Coletar amostra de monitoramento agora",
        "Executa uma única coleta local de CPU, memória e espaço livre, sem serviço 24/7.",
        "MONITORING", "LOW", "READ_ONLY", True, False, True, "NOT_REQUIRED",
        ("Persistência local disponível", "Nenhuma coleta imediata concorrente"),
        None, "collect_monitoring_sample_now", "validate_monitoring_sample", None, None, {},
        "REFERENCE_ONLY",
        "Gravar novas observações locais de CPU, memória e espaço livre.",
        ("CPU", "Memória", "Espaço livre do disco do sistema"),
        ("monitoring_runs", "monitoring_observations", "estado e transições quando aplicável"),
        ("Observação não é diagnóstico; falhas parciais permanecem explícitas.",),
    ),
    ActionDefinition(
        "SET_MONITORING_INTERVAL", 1, "Ajustar intervalo de monitoramento",
        "Altera somente a frequência de coleta local do Configurador TI entre valores seguros.",
        "MONITORING", "LOW", "LOCAL_REVERSIBLE_CHANGE", True, False, True, "REQUIRED",
        ("Persistência local disponível", "MonitoringService disponível",
         "Nenhuma transação equivalente", "Intervalo atual comprovado"),
        "snapshot_monitoring_interval", "set_monitoring_interval",
        "validate_monitoring_interval", "rollback_monitoring_interval",
        "validate_rollback_monitoring_interval",
        {"interval_seconds": {"type": "integer", "enum": [30, 60, 120, 300]}},
        "STRUCTURED_SNAPSHOT",
        "Persistir e aplicar ao runtime um novo intervalo local allowlisted.",
        ("Intervalo atual", "Estado do MonitoringService", "Versão da configuração"),
        ("monitoring_configuration", "monitoring_runs quando houver run ativo"),
        ("Não altera Windows, não cria serviço/timer e não executa coleta.",),
    ),
    ActionDefinition(
        "SET_MONITORING_RETENTION_POLICY", 1, "Ajustar política de retenção",
        "Altera somente por quantos dias as amostras locais serão mantidas em futuras rotinas normais.",
        "MONITORING", "LOW", "LOCAL_REVERSIBLE_CHANGE", True, False, True, "REQUIRED",
        ("Persistência local disponível", "MonitoringService disponível",
         "Nenhuma transação equivalente", "Retenção atual comprovada"),
        "snapshot_monitoring_retention", "set_monitoring_retention",
        "validate_monitoring_retention", "rollback_monitoring_retention",
        "validate_rollback_monitoring_retention",
        {"retention_days": {"type": "integer", "enum": [7, 14, 30, 60, 90]}},
        "STRUCTURED_SNAPSHOT",
        "Persistir e aplicar ao runtime uma política local de retenção allowlisted.",
        ("Retenção atual", "Retenção no runtime", "Versão da configuração"),
        ("monitoring_configuration",),
        ("Não apaga amostras durante a transação e não altera configurações do Windows.",),
    ),
)
ACTION_BY_ID = {item.action_id: item for item in ACTION_REGISTRY}
SAFE_ACTION_ALLOWLIST = frozenset(ACTION_BY_ID)

PROHIBITED_SIDE_EFFECT_CLASSES = frozenset({
    "PRIVILEGED_CHANGE", "DESTRUCTIVE", "REMOTE_CHANGE",
    "SECURITY_POLICY_CHANGE", "SYSTEM_UPDATE",
})
ACTION_POLICY_MATRIX = {
    "READ_ONLY": {
        "risk_levels": frozenset({"NONE", "LOW"}),
        "requires_elevation": False,
        "supports_dry_run": True,
        "rollback_mode": "NOT_REQUIRED",
        "requires_transaction_handlers": False,
    },
    "LOCAL_REVERSIBLE_CHANGE": {
        "risk_levels": frozenset({"LOW"}),
        "requires_elevation": False,
        "supports_dry_run": True,
        "rollback_mode": "REQUIRED",
        "requires_transaction_handlers": True,
    },
}
_TRANSACTION_SPECS = {
    "SET_MONITORING_INTERVAL": {
        "parameter_key": "interval_seconds",
        "before_key": "old_interval_seconds",
        "proposed_key": "interval_seconds",
        "effect": "Frequência de coleta local do Configurador TI",
        "unit": "s",
        "observer": _observe_monitoring_interval,
    },
    "SET_MONITORING_RETENTION_POLICY": {
        "parameter_key": "retention_days",
        "before_key": "old_retention_days",
        "proposed_key": "retention_days",
        "effect": "Política local para futuras rotinas de retenção do Configurador TI",
        "unit": "dias",
        "observer": _observe_monitoring_retention,
    },
}


def _validate_parameter_schema(schema, *, required):
    if not isinstance(schema, dict) or (required and not schema):
        raise ValueError("Mutação local exige schema de parâmetros tipado.")
    if not required and schema:
        raise ValueError("Ação read-only não deve aceitar parâmetros mutáveis.")
    for name, rule in schema.items():
        if not isinstance(name, str) or not name or not isinstance(rule, dict):
            raise ValueError("Schema de parâmetro inválido.")
        if set(rule) != {"type", "enum"} or rule.get("type") != "integer":
            raise ValueError("Somente enum integer estritamente tipado é autorizado.")
        values = rule.get("enum")
        if not isinstance(values, (list, tuple)) or not values:
            raise ValueError("Enum de parâmetro não pode ser vazio.")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise ValueError("Enum deve conter apenas inteiros tipados.")
        if len(values) != len(set(values)):
            raise ValueError("Enum de parâmetro contém duplicidade.")
    return True


def validate_action_registry(actions=ACTION_REGISTRY):
    identifiers = [item.action_id for item in actions]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("IDs duplicados no Action Registry.")
    for action in actions:
        if action.version < 1:
            raise ValueError("Ação sem versão válida.")
        if action.side_effect_class in PROHIBITED_SIDE_EFFECT_CLASSES:
            raise ValueError("Classe de efeito explicitamente proibida nesta fase.")
        policy = ACTION_POLICY_MATRIX.get(action.side_effect_class)
        if policy is None:
            raise ValueError("Classe de efeito não autorizada pela matriz central.")
        if action.risk_level not in policy["risk_levels"]:
            raise ValueError("Risco incompatível com a classe de efeito.")
        if action.requires_elevation != policy["requires_elevation"]:
            raise ValueError("Política de elevação incompatível com a classe de efeito.")
        if action.supports_dry_run != policy["supports_dry_run"]:
            raise ValueError("Dry-run obrigatório pela política central.")
        if action.rollback_mode != policy["rollback_mode"]:
            raise ValueError("Política de rollback incompatível com a classe de efeito.")
        if not action.requires_confirmation:
            raise ValueError("Confirmação humana explícita é obrigatória.")
        if not policy["requires_transaction_handlers"]:
            if any((action.snapshotter_ref, action.rollback_ref, action.rollback_validator_ref)):
                raise ValueError("Ação read-only não deve declarar rollback mutável.")
            _validate_parameter_schema(action.parameter_schema, required=False)
        else:
            if action.snapshotter_ref not in _ACTION_SNAPSHOTTER_ALLOWLIST:
                raise ValueError("Snapshotter obrigatório não autorizado.")
            if action.rollback_ref not in _ACTION_ROLLBACK_ALLOWLIST:
                raise ValueError("Rollback obrigatório não autorizado.")
            if action.rollback_validator_ref not in _ACTION_ROLLBACK_VALIDATOR_ALLOWLIST:
                raise ValueError("Validator de rollback obrigatório não autorizado.")
            _validate_parameter_schema(action.parameter_schema, required=True)
        if action.executor_ref not in _ACTION_EXECUTOR_ALLOWLIST:
            raise ValueError("Executor não autorizado pela allowlist interna.")
        if action.validator_ref not in _ACTION_VALIDATOR_ALLOWLIST:
            raise ValueError("Validator não autorizado pela allowlist interna.")
        if not callable(_ACTION_EXECUTOR_ALLOWLIST[action.executor_ref]):
            raise ValueError("Executor allowlisted inválido.")
    return True


def _guidance(step_id, title, description, evidence_hint, *, required=True):
    return StepDefinition(step_id, title, description, "GUIDANCE", required, evidence_hint)


def _navigate(step_id, title, description, evidence_hint, target_route, *, required=False):
    return StepDefinition(
        step_id, title, description, "NAVIGATE", required, evidence_hint,
        target_route=target_route,
    )


PLAYBOOKS = (
    PlaybookDefinition(
        "STORAGE_SPACE_REVIEW", 1, "Revisar espaço de armazenamento",
        "Revisão orientada de tendência e opções existentes de manutenção, sem limpeza automática.",
        "STORAGE", ("ALERT",), "LOW",
        (
            _guidance("confirm_alert", "Confirmar evidência do alerta", "Revise valor, unidade, horário e recorrência do alerta de espaço.", "Alerta e tendência local."),
            _navigate("open_trend", "Abrir tendência", "Compare a leitura atual com o histórico disponível.", "Tendência persistida do disco.", "monitoring", required=True),
            _navigate("open_storage", "Abrir manutenção de armazenamento", "Revise as opções existentes; nenhuma limpeza será executada pelo playbook.", "Saúde e manutenção local.", "maintenance"),
            _guidance("review_temp", "Revisar arquivos temporários", "Use somente a análise segura existente e confirme manualmente qualquer ação posterior.", "Resultado da análise existente.", required=False),
        ),
    ),
    PlaybookDefinition(
        "ENDPOINT_POSTURE_REVIEW", 1, "Revisar postura do endpoint",
        "Revisão da fonte, capacidade e contexto de uma mudança de postura sem remediação.",
        "POSTURE", ("POSTURE_CHANGE", "POSTURE_CHECK"), "LOW",
        (
            _guidance("review_source", "Revisar fonte e capacidade", "Confirme a fonte, a capacidade de coleta e a limitação declarada.", "Evidência sanitizada da postura."),
            _navigate("open_timeline", "Abrir Timeline", "Confira o evento associado e o contexto temporal.", "Evento Timeline referenciado.", "audit_timeline", required=True),
            _navigate("open_investigation", "Abrir investigação", "Relacione evidências apenas quando houver contexto operacional suficiente.", "Sessão ou mudança associada.", "investigation_replay"),
            _guidance("record_limit", "Registrar limitação", "Mantenha explícito quando o estado for limitado ou indeterminado.", "Limitação do contexto."),
            StepDefinition(
                "refresh_posture", "Atualizar Postura do Endpoint",
                "Prepare, revise e confirme uma nova coleta local somente leitura.",
                "EXISTING_SAFE_ACTION", False, "ActionRun e Proof of Work persistidos.",
                action_ref="REFRESH_ENDPOINT_POSTURE",
            ),
        ),
    ),
    PlaybookDefinition(
        "MONITORING_ALERT_REVIEW", 1, "Revisar alerta de monitoramento",
        "Revisão de histórico, tendência e contexto de CPU, memória ou disco.",
        "MONITORING", ("ALERT",), "LOW",
        (
            _guidance("review_alert", "Revisar alerta", "Confirme métrica, severidade, estado e horário da observação.", "Alerta local persistido."),
            _navigate("open_history", "Abrir histórico e tendência", "Compare a condição com amostras persistidas no período.", "Histórico local da métrica.", "monitoring", required=True),
            _guidance("review_context", "Revisar contexto", "Considere somente relações temporais/operacionais; correlação não prova causa.", "Contexto local do alerta."),
            _navigate("open_investigation", "Abrir investigação", "Abra uma sessão se a triagem precisar relacionar evidências.", "Referência do alerta.", "investigation_replay"),
            StepDefinition(
                "collect_sample", "Coletar nova amostra de monitoramento",
                "Prepare, revise e confirme uma coleta imediata somente leitura.",
                "EXISTING_SAFE_ACTION", False, "ActionRun e novas observações persistidas.",
                action_ref="COLLECT_MONITORING_SAMPLE_NOW",
            ),
            StepDefinition(
                "set_interval", "Ajustar intervalo de monitoramento",
                "Selecione um valor seguro, revise o dry-run e confirme a alteração local reversível.",
                "EXISTING_SAFE_ACTION", False,
                "Before/After, validação e rollback persistidos no ActionRun.",
                action_ref="SET_MONITORING_INTERVAL",
            ),
        ),
    ),
    PlaybookDefinition(
        "MONITORING_SETTINGS_REVIEW", 1, "Revisar configuração de monitoramento",
        "Revisão controlada da configuração local atual, sem pressupor alerta ou incidente.",
        "MONITORING", ("MONITORING_SETTINGS",), "LOW",
        (
            _guidance(
                "review_settings", "Revisar configuração atual",
                "Confirme o intervalo persistido, o estado do serviço e o run ativo. "
                "Os valores permitidos são 30, 60, 120 e 300 segundos; nenhum é recomendado como melhor.",
                "Configuração local persistida e estado atual do MonitoringService.",
            ),
            StepDefinition(
                "set_interval", "Ajustar intervalo de monitoramento",
                "Selecione um valor permitido, revise o dry-run e confirme a alteração local reversível.",
                "EXISTING_SAFE_ACTION", False,
                "Before/After, validação e rollback persistidos no ActionRun.",
                action_ref="SET_MONITORING_INTERVAL",
            ),
            StepDefinition(
                "set_retention", "Ajustar política de retenção",
                "Selecione 7, 14, 30, 60 ou 90 dias; a transação não apaga amostras.",
                "EXISTING_SAFE_ACTION", False,
                "Before/After da política, validação e rollback persistidos no ActionRun.",
                action_ref="SET_MONITORING_RETENTION_POLICY",
            ),
        ),
    ),
    PlaybookDefinition(
        "NETWORK_CHANGE_REVIEW", 1, "Revisar mudança de rede",
        "Revisão de fonte, antes/depois e contexto temporal, sem alteração automática de rede.",
        "NETWORK", ("CHANGE_GROUP", "TIMELINE_EVENT", "INVESTIGATION_SESSION"), "LOW",
        (
            _guidance("review_source", "Revisar fonte", "Confirme a origem da evidência e a cobertura informada.", "Fonte persistida da mudança."),
            _guidance("review_diff", "Revisar antes e depois", "Compare somente os campos registrados; ausência de dado não significa remoção.", "Mudanças classificadas persistidas."),
            _navigate("open_timeline", "Abrir Timeline", "Confira eventos no mesmo contexto temporal.", "Evento ou grupo associado.", "audit_timeline", required=True),
            _guidance("no_auto_change", "Confirmar controle humano", "Não aplique alteração de rede automaticamente; qualquer ação permanece fora deste playbook.", "Limitação de segurança."),
        ),
    ),
)
PLAYBOOK_BY_ID = {item.playbook_id: item for item in PLAYBOOKS}


def validate_registry(playbooks=PLAYBOOKS):
    ids = [item.playbook_id for item in playbooks]
    if len(ids) != len(set(ids)):
        raise ValueError("IDs duplicados no catálogo de playbooks.")
    for playbook in playbooks:
        if playbook.version < 1 or not playbook.steps:
            raise ValueError("Playbook sem versão ou etapas válidas.")
        if any(context not in CONTEXT_TYPES for context in playbook.applicable_contexts):
            raise ValueError("Contexto desconhecido no catálogo de playbooks.")
        step_ids = [step.step_id for step in playbook.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("IDs de etapas duplicados no playbook.")
        for step in playbook.steps:
            if step.step_type not in STEP_TYPES:
                raise ValueError("Tipo de etapa não permitido.")
            if step.step_type == "EXISTING_SAFE_ACTION" and step.action_ref not in SAFE_ACTION_ALLOWLIST:
                raise ValueError("Ação segura não autorizada pela allowlist estática.")
            if step.step_type != "EXISTING_SAFE_ACTION" and step.action_ref:
                raise ValueError("Referência de ação incompatível com o tipo da etapa.")
    return True


validate_registry()
validate_action_registry()


def sanitize_note(value):
    text = _clean_text(value, MAX_NOTE_CHARS)
    if text and _SENSITIVE_NOTE.search(text):
        raise ValueError("A nota não deve conter senha, token, credencial ou chave de recuperação.")
    return text or None


def _loads(value, default):
    try:
        loaded = json.loads(value) if value else default
        return loaded if isinstance(loaded, type(default)) else default
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _refs(*items):
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ref_type = _clean_text(item.get("type"), 40)
        ref_id = _clean_text(item.get("id"), 100)
        if ref_type and ref_id and {"type": ref_type, "id": ref_id} not in result:
            result.append({"type": ref_type, "id": ref_id})
    return result[:20]


class AssistStore(EndpointPostureStore):
    """Schema 9 sobre o mesmo timeline.db, compatível com o histórico existente."""

    def __init__(self, root, logger=None, timeout=5.0):
        super().__init__(root, logger=logger, timeout=timeout)
        self._initialize_assist()
        self._mark_abandoned_mutations_for_recovery()

    def _initialize_assist(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (6, 7, 8, DATABASE_SCHEMA_VERSION):
                raise RuntimeError("Versão do banco do Assistente Técnico não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS assist_contexts (
                        context_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        hostname TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        source_id TEXT,
                        summary TEXT NOT NULL,
                        evidence_refs_json TEXT NOT NULL,
                        limitations_json TEXT NOT NULL,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS playbook_sessions (
                        session_id TEXT PRIMARY KEY,
                        playbook_id TEXT NOT NULL,
                        playbook_version INTEGER NOT NULL,
                        context_id TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        source_context_type TEXT NOT NULL,
                        source_context_id TEXT,
                        status TEXT NOT NULL,
                        started_at_utc TEXT NOT NULL,
                        completed_at_utc TEXT,
                        created_by TEXT NOT NULL,
                        definition_json TEXT NOT NULL,
                        investigation_session_id TEXT,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL,
                        FOREIGN KEY(context_id) REFERENCES assist_contexts(context_id)
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS playbook_session_steps (
                        session_id TEXT NOT NULL,
                        step_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        completed_at_utc TEXT,
                        note TEXT,
                        evidence_ref_json TEXT,
                        updated_at_utc TEXT NOT NULL,
                        PRIMARY KEY(session_id, step_id),
                        FOREIGN KEY(session_id) REFERENCES playbook_sessions(session_id) ON DELETE CASCADE
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS action_runs (
                        action_run_id TEXT PRIMARY KEY,
                        action_id TEXT NOT NULL,
                        action_version INTEGER NOT NULL,
                        hostname TEXT NOT NULL,
                        source_playbook_session_id TEXT NOT NULL,
                        source_step_id TEXT NOT NULL,
                        source_context_type TEXT NOT NULL,
                        source_context_id TEXT,
                        status TEXT NOT NULL,
                        requested_by TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        result TEXT,
                        error_code TEXT,
                        error_summary TEXT,
                        before_evidence_ref TEXT,
                        after_evidence_ref TEXT,
                        validator_summary TEXT,
                        parameters_json TEXT NOT NULL,
                        preconditions_json TEXT NOT NULL,
                        dry_run_json TEXT,
                        confirmed_at TEXT,
                        accepted_at TEXT,
                        FOREIGN KEY(source_playbook_session_id)
                            REFERENCES playbook_sessions(session_id)
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS action_run_events (
                        event_id TEXT PRIMARY KEY,
                        action_run_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        evidence_ref TEXT,
                        FOREIGN KEY(action_run_id) REFERENCES action_runs(action_run_id)
                            ON DELETE CASCADE
                    )
                """)
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(action_runs)").fetchall()
                }
                additions = {
                    "before_json": "TEXT", "proposed_after_json": "TEXT",
                    "actual_after_json": "TEXT", "rollback_target_json": "TEXT",
                    "executor_outcome_json": "TEXT", "validator_outcome_json": "TEXT",
                    "rollback_outcome_json": "TEXT", "rollback_status": "TEXT",
                    "rollback_started_at": "TEXT", "rollback_completed_at": "TEXT",
                    "recovery_marked_at": "TEXT", "resource_key": "TEXT",
                }
                for column, sql_type in additions.items():
                    if column not in columns:
                        connection.execute(
                            f"ALTER TABLE action_runs ADD COLUMN {column} {sql_type}"
                        )
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS monitoring_configuration (
                        singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                        interval_seconds INTEGER NOT NULL
                            CHECK(interval_seconds IN (30,60,120,300)),
                        retention_days INTEGER NOT NULL DEFAULT 30
                            CHECK(retention_days IN (7,14,30,60,90)),
                        config_version INTEGER NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    )
                """)
                config_columns = {
                    row[1] for row in connection.execute(
                        "PRAGMA table_info(monitoring_configuration)"
                    ).fetchall()
                }
                if "retention_days" not in config_columns:
                    connection.execute(
                        "ALTER TABLE monitoring_configuration "
                        "ADD COLUMN retention_days INTEGER NOT NULL DEFAULT 30 "
                        "CHECK(retention_days IN (7,14,30,60,90))"
                    )
                existing_config = connection.execute(
                    "SELECT singleton_id FROM monitoring_configuration WHERE singleton_id=1"
                ).fetchone()
                if existing_config is None:
                    latest = connection.execute(
                        "SELECT interval_seconds FROM monitoring_runs "
                        "ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()
                    initial_interval = int(latest[0]) if latest else 60
                    connection.execute(
                        "INSERT INTO monitoring_configuration "
                        "(singleton_id,interval_seconds,retention_days,config_version,updated_at_utc) "
                        "VALUES (1,?,?,?,?)",
                        (initial_interval, 30, 1, _utc_text()),
                    )
                for name, table, expression in (
                    ("idx_assist_context_source", "assist_contexts", "source_type, source_id, updated_at_utc DESC"),
                    ("idx_assist_context_host", "assist_contexts", "hostname, updated_at_utc DESC"),
                    ("idx_playbook_session_updated", "playbook_sessions", "updated_at_utc DESC"),
                    ("idx_playbook_session_status", "playbook_sessions", "status, updated_at_utc DESC"),
                    ("idx_playbook_session_context", "playbook_sessions", "context_id, playbook_id"),
                    ("idx_playbook_steps_status", "playbook_session_steps", "session_id, status"),
                    ("idx_action_runs_action", "action_runs", "action_id, created_at DESC"),
                    ("idx_action_runs_host", "action_runs", "hostname, created_at DESC"),
                    ("idx_action_runs_status", "action_runs", "status, created_at DESC"),
                    ("idx_action_runs_session", "action_runs", "source_playbook_session_id, created_at DESC"),
                    ("idx_action_events_run", "action_run_events", "action_run_id, occurred_at"),
                ):
                    connection.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table}({expression})")
                connection.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_action_runs_active_resource
                    ON action_runs(resource_key)
                    WHERE resource_key IS NOT NULL AND status IN (
                        'PLANNED','READY','RUNNING','VALIDATING','ROLLBACK_READY',
                        'ROLLING_BACK','RECOVERY_REQUIRED'
                    )
                """)
                connection.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_assist_context_unique_source
                    ON assist_contexts(hostname, source_type, source_id)
                    WHERE source_id IS NOT NULL AND source_type <> 'MANUAL_CONTEXT'
                """)
                if current < DATABASE_SCHEMA_VERSION:
                    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
        finally:
            connection.close()

    def get_monitoring_configuration(self):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT interval_seconds,retention_days,config_version,updated_at_utc "
                "FROM monitoring_configuration WHERE singleton_id=1"
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RuntimeError("Configuração de Monitoring indisponível.")
        return dict(row)

    def set_monitoring_configuration(self, interval_seconds=None, *, expected_interval=None,
                                     retention_days=None, expected_retention=None):
        from monitoring_foundation import validate_interval, validate_retention_days

        if interval_seconds is None and retention_days is None:
            raise ValueError("Informe intervalo ou retenção para a atualização tipada.")
        interval = validate_interval(interval_seconds) if interval_seconds is not None else None
        retention = (
            validate_retention_days(retention_days) if retention_days is not None else None
        )
        connection = self._connect()
        try:
            with connection:
                current = connection.execute(
                    "SELECT interval_seconds,retention_days,config_version "
                    "FROM monitoring_configuration "
                    "WHERE singleton_id=1"
                ).fetchone()
                if current is None:
                    raise RuntimeError("Configuração de Monitoring indisponível.")
                if expected_interval is not None and int(current[0]) != int(expected_interval):
                    raise RuntimeError("Configuração mudou durante a transação.")
                if expected_retention is not None and int(current[1]) != int(expected_retention):
                    raise RuntimeError("Política de retenção mudou durante a transação.")
                connection.execute(
                    "UPDATE monitoring_configuration SET interval_seconds=?,retention_days=?,"
                    "config_version=?,updated_at_utc=? WHERE singleton_id=1",
                    (
                        int(current[0]) if interval is None else interval,
                        int(current[1]) if retention is None else retention,
                        int(current[2]) + 1, _utc_text(),
                    ),
                )
        finally:
            connection.close()
        return self.get_monitoring_configuration()

    @staticmethod
    def registry():
        return PLAYBOOKS

    @staticmethod
    def playbook(playbook_id):
        try:
            return PLAYBOOK_BY_ID[_clean_text(playbook_id, 80, required=True)]
        except KeyError as exc:
            raise ValueError("Playbook inexistente no catálogo estático.") from exc

    def _resolve_context(self, source_type, source_id=None, *, summary=None, hostname=None,
                         limitations=None, investigation_session_id=None,
                         monitoring_state=None, monitoring_run_id=None,
                         observed_at_utc=None):
        source_type = str(source_type or "").strip().upper()
        if source_type not in CONTEXT_TYPES:
            raise ValueError("Tipo de contexto do Assist inválido.")
        source_id = _clean_text(source_id, 100) or None
        hostname = _clean_text(hostname or socket.gethostname() or "Não disponível", 255, required=True)
        refs, limits = [], list(limitations or [])[:10]

        if source_type == "ALERT":
            item = self.get_alert(source_id) if source_id else None
            if item is None:
                raise ValueError("Alerta de origem inexistente.")
            hostname = item.get("hostname") or hostname
            summary = summary or (
                f"Alerta {item.get('metric_key') or 'de monitoramento'} em "
                f"{item.get('severity') or 'estado não informado'} ({item.get('status') or '—'})."
            )
            refs = _refs(
                {"type": "ALERT", "id": item.get("alert_id")},
                {"type": "TIMELINE_EVENT", "id": item.get("opening_event_id")},
                {"type": "MONITORING_OBSERVATION", "id": item.get("last_observation_id")},
            )
            limits.append("Alerta não é incidente; tendência e correlação não comprovam causalidade.")
        elif source_type == "POSTURE_CHANGE":
            item = self.get_change(source_id) if source_id else None
            if item is None:
                raise ValueError("Mudança de postura de origem inexistente.")
            hostname = item.get("hostname") or hostname
            after = _loads(item.get("after_json"), {})
            summary = summary or item.get("after_summary") or "Mudança significativa de postura observada."
            refs = _refs(
                {"type": "POSTURE_CHANGE", "id": item.get("change_id")},
                {"type": "TIMELINE_EVENT", "id": item.get("timeline_event_id")},
                {"type": "INVESTIGATION_SESSION", "id": item.get("investigation_session_id")},
            )
            if after.get("capability_state") in ("LIMITED", "UNAVAILABLE", "INDETERMINATE"):
                limits.append("A capacidade da fonte está limitada, indisponível ou indeterminada.")
            limits.append("Postura observada não é garantia de segurança; mudança não é incidente.")
        elif source_type == "POSTURE_CHECK":
            item = self.get_check(source_id) if source_id else None
            if item is None:
                raise ValueError("Check atual de postura inexistente.")
            hostname = item.get("hostname") or hostname
            summary = summary or item.get("summary") or "Check atual de postura selecionado."
            refs = _refs(
                {"type": "POSTURE_CHECK", "id": item.get("check_id")},
                {"type": "ENDPOINT_POSTURE_RUN", "id": item.get("run_id")},
            )
            if item.get("capability_state") in ("LIMITED", "UNAVAILABLE", "INDETERMINATE"):
                limits.append("A capacidade da fonte está limitada, indisponível ou indeterminada.")
            limits.append("Postura observada não é garantia de segurança; check atual não é incidente.")
        elif source_type == "TIMELINE_EVENT":
            item = self.get_event(source_id) if source_id else None
            if item is None:
                raise ValueError("Evento Timeline de origem inexistente.")
            hostname = item.get("hostname") or hostname
            summary = summary or item.get("summary") or "Evento Timeline selecionado."
            refs = _refs({"type": "TIMELINE_EVENT", "id": item.get("id")})
            limits.append("O evento registra evidência operacional e não determina causa raiz.")
        elif source_type == "CHANGE_GROUP":
            item = self.get_group(source_id) if source_id else None
            if item is None:
                raise ValueError("Grupo de mudanças de origem inexistente.")
            hostname = item.get("hostname") or hostname
            summary = summary or item.get("summary") or "Grupo de mudanças selecionado."
            refs = _refs({"type": "CHANGE_GROUP", "id": item.get("operation_id")})
            limits.append("Mudança não implica causa, incidente ou ameaça.")
        elif source_type == "INVESTIGATION_SESSION":
            item = self.get_session(source_id) if source_id else None
            if item is None:
                raise ValueError("Sessão de investigação de origem inexistente.")
            hostname = item.get("hostname") or hostname
            summary = summary or item.get("summary") or item.get("title") or "Sessão de investigação selecionada."
            investigation_session_id = item.get("session_id")
            refs = _refs({"type": "INVESTIGATION_SESSION", "id": item.get("session_id")})
            limits.append("Relações investigativas são contexto; correlação não comprova causalidade.")
        elif source_type == "MONITORING_SETTINGS":
            configuration = self.get_monitoring_configuration()
            source_id = source_id or "monitoring_configuration:1"
            interval = int(configuration["interval_seconds"])
            retention = int(configuration["retention_days"])
            state = str(monitoring_state or "INDISPONÍVEL").strip().upper()
            if state not in ("STOPPED", "RUNNING", "PAUSED", "ERROR"):
                state = "INDISPONÍVEL"
            run_id = _clean_text(monitoring_run_id, 64) or None
            observed = _clean_text(observed_at_utc or _utc_text(), 40, required=True)
            summary = summary or (
                "Configuração local atual do Monitoramento: "
                f"intervalo persistido {interval} s; retenção {retention} dias; serviço {state}; "
                f"run ativo {run_id or 'nenhum'}; consultado em {observed}."
            )
            refs = _refs(
                {"type": "MONITORING_CONFIGURATION", "id": "singleton:1"},
                {"type": "MONITORING_RUN", "id": run_id},
            )
            limits.extend((
                "Revisão aberta explicitamente pelo técnico; não representa alerta, incidente ou severidade.",
                "Abrir este contexto não altera a configuração, não inicia coleta e não executa ação.",
            ))
        else:
            summary = summary or "Contexto manual criado pelo técnico para orientação local."
            limits.append("Contexto manual depende da revisão humana e não contém diagnóstico automático.")

        return {
            "hostname": _clean_text(hostname, 255, required=True),
            "source_type": source_type,
            "source_id": source_id,
            "summary": _clean_text(summary, 600, required=True),
            "evidence_refs": refs,
            "limitations": [_clean_text(item, 300) for item in limits if _clean_text(item, 300)][:10],
            "investigation_session_id": _clean_text(investigation_session_id, 64) or None,
        }

    def create_context(self, source_type, source_id=None, **values):
        context = self._resolve_context(source_type, source_id, **values)
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                existing = None
                if context["source_id"] and context["source_type"] != "MANUAL_CONTEXT":
                    existing = connection.execute("""
                        SELECT context_id FROM assist_contexts
                        WHERE hostname=? AND source_type=? AND source_id=?
                    """, (context["hostname"], context["source_type"], context["source_id"])).fetchone()
                context_id = existing[0] if existing else uuid.uuid4().hex
                record = {
                    "context_id": context_id,
                    "schema_version": ASSIST_SCHEMA_VERSION,
                    "hostname": context["hostname"], "source_type": context["source_type"],
                    "source_id": context["source_id"], "summary": context["summary"],
                    "evidence_refs_json": json.dumps(context["evidence_refs"], ensure_ascii=False, separators=(",", ":")),
                    "limitations_json": json.dumps(context["limitations"], ensure_ascii=False, separators=(",", ":")),
                    "created_at_utc": now, "updated_at_utc": now,
                }
                if existing:
                    connection.execute("""
                        UPDATE assist_contexts SET summary=:summary,
                            evidence_refs_json=:evidence_refs_json,
                            limitations_json=:limitations_json, updated_at_utc=:updated_at_utc
                        WHERE context_id=:context_id
                    """, record)
                else:
                    connection.execute("""
                        INSERT INTO assist_contexts (
                            context_id,schema_version,hostname,source_type,source_id,summary,
                            evidence_refs_json,limitations_json,created_at_utc,updated_at_utc
                        ) VALUES (
                            :context_id,:schema_version,:hostname,:source_type,:source_id,:summary,
                            :evidence_refs_json,:limitations_json,:created_at_utc,:updated_at_utc
                        )
                    """, record)
        finally:
            connection.close()
        result = self.get_context(context_id)
        result["investigation_session_id"] = context.get("investigation_session_id")
        return result

    def get_context(self, context_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM assist_contexts WHERE context_id=?",
                (_clean_text(context_id, 64, required=True),),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        result = dict(row)
        result["evidence_refs"] = _loads(result.pop("evidence_refs_json"), [])
        result["limitations"] = _loads(result.pop("limitations_json"), [])
        return result

    def list_contexts(self, *, hostname=None, limit=50, offset=0):
        limit, offset = max(1, min(int(limit), MAX_QUERY_LIMIT)), max(0, int(offset))
        params = {"limit": limit, "offset": offset}
        where = ""
        if hostname:
            where = " WHERE hostname=:hostname"
            params["hostname"] = _clean_text(hostname, 255, required=True)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT context_id FROM assist_contexts" + where
                + " ORDER BY updated_at_utc DESC, context_id DESC LIMIT :limit OFFSET :offset", params,
            ).fetchall()
        finally:
            connection.close()
        return [self.get_context(row[0]) for row in rows]

    def recommend(self, context_or_id):
        context = self.get_context(context_or_id) if isinstance(context_or_id, str) else dict(context_or_id or {})
        if not context:
            raise ValueError("Contexto do Assist inexistente.")
        source_type, source_id = context.get("source_type"), context.get("source_id")
        selected = []
        if source_type == "ALERT":
            alert = self.get_alert(source_id) or {}
            if alert.get("metric_key") == "system_disk_free":
                selected.append(("RULE_ALERT_DISK_FREE", "STORAGE_SPACE_REVIEW", "O alerta persistido é de espaço livre em disco."))
            selected.append(("RULE_ALERT_MONITORING", "MONITORING_ALERT_REVIEW", "Há um alerta local persistido com histórico e contexto disponíveis."))
        elif source_type == "POSTURE_CHANGE":
            change = self.get_change(source_id) or {}
            after = _loads(change.get("after_json"), {})
            if after.get("assessment") in ("ATTENTION", "INDETERMINATE"):
                selected.append(("RULE_POSTURE_ATTENTION", "ENDPOINT_POSTURE_REVIEW", "A mudança de postura registrada requer revisão humana da fonte e da capacidade."))
        elif source_type == "POSTURE_CHECK":
            check = self.get_check(source_id) or {}
            if check.get("assessment") in ("ATTENTION", "INDETERMINATE"):
                selected.append(("RULE_POSTURE_CHECK_REVIEW", "ENDPOINT_POSTURE_REVIEW", "O check atual requer revisão humana da fonte, capacidade e evidência persistida."))
        elif source_type == "CHANGE_GROUP":
            group = self.get_group(source_id) or {}
            changes = self.query_changes(operation_id=source_id, limit=50)
            text = " ".join(
                (str(group.get("summary") or ""), str(group.get("source") or ""))
                + tuple(
                    " ".join(str(change.get(field) or "") for field in (
                        "source", "entity_type", "identity_key", "summary"
                    ))
                    for change in changes
                )
            ).casefold()
            if any(term in text for term in ("rede", "network", "dns", "adaptador", "ip")):
                selected.append(("RULE_NETWORK_CHANGE", "NETWORK_CHANGE_REVIEW", "O grupo persistido contém evidência relacionada à rede."))
        elif source_type == "TIMELINE_EVENT":
            event = self.get_event(source_id) or {}
            text = " ".join((str(event.get("source") or ""), str(event.get("summary") or ""))).casefold()
            if any(term in text for term in ("rede", "network", "dns", "adaptador", " ip ")):
                selected.append(("RULE_NETWORK_TIMELINE", "NETWORK_CHANGE_REVIEW", "O evento Timeline possui referência textual de rede."))
        elif source_type == "INVESTIGATION_SESSION":
            session = self.get_session(source_id) or {}
            text = " ".join((str(session.get("title") or ""), str(session.get("summary") or ""))).casefold()
            if any(term in text for term in ("rede", "network", "dns", "adaptador", " ip ")):
                selected.append(("RULE_NETWORK_INVESTIGATION", "NETWORK_CHANGE_REVIEW", "A sessão investigativa selecionada contém contexto de rede."))
        elif source_type == "MONITORING_SETTINGS":
            selected.append((
                "RULE_MONITORING_SETTINGS_REVIEW",
                "MONITORING_SETTINGS_REVIEW",
                "O técnico abriu a configuração local de monitoramento para revisão controlada.",
            ))

        result = []
        for rule_id, playbook_id, rationale in selected:
            playbook = self.playbook(playbook_id)
            result.append({
                "recommendation_id": f"{rule_id}:{context['context_id']}",
                "rule_id": rule_id, "title": playbook.title,
                "rationale": rationale,
                "evidence_refs": list(context.get("evidence_refs") or []),
                "limitations": list(context.get("limitations") or []),
                "confidence": "Baseada em regra explícita e evidência local disponível",
                "operational_priority": "REVIEW",
                "playbook_id": playbook_id, "playbook_version": playbook.version,
            })
        return result

    def start_session(self, context_id, playbook_id, *, created_by=None,
                      investigation_session_id=None):
        from licensing.runtime import require_feature
        require_feature("assist.playbooks")
        context = self.get_context(context_id)
        if context is None:
            raise ValueError("Contexto do Assist inexistente.")
        playbook = self.playbook(playbook_id)
        if context["source_type"] not in playbook.applicable_contexts:
            raise ValueError("Playbook não é aplicável ao contexto selecionado.")
        if not investigation_session_id and context["source_type"] == "INVESTIGATION_SESSION":
            investigation_session_id = context.get("source_id")
        connection = self._connect()
        now = _utc_text()
        try:
            existing = connection.execute("""
                SELECT session_id FROM playbook_sessions
                WHERE context_id=? AND playbook_id=? AND status='OPEN'
                ORDER BY started_at_utc DESC LIMIT 1
            """, (context_id, playbook_id)).fetchone()
            if existing:
                return self.get_session_details(existing[0])
            session_id = uuid.uuid4().hex
            record = {
                "session_id": session_id, "playbook_id": playbook.playbook_id,
                "playbook_version": playbook.version, "context_id": context_id,
                "hostname": context["hostname"], "source_context_type": context["source_type"],
                "source_context_id": context.get("source_id"), "status": "OPEN",
                "started_at_utc": now, "completed_at_utc": None,
                "created_by": _clean_text(created_by or local_technical_identity(), 100, required=True),
                "definition_json": json.dumps(asdict(playbook), ensure_ascii=False, separators=(",", ":")),
                "investigation_session_id": _clean_text(investigation_session_id, 64) or None,
                "created_at_utc": now, "updated_at_utc": now,
            }
            with connection:
                connection.execute("""
                    INSERT INTO playbook_sessions (
                        session_id,playbook_id,playbook_version,context_id,hostname,
                        source_context_type,source_context_id,status,started_at_utc,
                        completed_at_utc,created_by,definition_json,investigation_session_id,
                        created_at_utc,updated_at_utc
                    ) VALUES (
                        :session_id,:playbook_id,:playbook_version,:context_id,:hostname,
                        :source_context_type,:source_context_id,:status,:started_at_utc,
                        :completed_at_utc,:created_by,:definition_json,:investigation_session_id,
                        :created_at_utc,:updated_at_utc
                    )
                """, record)
                for step in playbook.steps:
                    connection.execute("""
                        INSERT INTO playbook_session_steps (
                            session_id,step_id,status,completed_at_utc,note,evidence_ref_json,updated_at_utc
                        ) VALUES (?,?,'PENDING',NULL,NULL,NULL,?)
                    """, (session_id, step.step_id, now))
        finally:
            connection.close()
        self._record_playbook_lifecycle(record, "STARTED", "Playbook seguro iniciado")
        return self.get_session_details(session_id)

    def get_session_details(self, session_id):
        session_id = _clean_text(session_id, 64, required=True)
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM playbook_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            steps = [dict(item) for item in connection.execute(
                "SELECT * FROM playbook_session_steps WHERE session_id=? ORDER BY rowid", (session_id,)
            ).fetchall()]
        finally:
            connection.close()
        definition = _loads(result.get("definition_json"), {})
        definitions = {item.get("step_id"): item for item in definition.get("steps") or []}
        for step in steps:
            step["definition"] = definitions.get(step["step_id"], {})
            step["evidence_ref"] = _loads(step.pop("evidence_ref_json"), {})
        result["definition"] = definition
        result["steps"] = steps
        return result

    def update_step(self, session_id, step_id, status, *, note=None, evidence_ref=None):
        status = str(status or "").strip().upper()
        if status not in STEP_STATUSES:
            raise ValueError("Status de etapa inválido.")
        session = self.get_session_details(session_id)
        if session is None or session["status"] != "OPEN":
            raise ValueError("Sessão aberta do playbook não encontrada.")
        step = next((item for item in session["steps"] if item["step_id"] == step_id), None)
        if step is None:
            raise ValueError("Etapa inexistente no snapshot versionado do playbook.")
        if status == "SKIPPED" and step["definition"].get("required"):
            raise ValueError("Etapa obrigatória não pode ser ignorada.")
        safe_ref = None
        if evidence_ref:
            safe_ref = _refs(evidence_ref)
            safe_ref = safe_ref[0] if safe_ref else None
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE playbook_session_steps
                    SET status=?,completed_at_utc=?,note=?,evidence_ref_json=?,updated_at_utc=?
                    WHERE session_id=? AND step_id=?
                """, (
                    status, now if status in ("DONE", "SKIPPED") else None,
                    sanitize_note(note), json.dumps(safe_ref, ensure_ascii=False) if safe_ref else None,
                    now, session_id, step_id,
                ))
                connection.execute("UPDATE playbook_sessions SET updated_at_utc=? WHERE session_id=?", (now, session_id))
        finally:
            connection.close()
        return self.get_session_details(session_id)

    def complete_session(self, session_id):
        session = self.get_session_details(session_id)
        if session is None or session["status"] != "OPEN":
            raise ValueError("Sessão aberta do playbook não encontrada.")
        pending_required = [
            item for item in session["steps"]
            if item["definition"].get("required") and item["status"] != "DONE"
        ]
        if pending_required:
            raise ValueError("Conclua todas as etapas obrigatórias antes de finalizar.")
        return self._close_session(session, "COMPLETED")

    def abort_session(self, session_id):
        session = self.get_session_details(session_id)
        if session is None or session["status"] != "OPEN":
            raise ValueError("Sessão aberta do playbook não encontrada.")
        return self._close_session(session, "ABORTED")

    def _close_session(self, session, status):
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE playbook_sessions SET status=?,completed_at_utc=?,updated_at_utc=?
                    WHERE session_id=?
                """, (status, now, now, session["session_id"]))
        finally:
            connection.close()
        updated = self.get_session_details(session["session_id"])
        self._record_playbook_lifecycle(
            updated, "COMPLETED" if status == "COMPLETED" else "CANCELLED",
            "Playbook seguro concluído" if status == "COMPLETED" else "Playbook seguro abortado",
        )
        return updated

    def reopen_session(self, session_id):
        session = self.get_session_details(session_id)
        if session is None or session["status"] == "OPEN":
            raise ValueError("Sessão encerrada do playbook não encontrada.")
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE playbook_sessions SET status='OPEN',completed_at_utc=NULL,updated_at_utc=?
                    WHERE session_id=?
                """, (now, session_id))
        finally:
            connection.close()
        updated = self.get_session_details(session_id)
        self._record_playbook_lifecycle(updated, "STARTED", "Playbook seguro reaberto", outcome="reopened")
        return updated

    def list_playbook_sessions(self, *, status=None, context_id=None, limit=50, offset=0):
        limit, offset = max(1, min(int(limit), MAX_QUERY_LIMIT)), max(0, int(offset))
        clauses, params = [], {"limit": limit, "offset": offset}
        if status:
            status = str(status).strip().upper()
            if status not in SESSION_STATUSES:
                raise ValueError("Status de sessão inválido.")
            clauses.append("status=:status")
            params["status"] = status
        if context_id:
            clauses.append("context_id=:context_id")
            params["context_id"] = _clean_text(context_id, 64, required=True)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT session_id FROM playbook_sessions" + where
                + " ORDER BY updated_at_utc DESC, session_id DESC LIMIT :limit OFFSET :offset", params,
            ).fetchall()
        finally:
            connection.close()
        return [self.get_session_details(row[0]) for row in rows]

    def _record_playbook_lifecycle(self, session, status, summary, *, outcome=None):
        if session.get("source_context_type") == "MONITORING_SETTINGS":
            return None
        return record_event_safe(
            self, logger=self.logger, source="Assistente Técnico", category="OPERATION",
            severity="INFO", status=status, summary=summary,
            details={
                "playbook_id": session.get("playbook_id"),
                "playbook_version": session.get("playbook_version"),
                "playbook_session_id": session.get("session_id"),
                "source_context_type": session.get("source_context_type"),
                "source_context_id": session.get("source_context_id"),
                "outcome": outcome or session.get("status"),
            },
            operation_id=session.get("session_id"),
            correlation_id=session.get("investigation_session_id"),
            hostname=session.get("hostname"),
        )

    @staticmethod
    def action_registry():
        return ACTION_REGISTRY

    @staticmethod
    def action_definition(action_id):
        try:
            return ACTION_BY_ID[_clean_text(action_id, 80, required=True)]
        except KeyError as exc:
            raise ValueError("Ação inexistente no Action Registry allowlisted.") from exc

    def action_catalog(self, *, posture_service=None, monitoring_service=None,
                       hostname=None):
        """Catálogo consultável derivado do registry e da matriz central."""
        runtime = {
            "posture_service": posture_service,
            "monitoring_service": monitoring_service,
        }
        hostname = _clean_text(hostname or socket.gethostname(), 255) or "Não disponível"
        catalog = []
        for action in ACTION_REGISTRY:
            checks = self._action_preconditions(action, runtime, hostname)
            failed = [item for item in checks if not item.get("ok")]
            if not failed:
                availability = "AVAILABLE"
                reason = "Pré-condições e capacidades locais disponíveis."
            elif any(item.get("kind") == "CAPABILITY" for item in failed):
                availability = "UNAVAILABLE_CAPABILITY"
                reason = " • ".join(item.get("reason") or item.get("name") for item in failed)
            else:
                availability = "UNAVAILABLE_PRECONDITION"
                reason = " • ".join(item.get("reason") or item.get("name") for item in failed)
            catalog.append({
                "action_id": action.action_id,
                "version": action.version,
                "title": action.title,
                "description": action.description,
                "action_kind": (
                    "READ_ONLY" if action.side_effect_class == "READ_ONLY" else "REVERSIBLE"
                ),
                "side_effect_class": action.side_effect_class,
                "risk_level": action.risk_level,
                "requires_uac": action.requires_elevation,
                "supports_dry_run": action.supports_dry_run,
                "rollback_mode": action.rollback_mode,
                "rollback_availability": (
                    "NOT_APPLICABLE" if action.rollback_mode == "NOT_REQUIRED"
                    else ("AVAILABLE" if action.rollback_ref in _ACTION_ROLLBACK_ALLOWLIST
                          else "UNAVAILABLE_CAPABILITY")
                ),
                "parameter_schema": action.parameter_schema,
                "preconditions": checks,
                "availability_state": availability,
                "availability_reason": reason,
            })
        return catalog

    @staticmethod
    def _action_parameters(definition, parameters):
        values = parameters if isinstance(parameters, dict) else {}
        serialized = json.dumps(values, ensure_ascii=False, sort_keys=True)
        if _SENSITIVE_NOTE.search(serialized):
            raise ValueError("Parâmetros não devem conter senha, token, credencial ou segredo.")
        schema = definition.parameter_schema or {}
        if not schema:
            if values:
                raise ValueError("Ação read-only não aceita parâmetros livres.")
            return {}
        if set(values) != set(schema):
            raise ValueError("Parâmetros ausentes ou não declarados no schema allowlisted.")
        sanitized = {}
        for name, rule in schema.items():
            value = values[name]
            if rule.get("type") == "integer":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"Parâmetro {name} deve ser inteiro tipado.")
                allowed = tuple(int(item) for item in rule.get("enum") or ())
                if value not in allowed:
                    raise ValueError(f"Parâmetro {name} fora da allowlist.")
                sanitized[name] = int(value)
            else:
                raise ValueError("Tipo de parâmetro não autorizado nesta fase.")
        return sanitized

    @staticmethod
    def _service_busy(service, lock_name):
        lock = getattr(service, lock_name, None)
        return bool(lock and callable(getattr(lock, "locked", None)) and lock.locked())

    def _action_preconditions(self, definition, runtime, hostname):
        checks = []
        service = None
        if definition.action_id == "REFRESH_ENDPOINT_POSTURE":
            service = runtime.get("posture_service")
            checks = [
                {"name": "Persistência local disponível", "ok": self.path.exists(), "reason": "timeline.db disponível"},
                {"name": "Coletor de postura disponível", "ok": callable(getattr(service, "collect_once", None)), "reason": "callable interna aprovada"},
                {"name": "Nenhuma coleta de postura concorrente", "ok": not self._service_busy(service, "_lock"), "reason": "lock do coletor livre"},
            ]
        elif definition.action_id == "COLLECT_MONITORING_SAMPLE_NOW":
            service = runtime.get("monitoring_service")
            checks = [
                {"name": "Persistência local disponível", "ok": self.path.exists(), "reason": "timeline.db disponível"},
                {"name": "MonitoringService utilizável", "ok": callable(getattr(service, "collect_once", None)), "reason": "callable interna aprovada"},
                {"name": "Nenhuma coleta imediata concorrente", "ok": not self._service_busy(service, "_collect_lock"), "reason": "lock do coletor livre"},
            ]
        elif definition.action_id == "SET_MONITORING_INTERVAL":
            service = runtime.get("monitoring_service")
            configuration_ok = False
            reason = "configuração indisponível"
            try:
                config = self.get_monitoring_configuration()
                configuration_ok = int(config["interval_seconds"]) == int(
                    getattr(service, "interval_seconds", -1)
                )
                reason = "persistência e runtime alinhados" if configuration_ok else "persistência/runtime divergentes"
            except Exception:
                pass
            checks = [
                {"name": "Persistência local disponível", "ok": self.path.exists(), "reason": "timeline.db disponível"},
                {"name": "MonitoringService disponível", "ok": callable(getattr(service, "set_interval", None)), "reason": "API interna tipada"},
                {"name": "Nenhuma coleta imediata concorrente", "ok": not self._service_busy(service, "_collect_lock"), "reason": "lock do coletor livre"},
                {"name": "Intervalo atual comprovado", "ok": configuration_ok, "reason": reason},
            ]
        elif definition.action_id == "SET_MONITORING_RETENTION_POLICY":
            service = runtime.get("monitoring_service")
            configuration_ok = False
            reason = "política de retenção indisponível"
            try:
                config = self.get_monitoring_configuration()
                configuration_ok = int(config["retention_days"]) == int(
                    getattr(service, "retention_days", -1)
                )
                reason = (
                    "persistência e runtime alinhados" if configuration_ok
                    else "persistência/runtime divergentes"
                )
            except Exception:
                pass
            checks = [
                {"name": "Persistência local disponível", "ok": self.path.exists(), "reason": "timeline.db disponível"},
                {"name": "MonitoringService disponível", "ok": callable(getattr(service, "set_retention_days", None)), "reason": "API interna tipada"},
                {"name": "Nenhuma coleta imediata concorrente", "ok": not self._service_busy(service, "_collect_lock"), "reason": "lock do coletor livre"},
                {"name": "Retenção atual comprovada", "ok": configuration_ok, "reason": reason},
            ]
        else:
            checks = [{"name": "Ação allowlisted", "ok": False, "reason": "action_id não autorizado"}]
        for item in checks:
            item["hostname"] = hostname
            item["kind"] = (
                "CAPABILITY" if "disponível" in item.get("name", "").lower()
                and not item.get("ok") else "PRECONDITION"
            )
        return checks

    def _before_evidence(self, action_id, hostname):
        if action_id == "REFRESH_ENDPOINT_POSTURE":
            snapshot = self.get_latest_snapshot(hostname=hostname)
            run_id = ((snapshot or {}).get("run") or {}).get("run_id")
            return {"type": "ENDPOINT_POSTURE_RUN", "id": run_id} if run_id else None
        observations = self.list_observations(hostname=hostname, limit=1)
        observation_id = (observations[0] if observations else {}).get("observation_id")
        return {"type": "MONITORING_OBSERVATION", "id": observation_id} if observation_id else None

    @staticmethod
    def _resource_key(action):
        if action.action_id == "SET_MONITORING_INTERVAL":
            return "LOCAL:MONITORING:INTERVAL"
        if action.action_id == "SET_MONITORING_RETENTION_POLICY":
            return "LOCAL:MONITORING:RETENTION_POLICY"
        return None

    def _add_action_event(self, action_run_id, event_type, summary, evidence_ref=None):
        event_type = str(event_type or "").strip().upper()
        if event_type not in ACTION_EVENT_TYPES:
            raise ValueError("Tipo de evento de ação inválido.")
        event = {
            "event_id": uuid.uuid4().hex,
            "action_run_id": _clean_text(action_run_id, 64, required=True),
            "event_type": event_type,
            "occurred_at": _utc_text(),
            "summary": _clean_text(summary, 400, required=True),
            "evidence_ref": json.dumps(evidence_ref, ensure_ascii=False, separators=(",", ":")) if evidence_ref else None,
        }
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO action_run_events (
                        event_id,action_run_id,event_type,occurred_at,summary,evidence_ref
                    ) VALUES (:event_id,:action_run_id,:event_type,:occurred_at,:summary,:evidence_ref)
                """, event)
        finally:
            connection.close()
        return event

    def get_action_run(self, action_run_id):
        action_run_id = _clean_text(action_run_id, 64, required=True)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM action_runs WHERE action_run_id=?", (action_run_id,)
            ).fetchone()
            if row is None:
                return None
            events = [dict(item) for item in connection.execute(
                "SELECT * FROM action_run_events WHERE action_run_id=? "
                "ORDER BY occurred_at,event_id", (action_run_id,)
            ).fetchall()]
        finally:
            connection.close()
        result = dict(row)
        for key, default in (
            ("parameters_json", {}), ("preconditions_json", []), ("dry_run_json", {}),
            ("before_evidence_ref", {}), ("after_evidence_ref", {}),
            ("before_json", {}), ("proposed_after_json", {}), ("actual_after_json", {}),
            ("rollback_target_json", {}), ("executor_outcome_json", {}),
            ("validator_outcome_json", {}), ("rollback_outcome_json", {}),
        ):
            result[key.removesuffix("_json")] = _loads(result.pop(key), default)
        for event in events:
            event["evidence_ref"] = _loads(event.get("evidence_ref"), {})
        result["events"] = events
        result["definition"] = asdict(self.action_definition(result["action_id"]))
        result["proof_of_work"] = {
            "before": result.get("before") or result.get("before_evidence_ref") or None,
            "planned_change": result.get("proposed_after") or None,
            "action": {
                "action_id": result["action_id"], "version": result["action_version"],
                "requested_by": result["requested_by"], "started_at": result.get("started_at"),
                "parameters": result.get("parameters") or {},
                "preconditions": result.get("preconditions") or [],
                "dry_run": result.get("dry_run") or {},
            },
            "after": result.get("actual_after") or result.get("after_evidence_ref") or None,
            "validation": result.get("validator_outcome") or {
                "summary": result.get("validator_summary")
            },
            "rollback": {
                "status": result.get("rollback_status") or (
                    "NOT_REQUIRED" if result["definition"].get("side_effect_class") == "READ_ONLY"
                    else "NOT_USED"
                ),
                "target": result.get("rollback_target") or None,
                "outcome": result.get("rollback_outcome") or None,
            },
            "result": {
                "status": result.get("status"), "result": result.get("result"),
                "validator_summary": result.get("validator_summary"),
                "error_code": result.get("error_code"),
                "error_summary": result.get("error_summary"),
                "limitations": result["definition"].get("limitations") or [],
            },
        }
        return result

    def list_action_runs(self, *, session_id=None, action_id=None, status=None, limit=50, offset=0):
        limit, offset = max(1, min(int(limit), MAX_QUERY_LIMIT)), max(0, int(offset))
        clauses, params = [], {"limit": limit, "offset": offset}
        if session_id:
            clauses.append("source_playbook_session_id=:session_id")
            params["session_id"] = _clean_text(session_id, 64, required=True)
        if action_id:
            clauses.append("action_id=:action_id")
            params["action_id"] = self.action_definition(action_id).action_id
        if status:
            status = str(status).strip().upper()
            if status not in ACTION_STATUSES:
                raise ValueError("Status de ActionRun inválido.")
            clauses.append("status=:status")
            params["status"] = status
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT action_run_id FROM action_runs" + where
                + " ORDER BY created_at DESC,action_run_id DESC LIMIT :limit OFFSET :offset", params,
            ).fetchall()
        finally:
            connection.close()
        return [self.get_action_run(row[0]) for row in rows]

    def plan_action(self, session_id, step_id, *, requested_by=None, parameters=None):
        session = self.get_session_details(session_id)
        if session is None or session["status"] != "OPEN":
            raise ValueError("Sessão aberta do playbook não encontrada.")
        step = next((item for item in session["steps"] if item["step_id"] == step_id), None)
        definition = (step or {}).get("definition") or {}
        if definition.get("step_type") != "EXISTING_SAFE_ACTION":
            raise ValueError("A etapa selecionada não é uma ação guiada.")
        action = self.action_definition(definition.get("action_ref"))
        parameters = self._action_parameters(action, parameters)
        connection = self._connect()
        try:
            resource_key = self._resource_key(action)
            overlap = connection.execute("""
                SELECT action_run_id FROM action_runs
                WHERE ((resource_key IS NOT NULL AND resource_key=?)
                       OR (resource_key IS NULL AND action_id=? AND hostname=?))
                  AND status IN ('PLANNED','READY','RUNNING','VALIDATING',
                                 'ROLLBACK_READY','ROLLING_BACK','RECOVERY_REQUIRED')
                LIMIT 1
            """, (resource_key, action.action_id, session["hostname"])).fetchone()
            if overlap:
                raise ValueError("Já existe uma execução equivalente em andamento.")
            now = _utc_text()
            record = {
                "action_run_id": uuid.uuid4().hex, "action_id": action.action_id,
                "action_version": action.version, "hostname": session["hostname"],
                "source_playbook_session_id": session["session_id"],
                "source_step_id": step["step_id"],
                "source_context_type": session["source_context_type"],
                "source_context_id": session.get("source_context_id"),
                "status": "PLANNED",
                "requested_by": _clean_text(requested_by or local_technical_identity(), 100, required=True),
                "created_at": now, "started_at": None, "completed_at": None,
                "result": None, "error_code": None, "error_summary": None,
                "before_evidence_ref": None, "after_evidence_ref": None,
                "validator_summary": None,
                "parameters_json": json.dumps(parameters, ensure_ascii=False, separators=(",", ":")),
                "preconditions_json": "[]", "dry_run_json": None,
                "confirmed_at": None, "accepted_at": None,
                "before_json": None, "proposed_after_json": None,
                "actual_after_json": None, "rollback_target_json": None,
                "executor_outcome_json": None, "validator_outcome_json": None,
                "rollback_outcome_json": None, "rollback_status": None,
                "rollback_started_at": None, "rollback_completed_at": None,
                "recovery_marked_at": None, "resource_key": resource_key,
            }
            with connection:
                connection.execute("""
                    INSERT INTO action_runs (
                        action_run_id,action_id,action_version,hostname,
                        source_playbook_session_id,source_step_id,source_context_type,
                        source_context_id,status,requested_by,created_at,started_at,
                        completed_at,result,error_code,error_summary,before_evidence_ref,
                        after_evidence_ref,validator_summary,parameters_json,
                        preconditions_json,dry_run_json,confirmed_at,accepted_at,
                        before_json,proposed_after_json,actual_after_json,
                        rollback_target_json,executor_outcome_json,
                        validator_outcome_json,rollback_outcome_json,rollback_status,
                        rollback_started_at,rollback_completed_at,recovery_marked_at,
                        resource_key
                    ) VALUES (
                        :action_run_id,:action_id,:action_version,:hostname,
                        :source_playbook_session_id,:source_step_id,:source_context_type,
                        :source_context_id,:status,:requested_by,:created_at,:started_at,
                        :completed_at,:result,:error_code,:error_summary,:before_evidence_ref,
                        :after_evidence_ref,:validator_summary,:parameters_json,
                        :preconditions_json,:dry_run_json,:confirmed_at,:accepted_at,
                        :before_json,:proposed_after_json,:actual_after_json,
                        :rollback_target_json,:executor_outcome_json,
                        :validator_outcome_json,:rollback_outcome_json,:rollback_status,
                        :rollback_started_at,:rollback_completed_at,:recovery_marked_at,
                        :resource_key
                    )
                """, record)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Já existe uma transação equivalente em andamento.") from exc
        finally:
            connection.close()
        self._add_action_event(record["action_run_id"], "PLANNED", "Ação guiada planejada pelo técnico.")
        return self.get_action_run(record["action_run_id"])

    def dry_run_action(self, action_run_id, *, posture_service=None, monitoring_service=None):
        action_run = self.get_action_run(action_run_id)
        if action_run is None or action_run["status"] != "PLANNED":
            raise ValueError("ActionRun planejado não encontrado.")
        action = self.action_definition(action_run["action_id"])
        runtime = {"posture_service": posture_service, "monitoring_service": monitoring_service}
        preconditions = self._action_preconditions(action, runtime, action_run["hostname"])
        before_payload, proposed_after, rollback_target = None, None, None
        before_reference = self._before_evidence(action.action_id, action_run["hostname"])
        if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE" and all(
            item.get("ok") for item in preconditions
        ):
            try:
                before_payload = _ACTION_SNAPSHOTTER_ALLOWLIST[action.snapshotter_ref](
                    self, runtime, action_run
                )
                spec = _TRANSACTION_SPECS[action.action_id]
                target = int(action_run["parameters"][spec["parameter_key"]])
                proposed_after = {
                    spec["proposed_key"]: target,
                    "effect": spec["effect"],
                    "windows_configuration_changed": False,
                    "purge_executed": False,
                }
                rollback_target = {
                    spec["proposed_key"]: int(before_payload[spec["before_key"]]),
                    "mode": "AUTOMATIC_DETERMINISTIC_LOCAL",
                }
                before_reference = {
                    "type": "ACTION_SNAPSHOT", "id": f"{action_run_id}:before"
                }
                preconditions.append({
                    "name": "Valor proposto diferente do atual",
                    "ok": target != int(before_payload[spec["before_key"]]),
                    "reason": (
                        "mudança efetiva" if target != int(before_payload[spec["before_key"]])
                        else "o valor proposto já está em uso"
                    ),
                    "hostname": action_run["hostname"],
                    "kind": "PRECONDITION",
                })
            except Exception as exc:
                preconditions.append({
                    "name": "Snapshot Before disponível", "ok": False,
                    "reason": f"falha controlada: {type(exc).__name__}",
                    "hostname": action_run["hostname"],
                })
        ready = all(item.get("ok") for item in preconditions)
        dry_run = {
            "action_id": action.action_id, "version": action.version,
            "description": action.description, "expected_effect": action.expected_effect,
            "side_effect_class": action.side_effect_class,
            "risk_level": action.risk_level, "requires_uac": action.requires_elevation,
            "rollback_mode": action.rollback_mode, "preconditions": preconditions,
            "collected_data": list(action.collected_data),
            "expected_persistence": list(action.expected_persistence),
            "limitations": list(action.limitations), "executed": False,
            "current_state": before_payload,
            "proposed_after": proposed_after,
            "rollback_target": rollback_target,
            "parameters": action_run.get("parameters") or {},
        }
        status = "READY" if ready else "PRECHECK_FAILED"
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE action_runs SET status=?,preconditions_json=?,dry_run_json=?,
                        before_evidence_ref=?,before_json=?,proposed_after_json=?,
                        rollback_target_json=?,rollback_status=?,completed_at=?,
                        error_code=?,error_summary=?
                    WHERE action_run_id=?
                """, (
                    status, json.dumps(preconditions, ensure_ascii=False, separators=(",", ":")),
                    json.dumps(dry_run, ensure_ascii=False, separators=(",", ":")),
                    json.dumps(before_reference, ensure_ascii=False, separators=(",", ":")) if before_reference else None,
                    json.dumps(before_payload, ensure_ascii=False, separators=(",", ":")) if before_payload else None,
                    json.dumps(proposed_after, ensure_ascii=False, separators=(",", ":")) if proposed_after else None,
                    json.dumps(rollback_target, ensure_ascii=False, separators=(",", ":")) if rollback_target else None,
                    ("NOT_USED" if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE" else "NOT_REQUIRED"),
                    None if ready else now, None if ready else "PRECONDITION_FAILED",
                    None if ready else "Uma ou mais pré-condições não foram atendidas.", action_run_id,
                ))
        finally:
            connection.close()
        if ready:
            self._add_action_event(
                action_run_id, "DRY_RUN_COMPLETED",
                "Dry-run concluído sem alterar configuração ou executar coleta.",
                before_reference,
            )
        else:
            self._add_action_event(action_run_id, "PRECHECK_FAILED", "Pré-condição não atendida; executor não chamado.")
        return self.get_action_run(action_run_id)

    def prepare_action(self, session_id, step_id, *, posture_service=None,
                       monitoring_service=None, requested_by=None, parameters=None):
        planned = self.plan_action(
            session_id, step_id, requested_by=requested_by, parameters=parameters
        )
        return self.dry_run_action(
            planned["action_run_id"], posture_service=posture_service,
            monitoring_service=monitoring_service,
        )

    def confirm_action(self, action_run_id):
        action_run = self.get_action_run(action_run_id)
        if action_run is None or action_run["status"] != "READY" or not action_run.get("dry_run"):
            raise ValueError("Ação precisa de dry-run válido antes da confirmação.")
        if action_run.get("confirmed_at"):
            return action_run
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE action_runs SET confirmed_at=? WHERE action_run_id=?", (now, action_run_id)
                )
        finally:
            connection.close()
        self._add_action_event(action_run_id, "CONFIRMED", "Execução confirmada explicitamente pelo técnico.")
        return self.get_action_run(action_run_id)

    def _update_action_outcome(self, action_run_id, *, status, result, after=None,
                               validator_summary=None, error_code=None, error_summary=None):
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE action_runs SET status=?,result=?,completed_at=?,
                        after_evidence_ref=?,validator_summary=?,error_code=?,error_summary=?
                    WHERE action_run_id=?
                """, (
                    status, result, now,
                    json.dumps(after, ensure_ascii=False, separators=(",", ":")) if after else None,
                    _clean_text(validator_summary, 600) or None,
                    _clean_text(error_code, 100) or None,
                    _clean_text(error_summary, 500) or None, action_run_id,
                ))
        finally:
            connection.close()

    def _update_transaction_evidence(self, action_run_id, *, executor_outcome=None,
                                     validator_outcome=None, actual_after=None):
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE action_runs SET executor_outcome_json=COALESCE(?,executor_outcome_json),
                        validator_outcome_json=COALESCE(?,validator_outcome_json),
                        actual_after_json=COALESCE(?,actual_after_json)
                    WHERE action_run_id=?
                """, (
                    json.dumps(executor_outcome, ensure_ascii=False, separators=(",", ":"))
                    if executor_outcome is not None else None,
                    json.dumps(validator_outcome, ensure_ascii=False, separators=(",", ":"))
                    if validator_outcome is not None else None,
                    json.dumps(actual_after, ensure_ascii=False, separators=(",", ":"))
                    if actual_after is not None else None,
                    action_run_id,
                ))
        finally:
            connection.close()

    def execute_action(self, action_run_id, *, posture_service=None,
                       monitoring_service=None, cancel_callback=None):
        action_run = self.get_action_run(action_run_id)
        if action_run is None or action_run["status"] != "READY":
            raise ValueError("ActionRun não está pronto para execução.")
        if not action_run.get("confirmed_at"):
            raise ValueError("Confirmação humana explícita é obrigatória.")
        action = self.action_definition(action_run["action_id"])
        from licensing.runtime import require_feature
        require_feature("guided_actions")
        if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE":
            require_feature("transactional_actions")
        runtime = {"posture_service": posture_service, "monitoring_service": monitoring_service}
        preconditions = self._action_preconditions(action, runtime, action_run["hostname"])
        if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE":
            try:
                spec = _TRANSACTION_SPECS[action.action_id]
                current_value = int(
                    self.get_monitoring_configuration()[spec["proposed_key"]]
                )
                original_value = int(action_run["before"][spec["before_key"]])
                unchanged = current_value == original_value
            except Exception:
                unchanged = False
            preconditions.append({
                "name": "Snapshot Before ainda vigente", "ok": unchanged,
                "reason": "configuração não mudou desde o dry-run" if unchanged else "Before ficou obsoleto",
                "hostname": action_run["hostname"],
            })
        if not all(item.get("ok") for item in preconditions):
            self._update_action_outcome(
                action_run_id, status="FAILED", result="FAILURE",
                error_code="PRECONDITION_CHANGED",
                error_summary="Uma pré-condição mudou após a confirmação.",
            )
            self._add_action_event(action_run_id, "FAILED", "Pré-condição mudou antes da execução.")
            failed = self.get_action_run(action_run_id)
            self._record_action_lifecycle(
                failed, "FAILED", "ACTION_FAILED", "Ação falhou em precondition revalidada"
            )
            return failed
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                active = connection.execute("""
                    SELECT action_run_id FROM action_runs
                    WHERE ((resource_key IS NOT NULL AND resource_key=?)
                           OR (resource_key IS NULL AND action_id=? AND hostname=?))
                      AND status IN ('RUNNING','VALIDATING','ROLLING_BACK')
                      AND action_run_id<>? LIMIT 1
                """, (
                    action_run.get("resource_key"), action.action_id,
                    action_run["hostname"], action_run_id,
                )).fetchone()
                if active:
                    raise ValueError("Já existe uma execução equivalente em andamento.")
                connection.execute(
                    "UPDATE action_runs SET status='RUNNING',started_at=? WHERE action_run_id=?",
                    (now, action_run_id),
                )
        finally:
            connection.close()
        self._add_action_event(action_run_id, "STARTED", "Executor allowlisted iniciado.")
        started = self.get_action_run(action_run_id)
        self._record_action_lifecycle(started, "STARTED", "ACTION_STARTED", "Ação guiada iniciada")
        try:
            execution_result = _ACTION_EXECUTOR_ALLOWLIST[action.executor_ref](
                runtime, cancel_callback=cancel_callback
            ) if action.side_effect_class == "READ_ONLY" else _ACTION_EXECUTOR_ALLOWLIST[
                action.executor_ref
            ](
                self, runtime, started, cancel_callback=cancel_callback
            )
            self._update_transaction_evidence(
                action_run_id, executor_outcome=execution_result
            )
            if isinstance(execution_result, dict) and execution_result.get("cancelled"):
                self._update_action_outcome(
                    action_run_id, status="CANCELLED", result="CANCELLED",
                    validator_summary="Coleta interrompida cooperativamente.",
                )
                self._add_action_event(action_run_id, "CANCELLED", "Execução cancelada cooperativamente.")
                cancelled = self.get_action_run(action_run_id)
                self._record_action_lifecycle(cancelled, "CANCELLED", "ACTION_CANCELLED", "Ação guiada cancelada")
                return cancelled
            connection = self._connect()
            try:
                with connection:
                    connection.execute(
                        "UPDATE action_runs SET status='VALIDATING' WHERE action_run_id=?", (action_run_id,)
                    )
            finally:
                connection.close()
            self._add_action_event(action_run_id, "VALIDATION_STARTED", "Validação pós-ação iniciada.")
            validating = self.get_action_run(action_run_id)
            if action.side_effect_class == "READ_ONLY":
                result, summary, after = _ACTION_VALIDATOR_ALLOWLIST[action.validator_ref](
                    self, validating, execution_result
                )
            else:
                result, summary, after = _ACTION_VALIDATOR_ALLOWLIST[action.validator_ref](
                    self, runtime, validating, execution_result
                )
            if result not in ACTION_RESULTS:
                raise RuntimeError("Validator retornou resultado inválido.")
            self._update_transaction_evidence(
                action_run_id,
                validator_outcome={"result": result, "summary": summary},
                actual_after=after if action.side_effect_class != "READ_ONLY" else None,
            )
            if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE" and result != "SUCCESS":
                self._mark_rollback_ready(
                    action_run_id, summary, error_code="VALIDATION_FAILED",
                    actual_after=after,
                )
                failed = self.get_action_run(action_run_id)
                self._record_action_lifecycle(
                    failed, "FAILED", "ACTION_FAILED", "Mutação falhou na validação"
                )
                return self._perform_rollback(action_run_id, runtime, automatic=True)
            status = "SUCCEEDED" if result in ("SUCCESS", "INDETERMINATE") else "FAILED"
            after_reference = after
            if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE":
                after_reference = {
                    "type": "ACTION_SNAPSHOT", "id": f"{action_run_id}:after"
                }
            self._update_action_outcome(
                action_run_id, status=status, result=result, after=after_reference,
                validator_summary=summary,
                error_code=None if status == "SUCCEEDED" else "VALIDATION_FAILED",
                error_summary=None if status == "SUCCEEDED" else summary,
            )
            completed = self.get_action_run(action_run_id)
            if status == "SUCCEEDED":
                self._add_action_event(action_run_id, "SUCCEEDED", summary, after_reference)
                self._record_action_lifecycle(completed, "COMPLETED", "ACTION_SUCCEEDED", "Ação guiada validada")
                if result == "SUCCESS":
                    try:
                        self.update_step(
                            completed["source_playbook_session_id"], completed["source_step_id"], "DONE",
                            evidence_ref={"type": "ACTION_RUN", "id": action_run_id},
                        )
                    except Exception:
                        if self.logger:
                            try:
                                self.logger.exception(
                                    "A ação foi validada, mas a etapa do playbook não pôde ser atualizada"
                                )
                            except Exception:
                                pass
            else:
                self._add_action_event(action_run_id, "FAILED", summary, after)
                self._record_action_lifecycle(completed, "FAILED", "ACTION_FAILED", "Ação guiada falhou na validação")
            return self.get_action_run(action_run_id)
        except Exception as exc:
            summary = f"Falha controlada no executor/validator: {type(exc).__name__}."
            if action.side_effect_class == "LOCAL_REVERSIBLE_CHANGE":
                try:
                    current = self.get_action_run(action_run_id)
                    spec = _TRANSACTION_SPECS[action.action_id]
                    before_value = int(current["before"][spec["before_key"]])
                    restored, actual = spec["observer"](
                        self, runtime, current, before_value
                    )
                except Exception:
                    restored, actual = False, None
                if not restored:
                    self._mark_rollback_ready(
                        action_run_id, summary, error_code=type(exc).__name__,
                        actual_after=actual,
                    )
                    failed = self.get_action_run(action_run_id)
                    self._record_action_lifecycle(
                        failed, "FAILED", "ACTION_FAILED",
                        "Mutação falhou após alteração parcial",
                    )
                    return self._perform_rollback(action_run_id, runtime, automatic=True)
            self._update_action_outcome(
                action_run_id, status="FAILED", result="FAILURE",
                error_code=type(exc).__name__, error_summary=summary,
            )
            self._add_action_event(action_run_id, "FAILED", summary)
            failed = self.get_action_run(action_run_id)
            self._record_action_lifecycle(failed, "FAILED", "ACTION_FAILED", "Ação guiada falhou")
            return failed

    def _mark_rollback_ready(self, action_run_id, summary, *, error_code=None,
                             actual_after=None):
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE action_runs SET status='ROLLBACK_READY',result='FAILURE',
                        error_code=?,error_summary=?,completed_at=NULL,
                        actual_after_json=COALESCE(?,actual_after_json),
                        rollback_status='READY' WHERE action_run_id=?
                """, (
                    _clean_text(error_code, 100) or "TRANSACTION_FAILED",
                    _clean_text(summary, 500) or "Falha transacional.",
                    json.dumps(actual_after, ensure_ascii=False, separators=(",", ":"))
                    if actual_after is not None else None,
                    action_run_id,
                ))
        finally:
            connection.close()
        self._add_action_event(
            action_run_id, "ROLLBACK_READY",
            "Rollback determinístico preparado após falha da transação.",
        )
        return self.get_action_run(action_run_id)

    def _perform_rollback(self, action_run_id, runtime, *, automatic=False):
        action_run = self.get_action_run(action_run_id)
        if action_run is None or action_run["status"] not in (
            "ROLLBACK_READY", "SUCCEEDED", "RECOVERY_REQUIRED"
        ):
            raise ValueError("ActionRun não está apto a rollback.")
        action = self.action_definition(action_run["action_id"])
        if action.side_effect_class != "LOCAL_REVERSIBLE_CHANGE":
            raise ValueError("Ação read-only não possui rollback mutável.")
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE action_runs SET status='ROLLING_BACK',rollback_status='RUNNING',
                        rollback_started_at=?,completed_at=NULL WHERE action_run_id=?
                """, (now, action_run_id))
        finally:
            connection.close()
        self._add_action_event(
            action_run_id, "ROLLBACK_STARTED",
            "Rollback automático iniciado." if automatic else "Rollback solicitado pelo técnico.",
        )
        rolling = self.get_action_run(action_run_id)
        self._record_action_lifecycle(
            rolling, "STARTED", "ACTION_ROLLBACK_STARTED", "Rollback de ação iniciado"
        )
        try:
            outcome = _ACTION_ROLLBACK_ALLOWLIST[action.rollback_ref](self, runtime, rolling)
            ok, summary, actual = _ACTION_ROLLBACK_VALIDATOR_ALLOWLIST[
                action.rollback_validator_ref
            ](self, runtime, rolling, outcome)
            status = "ROLLED_BACK" if ok else "ROLLBACK_FAILED"
            result = "ROLLED_BACK" if ok else "FAILURE"
            rollback_status = "SUCCEEDED" if ok else "FAILED"
            connection = self._connect()
            try:
                with connection:
                    connection.execute("""
                        UPDATE action_runs SET status=?,result=?,completed_at=?,
                            rollback_completed_at=?,rollback_status=?,
                            rollback_outcome_json=?,actual_after_json=?,
                            validator_summary=?,error_code=?,error_summary=?
                        WHERE action_run_id=?
                    """, (
                        status, result, _utc_text(), _utc_text(), rollback_status,
                        json.dumps({"executor": outcome, "validation": {"ok": ok, "summary": summary}}, ensure_ascii=False, separators=(",", ":")),
                        json.dumps(actual, ensure_ascii=False, separators=(",", ":")),
                        _clean_text(summary, 600), None if ok else "ROLLBACK_VALIDATION_FAILED",
                        None if ok else _clean_text(summary, 500), action_run_id,
                    ))
            finally:
                connection.close()
            completed = self.get_action_run(action_run_id)
            event_type = "ROLLED_BACK" if ok else "ROLLBACK_FAILED"
            self._add_action_event(action_run_id, event_type, summary)
            self._record_action_lifecycle(
                completed, "COMPLETED" if ok else "FAILED",
                "ACTION_ROLLED_BACK" if ok else "ACTION_ROLLBACK_FAILED",
                "Rollback validado" if ok else "Rollback falhou",
            )
            return self.get_action_run(action_run_id)
        except Exception as exc:
            summary = f"Falha controlada no rollback: {type(exc).__name__}."
            connection = self._connect()
            try:
                with connection:
                    connection.execute("""
                        UPDATE action_runs SET status='ROLLBACK_FAILED',result='FAILURE',
                            completed_at=?,rollback_completed_at=?,rollback_status='FAILED',
                            error_code=?,error_summary=? WHERE action_run_id=?
                    """, (_utc_text(), _utc_text(), type(exc).__name__, summary, action_run_id))
            finally:
                connection.close()
            failed = self.get_action_run(action_run_id)
            self._add_action_event(action_run_id, "ROLLBACK_FAILED", summary)
            self._record_action_lifecycle(
                failed, "FAILED", "ACTION_ROLLBACK_FAILED", "Rollback falhou"
            )
            return self.get_action_run(action_run_id)

    def rollback_action(self, action_run_id, *, monitoring_service=None):
        return self._perform_rollback(
            action_run_id, {"monitoring_service": monitoring_service}, automatic=False
        )

    def _mark_abandoned_mutations_for_recovery(self):
        """Converte runs interrompidos em revisão explícita, sem reexecutar."""
        connection = self._connect()
        try:
            rows = connection.execute("""
                SELECT action_run_id,action_id FROM action_runs
                WHERE status IN ('RUNNING','VALIDATING','ROLLING_BACK')
            """).fetchall()
            rows = [row for row in rows if row[1] in _TRANSACTION_SPECS]
            if not rows:
                return []
            now = _utc_text()
            with connection:
                for row in rows:
                    connection.execute("""
                        UPDATE action_runs SET status='RECOVERY_REQUIRED',
                            result='INDETERMINATE',recovery_marked_at=?,
                            rollback_status=CASE
                                WHEN rollback_status='RUNNING' THEN 'READY'
                                ELSE COALESCE(rollback_status,'READY') END,
                            error_code='INTERRUPTED_TRANSACTION',
                            error_summary='Transação interrompida; revisão obrigatória, sem reexecução automática.'
                        WHERE action_run_id=?
                    """, (now, row[0]))
        finally:
            connection.close()
        recovered = []
        for row in rows:
            self._add_action_event(
                row[0], "RECOVERY_REQUIRED",
                "Reinício detectou transação mutável interrompida; nenhuma mutação foi reexecutada.",
            )
            run = self.get_action_run(row[0])
            self._record_action_lifecycle(
                run, "FAILED", "ACTION_RECOVERY_REQUIRED",
                "Transação requer recuperação assistida",
            )
            recovered.append(run)
        return recovered

    def list_recovery_required(self, *, limit=50):
        return self.list_action_runs(status="RECOVERY_REQUIRED", limit=limit)

    def revalidate_recovery(self, action_run_id, *, monitoring_service=None):
        run = self.get_action_run(action_run_id)
        if run is None or run["status"] != "RECOVERY_REQUIRED":
            raise ValueError("ActionRun não requer recuperação.")
        action = self.action_definition(run["action_id"])
        if action.side_effect_class != "LOCAL_REVERSIBLE_CHANGE":
            raise ValueError("Recovery mutável não aplicável à ação read-only.")
        runtime = {"monitoring_service": monitoring_service}
        spec = _TRANSACTION_SPECS[run["action_id"]]
        target = int(run["parameters"][spec["parameter_key"]])
        before = int(run["before"][spec["before_key"]])
        target_ok, actual = spec["observer"](self, runtime, run, target)
        before_ok, before_actual = spec["observer"](self, runtime, run, before)
        if target_ok:
            status, result = "SUCCEEDED", "SUCCESS"
            summary = f"Recovery comprovou o estado After de {target} {spec['unit']}."
            event_kind, timeline_status = "ACTION_SUCCEEDED", "COMPLETED"
        elif before_ok:
            status, result = "ROLLED_BACK", "ROLLED_BACK"
            actual = before_actual
            summary = f"Recovery comprovou o estado Before restaurado em {before} {spec['unit']}."
            event_kind, timeline_status = "ACTION_ROLLED_BACK", "COMPLETED"
        else:
            self._update_transaction_evidence(
                action_run_id,
                validator_outcome={
                    "result": "INDETERMINATE",
                    "summary": "Recovery não comprovou Before nem After.",
                },
                actual_after=actual,
            )
            self._add_action_event(
                action_run_id, "RECOVERY_REVALIDATED",
                "Recovery revalidado; estado permanece indeterminado.",
            )
            return self.get_action_run(action_run_id)
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    UPDATE action_runs SET status=?,result=?,completed_at=?,
                        actual_after_json=?,validator_outcome_json=?,validator_summary=?,
                        rollback_status=CASE WHEN ?='ROLLED_BACK' THEN 'SUCCEEDED'
                            ELSE COALESCE(rollback_status,'NOT_USED') END,
                        error_code=NULL,error_summary=NULL WHERE action_run_id=?
                """, (
                    status, result, _utc_text(),
                    json.dumps(actual, ensure_ascii=False, separators=(",", ":")),
                    json.dumps({"result": result, "summary": summary}, ensure_ascii=False, separators=(",", ":")),
                    summary, status, action_run_id,
                ))
        finally:
            connection.close()
        completed = self.get_action_run(action_run_id)
        self._add_action_event(action_run_id, "RECOVERY_REVALIDATED", summary)
        self._record_action_lifecycle(
            completed, timeline_status, event_kind, "Recovery validado"
        )
        return completed

    def close_recovery_as_failure(self, action_run_id):
        run = self.get_action_run(action_run_id)
        if run is None or run["status"] != "RECOVERY_REQUIRED":
            raise ValueError("ActionRun não requer recuperação.")
        summary = "Recovery encerrado pelo técnico sem evidência suficiente para comprovar Before ou After."
        self._update_action_outcome(
            action_run_id, status="FAILED", result="INDETERMINATE",
            validator_summary=summary, error_code="RECOVERY_CLOSED_INDETERMINATE",
            error_summary=summary,
        )
        self._add_action_event(action_run_id, "FAILED", summary)
        failed = self.get_action_run(action_run_id)
        self._record_action_lifecycle(
            failed, "FAILED", "ACTION_FAILED", "Recovery encerrado como indeterminado"
        )
        return failed

    def cancel_action(self, action_run_id):
        action_run = self.get_action_run(action_run_id)
        if action_run is None or action_run["status"] not in ("PLANNED", "READY"):
            raise ValueError("Somente uma ação ainda não iniciada pode ser cancelada diretamente.")
        self._update_action_outcome(
            action_run_id, status="CANCELLED", result="CANCELLED",
            validator_summary="Cancelada antes de iniciar; nenhum executor foi chamado.",
        )
        self._add_action_event(action_run_id, "CANCELLED", "Ação cancelada antes de iniciar.")
        return self.get_action_run(action_run_id)

    def accept_indeterminate(self, action_run_id):
        action_run = self.get_action_run(action_run_id)
        if action_run is None or action_run["status"] != "SUCCEEDED" or action_run["result"] != "INDETERMINATE":
            raise ValueError("Não há resultado indeterminado validado para aceitar.")
        now = _utc_text()
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE action_runs SET accepted_at=? WHERE action_run_id=?", (now, action_run_id)
                )
        finally:
            connection.close()
        self.update_step(
            action_run["source_playbook_session_id"], action_run["source_step_id"], "DONE",
            evidence_ref={"type": "ACTION_RUN", "id": action_run_id},
        )
        return self.get_action_run(action_run_id)

    def _record_action_lifecycle(self, action_run, timeline_status, event_kind, summary):
        return record_event_safe(
            self, logger=self.logger, source="Assistente Técnico", category="OPERATION",
            severity="ERROR" if timeline_status == "FAILED" else "INFO",
            status=timeline_status, summary=summary, hostname=action_run.get("hostname"),
            operation_id=action_run.get("action_run_id"),
            correlation_id=action_run.get("source_playbook_session_id"),
            details={
                "event_kind": event_kind,
                "action_run_id": action_run.get("action_run_id"),
                "action_id": action_run.get("action_id"),
                "action_version": action_run.get("action_version"),
                "playbook_session_id": action_run.get("source_playbook_session_id"),
                "source_context_type": action_run.get("source_context_type"),
                "source_context_id": action_run.get("source_context_id"),
                "result": action_run.get("result"),
                "before_evidence_ref": action_run.get("before_evidence_ref") or None,
                "after_evidence_ref": action_run.get("after_evidence_ref") or None,
                "rollback_state": action_run.get("rollback_status") or "NOT_AVAILABLE",
            },
        )


def assist_action_safe(store, logger, action, *args, **kwargs):
    try:
        if store is None:
            return None
        return action(store, *args, **kwargs)
    except Exception as exc:
        if logger is not None:
            try:
                logger.error("ASSISTENTE_TECNICO_FALHA | tipo=%s", type(exc).__name__)
            except Exception:
                pass
        return None
