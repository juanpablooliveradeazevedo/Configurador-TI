"""Postura local do endpoint, somente leitura e sem remediação.

Postura observada não é garantia de segurança. Indisponível não significa
desabilitado, mudança não é incidente e correlação não prova causalidade.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import locale
import os
import re
import socket
import subprocess
import threading
import time
import uuid

from audit_timeline import _clean_text, _utc_text, record_event_safe, sanitize_details
from monitoring_intelligence import MonitoringIntelligenceStore


DATABASE_SCHEMA_VERSION = 6
POSTURE_SCHEMA_VERSION = 1
CAPABILITY_STATES = ("AVAILABLE", "LIMITED", "UNAVAILABLE", "INDETERMINATE")
ASSESSMENTS = ("OK", "ATTENTION", "INDETERMINATE", "NOT_APPLICABLE")
CHECK_KEYS = (
    "bitlocker", "tpm", "secure_boot", "antivirus",
    "defender_signature", "firewall",
)
CHECK_TITLES = {
    "bitlocker": "BitLocker",
    "tpm": "TPM",
    "secure_boot": "Secure Boot",
    "antivirus": "Antivírus",
    "defender_signature": "Defender e assinatura",
    "firewall": "Firewall",
}
DEFENDER_SIGNATURE_MAX_AGE_DAYS = 3
PER_CHECK_TIMEOUT_SECONDS = 12.0
GLOBAL_SCAN_TIMEOUT_SECONDS = 45.0
MAX_QUERY_LIMIT = 200
CONTEXT_WINDOW_MINUTES = 10
_SENSITIVE_EVIDENCE_KEY = re.compile(
    r"(?:recovery|password|passwd|senha|token|secret|segredo|credential|credencial|"
    r"authorization|protector|key|chave|command|comando|script|content|conteudo)",
    re.IGNORECASE,
)


class PostureCancelled(RuntimeError):
    pass


class PostureSourceError(RuntimeError):
    def __init__(self, kind="indeterminate"):
        super().__init__(kind)
        self.kind = kind


def _enum(value, allowed, field):
    normalized = str(value or "").strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{field} inválido para postura do endpoint.")
    return normalized


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    text = str(value or "").strip().casefold()
    if text in ("true", "1", "yes", "sim", "on", "enabled", "ativo"):
        return True
    if text in ("false", "0", "no", "não", "nao", "off", "disabled", "inativo"):
        return False
    return None


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sanitize_evidence(value, *, depth=0):
    """Mantém somente evidência técnica limitada e remove material sensível."""
    if depth >= 5:
        return "[limite de profundidade]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else None
    if isinstance(value, str):
        return _clean_text(value, 500)
    if isinstance(value, dict):
        result = {}
        for raw_key, item in list(value.items())[:40]:
            key = _clean_text(raw_key, 60) or "campo"
            if _SENSITIVE_EVIDENCE_KEY.search(key):
                continue
            result[key] = sanitize_evidence(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_evidence(item, depth=depth + 1) for item in list(value)[:30]]
    return _clean_text(type(value).__name__, 80)


def _check(check_key, capability_state, assessment, observed_state, summary,
           source, evidence=None, *, collected_at_utc=None):
    if check_key not in CHECK_KEYS:
        raise ValueError("Check de postura desconhecido.")
    safe_evidence = sanitize_evidence(evidence or {})
    return {
        "check_key": check_key,
        "capability_state": _enum(capability_state, CAPABILITY_STATES, "Capacidade"),
        "assessment": _enum(assessment, ASSESSMENTS, "Avaliação"),
        "observed_state": _clean_text(observed_state, 160, required=True),
        "summary": _clean_text(summary, 300, required=True),
        "source": _clean_text(source, 160, required=True),
        "evidence": safe_evidence,
        "collected_at_utc": _utc_text(collected_at_utc),
    }


def _source_limited(check_key, source, reason="permission"):
    if reason == "unavailable":
        return _check(
            check_key, "UNAVAILABLE", "NOT_APPLICABLE", "SOURCE_UNAVAILABLE",
            "A capacidade ou fonte não está disponível neste endpoint.", source,
            {"limitation": "capability_unavailable"},
        )
    if reason == "permission":
        return _check(
            check_key, "LIMITED", "INDETERMINATE", "LIMITED_WITHOUT_ELEVATION",
            "Informação limitada sem elevação; nenhuma conclusão negativa foi inferida.",
            source, {"limitation": "permission"},
        )
    return _check(
        check_key, "INDETERMINATE", "INDETERMINATE", "SOURCE_INDETERMINATE",
        "Não foi possível determinar o estado sem evidência suficiente.", source,
        {"limitation": "source_error"},
    )


def assess_bitlocker(raw):
    source = "Get-BitLockerVolume — unidade do sistema"
    if raw.get("source_error"):
        return _source_limited("bitlocker", source, raw["source_error"])
    if raw.get("available") is False:
        return _source_limited("bitlocker", source, "unavailable")
    protection = str(raw.get("protection_status") or "").replace(" ", "").casefold()
    volume = str(raw.get("volume_status") or "").replace(" ", "").casefold()
    try:
        percentage = float(raw.get("encryption_percentage"))
    except (TypeError, ValueError):
        percentage = None
    evidence = {
        "protection_status": raw.get("protection_status"),
        "volume_status": raw.get("volume_status"),
        "encryption_method": raw.get("encryption_method"),
        "encryption_percentage": percentage,
    }
    is_on = protection in ("on", "1", "protectionon")
    is_off = protection in ("off", "0", "protectionoff")
    fully_encrypted = volume in ("fullyencrypted", "encrypted") or (
        percentage is not None and percentage >= 99.9
    )
    in_progress = any(term in volume for term in ("progress", "encrypting", "decrypting", "suspend"))
    if is_on and fully_encrypted:
        return _check("bitlocker", "AVAILABLE", "OK", "PROTECTION_ON",
                      "BitLocker: proteção ativa na unidade do sistema.", source, evidence)
    if is_off:
        return _check("bitlocker", "AVAILABLE", "ATTENTION", "PROTECTION_OFF",
                      "BitLocker disponível, mas a proteção observada está desativada.", source, evidence)
    if in_progress or (percentage is not None and percentage < 99.9):
        return _check("bitlocker", "AVAILABLE", "ATTENTION", "TRANSITION_OR_SUSPENDED",
                      "BitLocker apresenta criptografia em andamento, parcial ou suspensa.", source, evidence)
    return _check("bitlocker", "INDETERMINATE", "INDETERMINATE", "STATE_INDETERMINATE",
                  "Não foi possível determinar o estado do BitLocker com segurança.", source, evidence)


def assess_tpm(raw):
    source = "Get-Tpm"
    if raw.get("source_error"):
        return _source_limited("tpm", source, raw["source_error"])
    present = _bool(raw.get("present"))
    ready = _bool(raw.get("ready"))
    evidence = {
        "present": present, "ready": ready,
        "enabled": _bool(raw.get("enabled")),
        "activated": _bool(raw.get("activated")),
        "manufacturer": raw.get("manufacturer"),
        "manufacturer_version": raw.get("manufacturer_version"),
    }
    if present is False:
        return _check("tpm", "UNAVAILABLE", "ATTENTION", "TPM_ABSENT",
                      "TPM não foi identificado neste endpoint; isso não é tratado como falha de coleta.",
                      source, evidence)
    if present is True and ready is True:
        return _check("tpm", "AVAILABLE", "OK", "PRESENT_READY",
                      "TPM presente e pronto.", source, evidence)
    if present is True and ready is False:
        return _check("tpm", "AVAILABLE", "ATTENTION", "PRESENT_NOT_READY",
                      "TPM presente, mas não está pronto no estado observado.", source, evidence)
    return _check("tpm", "INDETERMINATE", "INDETERMINATE", "STATE_INDETERMINATE",
                  "Não foi possível determinar presença e prontidão do TPM.", source, evidence)


def assess_secure_boot(raw):
    source = "Confirm-SecureBootUEFI"
    if raw.get("source_error"):
        return _source_limited("secure_boot", source, raw["source_error"])
    supported = _bool(raw.get("supported"))
    enabled = _bool(raw.get("enabled"))
    evidence = {"supported": supported, "enabled": enabled, "firmware_mode": raw.get("firmware_mode")}
    if supported is False:
        return _check("secure_boot", "UNAVAILABLE", "NOT_APPLICABLE", "LEGACY_OR_UNSUPPORTED",
                      "Secure Boot não está disponível neste modo de firmware.", source, evidence)
    if supported is True and enabled is True:
        return _check("secure_boot", "AVAILABLE", "OK", "SUPPORTED_ENABLED",
                      "Secure Boot disponível e habilitado.", source, evidence)
    if supported is True and enabled is False:
        return _check("secure_boot", "AVAILABLE", "ATTENTION", "SUPPORTED_DISABLED",
                      "Secure Boot disponível, mas desabilitado no estado observado.", source, evidence)
    return _check("secure_boot", "INDETERMINATE", "INDETERMINATE", "STATE_INDETERMINATE",
                  "Não foi possível determinar o estado do Secure Boot.", source, evidence)


def _provider_state(product_state):
    try:
        raw = int(product_state)
    except (TypeError, ValueError):
        return None
    nibble = (raw >> 12) & 0xF
    if nibble == 1:
        return True
    if nibble == 0:
        return False
    return None


def _antivirus_facts(raw):
    defender = raw.get("defender") if isinstance(raw.get("defender"), dict) else {}
    providers = raw.get("providers") if isinstance(raw.get("providers"), list) else []
    normalized = []
    for item in providers[:20]:
        if not isinstance(item, dict):
            continue
        name = _clean_text(item.get("name") or "Produto antivírus", 120)
        active = _provider_state(item.get("product_state"))
        normalized.append({"name": name, "active": active, "product_state": item.get("product_state")})
    defender_enabled = any(_bool(defender.get(key)) is True for key in (
        "antivirus_enabled", "antimalware_enabled", "real_time_enabled"
    ))
    active = [item for item in normalized if item["active"] is True]
    inactive = [item for item in normalized if item["active"] is False]
    unknown = [item for item in normalized if item["active"] is None]
    other_active = [item for item in active if "defender" not in item["name"].casefold()]
    defender_provider = [item for item in normalized if "defender" in item["name"].casefold()]
    return defender, normalized, defender_enabled, active, inactive, unknown, other_active, defender_provider


def assess_antivirus(raw):
    source = "Microsoft Defender + SecurityCenter2"
    if raw.get("source_error"):
        return _source_limited("antivirus", source, raw["source_error"])
    defender, providers, defender_enabled, active, _inactive, unknown, other_active, defender_provider = _antivirus_facts(raw)
    sc_available = _bool(raw.get("security_center_available"))
    defender_source_available = _bool(raw.get("defender_source_available"))
    if sc_available is None and providers:
        sc_available = True
    if defender_source_available is None and defender:
        defender_source_available = True
    evidence = {
        "defender_antivirus_enabled": _bool(defender.get("antivirus_enabled")),
        "defender_antimalware_enabled": _bool(defender.get("antimalware_enabled")),
        "defender_real_time_enabled": _bool(defender.get("real_time_enabled")),
        "providers": providers,
        "security_center_available": sc_available,
        "defender_source_available": defender_source_available,
    }
    defender_conflict = (
        defender_enabled and defender_provider
        and all(item["active"] is False for item in defender_provider)
        and not other_active
    )
    if defender_conflict:
        return _check("antivirus", "LIMITED", "INDETERMINATE", "SOURCES_CONFLICT",
                      "As fontes de antivírus apresentam estados conflitantes.", source, evidence)
    if (defender_source_available is True and defender_enabled) or active:
        if not defender_enabled and other_active:
            return _check("antivirus", "AVAILABLE", "OK", "THIRD_PARTY_ACTIVE",
                          "Defender não é o antivírus ativo; outro provedor foi identificado.", source, evidence)
        return _check("antivirus", "AVAILABLE", "OK", "ACTIVE_PROVIDER_CONFIRMED",
                      "Há proteção antivírus ativa confirmada pelas fontes locais.", source, evidence)
    if sc_available is True and providers and not unknown:
        return _check("antivirus", "AVAILABLE", "ATTENTION", "NO_ACTIVE_PROVIDER_CONFIRMED",
                      "Nenhum provedor antivírus ativo foi confirmado pela fonte local.", source, evidence)
    if sc_available is False or unknown or not providers:
        return _check("antivirus", "LIMITED", "INDETERMINATE", "PROVIDER_STATE_INDETERMINATE",
                      "Não foi possível confirmar o provedor antivírus ativo; Defender desativado não implica ausência de antivírus.",
                      source, evidence)
    return _source_limited("antivirus", source, "indeterminate")


def _parse_datetime(value):
    if isinstance(value, datetime):
        parsed = value
    elif value:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def assess_defender_signature(raw, *, now_utc=None):
    source = "Get-MpComputerStatus"
    if raw.get("source_error"):
        return _source_limited("defender_signature", source, raw["source_error"])
    defender_source_available = _bool(raw.get("defender_source_available"))
    if defender_source_available is None and isinstance(raw.get("defender"), dict):
        defender_source_available = True
    if defender_source_available is False:
        return _source_limited("defender_signature", source, "indeterminate")
    defender, providers, defender_enabled, _active, _inactive, _unknown, other_active, _defender_provider = _antivirus_facts(raw)
    evidence = {
        "signature_version": defender.get("signature_version"),
        "signature_last_updated": defender.get("signature_last_updated"),
        "defender_relevant": defender_enabled,
        "other_active_provider": bool(other_active),
        "threshold_days": DEFENDER_SIGNATURE_MAX_AGE_DAYS,
        "providers": [{"name": item["name"], "active": item["active"]} for item in providers],
    }
    if not defender_enabled and other_active:
        return _check("defender_signature", "AVAILABLE", "NOT_APPLICABLE", "OTHER_PROVIDER_RELEVANT",
                      "A assinatura do Defender não é avaliada porque outro antivírus ativo foi identificado.",
                      source, evidence)
    if not defender_enabled:
        return _check("defender_signature", "LIMITED", "INDETERMINATE", "DEFENDER_RELEVANCE_INDETERMINATE",
                      "A relevância da assinatura do Defender não pôde ser confirmada.", source, evidence)
    updated = _parse_datetime(defender.get("signature_last_updated"))
    if updated is None:
        return _check("defender_signature", "LIMITED", "INDETERMINATE", "SIGNATURE_DATE_INDETERMINATE",
                      "A data confiável da assinatura do Defender não está disponível.", source, evidence)
    now = _parse_datetime(now_utc) or datetime.now(timezone.utc)
    age_days = max(0.0, (now - updated).total_seconds() / 86400.0)
    evidence["signature_age_days"] = round(age_days, 2)
    if age_days > DEFENDER_SIGNATURE_MAX_AGE_DAYS:
        return _check("defender_signature", "AVAILABLE", "ATTENTION", "SIGNATURE_OLD",
                      f"A assinatura observada do Defender tem mais de {DEFENDER_SIGNATURE_MAX_AGE_DAYS} dias.",
                      source, evidence)
    return _check("defender_signature", "AVAILABLE", "OK", "SIGNATURE_RECENT",
                  "A assinatura observada do Defender está dentro do limite declarativo.", source, evidence)


def assess_firewall(raw):
    source = "Get-NetFirewallProfile"
    if raw.get("source_error"):
        return _source_limited("firewall", source, raw["source_error"])
    profiles = raw.get("profiles") if isinstance(raw.get("profiles"), list) else []
    normalized = {}
    for item in profiles:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().title()
        if name in ("Domain", "Private", "Public"):
            normalized[name] = _bool(item.get("enabled"))
    evidence = {"profiles": [{"name": key, "enabled": normalized[key]} for key in sorted(normalized)]}
    if set(normalized) != {"Domain", "Private", "Public"} or any(value is None for value in normalized.values()):
        return _check("firewall", "LIMITED", "INDETERMINATE", "PROFILES_INCOMPLETE",
                      "A fonte de perfis do Firewall retornou informação incompleta.", source, evidence)
    disabled = [name for name, enabled in normalized.items() if enabled is False]
    if disabled:
        return _check("firewall", "AVAILABLE", "ATTENTION", "PROFILE_DISABLED",
                      "Há perfil aplicável do Firewall desabilitado no estado observado.", source, evidence)
    return _check("firewall", "AVAILABLE", "OK", "ALL_PROFILES_ENABLED",
                  "Firewall habilitado nos perfis Domain, Private e Public.", source, evidence)


def _decode_output(raw):
    if not raw:
        return ""
    encodings = ["utf-8-sig"]
    if b"\x00" in raw[:200]:
        encodings.append("utf-16-le")
    encodings.extend([locale.getpreferredencoding(False), "cp850", "latin-1"])
    for encoding in dict.fromkeys(encodings):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def run_powershell_json(script, *, timeout=PER_CHECK_TIMEOUT_SECONDS, cancel_callback=None):
    """Executa somente script interno de leitura, sem shell e sem elevação."""
    executable = "powershell.exe" if os.name == "nt" else "powershell"
    args = [
        executable, "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command",
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();" + script,
    ]
    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, startupinfo=startupinfo, creationflags=creationflags,
        )
    except (FileNotFoundError, OSError) as exc:
        raise PostureSourceError("unavailable") from exc
    started = time.monotonic()
    while process.poll() is None:
        if cancel_callback and cancel_callback():
            process.terminate()
            try:
                process.wait(1)
            except subprocess.TimeoutExpired:
                process.kill()
            raise PostureCancelled("Coleta de postura cancelada.")
        if time.monotonic() - started >= float(timeout):
            process.kill()
            process.wait()
            raise TimeoutError("Tempo limite da fonte de postura excedido.")
        time.sleep(0.05)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        message = _decode_output(stderr).casefold()
        if any(term in message for term in ("access is denied", "acesso negado", "unauthorized", "permiss")):
            raise PostureSourceError("permission")
        if any(term in message for term in ("not recognized", "não é reconhecido", "could not be loaded", "não pôde ser carregado")):
            raise PostureSourceError("unavailable")
        raise PostureSourceError("indeterminate")
    text = _decode_output(stdout).strip()
    if not text:
        raise PostureSourceError("indeterminate")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise PostureSourceError("indeterminate") from exc


BITLOCKER_SCRIPT = r"""
$ErrorActionPreference='Stop'
$v=Get-BitLockerVolume -MountPoint $env:SystemDrive
[pscustomobject]@{
 available=$true; protection_status=[string]$v.ProtectionStatus
 volume_status=[string]$v.VolumeStatus; encryption_method=[string]$v.EncryptionMethod
 encryption_percentage=$v.EncryptionPercentage
}|ConvertTo-Json -Compress
"""
TPM_SCRIPT = r"""
$ErrorActionPreference='Stop';$t=Get-Tpm
[pscustomobject]@{
 present=$t.TpmPresent;ready=$t.TpmReady;enabled=$t.TpmEnabled;activated=$t.TpmActivated
 manufacturer=[string]$t.ManufacturerIdTxt;manufacturer_version=[string]$t.ManufacturerVersion
}|ConvertTo-Json -Compress
"""
SECURE_BOOT_SCRIPT = r"""
$ErrorActionPreference='Stop'
try{$enabled=Confirm-SecureBootUEFI -ErrorAction Stop
 [pscustomobject]@{supported=$true;enabled=[bool]$enabled;firmware_mode='UEFI'}|ConvertTo-Json -Compress
}catch{
 $m=[string]$_.Exception.Message
 if($m -match 'not supported|não.*suport|unsupported'){
  [pscustomobject]@{supported=$false;enabled=$null;firmware_mode='Legacy/unsupported'}|ConvertTo-Json -Compress
 }else{throw}
}
"""
ANTIVIRUS_SCRIPT = r"""
$ErrorActionPreference='Stop'
$d=$null;$defenderSource=$true
try{$d=Get-MpComputerStatus -ErrorAction Stop}catch{$defenderSource=$false}
$providers=@();$securityCenter=$true
try{
 $providers=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{name=[string]$_.displayName;product_state=$_.productState}
 })
}catch{$securityCenter=$false;$providers=@()}
[pscustomobject]@{
 security_center_available=$securityCenter
 defender_source_available=$defenderSource
 defender=[pscustomobject]@{
  antivirus_enabled=$d.AntivirusEnabled;antimalware_enabled=$d.AMServiceEnabled
  real_time_enabled=$d.RealTimeProtectionEnabled
  signature_version=[string]$d.AntivirusSignatureVersion
  signature_last_updated=if($d.AntivirusSignatureLastUpdated){$d.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}else{$null}
 }
 providers=$providers
}|ConvertTo-Json -Compress -Depth 5
"""
FIREWALL_SCRIPT = r"""
$ErrorActionPreference='Stop'
$profiles=@(Get-NetFirewallProfile | ForEach-Object {[pscustomobject]@{name=[string]$_.Name;enabled=[bool]$_.Enabled}})
[pscustomobject]@{profiles=$profiles}|ConvertTo-Json -Compress -Depth 4
"""


class EndpointPostureCollector:
    def __init__(self, runner=None, *, platform_name=None, per_check_timeout=PER_CHECK_TIMEOUT_SECONDS,
                 global_timeout=GLOBAL_SCAN_TIMEOUT_SECONDS):
        self.runner = runner or run_powershell_json
        self.platform_name = platform_name or os.name
        self.per_check_timeout = max(0.1, float(per_check_timeout))
        self.global_timeout = max(self.per_check_timeout, float(global_timeout))

    def _run_source(self, script, *, deadline, cancel_callback):
        if cancel_callback and cancel_callback():
            raise PostureCancelled("Coleta de postura cancelada.")
        if self.platform_name != "nt":
            raise PostureSourceError("indeterminate")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Tempo global da postura excedido.")
        return self.runner(
            script, timeout=min(self.per_check_timeout, remaining),
            cancel_callback=cancel_callback,
        )

    @staticmethod
    def _error_check(check_key, exc):
        source = {
            "bitlocker": "Get-BitLockerVolume — unidade do sistema",
            "tpm": "Get-Tpm", "secure_boot": "Confirm-SecureBootUEFI",
            "antivirus": "Microsoft Defender + SecurityCenter2",
            "defender_signature": "Get-MpComputerStatus",
            "firewall": "Get-NetFirewallProfile",
        }[check_key]
        reason = exc.kind if isinstance(exc, PostureSourceError) else "indeterminate"
        return _source_limited(check_key, source, reason)

    def collect_all(self, *, cancel_callback=None, now_utc=None):
        deadline = time.monotonic() + self.global_timeout
        checks = []
        sources = (
            ("bitlocker", BITLOCKER_SCRIPT, assess_bitlocker),
            ("tpm", TPM_SCRIPT, assess_tpm),
            ("secure_boot", SECURE_BOOT_SCRIPT, assess_secure_boot),
        )
        for check_key, script, assessor in sources:
            try:
                raw = self._run_source(script, deadline=deadline, cancel_callback=cancel_callback)
                checks.append(assessor(raw if isinstance(raw, dict) else {}))
            except PostureCancelled:
                raise
            except Exception as exc:
                checks.append(self._error_check(check_key, exc))
        try:
            antivirus_raw = self._run_source(
                ANTIVIRUS_SCRIPT, deadline=deadline, cancel_callback=cancel_callback
            )
            antivirus_raw = antivirus_raw if isinstance(antivirus_raw, dict) else {}
            checks.append(assess_antivirus(antivirus_raw))
            checks.append(assess_defender_signature(antivirus_raw, now_utc=now_utc))
        except PostureCancelled:
            raise
        except Exception as exc:
            checks.append(self._error_check("antivirus", exc))
            checks.append(self._error_check("defender_signature", exc))
        try:
            raw = self._run_source(FIREWALL_SCRIPT, deadline=deadline, cancel_callback=cancel_callback)
            checks.append(assess_firewall(raw if isinstance(raw, dict) else {}))
        except PostureCancelled:
            raise
        except Exception as exc:
            checks.append(self._error_check("firewall", exc))
        return checks


class EndpointPostureStore(MonitoringIntelligenceStore):
    def __init__(self, root, logger=None, timeout=5.0):
        super().__init__(root, logger=logger, timeout=timeout)
        self._initialize_posture()

    def _initialize_posture(self):
        connection = self._connect()
        try:
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in (5, DATABASE_SCHEMA_VERSION, 7, 8, 9):
                raise RuntimeError("Versão do banco de postura não suportada.")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS endpoint_posture_runs (
                        run_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
                        hostname TEXT NOT NULL, started_at_utc TEXT NOT NULL,
                        completed_at_utc TEXT, status TEXT NOT NULL,
                        trigger_type TEXT NOT NULL, created_at TEXT NOT NULL
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS endpoint_posture_checks (
                        check_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                        hostname TEXT NOT NULL, check_key TEXT NOT NULL,
                        capability_state TEXT NOT NULL, assessment TEXT NOT NULL,
                        observed_state TEXT NOT NULL, summary TEXT NOT NULL,
                        source TEXT NOT NULL, evidence_json TEXT,
                        collected_at_utc TEXT NOT NULL, change_id TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(run_id) REFERENCES endpoint_posture_runs(run_id)
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS endpoint_posture_state (
                        hostname TEXT NOT NULL, check_key TEXT NOT NULL,
                        capability_state TEXT NOT NULL, assessment TEXT NOT NULL,
                        observed_state TEXT NOT NULL, last_check_id TEXT NOT NULL,
                        changed_at_utc TEXT NOT NULL, updated_at_utc TEXT NOT NULL,
                        PRIMARY KEY(hostname, check_key)
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS endpoint_posture_changes (
                        change_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                        hostname TEXT NOT NULL, check_key TEXT NOT NULL,
                        changed_at_utc TEXT NOT NULL, before_check_id TEXT NOT NULL,
                        after_check_id TEXT NOT NULL, before_json TEXT NOT NULL,
                        after_json TEXT NOT NULL, timeline_event_id TEXT,
                        investigation_session_id TEXT, created_at TEXT NOT NULL
                    )
                """)
                for name, table, expression in (
                    ("idx_posture_runs_host_time", "endpoint_posture_runs", "hostname, started_at_utc DESC"),
                    ("idx_posture_checks_run", "endpoint_posture_checks", "run_id, check_key"),
                    ("idx_posture_checks_host_time", "endpoint_posture_checks", "hostname, collected_at_utc DESC"),
                    ("idx_posture_state_updated", "endpoint_posture_state", "updated_at_utc DESC"),
                    ("idx_posture_changes_host_time", "endpoint_posture_changes", "hostname, changed_at_utc DESC"),
                    ("idx_posture_changes_event", "endpoint_posture_changes", "timeline_event_id"),
                    ("idx_posture_changes_session", "endpoint_posture_changes", "investigation_session_id"),
                ):
                    connection.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table}({expression})")
                if current < DATABASE_SCHEMA_VERSION:
                    connection.execute(f"PRAGMA user_version={DATABASE_SCHEMA_VERSION}")
        finally:
            connection.close()

    @staticmethod
    def _state_payload(row):
        return {
            "capability_state": row["capability_state"],
            "assessment": row["assessment"],
            "observed_state": row["observed_state"],
        }

    def record_snapshot(self, checks, *, hostname=None, trigger_type="MANUAL", collected_at_utc=None):
        hostname = _clean_text(hostname or socket.gethostname() or "Não disponível", 255, required=True)
        trigger = _clean_text(trigger_type, 40, required=True).upper()
        if trigger not in ("MANUAL", "INITIAL"):
            raise ValueError("Gatilho de postura inválido.")
        check_list = list(checks or [])
        if not check_list or len(check_list) > len(CHECK_KEYS):
            raise ValueError("Snapshot de postura vazio ou excedente.")
        keys = [item.get("check_key") for item in check_list if isinstance(item, dict)]
        if len(keys) != len(check_list) or len(set(keys)) != len(keys) or any(key not in CHECK_KEYS for key in keys):
            raise ValueError("Snapshot de postura contém checks inválidos ou duplicados.")
        now = _utc_text(collected_at_utc)
        run = {
            "run_id": uuid.uuid4().hex, "schema_version": POSTURE_SCHEMA_VERSION,
            "hostname": hostname, "started_at_utc": now, "completed_at_utc": now,
            "status": "COMPLETED", "trigger_type": trigger, "created_at": _utc_text(),
        }
        persisted, changes = [], []
        connection = self._connect()
        try:
            with connection:
                connection.execute("""
                    INSERT INTO endpoint_posture_runs (
                        run_id, schema_version, hostname, started_at_utc,
                        completed_at_utc, status, trigger_type, created_at
                    ) VALUES (:run_id,:schema_version,:hostname,:started_at_utc,
                              :completed_at_utc,:status,:trigger_type,:created_at)
                """, run)
                for raw in check_list:
                    capability = _enum(raw.get("capability_state"), CAPABILITY_STATES, "Capacidade")
                    assessment = _enum(raw.get("assessment"), ASSESSMENTS, "Avaliação")
                    check_key = raw["check_key"]
                    evidence = sanitize_evidence(raw.get("evidence") or {})
                    check = {
                        "check_id": uuid.uuid4().hex, "run_id": run["run_id"],
                        "hostname": hostname, "check_key": check_key,
                        "capability_state": capability, "assessment": assessment,
                        "observed_state": _clean_text(raw.get("observed_state"), 160, required=True),
                        "summary": _clean_text(raw.get("summary"), 300, required=True),
                        "source": _clean_text(raw.get("source"), 160, required=True),
                        "evidence_json": sanitize_details(evidence),
                        "collected_at_utc": _utc_text(raw.get("collected_at_utc") or now),
                        "change_id": None, "created_at": _utc_text(),
                    }
                    previous_row = connection.execute(
                        "SELECT * FROM endpoint_posture_state WHERE hostname=? AND check_key=?",
                        (hostname, check_key),
                    ).fetchone()
                    previous = dict(previous_row) if previous_row else None
                    changed = bool(previous and self._state_payload(previous) != self._state_payload(check))
                    if changed:
                        change = {
                            "change_id": uuid.uuid4().hex, "run_id": run["run_id"],
                            "hostname": hostname, "check_key": check_key,
                            "changed_at_utc": check["collected_at_utc"],
                            "before_check_id": previous["last_check_id"],
                            "after_check_id": check["check_id"],
                            "before_json": _canonical(self._state_payload(previous)),
                            "after_json": _canonical(self._state_payload(check)),
                            "timeline_event_id": None, "investigation_session_id": None,
                            "created_at": _utc_text(),
                        }
                        check["change_id"] = change["change_id"]
                        connection.execute("""
                            INSERT INTO endpoint_posture_changes (
                                change_id,run_id,hostname,check_key,changed_at_utc,
                                before_check_id,after_check_id,before_json,after_json,
                                timeline_event_id,investigation_session_id,created_at
                            ) VALUES (
                                :change_id,:run_id,:hostname,:check_key,:changed_at_utc,
                                :before_check_id,:after_check_id,:before_json,:after_json,
                                :timeline_event_id,:investigation_session_id,:created_at
                            )
                        """, change)
                        changes.append(change)
                    connection.execute("""
                        INSERT INTO endpoint_posture_checks (
                            check_id,run_id,hostname,check_key,capability_state,
                            assessment,observed_state,summary,source,evidence_json,
                            collected_at_utc,change_id,created_at
                        ) VALUES (
                            :check_id,:run_id,:hostname,:check_key,:capability_state,
                            :assessment,:observed_state,:summary,:source,:evidence_json,
                            :collected_at_utc,:change_id,:created_at
                        )
                    """, check)
                    changed_at = check["collected_at_utc"] if changed or previous is None else previous["changed_at_utc"]
                    connection.execute("""
                        INSERT INTO endpoint_posture_state (
                            hostname,check_key,capability_state,assessment,observed_state,
                            last_check_id,changed_at_utc,updated_at_utc
                        ) VALUES (?,?,?,?,?,?,?,?)
                        ON CONFLICT(hostname,check_key) DO UPDATE SET
                            capability_state=excluded.capability_state,
                            assessment=excluded.assessment,
                            observed_state=excluded.observed_state,
                            last_check_id=excluded.last_check_id,
                            changed_at_utc=excluded.changed_at_utc,
                            updated_at_utc=excluded.updated_at_utc
                    """, (hostname, check_key, capability, assessment,
                          check["observed_state"], check["check_id"], changed_at,
                          check["collected_at_utc"]))
                    persisted.append(check)
        finally:
            connection.close()
        for change in changes:
            self._emit_change_event(change)
        return {"run": run, "checks": persisted, "changes": [self.get_change(x["change_id"]) for x in changes]}

    def _emit_change_event(self, change):
        current = self.get_change(change["change_id"])
        if current is None:
            return None
        before = json.loads(current["before_json"])
        after = json.loads(current["after_json"])
        title = CHECK_TITLES[current["check_key"]]
        event = record_event_safe(
            self, logger=self.logger, source="ENDPOINT_POSTURE", category="SYSTEM",
            severity="WARNING" if after["assessment"] == "ATTENTION" else "NOTICE",
            status="OBSERVED", hostname=current["hostname"],
            operation_id=current["run_id"], timestamp_utc=current["changed_at_utc"],
            summary=(
                f"Postura de {title} mudou: {before['assessment']} / "
                f"{before['capability_state']} para {after['assessment']} / {after['capability_state']}."
            ),
            details={
                "event_kind": "ENDPOINT_POSTURE_CHANGED",
                "change_id": current["change_id"], "check_key": current["check_key"],
                "before_capability_state": before["capability_state"],
                "after_capability_state": after["capability_state"],
                "before_assessment": before["assessment"],
                "after_assessment": after["assessment"],
                "before_observed_state": before["observed_state"],
                "after_observed_state": after["observed_state"],
                "check_id": current["after_check_id"], "run_id": current["run_id"],
                "principle": "Mudança não é incidente; correlação não prova causalidade.",
            },
        )
        if event:
            connection = self._connect()
            try:
                with connection:
                    connection.execute(
                        "UPDATE endpoint_posture_changes SET timeline_event_id=? WHERE change_id=?",
                        (event["id"], current["change_id"]),
                    )
            finally:
                connection.close()
        return event

    def get_latest_snapshot(self, *, hostname=None):
        hostname = _clean_text(hostname or socket.gethostname() or "Não disponível", 255, required=True)
        connection = self._connect()
        try:
            run_row = connection.execute("""
                SELECT * FROM endpoint_posture_runs
                WHERE hostname=? AND status='COMPLETED'
                ORDER BY completed_at_utc DESC, run_id DESC LIMIT 1
            """, (hostname,)).fetchone()
            if not run_row:
                return None
            run = dict(run_row)
            rows = connection.execute("""
                SELECT * FROM endpoint_posture_checks WHERE run_id=?
                ORDER BY CASE check_key
                    WHEN 'bitlocker' THEN 1 WHEN 'tpm' THEN 2
                    WHEN 'secure_boot' THEN 3 WHEN 'antivirus' THEN 4
                    WHEN 'defender_signature' THEN 5 ELSE 6 END
            """, (run["run_id"],)).fetchall()
            checks = [dict(row) for row in rows]
        finally:
            connection.close()
        counts = {key: 0 for key in ASSESSMENTS}
        for item in checks:
            counts[item["assessment"]] += 1
        return {"run": run, "checks": checks, "counts": counts}

    def get_check(self, check_id):
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM endpoint_posture_checks WHERE check_id=?",
                (_clean_text(check_id, 64, required=True),),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def get_change(self, change_id):
        connection = self._connect()
        try:
            row = connection.execute("""
                SELECT c.*, before_check.summary AS before_summary,
                       after_check.summary AS after_summary,
                       after_check.source AS source,
                       after_check.evidence_json AS evidence_json
                FROM endpoint_posture_changes c
                JOIN endpoint_posture_checks before_check ON before_check.check_id=c.before_check_id
                JOIN endpoint_posture_checks after_check ON after_check.check_id=c.after_check_id
                WHERE c.change_id=?
            """, (_clean_text(change_id, 64, required=True),)).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def list_changes(self, *, hostname=None, limit=50, offset=0):
        limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
        offset = max(0, int(offset))
        clauses, params = [], {"limit": limit, "offset": offset}
        if hostname:
            clauses.append("c.hostname=:hostname")
            params["hostname"] = _clean_text(hostname, 255, required=True)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        connection = self._connect()
        try:
            rows = connection.execute("""
                SELECT c.*, after_check.summary AS after_summary,
                       after_check.source AS source,
                       after_check.evidence_json AS evidence_json
                FROM endpoint_posture_changes c
                JOIN endpoint_posture_checks after_check ON after_check.check_id=c.after_check_id
            """ + where + " ORDER BY c.changed_at_utc DESC, c.change_id DESC LIMIT :limit OFFSET :offset", params).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def posture_context(self, change_id, *, window_minutes=CONTEXT_WINDOW_MINUTES, limit=50):
        change = self.get_change(change_id)
        if change is None:
            raise ValueError("Mudança de postura inexistente.")
        window = max(1, min(int(window_minutes), 60))
        limit = max(1, min(int(limit), 100))
        center = datetime.fromisoformat(change["changed_at_utc"].replace("Z", "+00:00"))
        start = _utc_text(center - timedelta(minutes=window))
        end = _utc_text(center + timedelta(minutes=window))
        connection = self._connect()
        try:
            anchor = None
            if change.get("timeline_event_id"):
                row = connection.execute("SELECT * FROM events WHERE id=?", (change["timeline_event_id"],)).fetchone()
                anchor = dict(row) if row else None
            operation_id = (anchor or {}).get("operation_id") or change["run_id"]
            correlation_id = (anchor or {}).get("correlation_id")
            events = [dict(row) for row in connection.execute("""
                SELECT id,timestamp_utc,source,operation_id,correlation_id,summary
                FROM events WHERE hostname=? AND timestamp_utc BETWEEN ? AND ?
                  AND id<>COALESCE(?, '') ORDER BY timestamp_utc DESC LIMIT 30
            """, (change["hostname"], start, end, change.get("timeline_event_id"))).fetchall()]
            groups = [dict(row) for row in connection.execute("""
                SELECT operation_id,detected_at_utc,source,correlation_id,summary
                FROM change_groups WHERE hostname=? AND detected_at_utc BETWEEN ? AND ?
                ORDER BY detected_at_utc DESC LIMIT 20
            """, (change["hostname"], start, end)).fetchall()]
            alerts = [dict(row) for row in connection.execute("""
                SELECT alert_id,metric_key,status,severity,first_seen_utc,last_seen_utc
                FROM monitoring_alerts WHERE hostname=? AND first_seen_utc<=?
                  AND COALESCE(resolved_at_utc,last_seen_utc)>=?
                ORDER BY first_seen_utc DESC LIMIT 20
            """, (change["hostname"], end, start)).fetchall()]
            sessions = [dict(row) for row in connection.execute("""
                SELECT session_id,updated_at_utc,title,primary_operation_id,
                       primary_correlation_id,status
                FROM investigation_sessions WHERE hostname=?
                  AND window_start_utc<=? AND window_end_utc>=?
                ORDER BY updated_at_utc DESC LIMIT 20
            """, (change["hostname"], end, start)).fetchall()]
        finally:
            connection.close()

        def relation(item_operation=None, item_correlation=None, fallback="TEMPORAL_CONTEXT"):
            if operation_id and item_operation == operation_id:
                return "SAME_OPERATION"
            if correlation_id and item_correlation == correlation_id:
                return "SAME_CORRELATION"
            return fallback

        items = []
        for item in events:
            items.append({"item_type": "TIMELINE_EVENT", "referenced_id": item["id"],
                          "observed_at_utc": item["timestamp_utc"],
                          "relation": relation(item.get("operation_id"), item.get("correlation_id")),
                          "summary": item["summary"], "source": item["source"]})
        for item in groups:
            items.append({"item_type": "CHANGE_GROUP", "referenced_id": item["operation_id"],
                          "observed_at_utc": item["detected_at_utc"],
                          "relation": relation(item.get("operation_id"), item.get("correlation_id")),
                          "summary": item["summary"], "source": item["source"]})
        for item in alerts:
            items.append({"item_type": "MONITORING_ALERT", "referenced_id": item["alert_id"],
                          "observed_at_utc": item["first_seen_utc"], "relation": "TEMPORAL_CONTEXT",
                          "summary": f"Alerta {item['metric_key']} — {item['severity']} / {item['status']}",
                          "source": "Monitoring Alerts"})
        for item in sessions:
            items.append({"item_type": "INVESTIGATION_SESSION", "referenced_id": item["session_id"],
                          "observed_at_utc": item["updated_at_utc"],
                          "relation": relation(item.get("primary_operation_id"), item.get("primary_correlation_id")),
                          "summary": item["title"], "source": "Incident Replay"})
        priority = {"SAME_OPERATION": 0, "SAME_CORRELATION": 1, "SAME_ENTITY": 2, "TEMPORAL_CONTEXT": 3}
        items.sort(key=lambda item: (
            priority.get(item["relation"], 9),
            abs((datetime.fromisoformat(item["observed_at_utc"].replace("Z", "+00:00")) - center).total_seconds()),
        ))
        return {
            "change_id": change["change_id"], "hostname": change["hostname"],
            "window_minutes": window, "items": items[:limit],
            "causality": "Não inferida; os itens são apenas contexto do mesmo equipamento.",
        }

    def create_investigation_from_posture_change(self, change_id):
        change = self.get_change(change_id)
        if change is None:
            raise ValueError("Mudança de postura inexistente.")
        if change.get("investigation_session_id"):
            session = self.get_session(change["investigation_session_id"])
            if session:
                return self.restore_session(session["session_id"]) if session["status"] == "ARCHIVED" else session
        event_id = change.get("timeline_event_id")
        if not event_id:
            raise ValueError("Mudança sem evento estruturado disponível para investigação.")
        session = self.find_session_for_reference("TIMELINE_EVENT", event_id)
        if session is None:
            session = self.create_from_timeline_event(
                event_id, title=f"Investigação — postura de {CHECK_TITLES[change['check_key']]}",
            )
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    "UPDATE endpoint_posture_changes SET investigation_session_id=? WHERE change_id=?",
                    (session["session_id"], change["change_id"]),
                )
        finally:
            connection.close()
        return session


class EndpointPostureService:
    def __init__(self, store, collector=None, logger=None):
        self.store = store
        self.collector = collector or EndpointPostureCollector()
        self.logger = logger
        self._lock = threading.Lock()

    def collect_once(self, *, cancel_callback=None):
        from licensing.runtime import require_feature
        require_feature("endpoint_posture")
        if not self._lock.acquire(blocking=False):
            return {"ok": False, "skipped": "overlap"}
        try:
            checks = self.collector.collect_all(cancel_callback=cancel_callback)
            if cancel_callback and cancel_callback():
                raise PostureCancelled("Coleta de postura cancelada.")
            snapshot = self.store.record_snapshot(checks, trigger_type="MANUAL")
            return {"ok": True, "snapshot": snapshot}
        except PostureCancelled:
            return {"ok": False, "cancelled": True}
        except Exception:
            if self.logger:
                try:
                    self.logger.exception("Falha controlada na coleta de postura")
                except Exception:
                    pass
            return {"ok": False, "error": "posture_collection_failed"}
        finally:
            self._lock.release()


def posture_action_safe(store, logger, action, *args, **kwargs):
    if store is None:
        return None
    try:
        return action(store, *args, **kwargs)
    except Exception:
        if logger:
            try:
                logger.exception("Falha controlada em ação de postura")
            except Exception:
                pass
        return None
