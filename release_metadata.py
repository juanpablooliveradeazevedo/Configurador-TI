"""Fonte única da identificação e metadata pública da release Configurador TI."""
from __future__ import annotations

import json
from pathlib import Path
import platform
import sys

PRODUCT = "Configurador TI"
PRODUCT_SHORT = "Configurador TI"
PRODUCT_VERSION = "5.0"
PHASE_ID = "2B"
PHASE_TITLE = "Central Web, Agent & Fleet Remote Operations"
BUILD_DATE = "2026-09-25"
VERSION = f"{PRODUCT_VERSION} • {PHASE_ID}"
BACKEND = "pyinstaller"
MANIFEST_VERSION = 1
RUNTIME_METADATA_FILE = "configurador_ti_build_metadata.json"


def status_label(mode):
    """Identificação compacta compartilhada pelo rodapé Fonte/EXE."""
    return f"{PRODUCT_SHORT} {PHASE_ID} | {str(mode)}"


def _asset_root() -> Path:
    if getattr(sys, "frozen", False) and getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS).resolve()
    return Path(__file__).resolve().parent


def runtime_build_metadata() -> dict:
    """Lê somente metadata pública empacotada; nunca usa a raiz persistente."""
    path = _asset_root() / RUNTIME_METADATA_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("manifest_version") == MANIFEST_VERSION:
            return data
    except (OSError, ValueError, TypeError):
        pass
    return {
        "manifest_version": MANIFEST_VERSION,
        "product": PRODUCT,
        "product_version": PRODUCT_VERSION,
        "phase_id": PHASE_ID,
        "phase_title": PHASE_TITLE,
        "build_date": BUILD_DATE,
        "profile": "SOURCE",
        "backend": BACKEND,
        "identity_contract_version": 1,
        "minimum_supported_version": "5.0",
        "release_channel": "INTERNAL",
        "python_version": platform.python_version(),
        "pyinstaller_version": None,
        "artifact_name": None,
        "artifact_sha256": None,
    }


# Snapshot público e imutável desta instância. Painéis de status reutilizam o
# valor sem reler arquivos ao serem abertos.
RUNTIME_BUILD_METADATA = runtime_build_metadata()


def build_metadata(
    *, profile, pyinstaller_version=None, artifact_name=None, artifact_sha256=None, release_channel="INTERNAL"
) -> dict:
    """Cria o contrato determinístico usado pelo runtime e pelo manifesto."""
    if release_channel not in ("INTERNAL", "BETA", "STABLE"):
        raise ValueError("Canal inválido")
    return {
        "manifest_version": MANIFEST_VERSION,
        "product": PRODUCT,
        "product_version": PRODUCT_VERSION,
        "phase_id": PHASE_ID,
        "phase_title": PHASE_TITLE,
        "build_date": BUILD_DATE,
        "profile": str(profile).upper(),
        "backend": BACKEND,
        "identity_contract_version": 1,
        "minimum_supported_version": "5.0",
        "release_channel": release_channel,
        "python_version": platform.python_version(),
        "pyinstaller_version": pyinstaller_version,
        "artifact_name": artifact_name,
        "artifact_sha256": artifact_sha256,
    }
