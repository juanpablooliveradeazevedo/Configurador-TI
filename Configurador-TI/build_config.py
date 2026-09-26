"""Configuração declarativa de build da release Configurador TI 2B.

PyInstaller permanece o único backend oficial. Este módulo descreve perfis e
monta argumentos estruturados; não executa shell, não compila no import e não
conhece dados persistentes do usuário.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import sys
from typing import Iterable


OFFICIAL_BACKEND = "pyinstaller"
MINIMUM_PYINSTALLER = "6.22.1"
ENTRYPOINT = "main_gui.pyw"
OUTPUT_NAME = "ConfiguradorTI"
RELEASE_MANIFEST_VERSION = 1

REQUIRED_SOURCE_FILES = (
    ENTRYPOINT,
    "main_gui.py",
    "core_logic.py",
    "app_paths.py",
    "app_status.py",
    "release_metadata.py",
    "navigation_registry.py",
    "domain_hubs.py",
    "audit_timeline.py",
    "audit_timeline_gui.py",
    "change_intelligence.py",
    "change_intelligence_gui.py",
    "incident_replay.py",
    "monitoring_foundation.py",
    "monitoring_intelligence.py",
    "monitoring_gui.py",
    "endpoint_posture.py",
    "endpoint_posture_gui.py",
    "assist.py",
    "assist_gui.py",
    "baseline_defensivo.py",
    "baseline_defensivo_gui.py",
    "network_intelligence.py",
    "network_intelligence_gui.py",
    "hostname_identification.py",
    "triagem_interativa.py",
    "operational_ui.py",
    "ui_components.py",
    "licensing/runtime.py",
    "licensing/client.py",
    "licensing_public.json",
    "style.qss",
    "distribuicao/LEIA-ME.txt",
)

FORBIDDEN_RELEASE_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "desenvolvimento",
    "testes",
    "evidencias",
    "validacao",
    "dados",
    "logs",
    "relatorios",
    "coletas",
    "control_plane",
    "backend-state",
    "agent",
    "central_web",
    "fleet_protocol",
}
FORBIDDEN_RELEASE_SUFFIXES = {".py", ".pyc", ".pyo", ".log", ".tmp"}


class BuildProfile(str, Enum):
    DEV = "DEV"
    QA = "QA"
    PRODUCTION = "PRODUCTION"
    PORTABLE = "PORTABLE"

    @classmethod
    def parse(cls, value: str) -> "BuildProfile":
        try:
            return cls(str(value).strip().upper())
        except ValueError as exc:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"Perfil inválido: {value!r}. Use: {choices}.") from exc


@dataclass(frozen=True)
class BuildSpec:
    profile: BuildProfile
    backend: str = OFFICIAL_BACKEND
    entrypoint: str = ENTRYPOINT
    output_name: str = OUTPUT_NAME
    onefile: bool = True
    console: bool = False
    package_portable: bool = False
    diagnostics: bool = False
    assets: tuple[tuple[str, str], ...] = (("style.qss", "."), ("licensing_public.json", "."))
    hidden_imports: tuple[str, ...] = ()
    expected_artifacts: tuple[str, ...] = (
        "ConfiguradorTI.exe",
        "LEIA-ME.txt",
        "release-manifest.json",
        "SHA256SUMS.txt",
    )

    @property
    def release_slug(self) -> str:
        return f"Configurador_TI_5_0_2B_{self.profile.value}"


PROFILES = {
    BuildProfile.DEV: BuildSpec(
        profile=BuildProfile.DEV,
        onefile=False,
        console=True,
        diagnostics=True,
        expected_artifacts=(
            "ConfiguradorTI/ConfiguradorTI.exe", "LEIA-ME.txt", "release-manifest.json", "SHA256SUMS.txt",
        ),
    ),
    BuildProfile.QA: BuildSpec(
        profile=BuildProfile.QA,
        onefile=True,
        console=True,
        diagnostics=True,
    ),
    BuildProfile.PRODUCTION: BuildSpec(
        profile=BuildProfile.PRODUCTION,
        onefile=True,
        console=False,
        package_portable=True,
        expected_artifacts=(
            "ConfiguradorTI.exe", "LEIA-ME.txt", "pacote-portatil/Configurador_TI_PORTATIL.zip",
            "release-manifest.json", "SHA256SUMS.txt",
        ),
    ),
    BuildProfile.PORTABLE: BuildSpec(
        profile=BuildProfile.PORTABLE,
        onefile=True,
        console=False,
        package_portable=True,
        expected_artifacts=(
            "ConfiguradorTI.exe", "LEIA-ME.txt", "pacote-portatil/Configurador_TI_PORTATIL.zip",
            "release-manifest.json", "SHA256SUMS.txt",
        ),
    ),
}


def project_root() -> Path:
    return Path(__file__).resolve().parent


def get_profile(profile: BuildProfile | str) -> BuildSpec:
    selected = profile if isinstance(profile, BuildProfile) else BuildProfile.parse(profile)
    return PROFILES[selected]


def validate_source_tree(root: Path | str) -> list[Path]:
    root = Path(root).resolve()
    missing = [root / relative for relative in REQUIRED_SOURCE_FILES if not (root / relative).is_file()]
    if missing:
        names = ", ".join(str(path.relative_to(root)) for path in missing)
        raise FileNotFoundError(f"Arquivos obrigatórios ausentes: {names}")
    style = root / "style.qss"
    if not style.read_text(encoding="utf-8").strip():
        raise ValueError("style.qss está vazio.")
    return [root / relative for relative in REQUIRED_SOURCE_FILES]


def pyinstaller_arguments(
    spec: BuildSpec,
    *,
    root: Path | str,
    dist_dir: Path | str,
    work_dir: Path | str,
    spec_dir: Path | str,
    metadata_asset: Path | str,
) -> list[str]:
    """Retorna argumentos allowlisted, independentes do cwd e sem shell."""
    root = Path(root).resolve()
    metadata_asset = Path(metadata_asset).resolve()
    args = [
        "--clean",
        "--noconfirm",
        "--name",
        spec.output_name,
        "--distpath",
        str(Path(dist_dir).resolve()),
        "--workpath",
        str(Path(work_dir).resolve()),
        "--specpath",
        str(Path(spec_dir).resolve()),
        "--onefile" if spec.onefile else "--onedir",
        "--console" if spec.console else "--noconsole",
    ]
    for source, target in spec.assets:
        args.extend(("--add-data", f"{(root / source).resolve()}{os.pathsep}{target}"))
    args.extend(("--add-data", f"{metadata_asset}{os.pathsep}."))
    for module in spec.hidden_imports:
        args.extend(("--hidden-import", module))
    for module in ("control_plane", "agent", "central_web", "fleet_protocol"):
        args.extend(("--exclude-module", module))
    args.append(str((root / spec.entrypoint).resolve()))
    return args


def pyinstaller_command(
    spec: BuildSpec,
    *,
    root: Path | str,
    dist_dir: Path | str,
    work_dir: Path | str,
    spec_dir: Path | str,
    metadata_asset: Path | str,
    python_executable: str | Path = sys.executable,
) -> list[str]:
    return [
        str(Path(python_executable).resolve()),
        "-m",
        "PyInstaller",
        *pyinstaller_arguments(
            spec,
            root=root,
            dist_dir=dist_dir,
            work_dir=work_dir,
            spec_dir=spec_dir,
            metadata_asset=metadata_asset,
        ),
    ]


def release_hygiene_violations(paths: Iterable[Path | str]) -> list[str]:
    violations: list[str] = []
    for raw in paths:
        path = Path(raw)
        lowered = {part.casefold() for part in path.parts}
        if lowered & {part.casefold() for part in FORBIDDEN_RELEASE_PARTS}:
            violations.append(str(path))
            continue
        if path.suffix.casefold() in FORBIDDEN_RELEASE_SUFFIXES:
            violations.append(str(path))
    return sorted(set(violations))
