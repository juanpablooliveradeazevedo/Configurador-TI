"""Pipeline oficial de build/distribuição da Fase 1G.

O backend é exclusivamente PyInstaller. A execução usa listas de argumentos e
``shell=False``. O diretório publicado recebe apenas artefatos finais,
manifesto e checksums; caches e workdirs ficam fora dele e são removidos após
uma validação bem-sucedida.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata as importlib_metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from build_config import (  # noqa: E402
    BuildProfile,
    MINIMUM_PYINSTALLER,
    RELEASE_MANIFEST_VERSION,
    get_profile,
    pyinstaller_command,
    release_hygiene_violations,
    validate_source_tree,
)
from release_metadata import (  # noqa: E402
    BUILD_DATE,
    PHASE_ID,
    PRODUCT,
    PRODUCT_VERSION,
    build_metadata,
)
from desenvolvimento.build_portatil import build_portable, validate_executable  # noqa: E402
from desenvolvimento.scan_branding import require_clean


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", str(value))[:3]]
    return tuple((parts + [0, 0, 0])[:3])


def pyinstaller_version() -> str:
    try:
        version = importlib_metadata.version("pyinstaller")
    except importlib_metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            f"PyInstaller>={MINIMUM_PYINSTALLER} não está instalado."
        ) from exc
    if _version_tuple(version) < _version_tuple(MINIMUM_PYINSTALLER):
        raise RuntimeError(
            f"PyInstaller {version} é antigo; mínimo: {MINIMUM_PYINSTALLER}."
        )
    return version


def allocate_release_directory(output_root: Path | str, release_slug: str) -> Path:
    """Reserva uma saída previsível sem apagar ou sobrescrever uma anterior."""
    output_root = Path(output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    index = 0
    while True:
        suffix = f"_{index}" if index else ""
        candidate = output_root / f"{release_slug}{suffix}"
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            index += 1


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _artifact_records(release_dir: Path) -> list[dict]:
    records = []
    for path in sorted(item for item in release_dir.rglob("*") if item.is_file()):
        relative = path.relative_to(release_dir).as_posix()
        if relative in {"release-manifest.json", "SHA256SUMS.txt"}:
            continue
        records.append(
            {
                "name": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "type": "portable_zip" if path.suffix.casefold() == ".zip" else "file",
            }
        )
    return records


def _write_checksums(release_dir: Path) -> Path:
    checksum = release_dir / "SHA256SUMS.txt"
    files = sorted(
        item for item in release_dir.rglob("*")
        if item.is_file() and item != checksum
    )
    checksum.write_text(
        "".join(
            f"{sha256_file(path)}  {path.relative_to(release_dir).as_posix()}\n"
            for path in files
        ),
        encoding="utf-8",
    )
    return checksum


def create_release_manifest(
    release_dir: Path,
    *,
    spec,
    pyinstaller_release: str,
    command: list[str],
    release_channel: str = "INTERNAL",
) -> Path:
    artifacts = _artifact_records(release_dir)
    for artifact in artifacts:
        artifact.update(
            profile=spec.profile.value,
            product_version=PRODUCT_VERSION,
            phase_id=PHASE_ID,
            build_date=BUILD_DATE,
        )
    primary = next(
        (item for item in artifacts if item["name"] == f"{spec.output_name}.exe"),
        artifacts[0] if artifacts else None,
    )
    flags = [
        value for value in command
        if value in {
            "--clean", "--noconfirm", "--onefile", "--onedir",
            "--console", "--noconsole", "--add-data", "--hidden-import",
        }
    ]
    metadata = build_metadata(
        profile=spec.profile.value,
        pyinstaller_version=pyinstaller_release,
        artifact_name=(primary["name"] if primary else None),
        artifact_sha256=(primary["sha256"] if primary else None),
        release_channel=release_channel,
    )
    manifest = {
        "manifest_version": RELEASE_MANIFEST_VERSION,
        "release": metadata,
        "build": {
            "backend": spec.backend,
            "entrypoint": spec.entrypoint,
            "output_name": spec.output_name,
            "onefile": spec.onefile,
            "console": spec.console,
            "assets": [source for source, _target in spec.assets],
            "hidden_imports": list(spec.hidden_imports),
            "expected_artifacts": list(spec.expected_artifacts),
            "command_flags": flags,
        },
        "artifacts": artifacts,
        "licensing": {"contract_version": 1, "verification": "Ed25519", "backend_in_client": False},
        "signing": {
            "status": "not_implemented",
            "provider": None,
            "note": "Hook reservado para Authenticode futuro; assinatura fora da Fase 1G.",
        },
    }
    path = release_dir / "release-manifest.json"
    _write_json(path, manifest)
    return path


def validate_release(release_dir: Path | str) -> dict:
    """Valida a saída publicada sem executar o binário Windows."""
    release_dir = Path(release_dir).resolve()
    manifest_path = release_dir / "release-manifest.json"
    checksum_path = release_dir / "SHA256SUMS.txt"
    if not manifest_path.is_file() or not checksum_path.is_file():
        raise ValueError("Manifesto ou SHA256SUMS ausente.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != RELEASE_MANIFEST_VERSION:
        raise ValueError("Versão de manifesto incompatível.")
    release = manifest.get("release") or {}
    if release.get("phase_id") != PHASE_ID or release.get("backend") != "pyinstaller":
        raise ValueError("Metadata da release não corresponde à Fase 1G/PyInstaller.")
    build = manifest.get("build") or {}
    if build.get("onefile") and "--onefile" not in build.get("command_flags", []):
        raise ValueError("Manifesto onefile sem flag correspondente.")
    if not build.get("console") and "--noconsole" not in build.get("command_flags", []):
        raise ValueError("Manifesto noconsole sem flag correspondente.")
    if "style.qss" not in build.get("assets", []):
        raise ValueError("Asset obrigatório style.qss não declarado.")
    if not release.get("artifact_name") or not release.get("artifact_sha256"):
        raise ValueError("Metadata não identifica o artefato principal e seu SHA-256.")

    recorded = {}
    for item in manifest.get("artifacts", []):
        relative = item.get("name")
        path = release_dir / str(relative)
        if not path.is_file():
            raise ValueError(f"Artefato ausente: {relative}")
        if path.stat().st_size != item.get("size") or sha256_file(path) != item.get("sha256"):
            raise ValueError(f"Artefato diverge do manifesto: {relative}")
        recorded[str(relative)] = item.get("sha256")

    checksum_lines = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or not relative:
            raise ValueError("Linha inválida em SHA256SUMS.txt.")
        path = release_dir / relative
        if not path.is_file() or sha256_file(path) != digest:
            raise ValueError(f"Checksum inválido: {relative}")
        checksum_lines[relative] = digest
    if "release-manifest.json" not in checksum_lines:
        raise ValueError("Manifesto não está coberto por SHA256SUMS.txt.")
    for expected in build.get("expected_artifacts", []):
        if not (release_dir / expected).is_file():
            raise ValueError(f"Artefato esperado ausente: {expected}")

    violations = release_hygiene_violations(
        path.relative_to(release_dir)
        for path in release_dir.rglob("*")
        if path.is_file()
    )
    if violations:
        raise ValueError("Saída contém item proibido: " + ", ".join(violations))
    for archive in release_dir.rglob("*.zip"):
        with zipfile.ZipFile(archive) as zipped:
            damaged = zipped.testzip()
            if damaged is not None:
                raise ValueError(f"ZIP corrompido em {damaged}.")
    require_clean(release_dir)
    return manifest


def _copy_compiled_artifact(spec, pyinstaller_dist: Path, release_dir: Path) -> Path:
    if spec.onefile:
        source = pyinstaller_dist / f"{spec.output_name}.exe"
        validate_executable(source)
        destination = release_dir / source.name
        shutil.copy2(source, destination)
        return destination
    source = pyinstaller_dist / spec.output_name
    if not source.is_dir():
        raise FileNotFoundError(f"Saída onedir ausente: {source}")
    destination = release_dir / spec.output_name
    shutil.copytree(source, destination)
    validate_executable(destination / f"{spec.output_name}.exe")
    return destination


def build_release(
    profile: BuildProfile | str,
    *,
    output_root: Path | str | None = None,
    keep_build_work: bool = False,
) -> Path:
    if os.name != "nt":
        raise RuntimeError("O build executável oficial deve ser realizado no Windows real.")
    root = PROJECT_ROOT
    validate_source_tree(root)
    spec = get_profile(profile)
    from licensing.build_guard import validate_public_config, inspect_client_tree, inspect_executable
    public_config = validate_public_config(json.loads((root / "licensing_public.json").read_text(encoding="utf-8")), spec.profile.value)
    inspect_client_tree(root)
    backend_version = pyinstaller_version()
    output_root = Path(output_root or root / "dist" / "releases").resolve()
    profile_root = output_root / spec.profile.value
    release_dir = allocate_release_directory(profile_root, spec.release_slug)
    build_root = output_root / ".build" / release_dir.name
    pyinstaller_dist = build_root / "dist"
    work_dir = build_root / "work"
    spec_dir = build_root / "spec"
    metadata_asset = build_root / "generated" / "configurador_ti_build_metadata.json"
    _write_json(
        metadata_asset,
        build_metadata(
            profile=spec.profile.value,
            pyinstaller_version=backend_version,
            artifact_name=f"{spec.output_name}.exe",
            release_channel=public_config["channel"],
        ),
    )
    command = pyinstaller_command(
        spec,
        root=root,
        dist_dir=pyinstaller_dist,
        work_dir=work_dir,
        spec_dir=spec_dir,
        metadata_asset=metadata_asset,
    )
    completed = execute_backend(spec.backend, command, cwd=root)
    if completed.returncode != 0:
        raise RuntimeError(f"PyInstaller falhou com código {completed.returncode}.")

    artifact = _copy_compiled_artifact(spec, pyinstaller_dist, release_dir)
    inspect_executable(artifact, spec.profile.value, public_config)
    shutil.copy2(root / "distribuicao" / "LEIA-ME.txt", release_dir / "LEIA-ME.txt")
    if spec.package_portable:
        package_root = release_dir / "pacote-portatil"
        build_portable(
            artifact,
            root / "distribuicao" / "LEIA-ME.txt",
            package_root,
        )
    create_release_manifest(
        release_dir,
        spec=spec,
        pyinstaller_release=backend_version,
        command=command,
        release_channel=public_config["channel"],
    )
    _write_checksums(release_dir)
    validate_release(release_dir)
    if not keep_build_work:
        shutil.rmtree(build_root, ignore_errors=False)
    return release_dir


def execute_backend(backend: str, command: list[str], *, cwd: Path) -> subprocess.CompletedProcess:
    """Ponto único para backends; a 1G autoriza somente PyInstaller."""
    if backend != "pyinstaller":
        raise ValueError(f"Backend não suportado nesta release: {backend}")
    return subprocess.run(command, cwd=cwd, shell=False, check=False)


def dry_run(profile: BuildProfile | str) -> dict:
    root = PROJECT_ROOT
    validate_source_tree(root)
    spec = get_profile(profile)
    with tempfile.TemporaryDirectory(prefix="configurador-ti-build-plan-") as temp:
        temp = Path(temp)
        metadata_asset = temp / "configurador_ti_build_metadata.json"
        _write_json(metadata_asset, build_metadata(profile=spec.profile.value))
        command = pyinstaller_command(
            spec,
            root=root,
            dist_dir=temp / "dist",
            work_dir=temp / "work",
            spec_dir=temp / "spec",
            metadata_asset=metadata_asset,
        )
        return {
            "profile": spec.profile.value,
            "backend": spec.backend,
            "onefile": spec.onefile,
            "console": spec.console,
            "package_portable": spec.package_portable,
            "command_flags": [arg for arg in command if arg.startswith("--")],
            "required_files": [str(path.relative_to(root)) for path in validate_source_tree(root)],
            "expected_artifacts": list(spec.expected_artifacts),
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build oficial Configurador TI 1G com PyInstaller.")
    parser.add_argument(
        "--profile",
        default=BuildProfile.PORTABLE.value,
        choices=[item.value for item in BuildProfile],
    )
    parser.add_argument("--output-root")
    parser.add_argument("--keep-build-work", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(json.dumps(dry_run(args.profile), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    release_dir = build_release(
        args.profile,
        output_root=args.output_root,
        keep_build_work=args.keep_build_work,
    )
    print(f"Release validada: {release_dir}")
    print(f"Manifesto: {release_dir / 'release-manifest.json'}")
    print(f"Checksums: {release_dir / 'SHA256SUMS.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
