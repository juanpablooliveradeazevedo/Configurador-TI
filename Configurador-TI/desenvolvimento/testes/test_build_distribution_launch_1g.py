"""Contratos focados da 1G; não compila EXE nem solicita UAC real."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_config
import core_logic
import app_paths
import release_metadata
import test_ux_global as base


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_release_1g", ROOT / "desenvolvimento" / "build_release.py"
)
build_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_release)


class BuildProfileTests(unittest.TestCase):
    def test_four_profiles_keep_pyinstaller_official(self):
        self.assertEqual(
            {profile.value for profile in build_config.BuildProfile},
            {"DEV", "QA", "PRODUCTION", "PORTABLE"},
        )
        self.assertTrue(all(spec.backend == "pyinstaller" for spec in build_config.PROFILES.values()))
        for name in ("PRODUCTION", "PORTABLE"):
            spec = build_config.get_profile(name)
            self.assertTrue(spec.onefile)
            self.assertFalse(spec.console)
            self.assertTrue(spec.package_portable)

    def test_structured_command_has_assets_paths_and_official_flags(self):
        with tempfile.TemporaryDirectory(prefix="Configurador TI build ç ") as temp:
            metadata = Path(temp) / "metadata.json"
            metadata.write_text("{}", encoding="utf-8")
            command = build_config.pyinstaller_command(
                build_config.get_profile("PORTABLE"),
                root=ROOT,
                dist_dir=Path(temp) / "dist com espaço",
                work_dir=Path(temp) / "work",
                spec_dir=Path(temp) / "spec",
                metadata_asset=metadata,
                python_executable=sys.executable,
            )
        self.assertEqual(command[1:3], ["-m", "PyInstaller"])
        self.assertIn("--onefile", command)
        self.assertIn("--noconsole", command)
        self.assertIn("--add-data", command)
        self.assertEqual(Path(command[-1]), ROOT / "main_gui.pyw")
        self.assertNotIn("shell=True", command)

    def test_source_validation_and_hygiene(self):
        validated = build_config.validate_source_tree(ROOT)
        self.assertIn(ROOT / "style.qss", validated)
        violations = build_config.release_hygiene_violations(
            [Path("ConfiguradorTI.exe"), Path("desenvolvimento/test.py"), Path("logs/a.log")]
        )
        self.assertEqual(len(violations), 2)

    def test_output_reservation_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            first = build_release.allocate_release_directory(temp, "Configurador_TI_5_0_2B_PORTABLE")
            sentinel = first / "preservado.txt"
            sentinel.write_text("ok", encoding="utf-8")
            second = build_release.allocate_release_directory(temp, "Configurador_TI_5_0_2B_PORTABLE")
            self.assertEqual(second.name, "Configurador_TI_5_0_2B_PORTABLE_1")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "ok")

    def test_dry_run_from_external_cwd_space_unicode(self):
        with tempfile.TemporaryDirectory(prefix="fora ç ") as temp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "desenvolvimento" / "build_release.py"),
                    "--profile",
                    "PORTABLE",
                    "--dry-run",
                ],
                cwd=temp,
                capture_output=True,
                text=True,
                timeout=20,
                shell=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["backend"], "pyinstaller")
        self.assertIn("--onefile", plan["command_flags"])
        self.assertIn("--noconsole", plan["command_flags"])


class ManifestTests(unittest.TestCase):
    def _synthetic_pe(self, path):
        header = bytearray(64)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 60, 64)
        path.write_bytes(header + b"PE\0\0SYNTHETIC")

    def test_manifest_checksums_and_future_signing_hook(self):
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp)
            self._synthetic_pe(release / "ConfiguradorTI.exe")
            (release / "LEIA-ME.txt").write_text("fixture", encoding="utf-8")
            package = release / "pacote-portatil" / "Configurador_TI_PORTATIL.zip"
            package.parent.mkdir()
            with zipfile.ZipFile(package, "w") as zipped:
                zipped.write(release / "ConfiguradorTI.exe", "Configurador_TI/ConfiguradorTI.exe")
            spec = build_config.get_profile("PORTABLE")
            command = [sys.executable, "-m", "PyInstaller", "--onefile", "--noconsole", "--add-data"]
            build_release.create_release_manifest(
                release,
                spec=spec,
                pyinstaller_release="6.22.1",
                command=command,
            )
            build_release._write_checksums(release)
            manifest = build_release.validate_release(release)
            self.assertEqual(manifest["release"]["phase_id"], "2B")
            self.assertEqual(manifest["release"]["profile"], "PORTABLE")
            self.assertEqual(len(manifest["release"]["artifact_sha256"]), 64)
            self.assertEqual(manifest["signing"]["status"], "not_implemented")
            self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest["artifacts"]))

    def test_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp)
            self._synthetic_pe(release / "ConfiguradorTI.exe")
            spec = build_config.get_profile("PORTABLE")
            build_release.create_release_manifest(
                release,
                spec=spec,
                pyinstaller_release="6.22.1",
                command=["--onefile", "--noconsole", "--add-data"],
            )
            build_release._write_checksums(release)
            (release / "ConfiguradorTI.exe").write_bytes(b"alterado")
            with self.assertRaisesRegex(ValueError, "diverge"):
                build_release.validate_release(release)


class RuntimePathTests(unittest.TestCase):
    def test_meipass_is_asset_only_and_persistence_stays_with_exe(self):
        with tempfile.TemporaryDirectory(prefix="Configurador TI portátil ç ") as temp:
            root = Path(temp)
            exe = root / "ConfiguradorTI.exe"
            meipass = root / "_MEI fixture"
            with patch.object(sys, "frozen", True, create=True), patch.object(
                sys, "executable", str(exe)
            ), patch.object(sys, "_MEIPASS", str(meipass), create=True):
                self.assertEqual(app_paths.runtime_root(), root)
                self.assertEqual(app_paths.asset_root(), meipass)
                self.assertEqual(app_paths.asset_path("style.qss"), meipass / "style.qss")
                paths = app_paths.PortablePaths()
                self.assertEqual(paths.file("configurador_ti_config.json").parent, root / "dados/configuracoes")

    def test_asset_path_rejects_escape(self):
        with self.assertRaises(ValueError):
            app_paths.asset_path("../segredo")


class AdminRelaunchTests(unittest.TestCase):
    def test_source_plan_is_allowlisted_and_drops_arbitrary_argv(self):
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic, "verificar_admin", return_value=False
        ), patch.object(core_logic, "_executavel_reinicio_gui", return_value="pythonw.exe"), patch.object(
            core_logic.sys, "argv", ["main_gui.pyw", "--token", "SEGREDO", "--shell", "whoami"]
        ):
            plan = core_logic.preparar_relancamento_gui_administrador()
        self.assertEqual(plan["Executavel"], "pythonw.exe")
        self.assertEqual(len(plan["Argumentos"]), 1)
        self.assertEqual(Path(plan["Argumentos"][0]).name, "main_gui.pyw")
        self.assertEqual(Path(plan["Argumentos"][0]).parent, Path(core_logic.DIRETORIO_BASE))
        self.assertNotIn("SEGREDO", plan["Parametros"])
        self.assertNotIn("whoami", plan["Parametros"])

    def test_frozen_plan_has_no_parameters_and_reset_path_is_reused(self):
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic, "verificar_admin", return_value=False
        ), patch.object(core_logic.sys, "frozen", True, create=True), patch.object(
            core_logic.sys, "executable", r"C:\Configurador TI Portátil\ConfiguradorTI.exe"
        ), patch.object(core_logic, "_executavel_reinicio_gui", return_value=r"C:\Configurador TI Portátil\ConfiguradorTI.exe"):
            plan = core_logic.preparar_relancamento_gui_administrador()
        self.assertEqual(plan["Argumentos"], [])
        self.assertEqual(plan["Parametros"], "")

    def test_dispatch_success_failure_admin_and_non_windows(self):
        plan = {
            "Status": "pronto", "Executavel": "ConfiguradorTI.exe", "Argumentos": [],
            "Parametros": "", "Diretorio": r"C:\Configurador TI",
        }
        with patch.object(core_logic, "preparar_relancamento_gui_administrador", return_value=plan), patch.object(
            core_logic, "executar_relancamento_uac", return_value=42
        ), patch.object(core_logic, "registrar_evento_instancia"):
            self.assertEqual(core_logic.reiniciar_gui_como_administrador()["Status"], "iniciado")
        with patch.object(core_logic, "preparar_relancamento_gui_administrador", return_value=plan), patch.object(
            core_logic, "executar_relancamento_uac", return_value=5
        ), patch.object(core_logic, "registrar_evento_instancia"):
            self.assertEqual(
                core_logic.reiniciar_gui_como_administrador()["Status"],
                "uac_cancelado_ou_falhou",
            )
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic, "verificar_admin", return_value=True
        ):
            self.assertEqual(core_logic.preparar_relancamento_gui_administrador()["Status"], "ja_administrador")
        with patch.object(core_logic.os, "name", "posix"):
            self.assertEqual(core_logic.preparar_relancamento_gui_administrador()["Status"], "nao_suportado")


class LaunchInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.case = base.UxTests()
        self.case.setUp()
        self.window = self.case.w

    def tearDown(self):
        self.case.tearDown()

    def test_status_and_explicit_button_follow_current_privilege(self):
        with patch.object(base.gui.core_logic, "verificar_admin", return_value=False):
            self.window._atualizar_status_admin()
        self.assertIn("UAC sob demanda", self.window.admin_label.text())
        self.assertFalse(self.window.restart_admin_button.isHidden())
        with patch.object(base.gui.core_logic, "verificar_admin", return_value=True):
            self.window._atualizar_status_admin()
        self.assertIn("Administrador", self.window.admin_label.text())
        self.assertTrue(self.window.restart_admin_button.isHidden())

    def test_cancel_keeps_window_and_accept_quits_after_dispatch(self):
        with patch.object(base.gui.core_logic, "verificar_admin", return_value=False), patch.object(
            base.gui.QMessageBox, "warning", return_value=base.gui.QMessageBox.StandardButton.No
        ), patch.object(base.gui.core_logic, "reiniciar_gui_como_administrador") as relaunch:
            self.window._reiniciar_como_administrador()
        relaunch.assert_not_called()
        with patch.object(base.gui.core_logic, "verificar_admin", return_value=False), patch.object(
            base.gui.QMessageBox, "warning", return_value=base.gui.QMessageBox.StandardButton.Yes
        ), patch.object(
            base.gui.core_logic, "reiniciar_gui_como_administrador", return_value={"Status": "iniciado"}
        ) as relaunch, patch.object(base.gui.QApplication.instance(), "quit") as quit_app:
            self.window._reiniciar_como_administrador()
        relaunch.assert_called_once()
        quit_app.assert_called_once()


class MetadataAndScopeTests(unittest.TestCase):
    def test_phase_footer_and_backend(self):
        self.assertEqual(release_metadata.PHASE_ID, "2B")
        self.assertEqual(
            release_metadata.PHASE_TITLE,
            "Central Web, Agent & Fleet Remote Operations",
        )
        self.assertEqual(release_metadata.BUILD_DATE, "2026-09-25")
        self.assertEqual(release_metadata.status_label("Fonte"), "Configurador TI 2B | Fonte")
        self.assertEqual(release_metadata.status_label("EXE"), "Configurador TI 2B | EXE")
        self.assertEqual(release_metadata.BACKEND, "pyinstaller")

    def test_batch_delegates_and_keeps_official_contract(self):
        bat = (ROOT / "CRIAR_EXE_E_PENDRIVE_TI_v5_0.bat").read_text(encoding="utf-8")
        self.assertIn("build_release.py", bat)
        self.assertIn("--profile PORTABLE", bat)
        self.assertIn("--onefile", bat)
        self.assertIn("--noconsole", bat)
        self.assertNotIn("Nuitka", bat)
        self.assertNotIn("shell=True", (ROOT / "desenvolvimento/build_release.py").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
