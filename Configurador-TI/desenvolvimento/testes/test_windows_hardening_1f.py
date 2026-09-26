"""Regressões focadas da Fase 1F; não executa ações Windows reais."""
import gc
import io
import json
import os
import tempfile
import unittest
import warnings
import subprocess
from pathlib import Path
from unittest.mock import patch

import core_logic
import release_metadata
from audit_timeline import AuditTimelineStore


class _FakeProcess:
    def __init__(self, output=b"", returncode=0):
        self.stdout = io.BytesIO(output)
        self.returncode = returncode
        self.pid = 4242
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 125

    def kill(self):
        self.terminated = True
        self.returncode = 125


class AtomicPersistenceTests(unittest.TestCase):
    def test_atomic_writer_retries_permission_error_and_commits(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventário empresa.json"
            path.write_text("anterior", encoding="utf-8")
            real_replace = os.replace
            calls = []

            def replace_retry(source, target):
                calls.append((source, target))
                if len(calls) < 3:
                    raise PermissionError("fixture")
                return real_replace(source, target)

            with patch.object(core_logic.os, "replace", side_effect=replace_retry), \
                    patch.object(core_logic.time, "sleep"):
                core_logic._gravar_arquivo_atomico(path, "novo")
            self.assertEqual(path.read_text(encoding="utf-8"), "novo")
            self.assertEqual(len(calls), 3)
            self.assertFalse(list(Path(temp).glob("*.tmp")))

    def test_atomic_writer_preserves_previous_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventario.json"
            path.write_bytes(b'{"estado":"anterior"}')
            with patch.object(
                core_logic.os, "replace", side_effect=PermissionError("fixture")
            ), patch.object(core_logic.time, "sleep"):
                with self.assertRaises(PermissionError):
                    core_logic._gravar_arquivo_atomico(path, "novo")
            self.assertEqual(path.read_bytes(), b'{"estado":"anterior"}')
            self.assertFalse(list(Path(temp).glob("*.tmp")))

    def test_inventory_and_report_use_atomic_writer(self):
        source = Path(core_logic.__file__).read_text(encoding="utf-8")
        self.assertNotIn("Path(ARQUIVO_INVENTARIO).write_text", source)
        self.assertGreaterEqual(source.count("_salvar_inventario_empresa("), 4)
        self.assertIn("_gravar_arquivo_atomico(arquivo_saida, html_relatorio)", source)


class WindowsUpdateIpcTests(unittest.TestCase):
    def _ipc(self, temp):
        root = Path(temp) / "ConfiguradorTI" / "windows_update"
        folder = root / "execucao_fixture"
        folder.mkdir(parents=True)
        path = folder / "resultado_fixture.json"
        path.write_text("", encoding="utf-8")
        return root, folder, path

    def test_ipc_in_place_nonce_limits_and_no_replace(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, path = self._ipc(temp)
            nonce = "A" * 43
            inode = path.stat().st_ino
            with patch.object(
                core_logic, "_raiz_temporaria_windows_update", return_value=root
            ), patch.object(
                core_logic.os, "replace", side_effect=AssertionError("replace indevido")
            ):
                core_logic._gravar_estado_windows_update(
                    path, nonce, "RUNNING", 37, "Processando"
                )
                envelope = core_logic._ler_estado_windows_update(path, nonce)
                self.assertEqual(envelope["Percentual"], 37)
                self.assertIsNone(core_logic._ler_estado_windows_update(path, "B" * 43))
            self.assertEqual(path.stat().st_ino, inode)

    def test_ipc_rejects_links_paths_and_partial_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, path = self._ipc(temp)
            with patch.object(
                core_logic, "_raiz_temporaria_windows_update", return_value=root
            ):
                path.write_text("{", encoding="utf-8")
                self.assertIsNone(core_logic._ler_estado_windows_update(path, "A" * 43))
                outside = Path(temp) / "resultado_outside.json"
                outside.write_text("{}", encoding="utf-8")
                with self.assertRaises(ValueError):
                    core_logic._validar_destino_windows_update(outside)

    def test_access_denied_is_explicit_and_cleanup_is_local(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "windows_update"
            with patch.object(
                core_logic, "_raiz_temporaria_windows_update", return_value=root
            ), patch.object(
                core_logic, "_executavel_reinicio_gui", return_value="pythonw.exe"
            ), patch.object(
                core_logic, "executar_auxiliar_elevado_aguardando",
                return_value={"Status": "erro", "Tipo": "ShellExecuteEx", "Codigo": 5},
            ):
                ok, message = core_logic._executar_windows_update_elevado_isolado()
            self.assertFalse(ok)
            self.assertIn("WinError 5", message)
            self.assertTrue(root.is_dir())
            self.assertFalse(list(root.glob("execucao_*")))

    def test_dacl_uses_current_user_sid_and_administrators_without_shell(self):
        responses = [
            subprocess.CompletedProcess([], 0, b'"HOST\\user","S-1-5-21-1-2-3-1001"\r\n', b""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic.subprocess, "run", side_effect=responses
        ) as run:
            core_logic.restringir_acl_arquivo(r"C:\\Temp\\resultado.json")
        acl_args = run.call_args_list[1].args[0]
        self.assertIn("*S-1-5-21-1-2-3-1001:F", acl_args)
        self.assertIn("*S-1-5-32-544:F", acl_args)
        self.assertIs(run.call_args_list[0].kwargs["shell"], False)
        self.assertIs(run.call_args_list[1].kwargs["shell"], False)


class WindowsUpdateLifecycleTests(unittest.TestCase):
    def test_reader_is_nonblocking_shell_false_and_requires_marker(self):
        output = (
            b"PROGRESSO|10|Procurando\n"
            b"RESULTADO|Nenhuma atualizacao pendente.\n"
        )
        fake = _FakeProcess(output, 0)
        progress = []
        with patch.object(core_logic.subprocess, "Popen", return_value=fake) as popen:
            ok, message = core_logic.executar_windows_update_com_progresso(
                "fixture", lambda value, text: progress.append((value, text))
            )
        self.assertTrue(ok)
        self.assertIn("Nenhuma", message)
        self.assertEqual(progress, [(10, "Procurando")])
        self.assertIs(popen.call_args.kwargs["shell"], False)
        self.assertIs(popen.call_args.kwargs["stdin"], core_logic.subprocess.DEVNULL)

        missing = _FakeProcess(b"INFO|sem marcador\n", 0)
        with patch.object(core_logic.subprocess, "Popen", return_value=missing):
            ok, message = core_logic.executar_windows_update_com_progresso("fixture")
        self.assertFalse(ok)
        self.assertIn("marcador", message)

    def test_cancel_terminates_process_without_waiting_for_output(self):
        fake = _FakeProcess(b"", None)
        with patch.object(core_logic.subprocess, "Popen", return_value=fake):
            ok, message = core_logic.executar_windows_update_com_progresso(
                "fixture", cancel_callback=lambda: True
            )
        self.assertFalse(ok)
        self.assertTrue(fake.terminated)
        self.assertIn("cancelado", message.casefold())

    def test_gui_uses_isolated_helper_operation_key(self):
        source = Path(core_logic.__file__).with_name("main_gui.py").read_text(
            encoding="utf-8"
        )
        start = source.index("    def _windows_update(self):")
        end = source.index("    def _versao_windows(self):", start)
        block = source[start:end]
        self.assertIn('operation_key="windows_update"', block)
        self.assertNotIn("admin_reason=", block)

    def test_headless_contract_rejects_arbitrary_arguments(self):
        with patch.object(
            core_logic.ModuloSistema, "executar_windows_update",
            side_effect=AssertionError("execução indevida"),
        ):
            self.assertEqual(
                core_logic.executar_modo_windows_update_elevado(
                    [core_logic.MODO_WINDOWS_UPDATE_ELEVADO, "--shell", "whoami"]
                ),
                2,
            )


class ExistingHardeningRegressionTests(unittest.TestCase):
    def test_metadata_schema_build_and_meipass_contracts(self):
        self.assertEqual(release_metadata.PHASE_ID, "2B")
        self.assertEqual(
            release_metadata.PHASE_TITLE,
            "Central Web, Agent & Fleet Remote Operations",
        )
        self.assertEqual(release_metadata.status_label("Fonte"), "Configurador TI 2B | Fonte")
        root = Path(core_logic.__file__).resolve().parent
        bat = (root / "CRIAR_EXE_E_PENDRIVE_TI_v5_0.bat").read_text(
            encoding="utf-8"
        )
        self.assertIn("--onefile", bat)
        self.assertIn("--noconsole", bat)
        self.assertIn("pyinstaller>=6.22.1", bat)
        self.assertNotIn("_MEIPASS", str(core_logic.DIRETORIO_BASE))
        import assist
        self.assertEqual(assist.DATABASE_SCHEMA_VERSION, 9)

    def test_sqlite_store_closes_and_reopens_without_resource_warning(self):
        with tempfile.TemporaryDirectory() as temp, warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            store = AuditTimelineStore(temp)
            event = store.record_event(
                source="TEST", category="SYSTEM", severity="INFO",
                status="COMPLETED", summary="fixture",
            )
            del store
            gc.collect()
            reopened = AuditTimelineStore(temp)
            self.assertEqual(reopened.get_event(event["id"])["summary"], "fixture")
            del reopened
            gc.collect()
            self.assertFalse(
                [item for item in caught if issubclass(item.category, ResourceWarning)]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
