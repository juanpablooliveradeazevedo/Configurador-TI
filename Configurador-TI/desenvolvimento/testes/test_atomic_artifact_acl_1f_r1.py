"""Regressões focadas da 1F-R1; não altera ACLs reais nem executa UAC."""
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

import core_logic
import release_metadata


class AtomicArtifactPublicationTests(unittest.TestCase):
    def test_new_file_space_unicode_is_atomic_readable_and_has_no_temp(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "pasta com espaço" / "relatório_ação.html"
            published = core_logic._gravar_arquivo_atomico(target, "<html>ok</html>")
            self.assertEqual(published, target)
            self.assertEqual(target.read_text(encoding="utf-8"), "<html>ok</html>")
            self.assertFalse(list(target.parent.glob("*.tmp")))

    def test_existing_file_is_replaced_after_acl_preparation(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "inventario.json"
            target.write_text("anterior", encoding="utf-8")
            with patch.object(core_logic, "_ajustar_acl_publicacao_atomica") as acl:
                core_logic._gravar_arquivo_atomico(target, "novo")
            self.assertEqual(target.read_text(encoding="utf-8"), "novo")
            temporary = Path(acl.call_args.args[0])
            self.assertNotEqual(temporary, target)
            self.assertEqual(temporary.parent, target.parent)
            self.assertFalse(temporary.exists())

    def test_acl_failure_happens_before_replace_and_preserves_previous(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "inventario.json"
            target.write_text("anterior", encoding="utf-8")
            with patch.object(
                core_logic, "_ajustar_acl_publicacao_atomica",
                side_effect=PermissionError("ACL fixture"),
            ), patch.object(core_logic.os, "replace") as replace:
                with self.assertRaises(PermissionError):
                    core_logic._gravar_arquivo_atomico(target, "novo")
            replace.assert_not_called()
            self.assertEqual(target.read_text(encoding="utf-8"), "anterior")
            self.assertFalse(list(Path(temp).glob("*.tmp")))

    def test_final_read_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "relatorio.html"
            real_validator = core_logic._validar_leitura_artefato
            calls = []

            def validate(path, **kwargs):
                calls.append(Path(path))
                if len(calls) == 2:
                    raise PermissionError("leitura final negada")
                return real_validator(path, **kwargs)

            with patch.object(core_logic, "_validar_leitura_artefato", side_effect=validate):
                with self.assertRaises(PermissionError):
                    core_logic._gravar_arquivo_atomico(target, "conteúdo")
            self.assertEqual(calls[-1], target)

    def test_inventory_remains_readable_after_two_atomic_restarts(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "dados" / "empresa" / "inventario_empresa.json"
            with patch.object(core_logic, "ARQUIVO_INVENTARIO", str(target)):
                core_logic._salvar_inventario_empresa({"estado": 1})
                self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["estado"], 1)
                core_logic._salvar_inventario_empresa({"estado": 2})
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["estado"], 2)
            self.assertFalse(list(target.parent.glob("*.tmp")))


class WindowsAclPolicyTests(unittest.TestCase):
    def test_windows_volume_capability_uses_persistent_acl_flag(self):
        class Kernel32Fixture:
            @staticmethod
            def GetVolumePathNameW(_path, buffer, _size):
                buffer.value = "C:\\"
                return 1

            @staticmethod
            def GetVolumeInformationW(_root, _name, _name_size, _serial,
                                      _component_size, flags, _fs_name, _fs_size):
                flags._obj.value = 0x00000008
                return 1

        windll = type("WindllFixture", (), {"kernel32": Kernel32Fixture()})()
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic.ctypes, "windll", windll, create=True
        ):
            self.assertTrue(core_logic._volume_suporta_acl_persistente(r"C:\Teste\a.tmp"))

    def test_ntfs_resets_inheritance_grants_only_user_and_admin_and_verifies(self):
        responses = [
            subprocess.CompletedProcess([], 0, b'"HOST\\user","S-1-5-21-1-2-3-1001"\r\n', b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"acl ok", b""),
        ]
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic, "_volume_suporta_acl_persistente", return_value=True
        ), patch.object(core_logic.subprocess, "run", side_effect=responses) as run:
            core_logic._ajustar_acl_publicacao_atomica(r"C:\Teste Unicode\relatório.tmp")

        reset_args = run.call_args_list[1].args[0]
        grant_args = run.call_args_list[2].args[0]
        query_args = run.call_args_list[3].args[0]
        self.assertIn("/reset", reset_args)
        self.assertIn("/inheritance:e", grant_args)
        self.assertIn("*S-1-5-21-1-2-3-1001:M", grant_args)
        self.assertIn("*S-1-5-32-544:F", grant_args)
        self.assertFalse(any("Everyone" in value or "S-1-1-0" in value for value in grant_args))
        self.assertEqual(query_args, ["icacls.exe", r"C:\Teste Unicode\relatório.tmp"])
        for call in run.call_args_list:
            self.assertIs(call.kwargs["shell"], False)
            self.assertIn("timeout", call.kwargs)

    def test_acl_less_volume_is_safe_noop(self):
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic, "_volume_suporta_acl_persistente", return_value=False
        ), patch.object(core_logic.subprocess, "run") as run:
            core_logic._ajustar_acl_publicacao_atomica(r"E:\relatorio.tmp")
        run.assert_not_called()

    def test_ntfs_icacls_failure_is_explicit(self):
        responses = [
            subprocess.CompletedProcess([], 0, b'"HOST\\user","S-1-5-21-1-2-3-1001"\r\n', b""),
            subprocess.CompletedProcess([], 5, b"", b"Acesso negado"),
        ]
        with patch.object(core_logic.os, "name", "nt"), patch.object(
            core_logic, "_volume_suporta_acl_persistente", return_value=True
        ), patch.object(core_logic.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(PermissionError, "ACL segura"):
                core_logic._ajustar_acl_publicacao_atomica(r"C:\relatorio.tmp")


class ReportPublicationTests(unittest.TestCase):
    def _report_context(self, temp, *, startfile_error=None):
        stack = ExitStack()
        report_dir = Path(temp) / "Relatórios com espaço e ação"
        stack.enter_context(patch.object(core_logic, "PASTA_RELATORIOS", report_dir))
        stack.enter_context(patch.object(
            core_logic, "ARQUIVO_INVENTARIO", str(Path(temp) / "inventario.json")
        ))
        stack.enter_context(patch.object(
            core_logic.ModuloSistema, "obter_informacoes_sistema",
            return_value={"HostName": "fixture", "Particoes": []},
        ))
        stack.enter_context(patch.object(
            core_logic.ModuloSistema, "obter_hardware_detalhado",
            return_value={"RAM": [], "Discos": []},
        ))
        stack.enter_context(patch.object(
            core_logic.ModuloRede, "listar_adaptadores_detalhados", return_value=[]
        ))
        stack.enter_context(patch.object(
            core_logic, "executar_powershell", return_value=Mock(returncode=0, stdout="{}")
        ))
        stack.enter_context(patch.object(core_logic.ModuloEmpresa, "carregar_perfil", return_value={}))
        stack.enter_context(patch.object(core_logic.ModuloCentralizacao, "carregar_config", return_value={}))
        stack.enter_context(patch.object(core_logic.ModuloCentralizacao, "carregar_coletas", return_value=[]))
        start = stack.enter_context(patch.object(
            core_logic.os, "startfile", create=True, side_effect=startfile_error
        ))
        return stack, start

    def test_report_opens_the_valid_final_path(self):
        with tempfile.TemporaryDirectory() as temp:
            stack, start = self._report_context(temp)
            with stack:
                ok, path = core_logic.gerar_relatorio(interativo=False)
            self.assertTrue(ok, path)
            final = Path(path)
            self.assertTrue(final.is_file())
            self.assertGreater(final.stat().st_size, 0)
            self.assertIn("<html", final.read_text(encoding="utf-8"))
            start.assert_called_once_with(os.path.abspath(final))

    def test_report_open_error_is_clear_and_not_marked_success(self):
        with tempfile.TemporaryDirectory() as temp:
            stack, _ = self._report_context(temp, startfile_error=PermissionError("fixture"))
            with stack:
                ok, message = core_logic.gerar_relatorio(interativo=False)
            self.assertFalse(ok)
            self.assertIn("não pôde ser aberto", message)
            self.assertIn("Verifique o acesso", message)

    def test_report_and_inventory_share_corrected_writer(self):
        source = Path(core_logic.__file__).read_text(encoding="utf-8")
        self.assertIn("_ajustar_acl_publicacao_atomica(temporario)", source)
        self.assertIn("_gravar_arquivo_atomico(arquivo_saida, html_relatorio)", source)
        self.assertIn("return _gravar_arquivo_atomico(ARQUIVO_INVENTARIO, conteudo)", source)


class ScopeAndMetadataTests(unittest.TestCase):
    def test_metadata_and_windows_update_hardening_remain_intact(self):
        self.assertEqual(release_metadata.PHASE_ID, "2B")
        self.assertEqual(release_metadata.status_label("Fonte"), "Configurador TI 2B | Fonte")
        self.assertEqual(release_metadata.status_label("EXE"), "Configurador TI 2B | EXE")
        source = Path(core_logic.__file__).read_text(encoding="utf-8")
        self.assertIn("def executar_windows_update_com_progresso", source)
        self.assertIn("MODO_WINDOWS_UPDATE_ELEVADO", source)
        self.assertIn("KILL_ON_JOB_CLOSE", source)
        self.assertIn('shell=False', source)


if __name__ == "__main__":
    unittest.main()
