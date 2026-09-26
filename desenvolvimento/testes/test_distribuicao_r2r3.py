"""Contratos R2-R3; PE sintético existe apenas dentro de TemporaryDirectory."""
import copy
import importlib.util
import json
import logging
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_ux_global as base
import app_status as status
from app_paths import PortablePaths
spec=importlib.util.spec_from_file_location('build_portatil',base.SOURCE/'desenvolvimento/build_portatil.py')
pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)

class StatusTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='Configurador TI portátil ç ')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def state(self,**changes):
        args=dict(root=self.root,data_paths=[self.root/'dados/configuracoes'],log_path=self.root/'logs/configurador_ti.log',report_path=self.root/'relatorios',collection_path=self.root/'coletas',qss_loaded=True,administrator=False,log_active=True)
        args.update(changes);return status.environment_status(**args)
    def layout(self):
        paths=PortablePaths(self.root)
        for name in ('configurador_ti_config.json','configurador_ti.log'):paths.file(name)
        paths.directory('relatorios');paths.directory('coletas','coletas_centralizadas')
        return paths
    def test_first_use_empty_directories_and_source_status(self):
        self.layout();before=set(self.root.rglob('*'));s=self.state()
        self.assertEqual(before,set(self.root.rglob('*')))
        self.assertFalse(any(p.is_file() for p in before))
        self.assertTrue(s['data_ok']);self.assertTrue(s['logs']['ok']);self.assertTrue(s['reports']['ok']);self.assertTrue(s['collections']['ok']);self.assertFalse(s['warnings'])
        self.assertEqual(s['mode'],'Fonte');self.assertIn('2B',s['version']);self.assertEqual(s['build'],'2026-09-25');self.assertEqual(s['administrator'],'Não')
    def test_frozen_uses_executable_folder_not_meipass(self):
        import app_paths
        exe=self.root/'ConfiguradorTI.exe'
        with patch.object(sys,'frozen',True,create=True),patch.object(sys,'executable',str(exe)),patch.object(sys,'_MEIPASS','/temporary/_MEI_example',create=True):
            self.assertEqual(app_paths.runtime_root(),self.root)
            self.layout();self.assertEqual(self.state()['mode'],'EXE')
            self.assertNotIn('_MEI',json.dumps(self.state()))
    def test_failures_visible_and_no_persistent_changes(self):
        self.layout();sentinel=self.root/'dados/configuracoes/config.json';sentinel.write_bytes(b'UNCHANGED')
        with patch.object(status.tempfile,'TemporaryFile',side_effect=PermissionError('SECRET_SENTINEL')):
            s=self.state()
        self.assertFalse(s['data_ok']);self.assertFalse(s['logs']['ok']);self.assertFalse(s['reports']['ok']);self.assertTrue(s['warnings']);self.assertNotIn('SECRET_SENTINEL',json.dumps(s));self.assertEqual(sentinel.read_bytes(),b'UNCHANGED')
    def test_missing_folders_and_missing_qss(self):
        s=self.state(qss_loaded=False,log_active=False)
        self.assertFalse(s['data_ok']);self.assertFalse(s['qss_ok']);self.assertGreaterEqual(len(s['warnings']),4)
        self.assertEqual(list(self.root.iterdir()),[])
    def test_status_never_reads_credentials_or_starts_processes(self):
        self.layout();secret=self.root/'dados/configuracoes/centralizacao_ti.json';secret.write_text('{"senha":"SECRET_SENTINEL"}')
        with patch.object(Path,'read_text',side_effect=AssertionError('Leitura indevida')),patch.object(Path,'read_bytes',side_effect=AssertionError('Leitura indevida')),patch('subprocess.run',side_effect=AssertionError('Processo indevido')),patch('socket.create_connection',side_effect=AssertionError('Rede indevida')):
            s=self.state()
        self.assertNotIn('SECRET_SENTINEL',json.dumps(s));self.assertEqual(s['administrator'],'Não')
    def test_log_handler_effective_fallback_and_no_handler(self):
        folder=self.root/'fallback';folder.mkdir();log=folder/'log.txt'
        logger=logging.Logger('fixture');handler=logging.FileHandler(log);logger.addHandler(handler)
        self.addCleanup(handler.close)
        path,active=status.active_log_file(logger,'unavailable');self.assertTrue(active);self.assertEqual(path,log)
        self.layout();s=self.state(log_path=path,log_active=active);self.assertTrue(s['logs']['ok']);self.assertTrue(any('alternativo' in x for x in s['warnings']))
        handler.close();self.assertFalse(status.active_log_file(logger,log)[1])
    def test_legacy_bytes_conflict_and_status(self):
        old=self.root/'perfis_dns.json';old.write_bytes(b'{"legado":"preservado"}')
        paths=PortablePaths(self.root);new=paths.file(old.name)
        self.assertEqual(new.read_bytes(),b'{"legado":"preservado"}');self.assertFalse(old.exists())
        old.write_bytes(b'CONFLITO');self.assertEqual(PortablePaths(self.root).file(old.name),new);self.assertEqual(old.read_bytes(),b'CONFLITO')
        self.layout();s=self.state(data_paths=[self.root]);self.assertTrue(s['data_ok']);self.assertTrue(any('legado' in x for x in s['warnings']))

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='Configurador TI pacote ç ');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.output=self.root/'dist';self.output.mkdir()
        self.exe=self.root/'fixture.exe';header=bytearray(64);header[:2]=b'MZ';struct.pack_into('<I',header,60,64);self.exe.write_bytes(header+b'PE\0\0SYNTHETIC_TEST_ONLY_NOT_EXECUTABLE')
        self.readme=base.SOURCE/'distribuicao/LEIA-ME.txt'
    def build(self):return pack.build_portable(self.exe,self.readme,self.output)
    def test_whitelist_archive_byte_equality_and_extract(self):
        import zipfile
        (self.output/'secret.py').write_text('not packaged')
        folder,archive=self.build();self.assertEqual(sorted(p.name for p in folder.iterdir()),['ConfiguradorTI.exe','LEIA-ME.txt'])
        with zipfile.ZipFile(archive) as z:
            self.assertEqual(sorted(z.namelist()),['Configurador_TI/ConfiguradorTI.exe','Configurador_TI/LEIA-ME.txt']);self.assertIsNone(z.testzip());self.assertEqual(z.read('Configurador_TI/ConfiguradorTI.exe'),self.exe.read_bytes())
            z.extractall(self.root/'extraído ç')
        self.assertEqual((self.root/'extraído ç/Configurador_TI/LEIA-ME.txt').read_bytes(),self.readme.read_bytes())
    def test_existing_folder_zip_and_data_preserved_numbered(self):
        prior=self.output/'Configurador_TI_PORTATIL';prior.mkdir();(prior/'dados.json').write_bytes(b'SAVED')
        (self.output/'Configurador_TI_PORTATIL_1.zip').write_bytes(b'OLDZIP')
        folder,archive=self.build();self.assertEqual(folder.name,'Configurador_TI_PORTATIL_2');self.assertEqual(archive.stem,folder.name)
        self.assertEqual((prior/'dados.json').read_bytes(),b'SAVED');self.assertEqual((self.output/'Configurador_TI_PORTATIL_1.zip').read_bytes(),b'OLDZIP')
        self.assertEqual(self.build()[0].name,'Configurador_TI_PORTATIL_3')
    def test_collision_during_reservation_preserves_other_folder(self):
        original=Path.mkdir;once=[True]
        def racing(path,*a,**kw):
            if path.name=='Configurador_TI_PORTATIL' and once[0]:
                once[0]=False;original(path);(path/'old.txt').write_bytes(b'OTHER');raise FileExistsError()
            return original(path,*a,**kw)
        with patch.object(Path,'mkdir',racing):folder,archive=self.build()
        self.assertEqual(folder.name,'Configurador_TI_PORTATIL_1');self.assertEqual((self.output/'Configurador_TI_PORTATIL/old.txt').read_bytes(),b'OTHER');self.assertFalse((self.output/'Configurador_TI_PORTATIL.zip').exists())
    def test_partial_copy_failure_preserves_previous_and_no_false_zip(self):
        prior=self.output/'Configurador_TI_PORTATIL.zip';prior.write_bytes(b'PREVIOUS')
        with patch.object(pack.shutil,'copy2',side_effect=PermissionError('fixture')):
            with self.assertRaises(PermissionError):self.build()
        self.assertEqual(prior.read_bytes(),b'PREVIOUS');self.assertFalse((self.output/'Configurador_TI_PORTATIL_1.zip').exists());self.assertTrue((self.output/'Configurador_TI_PORTATIL_1').exists())
    def test_invalid_exe_rejected_without_distribution(self):
        self.exe.write_bytes(b'NOT_AN_EXE')
        with self.assertRaises(ValueError):self.build()
        self.assertEqual(list(self.output.iterdir()),[])
    def test_final_readme_short_and_no_development_instructions(self):
        text=self.readme.read_text();self.assertIn('Extraia o ZIP',text);self.assertIn('Abra ConfiguradorTI.exe',text)
        for x in ('dados','logs','relatorios','coletas'):self.assertIn(x,text)
        for x in ('PyInstaller','main_gui','BAT','pip','VS Code'):self.assertNotIn(x,text)
        self.assertLess(len(text.splitlines()),20)
    def test_cli_from_external_cwd_with_spaces_and_accents(self):
        result=subprocess.run([sys.executable,str(base.SOURCE/'desenvolvimento/build_portatil.py'),'--exe',str(self.exe),'--readme',str(self.readme),'--output',str(self.output)],cwd=self.temp.name,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('Configurador_TI_PORTATIL.zip',result.stdout);self.assertIn('SHA-256',result.stdout)

class InterfaceTests(unittest.TestCase):
    def setUp(self):
        base.app.setProperty('configurador_ti_qss_loaded',True)
        self.case=base.UxTests();self.case.setUp();self.w=self.case.w
    def tearDown(self):
        if getattr(self.w,'_configurador_ti_about',None):self.w._configurador_ti_about.close()
        self.case.tearDown()
    def test_about_eleven_pages_no_new_collection_and_plain_paths(self):
        from PyQt6.QtCore import QTimer,Qt
        from PyQt6.QtWidgets import QLabel
        before=len(self.w.findChildren(QTimer))
        with patch.object(base.gui.core_logic,'executar_powershell',side_effect=AssertionError('Coleta indevida')),patch.object(self.w,'_run',side_effect=AssertionError('Worker indevido')):
            self.w.about_button.click();base.app.processEvents()
        self.assertEqual(self.w.pages.count(),21);self.assertEqual(len(self.w.findChildren(QTimer)),before);self.assertTrue(self.w._configurador_ti_environment['qss_ok'])
        labels=self.w._configurador_ti_about.findChildren(QLabel);text='\n'.join(x.text() for x in labels)
        self.assertIn('2B',text);self.assertIn('Fonte',text);self.assertIn('configurador_ti.log',text)
        for x in labels:
            if 'configurador_ti.log' in x.text():self.assertEqual(x.textFormat(),Qt.TextFormat.PlainText)
    def test_failure_banner_and_log_visible_without_modal(self):
        with patch.object(status.tempfile,'TemporaryFile',side_effect=PermissionError()),patch.object(base.gui.core_logic.logger,'warning') as warning,patch.object(base.gui.QMessageBox,'warning',side_effect=AssertionError('Modal')):
            s=self.w._atualizar_ambiente_configurador_ti()
        self.assertFalse(s['data_ok']);self.assertFalse(self.w.environment_notice.isHidden());self.assertIn('Atenção',self.w.version_label.text());self.assertTrue(warning.called)
    def test_main_loads_qss_version_and_local_status(self):
        from contextlib import ExitStack
        gui=base.gui
        captured=[]
        window_class=gui.MainWindow
        def create_window():
            w=window_class();captured.append(w);return w
        with ExitStack() as stack:
            stack.enter_context(patch.object(gui.core_logic,'despachar_modo_headless',return_value=None))
            stack.enter_context(patch.object(gui.core_logic,'registrar_evento_instancia'))
            for name in ('_pagina_dashboard','_carregar_adaptadores','_carregar_unidades','_run'):
                stack.enter_context(patch.object(window_class,name))
            stack.enter_context(patch.object(gui,'QApplication',return_value=base.app))
            gui.QApplication.instance.return_value=base.app
            stack.enter_context(patch.object(base.app,'exec',return_value=0))
            stack.enter_context(patch.object(gui,'MainWindow',side_effect=create_window))
            self.assertEqual(gui.main(),0)
        self.assertIn('2B',base.app.applicationVersion())
        self.assertTrue(base.app.property('configurador_ti_qss_loaded'))
        self.assertTrue(captured[0]._configurador_ti_environment['qss_ok'])
        captured[0].close();captured[0].deleteLater();base.app.processEvents()

    def test_theme_failure_is_reported(self):
        base.app.setProperty('configurador_ti_qss_loaded',False);s=self.w._atualizar_ambiente_configurador_ti()
        self.assertFalse(s['qss_ok']);self.assertTrue(any('style.qss' in x for x in s['warnings']))

if __name__=='__main__':unittest.main(verbosity=2)
