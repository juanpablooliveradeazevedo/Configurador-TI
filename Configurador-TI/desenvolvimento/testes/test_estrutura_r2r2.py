"""Migração/estrutura: fixtures isoladas; sem coleta nativa nem dados do usuário."""
import copy, json, os, sys, tempfile, shutil, subprocess, unittest, runpy, time
from pathlib import Path
from unittest.mock import patch, Mock
from contextlib import ExitStack
import test_ux_global as base
import test_ux_r2r1 as prior
import app_paths as paths
import network_intelligence as net
import triagem_interativa as triagem

class PathTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'Configurador_TI';self.root.mkdir()
    def tearDown(self):self.temp.cleanup()
    def test_first_run_absolute_paths_and_no_empty_json(self):
        p=paths.PortablePaths(self.root)
        for name,relative in paths.FILE_MAP.items():
            result=p.file(name);self.assertEqual(result,self.root/relative);self.assertTrue(result.parent.is_dir());self.assertFalse(result.exists())
        self.assertEqual(p.directory('relatorios'),self.root/'relatorios')
        self.assertEqual(p.directory('coletas','coletas_centralizadas'),self.root/'coletas')
    def test_migrate_all_known_files_bytes_and_restart(self):
        raw=b'{"fixture":"untouched", "schema":1}\n'
        for name in paths.FILE_MAP:(self.root/name).write_bytes(raw)
        p=paths.PortablePaths(self.root)
        for name,relative in paths.FILE_MAP.items():
            result=p.file(name);self.assertEqual(result.read_bytes(),raw);self.assertFalse((self.root/name).exists())
            self.assertEqual(paths.PortablePaths(self.root).file(name),result)
            self.assertEqual(result.read_bytes(),raw)
        self.assertEqual(sum('PATHS_MIGRADO' in e for e in p.events),len(paths.FILE_MAP))
        logger=Mock();p.log_events(logger);self.assertEqual(logger.info.call_count,len(paths.FILE_MAP));self.assertFalse(p.events)
    def test_conflict_never_overwrites_or_merges(self):
        p=paths.PortablePaths(self.root);old=self.root/'perfis_dns.json';old.write_bytes(b'legacy')
        new=self.root/paths.FILE_MAP[old.name];new.parent.mkdir(parents=True);new.write_bytes(b'new')
        self.assertEqual(p.file(old.name),new);self.assertEqual(old.read_bytes(),b'legacy');self.assertEqual(new.read_bytes(),b'new')
        self.assertIn('CONFLITO',p.events[0]);logger=Mock();p.log_events(logger);logger.warning.assert_called_once()
    def test_locked_store_preserved(self):
        old=self.root/'inteligencia_rede.json';old.write_text('{}');lock=old.with_suffix('.lock');lock.write_text('occupied')
        with self.assertRaises(RuntimeError):paths.PortablePaths(self.root).file(old.name)
        self.assertEqual(old.read_text(),'{}');self.assertEqual(lock.read_text(),'occupied')
        self.assertFalse((self.root/paths.FILE_MAP[old.name]).exists())
    def test_move_failure_preserves_legacy_and_releases_owned_locks(self):
        old=self.root/'perfis_dns.json';old.write_bytes(b'preservado')
        method='rename' if os.name=='nt' else 'link'
        with patch.object(paths.os,method,side_effect=PermissionError('fixture')):
            self.assertEqual(paths.PortablePaths(self.root).file(old.name),old)
        self.assertEqual(old.read_bytes(),b'preservado');self.assertFalse(list(self.root.glob('*.lock')))
    def test_race_destination_created_keeps_both(self):
        old=self.root/'perfis_dns.json';old.write_bytes(b'old');new=self.root/paths.FILE_MAP[old.name]
        def occupied(*args,**kwargs):new.write_bytes(b'concurrent');raise FileExistsError()
        with patch.object(paths.os,'rename' if os.name=='nt' else 'link',side_effect=occupied):
            self.assertEqual(paths.PortablePaths(self.root).file(old.name),new)
        self.assertEqual(old.read_bytes(),b'old');self.assertEqual(new.read_bytes(),b'concurrent')
    def test_legacy_directories_and_conflict(self):
        p=paths.PortablePaths(self.root);old=self.root/'backups_dns';old.mkdir();(old/'fixture.json').write_text('old')
        new=self.root/'dados/backups/dns';new.mkdir(parents=True)
        self.assertEqual(p.directory('dados/backups/dns','backups_dns'),old)
        (new/'new.json').write_text('new')
        self.assertEqual(p.directory('dados/backups/dns','backups_dns'),new)
        self.assertEqual((old/'fixture.json').read_text(),'old');self.assertIn('CONFLITO',p.events[-1])
    def test_symlink_destination_refused(self):
        target=Path(self.temp.name)/'outside';target.mkdir()
        try:(self.root/'dados').symlink_to(target,target_is_directory=True)
        except OSError:self.skipTest('Criação de symlink não disponível')
        with self.assertRaises(RuntimeError):paths.PortablePaths(self.root).file('perfis_dns.json')
        self.assertFalse(list(target.iterdir()))
    def test_readonly_parent_keeps_previous_fallback_contract(self):
        p=paths.PortablePaths(self.root)
        with patch.object(p,'_parent',side_effect=PermissionError()):
            self.assertEqual(p.file('perfis_dns.json'),self.root/'perfis_dns.json')
            self.assertEqual(p.directory('relatorios'),self.root)
        self.assertTrue(all('FALLBACK' in e for e in p.events))
    def test_history_store_migrated_and_existing_fallback(self):
        old=self.root/'inteligencia_rede.json';old.write_text(json.dumps({'schema':1,'scopes':{},'fixture':12}))
        migrated=paths.PortablePaths(self.root).file(old.name)
        store=net.HistoryStore(migrated.parent);self.assertEqual(store.read()[0]['fixture'],12)
        store.transaction(lambda data:data.update(fixture=13))
        self.assertEqual(net.HistoryStore(paths.PortablePaths(self.root).file(old.name).parent).read()[0]['fixture'],13)
        fallback=Path(self.temp.name)/'fallback';(fallback/'ConfiguradorTI').mkdir(parents=True)
        (fallback/'ConfiguradorTI/inteligencia_rede.json').write_text('{"schema":1,"scopes":{},"fixture":14}')
        fresh=Path(self.temp.name)/'fresh';fresh.mkdir()
        self.assertEqual(net.HistoryStore(paths.PortablePaths(fresh).file(old.name).parent,fallback).read()[0]['fixture'],14)
    def test_frozen_uses_executable_not_meipass(self):
        executable=self.root/'ConfiguradorTI.exe'
        with patch.object(paths.sys,'frozen',True,create=True),patch.object(paths.sys,'executable',str(executable)),patch.object(paths.sys,'_MEIPASS','/different/temp',create=True):
            self.assertEqual(paths.runtime_root(),self.root)
    def test_source_restart_moved_directory_and_bootstrap_imports(self):
        app=self.root
        for p in base.SOURCE.iterdir():
            if p.suffix in ('.py','.pyw','.qss'):shutil.copy2(p,app/p.name)
        (app/'perfil_empresa.json').write_text('{"empresa":"Fixture preservada"}')
        code='''import core_logic as c, main_gui, operational_ui, ui_components, network_intelligence, network_intelligence_gui, hostname_identification, triagem_interativa
import runpy, json
from pathlib import Path
runpy.run_path(str(Path(c.DIRETORIO_BASE)/'main_gui.pyw'),run_name='bootstrap_test')
print(json.dumps({'root':str(c.DIRETORIO_BASE),'perfil':c.ModuloEmpresa.carregar_perfil(),'log':c.ARQUIVO_LOG,'reports':str(c.PASTA_RELATORIOS)},ensure_ascii=False))'''
        for iteration in range(2):
            if iteration:
                moved=Path(self.temp.name)/'pasta movida ç';app.rename(moved);app=moved
            run=subprocess.run([sys.executable,'-c',code],cwd=self.temp.name,env={**os.environ,'PYTHONPATH':str(app),'QT_QPA_PLATFORM':'offscreen'},capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            result=json.loads(run.stdout.strip().splitlines()[-1]);self.assertEqual(Path(result['root']),app)
            self.assertEqual(result['perfil']['empresa'],'Fixture preservada')
            self.assertEqual(Path(result['log']),app/'logs/configurador_ti.log')
            self.assertEqual(Path(result['reports']),app/'relatorios')
            self.assertTrue((app/'logs/configurador_ti.log').exists());self.assertFalse((app/'perfil_empresa.json').exists())
    def test_launcher_build_static_contract(self):
        source=base.SOURCE;cmd=(source/'INICIAR_CONFIGURADOR_TI.cmd').read_text();bat=(source/'CRIAR_EXE_E_PENDRIVE_TI_v5_0.bat').read_text()
        self.assertIn('cd /d "%~dp0"',cmd);self.assertIn('main_gui.pyw',cmd)
        for name in ('pyw','pythonw','py','python'):self.assertIn('where '+name,cmd)
        self.assertNotIn('runas',cmd.casefold())
        for arg in ('--onefile','--noconsole','style.qss','main_gui.pyw','app_paths.py'):self.assertIn(arg,bat)
        self.assertNotIn('rmdir',bat.casefold());self.assertNotIn('copy /y core_logic',bat)
        # R2-R3: montagem agora delegada ao helper, com whitelist e ZIP automático.
        self.assertIn('build_portatil.py',bat)
        helper=(base.SOURCE/'desenvolvimento'/'build_portatil.py').read_text()
        self.assertIn("('ConfiguradorTI.exe', 'LEIA-ME.txt')",helper)
        self.assertNotIn('copytree',helper)
    @unittest.skipUnless(os.name=='nt','PENDENTE DE WINDOWS REAL: execução CMD/pythonw nativa')
    def test_native_cmd_relay(self):
        shutil.copy2(base.SOURCE/'INICIAR_CONFIGURADOR_TI.cmd',self.root/'INICIAR_CONFIGURADOR_TI.cmd')
        (self.root/'main_gui.pyw').write_text("from pathlib import Path\nPath(__file__).with_name('inicio.ok').write_text('ok')\n")
        subprocess.run(['cmd','/d','/c',str(self.root/'INICIAR_CONFIGURADOR_TI.cmd')],cwd=self.temp.name,timeout=15,check=True)
        for _ in range(50):
            if (self.root/'inicio.ok').exists():break
            time.sleep(.1)
        self.assertTrue((self.root/'inicio.ok').exists())

class InterfaceTests(unittest.TestCase):
    def setUp(self):self.case=base.UxTests();self.case.setUp();self.w=self.case.w
    def tearDown(self):self.case.tearDown()
    def test_dns_exact_duplicates_order_and_raw_intact(self):
        dns=['fe80::1','fe80::1','192.168.15.1','192.168.15.1','FE80::1','fe80::1%12','fe80::1%13']
        data={**prior.SNAPSHOT,'DNS':dns};raw=copy.deepcopy(data)
        with patch.object(self.w,'_run',side_effect=AssertionError('Nova consulta')):
            self.w._aplicar_snapshot_monitoramento((True,data,'fixture'))
        self.assertEqual(self.w.monitor_dns.text(),'fe80::1\n192.168.15.1\nFE80::1\nfe80::1%12\nfe80::1%13')
        self.assertEqual(data,raw);self.assertEqual(self.w.monitor_dns_validacao.text(),'Falha')
        self.assertEqual(self.w.monitor_internet.text(),'Online (19 ms)')
    def test_reports_new_location_real_render_with_mocked_collection(self):
        c=base.gui.core_logic
        with ExitStack() as stack:
            for name in ('obter_informacoes_sistema','obter_hardware_detalhado'):
                stack.enter_context(patch.object(c.ModuloSistema,name,return_value={}))
            stack.enter_context(patch.object(c.ModuloRede,'listar_adaptadores_detalhados',return_value=[]))
            stack.enter_context(patch.object(c,'executar_powershell',return_value=Mock(returncode=0,stdout='{}')))
            stack.enter_context(patch.object(c.os,'startfile',create=True))
            stack.enter_context(patch('builtins.input',side_effect=AssertionError('Interativo')))
            ok,path=c.gerar_relatorio(interativo=False)
        self.assertTrue(ok,path);self.assertEqual(Path(path).parent,c.PASTA_RELATORIOS);self.assertIn('<html',Path(path).read_text())
        with patch.object(c.os,'startfile',create=True) as start:self.w._abrir_pasta_relatorios();start.assert_called_once_with(str(c.PASTA_RELATORIOS))
    def test_worker_no_overlap_cooperative_close(self):
        import threading
        from PyQt6.QtGui import QCloseEvent
        from PyQt6.QtCore import QTimer
        from PyQt6.QtTest import QTest
        started=threading.Event();cancelled=threading.Event()
        def operation(cancel_callback=None):
            started.set()
            limit=time.monotonic()+3
            while time.monotonic()<limit:
                if cancel_callback():cancelled.set();return
                time.sleep(.005)
        w=self.w
        worker=w._run(operation,operation_key='fixture_close',blocks_navigation=False)
        self.assertIsNotNone(worker);self.assertTrue(started.wait(1))
        self.assertIsNone(w._run(operation,operation_key='fixture_close',silent_if_busy=True))
        event=QCloseEvent()
        with patch.object(base.gui.QMessageBox,'warning',return_value=base.gui.QMessageBox.StandardButton.Yes):
            w.closeEvent(event)
        self.assertTrue(event.isAccepted());self.assertTrue(w._closing)
        self.assertFalse(any(t.isActive() for t in w.findChildren(QTimer)))
        limit=time.monotonic()+3
        while w._workers and time.monotonic()<limit:
            base.app.processEvents();QTest.qWait(5)
        self.assertTrue(cancelled.is_set());self.assertFalse(w._workers)
        self.assertIsNone(w._run(operation))

    def test_triage_new_path_and_restart(self):
        c=base.gui.core_logic;store=self.w._revisoes_tecnicas
        item={'Tipo':'Processo','Nome':'Fixture','Caminho':r'C:\Fixture\app.exe','Classificacao':'Informativo','Existe':True,'TamanhoBytes':123,'ModificadoUtc':'2026-09-11T12:00:00Z','Assinatura':'Não assinada'}
        store.reaplicar([item]);result=store.alterar(item,nota='Nota R2-R2',prioridade=True)
        self.assertIn('salva localmente',result)
        self.assertEqual(store.caminho.parent,c.PASTA_TRIAGEM)
        again=triagem.RevisoesLocais(c.PASTA_TRIAGEM,c.ModuloSistema._sanitizar_comando_analise_defensiva,c.logger,escopo=store.escopo)
        again.reaplicar([item]);self.assertEqual(again.estado(item)['nota'],'Nota R2-R2');self.assertTrue(again.estado(item)['prioridade'])

if __name__=='__main__':unittest.main(verbosity=2)
