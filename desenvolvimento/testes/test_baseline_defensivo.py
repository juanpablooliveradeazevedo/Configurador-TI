"""Contratos determinísticos da referência temporal, disco e GUI; sem coleta real."""
import copy,json,logging,os,stat,tempfile,time,unittest,hashlib
from pathlib import Path
from unittest.mock import patch
import test_ux_global as base
import baseline_defensivo as bl
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QMessageBox

SCOPE='a'*64;OTHER='b'*64
sanitize=base.gui.core_logic.ModuloSistema._sanitizar_comando_analise_defensiva

def item(n=1,kind='Processo',**changes):
    d={'Tipo':kind,'Nome':f'app{n}.exe','NomeTecnico':f'svc{n}','Fonte':'Win32_Process' if kind=='Processo' else 'Win32_Service',
       'Caminho':fr'C:\Apps\app{n}.exe','CaminhoExibicao':fr'C:\Apps\app{n}.exe','Usuario':'USER',
       'Comando':fr'C:\Apps\app{n}.exe --quiet','Existe':True,'TamanhoBytes':123,'ModificadoUtc':'2026-09-14T10:00:00Z',
       'CriadoUtc':'2026-09-01T10:00:00Z','Assinatura':'Válida','Publisher':'Publisher','Classificacao':'Atenção','PID':str(n),'Id':f'analise-{n:05d}'}
    d.update(changes);return d

def result(items=None,**changes):
    d={'Sucesso':True,'Cancelada':False,'FontesIndisponiveis':[],'Defender':{'Disponivel':True},'Contexto':{'StartupUser':r'C:\StartupUser','StartupCommon':r'C:\StartupCommon'},'Itens':items if items is not None else [item()]}
    d.update(changes);return d

def reference(items=None):return bl.prepare(result(items),sanitize)

def counts(old,new):return bl.compare(reference(old),reference(new))['counts']

class ComparisonTests(unittest.TestCase):
    def test_same_collection(self):self.assertEqual(counts([item()],[item()])['Sem alteração'],1)
    def test_new(self):self.assertEqual(counts([item()],[item(),item(2)])['Novo'],1)
    def test_absent_available_not_removed_assertion(self):
        rows=bl.compare(reference([item()]),reference([]))['rows'];self.assertEqual(rows[0]['state'],'Ausente');self.assertIn('não confirma remoção',rows[0]['reason'])
    def test_mutable_metadata_is_changed_not_new_absent(self):
        r=bl.compare(reference(),reference([item(TamanhoBytes=456,Assinatura='Não assinada')]))
        self.assertEqual(r['counts']['Alterado'],1);self.assertEqual(r['counts']['Novo']+r['counts']['Ausente'],0)
        self.assertIn(('TamanhoBytes',123,456),r['rows'][0]['changes'])
    def test_ephemeral_fields_and_sha_do_not_change(self):
        changed=item(PID='999',ParentPID='777',Id='different',CriadoProcesso='tomorrow',Classificacao='Suspeito',SHA256='abc',Estado='Stopped',Nota='humana',Prioridade=True)
        self.assertEqual(counts([item()],[changed])['Sem alteração'],1)
    def test_path_case_and_separator_are_stable(self):self.assertEqual(counts([item()],[item(Caminho='c:/apps/APP1.EXE')])['Sem alteração'],1)
    def test_service_target_and_account_changes_match_logical_entity(self):
        original=item(kind='Serviço');changed={**original,'Caminho':r'C:\Other\app.exe','Usuario':'OTHER','Comando':'other.exe'}
        self.assertEqual(counts([original],[changed])['Alterado'],1)
    def test_task_command_change_and_ambiguous_actions(self):
        task=item(kind='Tarefa agendada',Fonte='Get-ScheduledTask',CaminhoTarefa='\\Folder\\',TipoAcao='Exec')
        self.assertEqual(counts([task],[{**task,'Comando':'changed.exe'}])['Alterado'],1)
        r=counts([task,task],[task]);self.assertEqual(r['Alterado'],0);self.assertEqual(r['Indeterminado'],3)
    def test_run_startup_associated_keys_have_provenance(self):
        for sample in [item(kind='Run',Fonte='HKCU / 64-bit',ContextoUsuario='HKCU'),item(kind='RunOnce',Fonte='HKLM / 64-bit',ContextoUsuario='HKLM'),item(kind='Startup',Fonte='Pasta Startup',ArquivoStartup=r'C:\Startup\Link.lnk',ContextoUsuario='USER'),item(kind='Arquivo associado',Fonte='Associado a Processo: app1.exe',OrigemTipo='Processo',OrigemNome='app1.exe')]:
            self.assertIsNotNone(bl.snapshot(sample,sanitize)['key'])
    def test_no_identity_by_name_alone(self):
        self.assertIsNone(bl.snapshot({'Tipo':'Processo','Nome':'x'},sanitize)['key'])
    def test_missing_source_blocks_absence(self):
        for errors in (['Processos:coleta_indisponivel'],['unknown'],None):
            cur=bl.prepare(result([],FontesIndisponiveis=errors),sanitize)
            r=bl.compare(reference(),cur);self.assertEqual(r['counts']['Ausente'],0);self.assertEqual(r['counts']['Indeterminado'],1)
    def test_missing_identity_blocks_same_type_absence(self):
        r=counts([item()],[item(Caminho='')]);self.assertEqual(r['Ausente'],0);self.assertEqual(r['Indeterminado'],2)
    def test_duplicates_both_sides_not_arbitrarily_matched(self):
        r=counts([item(),item()],[item(TamanhoBytes=999),item()]);self.assertEqual(r['Alterado']+r['Novo']+r['Ausente'],0);self.assertEqual(r['Indeterminado'],4)
    def test_missing_metadata_not_false_changed(self):
        r=counts([item()],[item(TamanhoBytes=None,ModificadoUtc='—',Assinatura='Não disponível')]);self.assertEqual(r['Alterado'],0);self.assertEqual(r['Indeterminado'],1)
    def test_known_change_with_missing_other_evidence(self):self.assertEqual(counts([item()],[item(TamanhoBytes=321,Assinatura='Não disponível')])['Alterado'],1)
    def test_partial_reference_accepted_only_after_success(self):
        self.assertTrue(bl.can_reference(result(FontesIndisponiveis=['Defender:status_indisponivel'])))
        self.assertFalse(bl.can_reference(result(Cancelada=True)))
        for bad in (None,{},result(Sucesso=False),result(Cancelada=True)):
            with self.assertRaises(bl.BaselineError):bl.prepare(bad,sanitize)
    def test_input_classification_triage_and_raw_untouched(self):
        data=result([item(ComandoOriginal='RAW_SECRET',Avaliacao='Requer investigação',Nota='nota',Prioridade=True)])
        before=copy.deepcopy(data);prepared=bl.prepare(data,sanitize);bl.compare(prepared,prepared)
        self.assertEqual(data,before);self.assertNotIn('RAW_SECRET',json.dumps(prepared));self.assertNotIn('Classificacao',json.dumps(prepared));self.assertNotIn('Avaliacao',json.dumps(prepared))
    def test_command_and_all_text_sanitized(self):
        prepared=reference([item(Comando='app --password SENTINEL_PASSWORD --token SENTINEL_TOKEN',Publisher='token=SENTINEL_PUBLISHER',ComandoOriginal='NEVER_PERSIST')])
        text=json.dumps(prepared)
        for secret in ('SENTINEL_PASSWORD','SENTINEL_TOKEN','SENTINEL_PUBLISHER','NEVER_PERSIST','ComandoOriginal'):self.assertNotIn(secret,text)
    def test_comparison_cancellation(self):
        with self.assertRaises(bl.BaselineError):bl.compare(reference(),reference(),lambda:True)
    def test_no_file_hash_or_target_io(self):
        with patch.object(Path,'open',side_effect=AssertionError('Alvo aberto')),patch.object(bl.os,'open',side_effect=AssertionError('Arquivo aberto')):
            r=bl.compare(reference(),reference())
        self.assertEqual(r['counts']['Sem alteração'],1)

    def test_800_items_linear_and_unchanged(self):
        items=[item(n) for n in range(800)];t=time.perf_counter();p=reference(items);r=bl.compare(p,p);elapsed=time.perf_counter()-t
        self.assertEqual(r['counts']['Sem alteração'],800);self.assertLess(elapsed,2);print('BASELINE 800 snapshot+comparação:',round(elapsed,4))

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='Configurador TI baseline ç ');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.store=bl.BaselineStore(self.root,SCOPE,sanitize,logging.Logger('test'));self.prepared=reference()
    def save(self,**changes):
        args=dict(explicit=True);args.update(changes);return self.store.save(self.prepared,self.store.load()['token'],**args)
    def test_no_baseline_no_creation(self):
        self.assertEqual(self.store.load()['state'],'inexistente');self.assertFalse(self.store.path.exists());self.assertFalse((self.root/'dados').exists())
    def test_create_load_restart(self):
        saved=self.save();again=bl.BaselineStore(self.root,SCOPE,sanitize,logging.Logger('test')).load();self.assertEqual(saved,again);self.assertEqual(again['reference']['records'],self.prepared['records'])
    def test_action_and_substitution_explicit(self):
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,None)
        info=self.save();before=self.store.path.read_bytes()
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,info['token'],explicit=True)
        self.assertEqual(self.store.path.read_bytes(),before);self.save(replace=True)
    def test_different_scope_not_applied_and_preserved(self):
        self.save();other=bl.BaselineStore(self.root,OTHER,sanitize,logging.Logger('test'));info=other.load();self.assertEqual(info['state'],'incompatível');self.assertIsNone(info['reference'])
        other.save(reference([item(2)]),info['token'],explicit=True)
        self.assertEqual(self.store.load()['reference']['records'],self.prepared['records']);self.assertEqual(other.load()['reference']['records'][0]['evidence']['Nome'],'app2.exe')
    def test_corrupt_json_preserved_blocks_read_and_write(self):
        self.store.path.parent.mkdir(parents=True);self.store.path.write_bytes(b'{INVALID SECRET')
        with self.assertRaises(bl.BaselineError):self.store.load()
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,None,explicit=True)
        self.assertEqual(self.store.path.read_bytes(),b'{INVALID SECRET')
    def test_strict_schema_duplicate_unknown_fields_and_types(self):
        self.save();document=json.loads(self.store.path.read_bytes())
        bad=copy.deepcopy(document);bad['scopes'][SCOPE]['records'][0]['evidence']['ComandoOriginal']='SECRET'
        cases=[json.dumps(bad).encode(),b'{"schema":1,"schema":1,"scopes":{}}',b'{"schema":true,"scopes":{}}']
        bad=copy.deepcopy(document);bad['scopes'][SCOPE]['records'][0]['evidence']['Existe']=1;cases.append(json.dumps(bad).encode())
        for raw in cases:
            self.store.path.write_bytes(raw)
            with self.assertRaises(bl.BaselineError):self.store.load()
            self.assertEqual(self.store.path.read_bytes(),raw)
    def test_atomic_replace_failure_preserves_bytes(self):
        self.save();before=self.store.path.read_bytes();seen=[]
        def failing(src,dst,**kw):
            seen.append(src);self.assertEqual(self.store.path.read_bytes(),before);raise OSError('injected')
        with patch.object(bl.os,'replace',side_effect=failing):
            with self.assertRaises(bl.BaselineError):self.save(replace=True)
        self.assertTrue(seen);self.assertEqual(self.store.path.read_bytes(),before);self.assertFalse(list(self.store.path.parent.glob('.baseline-*')))
    def test_conflict_token_does_not_overwrite(self):
        self.save();before=self.store.path.read_bytes()
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,'wrong',explicit=True,replace=True)
        self.assertEqual(before,self.store.path.read_bytes())
    def test_lock_owned_by_other_is_preserved(self):
        self.save();lock=self.store.path.with_name(self.store.path.name+'.lock');lock.write_text('OTHER')
        with self.assertRaises(bl.BaselineError):self.save(replace=True)
        self.assertEqual(lock.read_text(),'OTHER')
    def test_failed_fsync_preserves_old_and_releases_own_lock(self):
        self.save();before=self.store.path.read_bytes()
        with patch.object(bl.os,'fsync',side_effect=OSError('injected')):
            with self.assertRaises(bl.BaselineError):self.save(replace=True)
        self.assertEqual(before,self.store.path.read_bytes())
        self.assertFalse(self.store.path.with_name(self.store.path.name+'.lock').exists())
    def test_scope_record_total_limits(self):
        self.save();before=self.store.path.read_bytes()
        with patch.object(bl,'MAX_SCOPES',0):
            with self.assertRaises(bl.BaselineError):self.store.load()
        with patch.object(bl,'MAX_TOTAL',0):
            with self.assertRaises(bl.BaselineError):self.store.load()
        self.assertEqual(before,self.store.path.read_bytes())
    @unittest.skipUnless(os.name=='nt','PENDENTE DE WINDOWS REAL: handles/reparse/DACL nativos')
    def test_native_handles_and_dacl_replacement(self):
        self.save();before=self.store.load();self.save(replace=True)
        self.assertEqual(self.store.load()['reference']['records'],before['reference']['records'])

    def test_limits_records_bytes_and_text(self):
        with self.assertRaises(bl.BaselineError):reference([item()]*(bl.MAX_ITEMS+1))
        with self.assertRaises(bl.BaselineError):reference([item(Nome='x'*1201)])
        self.save();before=self.store.path.read_bytes()
        with patch.object(bl,'MAX_BYTES',32):
            with self.assertRaises(bl.BaselineError):self.store.load()
        self.assertEqual(before,self.store.path.read_bytes())
    def test_missing_coverage_write_refused(self):
        with self.assertRaises(bl.BaselineError):self.store.save({'complete':False,'records':[]},None,explicit=True)
        self.assertFalse(self.store.path.exists())
    def test_cancel_before_commit_no_file(self):
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,None,explicit=True,cancel_callback=lambda:True)
        self.assertFalse(self.store.path.exists())
    @unittest.skipUnless(os.name!='nt','Link POSIX; junção/ACL nativa pendente Windows')
    def test_file_symlink_and_directory_symlink_refused(self):
        self.save();before=self.store.path.read_bytes();external=self.root/'external.json';self.store.path.rename(external);self.store.path.symlink_to(external)
        with self.assertRaises(bl.BaselineError):self.store.load()
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,None,explicit=True)
        self.assertEqual(external.read_bytes(),before)
        self.store.path.unlink();self.store.path.parent.rmdir();outside=self.root/'outside';outside.mkdir();self.store.path.parent.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,None,explicit=True)
        self.assertEqual(list(outside.iterdir()),[])
    @unittest.skipUnless(os.name!='nt','Permissões POSIX; DACL nativa pendente Windows')
    def test_private_mode_retained(self):
        self.save();os.chmod(self.store.path,0o600);self.save(replace=True);self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode),0o600)

class GuiTests(unittest.TestCase):
    def setUp(self):
        self.case=base.UxTests();self.case.setUp();self.w=self.case.w;self.panel=self.w.baseline_panel
        self.w._set_nav(6);self.w.abas_processos.setCurrentIndex(2)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.panel.store=bl.BaselineStore(self.tmp.name,self.w._revisoes_tecnicas.escopo,sanitize,logging.Logger('gui'))
    def tearDown(self):self.case.tearDown()
    def wait(self):
        end=time.monotonic()+8
        while (self.panel.busy or self.w._workers) and time.monotonic()<end:base.app.processEvents();QTest.qWait(5)
        self.assertFalse(self.panel.busy);self.assertFalse(self.w._workers)
    def analyse(self,items):self.w._analise_defensiva_carregada(result(items));self.wait()
    def create(self):
        with patch.object(QMessageBox,'question',return_value=QMessageBox.StandardButton.Yes):self.panel.save_button.click()
        self.wait()
        self.assertNotIn("('Hoje",self.panel.summary.text())
    def test_no_automatic_save_and_confirmation_no(self):
        self.analyse([item()]);self.assertFalse(self.panel.store.path.exists());self.assertTrue(self.panel.save_button.isEnabled())
        with patch.object(QMessageBox,'question',return_value=QMessageBox.StandardButton.No):self.panel.save_button.click()
        self.assertFalse(self.panel.store.path.exists());self.create();self.assertTrue(self.panel.store.path.exists())
    def test_absent_separate_no_current_actions_and_differences(self):
        self.analyse([item(),item(2)]);self.create();self.analyse([item(TamanhoBytes=999),item(3)])
        self.assertEqual(len(self.w._dados_analise_defensiva),2);self.assertEqual(self.w.tabela_analise_defensiva.rowCount(),2)
        self.assertEqual({r['state'] for r in self.panel.rows},{'Novo','Ausente','Alterado'})
        absent=next(i for i,r in enumerate(self.panel.rows) if r['state']=='Ausente');self.panel.table.selectRow(absent)
        self.assertFalse(self.panel.current_button.isEnabled());self.assertIn('Snapshot da referência',self.panel.details.toPlainText())
        changed=next(i for i,r in enumerate(self.panel.rows) if r['state']=='Alterado');self.panel.table.selectRow(changed);self.assertIn('123 → 999',self.panel.details.toPlainText())
    def test_filters_selection_cache_and_800(self):
        items=[item(n) for n in range(800)];self.analyse(items);self.create()
        current=[*items[:-1],item(900)];self.analyse(current)
        table=self.w.tabela_analise_defensiva;table.selectRow(5);cell=table.item(5,1);original=list(self.w._dados_analise_defensiva)
        self.panel.filter.setCurrentText('Somente mudanças');self.assertEqual(table.currentRow(),5);self.assertEqual(sum(not self.panel.table.isRowHidden(i) for i in range(self.panel.table.rowCount())),2)
        with patch.object(self.w,'_materializar_tabela_analise_defensiva',side_effect=AssertionError('Rematerialização indevida')):
            t=time.perf_counter()
            for text in ('inexistente','app900',''):
                self.panel.search.setText(text)
            self.assertLess(time.perf_counter()-t,1)
            self.w.filtro_texto_analise.setText('app900');QTest.qWait(350);base.app.processEvents()
        self.assertIs(cell,table.item(5,1));self.assertEqual(original,self.w._dados_analise_defensiva)
        self.assertEqual(sum(not table.isRowHidden(i) for i in range(table.rowCount())),1)
    def test_classification_notes_priority_reapplied_and_baseline_separate(self):
        self.analyse([item()]);active=self.w._dados_analise_defensiva[0];triage=self.w._revisoes_tecnicas
        triage.alterar(active,avaliacao='Requer investigação',nota='Nota preservada',prioridade=True)
        self.create();self.analyse([item(PID='other')]);active=self.w._dados_analise_defensiva[0]
        self.assertEqual(active['Classificacao'],'Atenção');self.assertEqual(triage.estado(active)['nota'],'Nota preservada');self.assertTrue(triage.estado(active)['prioridade']);self.assertEqual(triage.estado(active)['avaliacao'],'Requer investigação')
        self.assertEqual(self.panel.rows[0]['state'],'Sem alteração')
    def test_partial_allows_creation_without_false_absence(self):
        self.analyse([item()]);self.create();self.w._analise_defensiva_carregada(result([],FontesIndisponiveis=['Processos:coleta_indisponivel']));self.wait()
        self.assertTrue(self.panel.save_button.isEnabled());self.assertEqual(self.panel.rows[0]['state'],'Indeterminado')
    def test_invalidation_cancels_stale_and_disables_save(self):
        self.analyse([item()]);self.panel.invalidate();self.assertIsNone(self.panel.result);self.assertFalse(self.panel.save_button.isEnabled());self.assertEqual(self.panel.table.rowCount(),0)
    def test_generation_discards_old_worker_and_compares_latest(self):
        import threading
        entered=threading.Event();release=threading.Event();original=self.panel.store.load;calls=[0]
        def slow_load():
            calls[0]+=1
            if calls[0]==1:entered.set();release.wait(2)
            return original()
        with patch.object(self.panel.store,'load',side_effect=slow_load):
            self.w._analise_defensiva_carregada(result([item()]))
            self.assertTrue(entered.wait(1))
            self.panel.invalidate();self.w._analise_defensiva_carregada(result([item(2)]))
            release.set();self.wait()
        self.assertEqual(self.panel.result['Itens'][0]['Nome'],'app2.exe');self.assertIsNotNone(self.panel.loaded)
        self.assertGreaterEqual(calls[0],2)
    def test_close_cancels_baseline_worker_without_new_timer(self):
        import threading
        from PyQt6.QtGui import QCloseEvent
        from PyQt6.QtCore import QTimer
        entered=threading.Event();original=bl.prepare
        def slow_prepare(result,sanitize,cancel_callback=None):
            entered.set()
            end=time.monotonic()+2
            while not cancel_callback() and time.monotonic()<end:time.sleep(.005)
            return original(result,sanitize,cancel_callback)
        with patch('baseline_defensivo_gui.prepare',side_effect=slow_prepare):
            self.w._analise_defensiva_carregada(result([item()]));self.assertTrue(entered.wait(1))
            event=QCloseEvent()
            with patch.object(QMessageBox,'warning',return_value=QMessageBox.StandardButton.Yes):self.w.closeEvent(event)
            self.assertTrue(event.isAccepted())
            deadline=time.monotonic()+5
            while self.w._workers and time.monotonic()<deadline:base.app.processEvents();QTest.qWait(5)
            self.assertFalse(self.w._workers)
        self.assertEqual(len(self.w.findChildren(QTimer)),5);self.assertFalse(self.panel.store.path.exists())

    def test_invalid_file_error_visible_not_empty_baseline(self):
        self.panel.store.path.parent.mkdir(parents=True);self.panel.store.path.write_text('{bad')
        self.analyse([item()]);self.assertIn('erro',self.panel.summary.text());self.assertFalse(self.panel.save_button.isEnabled());self.assertEqual(self.panel.store.path.read_text(),'{bad')

if __name__=='__main__':unittest.main(verbosity=2)
