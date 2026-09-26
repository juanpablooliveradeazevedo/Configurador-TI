"""Cobertura por fonte nos dois sentidos, legado e confirmação parcial; offline."""
import copy,json,logging,time,unittest
from unittest.mock import patch
import test_baseline_defensivo as old
from PyQt6.QtWidgets import QMessageBox
bl=old.bl
item,result,sanitize=old.item,old.result,old.sanitize

def prepared(items=None,errors=None,**kwargs):
    return bl.prepare(result(items,FontesIndisponiveis=[] if errors is None else errors,**kwargs),sanitize)

def source_item(kind='Processo',n=1,scope='HKCU'):
    if kind=='Run' or kind=='RunOnce':return item(n,kind,Fonte=f'{scope} / 64-bit',ContextoUsuario=scope)
    if kind=='Startup':return item(n,kind,Fonte='Pasta Startup',ContextoUsuario=scope,ArquivoStartup=fr'C:\Startup\app{n}.lnk')
    if kind=='Tarefa agendada':return item(n,kind,Fonte='Get-ScheduledTask',CaminhoTarefa='\\Folder\\',TipoAcao='Exec')
    return item(n,kind)

def states(a,b):return bl.compare(a,b)['counts']

class CoverageTests(unittest.TestCase):
    def test_complete_and_partial_flags(self):
        self.assertTrue(prepared()['complete'])
        p=prepared(errors=['Defender:status_indisponivel'])
        self.assertFalse(p['complete']);self.assertEqual(p['coverage']['version'],1)
        self.assertEqual(p['coverage']['sources']['Defender']['state'],'Indisponível')
        self.assertTrue(bl.can_reference(result(FontesIndisponiveis=['Defender:status_indisponivel'])))
    def test_each_real_error_blocks_only_its_sources_both_directions(self):
        examples=[('Processo','HKCU','Processos:coleta_indisponivel'),('Processo','HKCU','Processos:usuario_indisponivel'),
                  ('Serviço','HKCU','Servicos:coleta_indisponivel'),('Tarefa agendada','HKCU','TarefasAgendadas:coleta_indisponivel'),
                  ('Startup','Usuário','Startup:Usuário'),('Startup','Comum','Startup:Comum'),('Startup','Comum','Startup:atalhos_indisponiveis')]
        examples += [(kind,hive,f'Registro:{hive}:{view}:{kind}') for kind in ('Run','RunOnce') for hive in ('HKCU','HKLM') for view in ('32-bit','64-bit')]
        for kind,scope,error in examples:
            with self.subTest(error=error):
                sample=source_item(kind,scope=scope)
                oldref=prepared([sample]);partial_empty=prepared([],errors=[error])
                self.assertEqual(states(oldref,partial_empty)['Ausente'],0)
                self.assertEqual(states(partial_empty,oldref)['Novo'],0)
                self.assertEqual(states(oldref,partial_empty)['Indeterminado'],1)
                self.assertEqual(states(partial_empty,oldref)['Indeterminado'],1)
    def test_complete_source_allows_new_and_absent_despite_defender_failure(self):
        partial=prepared([],errors=['Defender:status_indisponivel'])
        full=prepared([item()])
        self.assertEqual(states(partial,full)['Novo'],1)
        self.assertEqual(states(full,partial)['Ausente'],1)
    def test_partial_startup_does_not_invalidate_other_families(self):
        others=[source_item(k,i) for i,k in enumerate(('Processo','Serviço','Tarefa agendada','Run','RunOnce'))]
        a=prepared(others);b=prepared([],errors=['Startup:Usuário'])
        self.assertEqual(states(a,b)['Ausente'],5);self.assertEqual(states(b,a)['Novo'],5)
    def test_registry_hive_and_type_are_independent_but_views_aggregate(self):
        partial=prepared([],errors=['Registro:HKCU:32-bit:Run'])
        self.assertEqual(states(partial,prepared([source_item('Run',scope='HKCU')]))['Indeterminado'],1)
        for k,h in [('RunOnce','HKCU'),('Run','HKLM')]:
            self.assertEqual(states(partial,prepared([source_item(k,scope=h)]))['Novo'],1)
    def test_startup_scopes_independent(self):
        partial=prepared([],errors=['Startup:Usuário'])
        common=prepared([source_item('Startup',scope='Comum')])
        self.assertEqual(states(partial,common)['Novo'],1);self.assertEqual(states(common,partial)['Ausente'],1)
    def test_observed_pairs_still_changed_or_unchanged_with_partial_source(self):
        a=prepared([item(),item(2)],errors=['Processos:usuario_indisponivel'])
        b=prepared([item(TamanhoBytes=999),item(2)],errors=['Processos:coleta_indisponivel'])
        self.assertEqual(states(a,b)['Alterado'],1);self.assertEqual(states(a,b)['Sem alteração'],1)
    def test_unknown_error_conservative_and_does_not_persist_arbitrary_text(self):
        partial=prepared([],errors=['Something token=SECRET password=PASSWORD'])
        self.assertTrue(all(e['state']=='Desconhecida' for e in partial['coverage']['sources'].values()))
        self.assertEqual(states(partial,prepared())['Indeterminado'],1)
        self.assertEqual(states(prepared(),partial)['Indeterminado'],1)
        self.assertNotIn('SECRET',json.dumps(partial));self.assertNotIn('PASSWORD',json.dumps(partial))
        self.assertNotIn('Something',json.dumps(partial))
    def test_unknown_report_does_not_block_observed_pairs(self):
        a=prepared(errors=['unrecognized']);b=prepared()
        self.assertEqual(states(a,b)['Sem alteração'],1)
    def test_missing_malformed_or_oversize_reports_unknown(self):
        for value in [None,{},'Processos:coleta_indisponivel',[123],['x']*65]:
            with self.subTest(value=type(value)):
                a=bl.prepare(result([],FontesIndisponiveis=value),sanitize)
                self.assertEqual(states(a,prepared())['Indeterminado'],1)
                self.assertFalse(a['complete'])
    def test_silent_unavailable_defender_and_missing_startup_folder(self):
        a=prepared([],Defender={'Disponivel':False})
        self.assertEqual(a['coverage']['sources']['Defender']['state'],'Indisponível')
        self.assertEqual(states(a,prepared())['Novo'],1)
        a=prepared([],Contexto={'StartupCommon':r'C:\Startup'})
        self.assertEqual(a['coverage']['sources']['Startup:Usuário']['state'],'Desconhecida')
        self.assertEqual(states(a,prepared([source_item('Startup',scope='Usuário')]))['Indeterminado'],1)
    def test_associated_files_inherit_real_origin_not_new_source(self):
        for kind,scope,error in [('Processo','USER','Processos:coleta_indisponivel'),('Serviço','SYSTEM','Servicos:coleta_indisponivel'),('Tarefa agendada','USER','TarefasAgendadas:coleta_indisponivel'),('Run','HKCU','Registro:HKCU:32-bit:Run'),('Startup','Comum','Startup:Comum')]:
            with self.subTest(kind=kind):
                sample=item(kind='Arquivo associado',Fonte=f'Associado a {kind}: parent',OrigemTipo=kind,OrigemNome='parent',ContextoUsuario=scope)
                a=prepared([sample]);b=prepared([],errors=[error])
                self.assertEqual(states(a,b)['Indeterminado'],1);self.assertEqual(states(b,a)['Indeterminado'],1)
                self.assertEqual(states(a,prepared([]))['Ausente'],1)
    def test_unrecognized_provenance_never_confirms_new_or_absent(self):
        sample=item(Fonte='another process source')
        a=prepared([sample]);b=prepared([])
        self.assertEqual(states(a,b)['Indeterminado'],1);self.assertEqual(states(b,a)['Indeterminado'],1)
    def test_classification_not_available_independent_of_source(self):
        a=prepared([item(Classificacao='Não disponível',Assinatura='Não disponível')])
        self.assertTrue(a['complete']);self.assertEqual(states(prepared([]),a)['Novo'],1)
        self.assertEqual(states(a,prepared([]))['Ausente'],1)
    def test_metadata_does_not_override_source_gap(self):
        a=prepared([item()],errors=['Processos:usuario_indisponivel'])
        self.assertEqual(states(a,prepared([item(),item(2)]))['Novo'],0)
    def test_reasons_name_side_and_source(self):
        a=prepared([],errors=['Processos:usuario_indisponivel']);b=prepared()
        for oldref,newref,side,verb in [(a,b,'Baseline','novidade'),(b,a,'Fonte atual','ausência')]:
            row=bl.compare(oldref,newref)['rows'][0]
            self.assertIn(side,row['reason']);self.assertIn(verb,row['reason']);self.assertIn('Win32_Process',row['reason'])
    def test_cancelled_fatal_and_invalid_results_refused(self):
        for value in [result(Cancelada=True),result(Sucesso=False),result(Itens=None),result(Itens=[None])]:
            with self.assertRaises(bl.BaselineError):bl.prepare(value,sanitize)
            self.assertFalse(bl.can_reference(value))
    def test_performance_800_mixed_with_partial_source(self):
        samples=[source_item('Processo' if n%2 else 'Serviço',n) for n in range(800)]
        t=time.perf_counter();a=prepared(samples,errors=['Processos:usuario_indisponivel']);b=prepared(samples[400:]+[item(1000+n) for n in range(400)])
        counts=states(a,b);elapsed=time.perf_counter()-t
        self.assertEqual(counts['Sem alteração'],400);self.assertEqual(counts['Indeterminado'],400);self.assertEqual(counts['Ausente'],400)
        self.assertLess(elapsed,2);print('R1 800 dois snapshots+comparação:',round(elapsed,4))

class CoverageStoreTests(unittest.TestCase):
    setUp=old.StoreTests.setUp
    save=old.StoreTests.save
    def test_partial_persist_reload_and_explicit_replace(self):
        self.prepared=prepared(errors=['Defender:status_indisponivel'])
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,None)
        info=self.save();self.assertFalse(info['reference']['complete'])
        self.assertEqual(self.store.load()['reference']['coverage'],self.prepared['coverage'])
        before=self.store.path.read_bytes()
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,info['token'],explicit=True)
        self.assertEqual(before,self.store.path.read_bytes());self.save(replace=True)
        self.assertEqual(json.loads(self.store.path.read_bytes())['schema'],2)
    def legacy(self):
        self.save();doc=json.loads(self.store.path.read_bytes());doc['schema']=1
        for ref in doc['scopes'].values():ref.pop('coverage');ref['complete']=True
        self.store.path.write_text(json.dumps(doc));return self.store.path.read_bytes()
    def test_legacy_load_unknown_no_write_no_false_new(self):
        before=self.legacy();ref=self.store.load()['reference']
        self.assertEqual(before,self.store.path.read_bytes());self.assertFalse(ref['complete'])
        self.assertEqual(states(ref,prepared([item(),item(2)]))['Indeterminado'],1)
        self.assertEqual(states(ref,prepared([item(),item(2)]))['Sem alteração'],1)
        self.assertEqual(states(ref,prepared([]))['Ausente'],1)
    def test_legacy_multiscope_explicit_migration_retains_unknown_other(self):
        self.legacy();other=bl.BaselineStore(self.root,old.OTHER,sanitize,logging.Logger('other'))
        other.save(prepared([item(2)]),other.load()['token'],explicit=True)
        self.assertFalse(self.store.load()['reference']['complete'])
        self.assertTrue(other.load()['reference']['complete'])
        self.save(replace=True);self.assertTrue(self.store.load()['reference']['complete'])
    def test_coverage_strict_schema_limits_states_and_secrets(self):
        self.save();original=json.loads(self.store.path.read_bytes())
        mutations=[lambda c:c.update(version=2),lambda c:c.update(version=True),lambda c:c['sources'].pop('Defender'),lambda c:c['sources'].update(secret={'state':'Disponível','reasons':[]}),lambda c:c['sources']['Defender'].update(state='unknown'),lambda c:c['sources']['Defender'].update(state='Parcial',reasons=['token=SECRET']),lambda c:c['sources']['Defender'].update(state='Disponível',reasons=['Defender:status_indisponivel']),lambda c:c['sources']['Defender'].update(state='Parcial',reasons=['Defender:status_indisponivel']*17)]
        for mutate in mutations:
            doc=copy.deepcopy(original);mutate(doc['scopes'][old.SCOPE]['coverage']);raw=json.dumps(doc).encode();self.store.path.write_bytes(raw)
            with self.assertRaises(bl.BaselineError):self.store.load()
            with self.assertRaises(bl.BaselineError):self.store.save(prepared(),None,explicit=True)
            self.assertEqual(raw,self.store.path.read_bytes())
    def test_partial_still_preserves_atomic_conflict_and_cancel(self):
        self.prepared=prepared(errors=['Startup:Comum']);info=self.save();before=self.store.path.read_bytes()
        with patch.object(bl.os,'replace',side_effect=OSError('injected')):
            with self.assertRaises(bl.BaselineError):self.save(replace=True)
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,'wrong',explicit=True,replace=True)
        with self.assertRaises(bl.BaselineError):self.store.save(self.prepared,info['token'],explicit=True,replace=True,cancel_callback=lambda:True)
        self.assertEqual(before,self.store.path.read_bytes())
    def test_partial_persistence_contains_only_allowed_metadata(self):
        self.prepared=prepared([item(ComandoOriginal='RAW_SECRET',Comando='app --token TOKEN_SECRET',Nota='NOTE_SECRET')],errors=['unknown SECRET_ERROR'])
        self.save();raw=self.store.path.read_text()
        for secret in ('RAW_SECRET','TOKEN_SECRET','NOTE_SECRET','SECRET_ERROR','ComandoOriginal','Classificacao'):
            self.assertNotIn(secret,raw)

class CoverageGuiTests(unittest.TestCase):
    setUp=old.GuiTests.setUp
    tearDown=old.GuiTests.tearDown
    wait=old.GuiTests.wait
    analyse=old.GuiTests.analyse
    create=old.GuiTests.create
    def partial(self,items=None,error='Defender:status_indisponivel'):
        self.w._analise_defensiva_carregada(result(items,FontesIndisponiveis=[error]));self.wait()
    def test_partial_create_confirmation_names_states_and_decline(self):
        self.partial();self.assertTrue(self.panel.save_button.isEnabled())
        with patch.object(QMessageBox,'question',return_value=QMessageBox.StandardButton.No) as ask:self.panel.save_button.click()
        self.assertIn('cobertura parcial em 1 fonte',ask.call_args.args[2]);self.assertIn('Defender: Indisponível',ask.call_args.args[2]);self.assertIn('Indeterminados',ask.call_args.args[2])
        self.assertFalse(self.panel.store.path.exists());self.create()
        self.assertIn('Baseline: Parcial',self.panel.summary.text());self.assertIn('9/10',self.panel.summary.text())
        self.assertFalse(self.panel.store.load()['reference']['complete'])
    def test_partial_replace_requires_confirmation_preserves_declined_bytes(self):
        self.analyse([item()]);self.create();before=self.panel.store.path.read_bytes();self.partial([item(2)])
        with patch.object(QMessageBox,'question',return_value=QMessageBox.StandardButton.No) as ask:self.panel.save_button.click()
        self.assertIn('Substituir',ask.call_args.args[2]);self.assertIn('cobertura parcial',ask.call_args.args[2]);self.assertEqual(before,self.panel.store.path.read_bytes())
        self.create();self.assertFalse(self.panel.store.load()['reference']['complete'])
    def test_ui_source_names_reasons_current_and_baseline(self):
        self.partial(error='Processos:usuario_indisponivel');self.create()
        text=self.panel.coverage_text.toPlainText()
        for word in ('COLETA ATUAL','BASELINE','Win32_Process: Parcial','Processos:usuario_indisponivel'):self.assertIn(word,text)
        self.assertIn('Win32_Process: Parcial',self.panel.coverage_line.text())
        self.assertIn('Processos:usuario_indisponivel',self.panel.coverage_line.toolTip())
        self.panel.coverage_section.set_expanded(True)
        self.assertFalse(self.panel.coverage_text.isHidden())
    def test_generation_change_during_confirmation_never_saves(self):
        self.partial()
        def answer(*a,**k):self.panel.invalidate();return QMessageBox.StandardButton.Yes
        with patch.object(QMessageBox,'question',side_effect=answer):self.panel.save_button.click()
        self.wait();self.assertFalse(self.panel.store.path.exists())
    def test_partial_keeps_classification_triage_and_current_actions(self):
        self.analyse([item()]);active=self.w._dados_analise_defensiva[0]
        self.w._revisoes_tecnicas.alterar(active,avaliacao='Requer investigação',nota='Nota preservada',prioridade=True)
        self.partial([item(Classificacao='Não disponível')]);self.create()
        current=self.w._dados_analise_defensiva[0];self.assertEqual(current['Classificacao'],'Não disponível')
        state=self.w._revisoes_tecnicas.estado(current);self.assertEqual(state['nota'],'Nota preservada');self.assertTrue(state['prioridade'])
        self.assertEqual(self.panel.rows[0]['state'],'Sem alteração')
    def test_unknown_gui_error_contents_omitted(self):
        self.partial(error='Unknown token=NEVER_VISIBLE')
        self.assertNotIn('NEVER_VISIBLE',self.panel.coverage_text.toPlainText());self.assertIn('alcance desconhecido',self.panel.coverage_text.toPlainText())
        self.create();self.assertNotIn('NEVER_VISIBLE',self.panel.store.path.read_text())

if __name__=='__main__':unittest.main(verbosity=2)
