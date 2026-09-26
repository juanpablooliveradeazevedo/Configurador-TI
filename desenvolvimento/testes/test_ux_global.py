"""Fumaça de UX com dados sintéticos; não executa consultas nativas nem ações destrutivas."""
import os,sys,tempfile,shutil,unittest,copy,time
from pathlib import Path
from unittest.mock import patch
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
SOURCE=Path(__file__).resolve().parents[2]
# Copiar para não criar logs/dados de teste dentro da entrega.
TEMP=tempfile.TemporaryDirectory()
APP_DIR=Path(TEMP.name)/'app'
shutil.copytree(SOURCE,APP_DIR,ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.log','build','dist'))
sys.path.insert(0,str(APP_DIR))
from PyQt6.QtWidgets import QApplication,QTableWidget,QPushButton,QMessageBox
from PyQt6.QtCore import QTimer,QRect
from PyQt6.QtTest import QTest
import main_gui as gui
import ui_components as ux
import network_intelligence as net
app=QApplication.instance() or QApplication([])
app.setStyleSheet((APP_DIR/'style.qss').read_text())

class UxTests(unittest.TestCase):
    def setUp(self):
        with patch.object(gui.MainWindow,'_run'),patch.object(gui.MainWindow,'_pagina_dashboard'),patch.object(gui.MainWindow,'_carregar_adaptadores'),patch.object(gui.MainWindow,'_carregar_unidades'):
            self.w=gui.MainWindow()
        self.w.resize(1366,720);self.w.show();app.processEvents()

    def tearDown(self):
        self.w._closing=True
        for worker in list(self.w._workers):
            worker.requestInterruption()
            self.assertTrue(worker.wait(5000), 'Worker deve encerrar antes de destruir a janela')
        app.processEvents()
        for timer in self.w.findChildren(QTimer):timer.stop()
        self.w.hide()
        self.w.deleteLater()
        app.processEvents()

    def test_navigation_tabs_and_fields(self):
        w=self.w
        self.assertEqual(w.pages.count(),21)
        self.assertEqual(len(w.nav_buttons),8)
        self.assertEqual(len(w.findChildren(QTimer)),5)
        for i in range(14):
            w._set_nav(i);app.processEvents()
            self.assertEqual(w.pages.currentIndex(),i)
        for domain_id,page_index in w.domain_page_indexes.items():
            w._open_domain(domain_id);app.processEvents()
            self.assertEqual(w.pages.currentIndex(),page_index)
            self.assertTrue(next(b for b in w.nav_buttons if b.property('domain_id')==domain_id).isChecked())
        self.assertEqual(w.abas_manutencao.count(),5)
        self.assertEqual(w.abas_processos.count(),3)
        self.assertIs(w.campo_dns,w.campo_dns)
        self.assertTrue(w.campo_dns.accessibleName())
        self.assertTrue(w.campo_dns.isClearButtonEnabled())

    def test_responsive_controls_and_readonly_tables(self):
        w=self.w;w.resize(910,500)
        for i in range(21):
            w._set_nav(i);app.processEvents()
            for row in w.pages.widget(i).findChildren(ux.FlowRow):
                if not row.parentWidget() or not row.parentWidget().isVisible():continue
                rects=[row.itemAt(j).geometry() for j in range(row.count()) if not row.itemAt(j).isEmpty()]
                for a,rect in enumerate(rects):
                    for other in rects[a+1:]:
                        self.assertFalse(rect.intersects(other),'Sobreposição em FlowRow')
        self.assertEqual(w.network_panel.table.editTriggers(),QTableWidget.EditTrigger.NoEditTriggers)
        self.assertEqual(w.tabela_analise_defensiva.editTriggers(),QTableWidget.EditTrigger.NoEditTriggers)

    def test_dashboard_processes_services_and_reports(self):
        w=self.w
        w._mostrar_dashboard((dict(HostName='Configurador TI-TEST',RAMTotalGB=16),dict(Nome='Windows fixture',DisplayVersion='teste'),dict(CPU='CPU fixture')))
        self.assertEqual(w.card_host.text(),'Configurador TI-TEST')
        data=[dict(PID=12,Nome='Processo fixture',CPU=0,Memoria=1048576,Handles=1)]
        w._renderizar_processos(data);w.tabela_processos.selectRow(0);w._renderizar_processos(data)
        self.assertEqual(w._selected_process_pid(),12)
        w._servicos_carregados([dict(Name='fixture',DisplayName='Serviço fixture',State='Running',StartMode='Auto')])
        self.assertEqual(w.tabela_servicos.item(0,1).text(),'Serviço fixture')
        with patch.object(gui.QMessageBox,'information') as modal:
            w._resultado_relatorio((True,'relatorio_fixture.html'))
            self.assertFalse(modal.called)
        self.assertIn('relatorio_fixture.html',w.report_status.text())

    def test_health_empty_error_cancelled_without_actions(self):
        w=self.w
        for method,label in ((w._mostrar_analise_limpeza_segura,w.lbl_resultado_limpeza_segura),
                             (w._mostrar_saude_sistema,w.lbl_saude_sistema),
                             (w._mostrar_saude_armazenamento,w.lbl_saude_armazenamento),
                             (w._mostrar_sensores_hardware,w.lbl_sensores_hardware)):
            method(dict(Sucesso=False,Mensagem='Falha simulada'))
            self.assertIn('Falha simulada',label.text())
            method(dict(Cancelada=True))
            self.assertIn('cancelad',label.text().lower())
        w._mostrar_saude_sistema(dict(Sucesso=True,Itens=[],Recomendacoes=[]))
        self.assertEqual(w.tabela_saude_sistema.rowCount(),0)
        w._mostrar_analise_limpeza_segura(dict(Sucesso=True,Categorias=[]))
        self.assertIn('0 B',w.lbl_resultado_limpeza_segura.text())

    def test_monitoring_start_snapshot_stop(self):
        w=self.w
        with patch.object(w,'_run',return_value=None):
            w._iniciar_monitoramento()
            self.assertTrue(w._timer_monitoramento.isActive())
            w._aplicar_snapshot_monitoramento((True,dict(Status='Online',IPv4='10.1.1.10',Interface='Fixture',CPU=12,RAM=30),'fixture'))
            self.assertEqual(w.monitoramento_status.text(),'Online')
            w._parar_monitoramento('teste')
            self.assertFalse(w._timer_monitoramento.isActive())
            self.assertEqual(w.monitor_ipv4.text(),'10.1.1.10')

    def test_network_details_escape_and_copy_contract(self):
        p=self.w.network_panel
        context=dict(Rede='10.1.1.0/24',Alias='Fixture',Gateway='10.1.1.1',network_scope_id='fixture')
        record=net.consolidate(net.observe('10.1.1.50',context,None,[net.evidence('ICMP',responded=True,strength=80)]))
        record['hostname']='<img src="file:///fixture">'
        original=copy.deepcopy(record)
        p.records={record['ip']:record};p.rows={record['ip']:0}
        p.result=dict(context=context,history_ok=True,unavailable=[])
        p.table.setRowCount(1);p.fill_row(0,record);p.table.selectRow(0);p.details()
        self.assertNotIn('<img ',p.detail.toHtml())
        self.assertIn('Evidências',p.detail.toPlainText())
        self.assertIn('Decisão operacional',p.detail.toPlainText())
        self.assertEqual(record,original)
        expected=net.technical_summary(net.consolidate(record,history_ok=True),context,[])
        self.assertEqual(p.raw_detail.toPlainText(),expected)
        p.copy_summary()
        self.assertEqual(QApplication.clipboard().text(),expected)
        for state,text in [('error','Falha'),('cancelled','Cancelado')]:
            p.finished(state);self.assertIn(text,p.status.text())
            self.assertNotIn('em background',self.w.status_inventario.text())
        p.finished('success')
        self.assertIn('concluída',self.w.status_inventario.text())
        p.search.setText('inexistente');p.apply_filter()
        self.assertIn('Nenhum IP corresponde',p.detail.toPlainText())
        p.clear_filters();self.assertEqual(p.selected_ip(),'10.1.1.50')

    def test_worker_failure_visible_with_details_and_log(self):
        w=self.w
        def failure():raise ValueError('Falha sintética para copiar')
        with patch.object(gui,'error_dialog') as dialog:
            w._run(failure,progress=w.progress_dashboard,blocks_navigation=False,operation_key='fixture')
            deadline=time.monotonic()+3
            while w._workers and time.monotonic()<deadline:
                app.processEvents();QTest.qWait(5)
            self.assertFalse(w._workers)
            self.assertIn('Falha',w.dashboard_status.text())
            self.assertIn('Falha',w.progress_dashboard.format())
            self.assertIn('Falha sintética',dialog.call_args.args[-1])
            self.assertFalse(w._busy_count)

    def test_visible_defensive_table_repeated_result(self):
        w=self.w
        w._set_nav(6);w.abas_processos.setCurrentIndex(2);app.processEvents()
        items=[dict(Id=str(i),Tipo="Processo",Nome="Aplicativo "+str(i),PID=str(i),
                    Caminho=r"C:\Apps\fixture.exe",CaminhoExibicao=r"C:\Apps\fixture.exe",
                    Classificacao="Informativo",Assinatura="Não disponível",
                    MotivoPrincipal="Fixture somente visual") for i in range(800)]
        result=dict(Sucesso=True,Itens=items,Contagens={"Informativo":800},
                    CaminhosPermitidosHash=[],Defender={},FontesIndisponiveis=[])
        start=time.monotonic()
        for _ in range(2):
            w._analise_defensiva_carregada(result);app.processEvents()
            self.assertEqual(w.tabela_analise_defensiva.rowCount(),800)
        self.assertLess(time.monotonic()-start,5,"Materialização visível lenta")
        for column in (0,4,5):
            self.assertEqual(w.tabela_analise_defensiva.horizontalHeader().sectionResizeMode(column),
                             gui.QHeaderView.ResizeMode.Interactive)

    def test_log_search_existing_text(self):
        w=self.w
        w.console_visual.setPlainText("Primeiro evento\nSegundo evento")
        w.busca_logs.setText("Segundo")
        w._localizar_log_visual()
        self.assertEqual(w.console_visual.textCursor().selectedText(),"Segundo")
        w.busca_logs.setText("ausente")
        w._localizar_log_visual()
        self.assertIn("Nenhuma ocorrência",w.statusBar().currentMessage())

    def test_error_dialog_copyable_details(self):
        captured=[]
        def inspect(dialog):
            captured.append((dialog.text(),dialog.detailedText()))
            button=next(b for b in dialog.buttons() if b.text()=='Copiar detalhes')
            button.click()
            return 0
        with patch.object(QMessageBox,'exec',inspect):
            ux.error_dialog(self.w,'Falha','Não foi possível consultar.','trace fixture')
        self.assertEqual(captured,[('Não foi possível consultar.','trace fixture')])
        self.assertEqual(QApplication.clipboard().text(),'trace fixture')

if __name__=='__main__':
    unittest.main(verbosity=2)
