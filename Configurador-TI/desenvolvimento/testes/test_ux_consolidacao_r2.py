"""R2: testes de apresentação e carga sintética. Não consulta Windows/rede real."""
import os, sys, json, time, copy, unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
import test_ux_global as base
import test_network_intelligence as previous
import operational_ui as ui
import network_intelligence as net
import hostname_identification as hostnames
from PyQt6.QtCore import Qt, QTimer, QPoint
from PyQt6.QtWidgets import QLabel, QTabWidget, QScrollArea, QApplication
from PyQt6.QtTest import QTest

STAMP = datetime.now(timezone.utc).isoformat(timespec='seconds')
DIAGNOSTIC = '''Computador: Configurador TI-LAB-01 (Técnico)
Domínio: LAB
Sistema Operacional: Windows 11 Pro • DADOS SIMULADOS
Versão: 24H2
Processador: CPU de referência
Fabricante: Exemplo | Núcleos: 8 | Lógicos: 16 | Clock máx.: 4200 MHz
Placa-Mãe: Modelo de referência
BIOS: Firmware de referência
Memória RAM:
Total: 16 GB | Usada: 6 GB | Livre: 10 GB
Módulo 1: 16 GB DDR4 | Fabricante de referência | 3200 MHz
Armazenamento Físico:
• SSD de referência (SSD) - 512 GB [Unknown]
Detalhe: SSD | Interface: NVMe | Tipo: SSD | 512 GB | Saúde: Indeterminado
Volumes / Partições:
[C:] 40% | 200GB / 500GB | Livre: 300GB'''
NETWORK = dict(Sucesso=True, Interface=dict(Alias='Ethernet • SIMULAÇÃO',Nome='Ethernet',Descricao='Adaptador de laboratório',InterfaceIndex=12,StatusNormalizado='Conectado',Status='Up',TipoMidia='Ethernet',IPv4='10.1.1.10',Mascara='255.255.255.0',PrefixLength=24,Rede='10.1.1.0/24',Gateway='10.1.1.1',MAC='00:11:22:33:44:10',VelocidadeLink='1 Gbps',DNSIPv4=['10.1.1.1','1.1.1.1'],DNSIPv6=[],DHCPHabilitado='Sim',ServidorDHCP='10.1.1.1',IPv6='Não disponível',PerfilRede='Privado',MetricaEfetiva=25,AtualizadoEm=STAMP))
SMART = dict(Sucesso=True,ColetadoEm=STAMP,Mensagem='Dados sintéticos • hardware não consultado',Discos=[dict(Numero=0,Modelo='SSD de referência',Tipo='SSD',BusType='NVMe',Capacidade='512 GB',Unidades='C:',Saude='Indeterminado',Temperatura='Não disponível',SMART='Não disponível',Fabricante='Exemplo',Serial='LAB-SIMULADO',Firmware='F1',MediaType='SSD',HealthStatus='Unknown',OperationalStatus='OK',PredictiveFailure='Não disponível',HorasLigado=0,PowerCycles=22,ReadErrors=0,ReadErrorsUncorrected=0,WriteErrors=0,WriteErrorsUncorrected=0,UnsafeShutdowns=1,MediaErrors=0,Wear='Não disponível',Motivos=['SMART indisponível na fonte'],Limitacoes=['Driver não expôs contadores SMART'],Volumes=[dict(Unidade='C:',Livre='300 GB')])],Limitacoes=['Referência visual com dados sintéticos'])

def sensors():
    items=[]
    groups={
        'CPU': [('Uso total','12 %'),('Frequência atual','2800 MHz'),('Frequência máxima conhecida','4200 MHz'),('Núcleos',8),('Processadores lógicos',16),('Temperatura','Não disponível')],
        'Memória RAM':[('Uso atual','38 %'),('Disponível','10 GB'),('Módulos','1 × 16 GB')],
        'GPU de laboratório':[('Adaptador','GPU de laboratório'),('Uso atual','3 %'),('Memória dedicada informada','4 GB')],
        'Disco 0 C:':[('Atividade','2 %'),('Temperatura','Não disponível')],
        'Bateria':[('Carga','80 %'),('Energia','Conectada')],
        'Ventoinha':[('RPM','Não disponível')],
    }
    for component, values in groups.items():
        for name,value in values:
            items.append(dict(Componente=component,Medida=name,Valor=value,Estado='Não disponível' if value=='Não disponível' else 'Informativo',Origem='Win32_VideoController' if name=='Adaptador' else 'Fixture nativa',Limitacao='Dado sintético para validar apresentação'))
    items.append(dict(Componente='Outro sensor',Medida='Valor zero',Valor=0,Estado='Informativo',Origem='Fixture',Limitacao='Zero deve ser preservado'))
    return dict(Sucesso=True,Componentes=items,ColetadoEm=STAMP,Mensagem='SIMULAÇÃO • sensores não consultados')

def records():
    result=[]
    for i in range(1,255):
        evid=[net.evidence('ICMP',responded=i%3==0,strength=80 if i%3==0 else 0)]
        if i%3==0:evid.append(net.evidence('Reverse DNS',hostname=f'PC-LAB-{i:03}'))
        r=net.consolidate(net.observe(f'10.1.1.{i}',previous.CTX,None,evid))
        if i==6:
            r['identifications']=hostnames.metadata([],{'hostname':'PC-LAB-006'},{'names':['PC-DIVERGENTE']},'',STAMP)
            r['identification_checked']=STAMP
        result.append(r)
    return dict(Sucesso=True,records=result,context=previous.CTX,scope='a'*64,history_ok=True,message='SIMULAÇÃO • 254 IPs, nenhuma consulta de rede',unavailable=[])

def defensive():
    items=[]
    for i in range(800):
        name=('Desktop agent ' if i%2==0 else 'Aplicativo ') + str(i)
        if i==6:name='unico_r2_006'
        items.append(dict(Id=str(i),Tipo='Processo',Nome=name,PID=str(1000+i),Caminho=rf'C:\Lab\item_{i}.exe',CaminhoExibicao=rf'C:\Lab\item_{i}.exe',Classificacao='Atenção' if i%5==0 else 'Informativo',Assinatura='Não disponível',MotivoPrincipal='SIMULAÇÃO',Recomendacao='Revisar evidências existentes'))
    return dict(Sucesso=True,Itens=items,Contagens={'Informativo':640,'Atenção':160},CaminhosPermitidosHash=[],Defender={},FontesIndisponiveis=[])

class R2Tests(unittest.TestCase):
    def setUp(self):
        self.case=base.UxTests();self.case.setUp();self.w=self.case.w
    def tearDown(self):self.case.tearDown()
    def pump(self):
        for _ in range(4):base.app.processEvents()
    def test_diagnostic_one_view_original_copy(self):
        with patch.object(self.w,'_run',side_effect=AssertionError('Coleta nova')):
            self.w.texto_detalhes_rede.setPlainText(self.w._formatar_detalhes_rede(NETWORK))
            self.w._mostrar_diagnostico_integrado(DIAGNOSTIC)
        p=self.w.diagnostico_integrado
        self.assertFalse(p.findChildren(QTabWidget))
        self.assertEqual(p.views['Texto técnico'].toPlainText(),DIAGNOSTIC)
        for k in ('Resumo','Hardware','Rede','Armazenamento'):
            self.assertFalse(p.views[k].isHidden())
        self.assertIn('consulta independente',p.views['Rede'].toPlainText())
        self.assertTrue(p.tabs.sections[4].content.isHidden())
        p.tabs.setCurrentIndex(4);p.copy.click()
        self.assertEqual(base.app.clipboard().text(),DIAGNOSTIC)
    def test_network_all_fields_raw_and_escape(self):
        raw=self.w._formatar_detalhes_rede(NETWORK)
        p=self.w.texto_detalhes_rede;p.setPlainText(raw)
        self.assertFalse(p.findChildren(QTabWidget))
        self.assertEqual(p.toPlainText(),raw);self.assertEqual(p.raw.toPlainText(),raw)
        self.assertTrue(p.raw.content.isHidden())
        labels=' '.join(x.text() for x in p.content.findChildren(QLabel))
        for key in ('IPv4','MAC','DHCP','Gateway','DNS IPv4','Perfil de rede','Máscara / prefixo','Velocidade do link'):
            self.assertIn(key,labels)
        p.raw.toggle.click();p.raw.copy.click();self.assertEqual(base.app.clipboard().text(),raw)
        p.setPlainText('Descrição: <img src=x>');self.assertNotIn('<img ',p.toHtml())
    def test_sensors_preserve_all_sources_zero_no_tabs(self):
        result=sensors();snapshot=copy.deepcopy(result)
        self.w._mostrar_sensores_hardware(result);p=self.w.abas_sensores_hardware
        self.assertFalse(p.findChildren(QTabWidget));self.assertEqual(result,snapshot)
        raw=p.findChildren(ui.RawDataSection)[0]
        self.assertEqual(json.loads(raw.toPlainText()),result)
        self.assertTrue(raw.content.isHidden())
        text=' '.join(x.text() for x in p.findChildren(QLabel))
        for key in ('CPU','Memória RAM','GPU','Armazenamento','Bateria','Hardware térmico','Valor zero'):
            self.assertIn(key,text)
        self.assertNotIn('throttling',text)
        zero=next(c for c in p.findChildren(ui.MetricCard) if any('Valor zero' in l.text() for l in c.findChildren(QLabel)))
        self.assertEqual(zero.value_label.text(),'0')
    def test_smart_full_payload_no_false_health(self):
        self.w._preencher_detalhes_saude_armazenamento(SMART)
        self.assertFalse(self.w.abas_saude_armazenamento.findChildren(QTabWidget))
        self.assertEqual(json.loads(self.w.raw_saude_armazenamento.toPlainText()),SMART)
        summary=self.w.texto_saude_resumo.toPlainText()
        self.assertIn('C:',summary);self.assertIn('Indeterminado',summary);self.assertNotIn('Saudável',summary)
        self.assertIn('Horas ligado: 0',self.w.texto_saude_contadores.toPlainText())
        self.w._limpar_saude_armazenamento('Falha simulada');self.assertNotIn('LAB-SIMULADO',self.w.raw_saude_armazenamento.toPlainText())
    def test_timestamp_formats_timezone_original(self):
        local=datetime.now().astimezone()
        for stamp in (local.isoformat(),local.strftime('%d/%m/%Y %H:%M:%S'),local.astimezone(timezone.utc).isoformat().replace('+00:00','Z')):
            shown,tip=ui.local_timestamp(stamp);self.assertIn('Hoje',shown);self.assertIn(stamp,tip)
        self.assertIn('Ontem',ui.local_timestamp((local-timedelta(days=1)).isoformat())[0])
        self.assertEqual(ui.local_timestamp('inválido')[0],'inválido')
        if hasattr(time,'tzset'):
            old=os.environ.get('TZ')
            try:
                os.environ['TZ']='Asia/Tokyo';time.tzset()
                shown,tip=ui.local_timestamp('2026-01-01T23:00:00Z',datetime(2026,1,2,8,tzinfo=timezone(timedelta(hours=9))))
                self.assertEqual(shown,'Hoje, 08:00');self.assertIn('+0900',tip)
            finally:
                if old is None:os.environ.pop('TZ',None)
                else:os.environ['TZ']=old
                time.tzset()
    def test_254_modes_filters_selection_scroll_context(self):
        w=self.w;p=w.network_panel;w._set_nav(3);start=time.perf_counter();p.receive(records());self.pump()
        print('R2 materializar 254:',round(time.perf_counter()-start,4))
        p.table.selectRow(119);self.pump();ip=p.selected_ip();p.table.verticalScrollBar().setValue(50)
        cell=p.table.item(119,0);cache=p.search_cache;scroll=p.table.verticalScrollBar().value()
        with patch.object(p.table,'setItem',side_effect=AssertionError('Células recriadas')),patch.object(p.table,'setRowCount',side_effect=AssertionError('Linhas recriadas')):
            for mode in (1,0,1,0):
                p.view_mode.setCurrentIndex(mode);self.pump();self.assertEqual(p.selected_ip(),ip);self.assertEqual(p.table.verticalScrollBar().value(),scroll)
            for query,count in (('10.1.1.',254),('PC-LAB-120',1),('inexistente_r2',0)):
                p.search.setText(query);p.apply_filter();self.assertEqual(sum(not p.table.isRowHidden(i) for i in range(254)),count)
        self.assertIs(cache,p.search_cache);self.assertIs(cell,p.table.item(119,0))
        p.clear_filters();p.table.selectRow(5);self.pump()
        p.filter.setCurrentText('Identificação divergente');self.assertEqual(sum(not p.table.isRowHidden(i) for i in range(254)),1)
        p.detail_tabs.setCurrentIndex(1);self.pump()
        for area in w.pages.widget(3).findChildren(QScrollArea):area.verticalScrollBar().setValue(area.verticalScrollBar().maximum())
        self.pump();header=p.device_context;pos=header.mapTo(w,QPoint(0,0))
        self.assertTrue(header.isVisible());self.assertLess(pos.y()+header.height(),w.height())
        self.assertIn('10.1.1.6',header.text());self.assertIn('Último online',header.text())
        self.assertEqual(p.table.horizontalScrollMode(),p.table.ScrollMode.ScrollPerPixel)
        self.assertIn(STAMP,p.raw_detail.toPlainText());self.assertFalse(p.detail_tabs.findChildren(QTabWidget))
    def test_ip_missing_last_online_and_historical_name(self):
        p=self.w.network_panel;p.receive(records())
        self.assertEqual(p.table.item(0,6).text(),'Não registrado')
        self.assertEqual(p.table.item(0,4).text(),'Hostname não identificado')
        self.assertIn('Último visto',p.table.item(0,6).toolTip())
        old=dict(hostname='PC-ANTIGO',hostnames=['PC-ANTIGO'],evidence=[])
        self.assertEqual(p.display_name(old),'Último nome conhecido: PC-ANTIGO')
    def test_density_resize_1366_1920_and_manual_width(self):
        w=self.w;w._mostrar_sensores_hardware(sensors());w._set_nav(2);w.abas_manutencao.setCurrentIndex(3)
        cols=[]
        for width,height in ((1366,768),(1920,1080)):
            w.resize(width,height);self.pump()
            grid=w.abas_sensores_hardware.findChildren(ui.ResponsiveGrid)[0];cols.append(grid.columns)
        self.assertGreater(cols[1],cols[0])
        w._set_nav(3);p=w.network_panel;p.receive(records())
        for width,height in ((1366,768),(1920,1080)):
            w.resize(width,height);self.pump()
            self.assertLessEqual(p.table.horizontalScrollBar().maximum(),80)
            self.assertEqual([p.table.horizontalHeader().logicalIndex(i) for i in range(7)],[0,4,1,5,2,6,9])
        p.table.setColumnWidth(4,240);p.view_mode.setCurrentIndex(1);p.view_mode.setCurrentIndex(0)
        self.assertEqual(p.table.columnWidth(4),240)
    def test_800_defensive_visible_d_de_des_triage(self):
        w=self.w;w._set_nav(6);w.abas_processos.setCurrentIndex(2);self.pump()
        start=time.perf_counter();w._analise_defensiva_carregada(defensive());self.pump();elapsed=time.perf_counter()-start
        self.assertEqual(w.tabela_analise_defensiva.rowCount(),800);self.assertLess(elapsed,5)
        table=w.tabela_analise_defensiva;cell=table.item(0,0);timings={}
        with patch.object(table,'setItem',side_effect=AssertionError('Rebuild')),patch.object(table,'setRowCount',side_effect=AssertionError('Rebuild')):
            for query,count in [('D',800),('DE',399),('DES',399),('unico_r2_006',1),('zzzz_inexistente',0),('',800)]:
                start=time.perf_counter();w.filtro_texto_analise.setText(query);QTest.qWait(330);self.pump()
                timings[query]=round(time.perf_counter()-start,4)
                self.assertEqual(sum(not table.isRowHidden(i) for i in range(800)),count)
                self.assertLess(timings[query],1.5)
        self.assertIs(cell,table.item(0,0))
        item=w._dados_analise_defensiva[6];original=item['Classificacao']
        item['CriadoUtc']=STAMP;item['ModificadoUtc']=STAMP
        table.selectRow(6)
        w._alterar_triagem(item,nota='Nota sintética R2',prioridade=True,avaliacao=base.gui.triagem.AVALIACOES[1]);state=w._revisoes_tecnicas.estado(item)
        self.assertEqual(state['nota'],'Nota sintética R2');self.assertTrue(state['prioridade']);self.assertEqual(item['Classificacao'],original)
        self.assertIn('Última revisão (local): Hoje',w.detalhes_analise_defensiva.toPlainText())
        self.assertIn(STAMP,w.detalhes_analise_defensiva.toolTip())
        for option in base.gui.triagem.FILTROS:
            w.filtro_revisao_triagem.setCurrentText(option);self.pump()
        w._limpar_filtros_triagem();self.assertEqual(sum(not table.isRowHidden(i) for i in range(800)),800)
        print('R2 defensiva materialização:',round(elapsed,4),'filtros + debounce:',timings)


def screenshots(destination):
    out=Path(destination);out.mkdir(parents=True,exist_ok=True)
    case=base.UxTests();case.setUp();w=case.w
    w._mostrar_dashboard((dict(HostName='Configurador TI-LAB-01',RAMTotalGB=16),dict(Nome='Windows 11 Pro • SIMULAÇÃO',DisplayVersion='24H2'),dict(CPU='CPU de referência • 8 núcleos')))
    w.combo_adaptador.addItem('Ethernet','Ethernet')
    w._mostrar_detalhes_rede(NETWORK)
    w._mostrar_diagnostico_integrado(DIAGNOSTIC)
    w._mostrar_sensores_hardware(sensors());w._mostrar_saude_armazenamento(SMART)
    w.network_panel.receive(records());w.network_panel.table.selectRow(5)
    w._analise_defensiva_carregada(defensive())
    w._renderizar_processos([dict(PID=100+i,Nome=f'Processo de laboratório {i}',CPU=i,Memoria=1048576*(i+1),Handles=10+i) for i in range(14)])
    metrics=[]
    scenes=[('visao_geral',0,None,None),('rede_dns',1,None,w.texto_detalhes_rede),('sensores',2,3,w.abas_sensores_hardware),('smart',2,2,w.abas_saude_armazenamento),('inventario_ips',3,None,w.network_panel.table),('processos_servicos',6,0,w.tabela_processos),('diagnostico',0,None,w.diagnostico_integrado),('defensiva_800',6,2,w.tabela_analise_defensiva)]
    for width,height in ((1366,768),(1920,1080)):
        w.resize(width,height)
        for name,page,tab,focus in scenes:
            w._set_nav(page)
            if tab is not None:(w.abas_manutencao if page==2 else w.abas_processos).setCurrentIndex(tab)
            for _ in range(6):base.app.processEvents()
            for area in w.pages.widget(page).findChildren(QScrollArea):area.verticalScrollBar().setValue(0)
            if isinstance(w.pages.widget(page),QScrollArea):w.pages.widget(page).verticalScrollBar().setValue(0)
            for _ in range(4):base.app.processEvents()
            if focus:
                # Posicionar o começo do painel dentro de cada ancestral rolável.
                parent=focus.parentWidget()
                areas=[]
                while parent:
                    if isinstance(parent,QScrollArea):areas.append(parent)
                    parent=parent.parentWidget()
                for area in areas:
                    point=focus.mapTo(area.widget(),QPoint(0,0))
                    area.verticalScrollBar().setValue(max(0,point.y()-50))
                    for _ in range(3):base.app.processEvents()
            for _ in range(4):base.app.processEvents()
            path=out/f'{name}_{width}x{height}.png';w.grab().save(str(path))
            metrics.append(dict(scene=name,width=w.width(),height=w.height(),ip_horizontal_max=w.network_panel.table.horizontalScrollBar().maximum()))
    (out/'geometrias.json').write_text(json.dumps(metrics,indent=2))
    case.tearDown()

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--screenshots':screenshots(sys.argv[2])
    else:unittest.main(verbosity=2)
