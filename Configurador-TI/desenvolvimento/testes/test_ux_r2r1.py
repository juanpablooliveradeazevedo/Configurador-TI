"""R2-R1: apresentação pura, fixtures; nenhuma coleta nativa executada."""
import sys, copy, unittest, time, json
from pathlib import Path
from unittest.mock import patch
import test_ux_global as base
import test_ux_consolidacao_r2 as r2
import operational_ui as ui
from PyQt6.QtWidgets import QLabel, QProgressBar, QScrollArea, QWidget, QVBoxLayout
from PyQt6.QtCore import QTimer, QPoint
from PyQt6.QtTest import QTest

SNAPSHOT = dict(Status='Online', Interface='Ethernet • SIMULAÇÃO', IPv4='192.168.15.10',
    Gateway='192.168.15.1', GatewayOk=True, GatewayLatencia_ms=0,
    DNS=['fe80::ea45:8bff:fe11:8440', '192.168.15.1'], DNSOk=False,
    InternetOk=True, InternetLatencia_ms=19, AtualizadoEm=r2.STAMP, CPU=12,RAM=37.5,DISCO=40)


def diagnostic(percent='37.5', health='Healthy'):
    return f'''Computador: Configurador TI-LAB-01 (SIMULAÇÃO)
Sistema Operacional: Windows 11 Pro
Processador: CPU de referência
Fabricante: Exemplo | Núcleos: 8 | Lógicos: 16
Memória RAM:
   [███████░░░░░░░░░░░░░] {percent}%
   Total: 16 GB | Usada: 6 GB | Livre: 10 GB
Armazenamento Físico:
   • SSD de referência (SSD) - 512 GB [{health}]
   Detalhe: SSD de referência | Interface: NVMe | Tipo: SSD | 512 GB | Saúde: {health}
Volumes / Partições:
   [C:] [███████░░░░░░░░░░░░░] {percent}% | 187.5GB / 500GB | Livre: 312.5GB'''


def labels(widget):
    return '\n'.join(x.text() for x in widget.findChildren(QLabel))


class RefinementTests(unittest.TestCase):
    def setUp(self):
        self.case=base.UxTests();self.case.setUp();self.w=self.case.w
    def tearDown(self):self.case.tearDown()
    def pump(self):
        for _ in range(5):base.app.processEvents()
    def test_dns_separate_no_collection_and_reset(self):
        w=self.w
        for servers in ([],None,['192.168.1.1'],SNAPSHOT['DNS']):
            for state in (True,False,None):
                data={**SNAPSHOT,'DNS':servers,'DNSOk':state};original=copy.deepcopy(data)
                with patch.object(w,'_run',side_effect=AssertionError('nova coleta')),patch.object(base.gui.core_logic,'registrar_log'):
                    w._aplicar_snapshot_monitoramento((True,data,'fixture'))
                self.assertEqual(data,original)
                self.assertEqual(w.monitor_dns.text(),'\n'.join(servers or []) or 'Não disponível')
                self.assertEqual(w.monitor_dns_validacao.text(),{True:'OK',False:'Falha',None:'Não disponível'}[state])
                self.assertEqual(w.monitor_internet.text(),'Online (19 ms)')
                self.assertEqual(w.monitor_latencia_gateway.text(),'0 ms')
        with patch.object(base.gui.core_logic,'registrar_log'):
            w._aplicar_snapshot_monitoramento((False,{},'Falha na coleta'))
        for label in (w.monitor_interface,w.monitor_ipv4,w.monitor_gateway,w.monitor_internet,w.monitor_ultima_atualizacao):
            self.assertEqual(label.text(),'—')
        self.assertEqual(w.monitor_dns.text(),'Não disponível')
        self.assertEqual(w.monitor_dns_validacao.text(),'Não disponível')
    def test_percentages_exact_and_original_data(self):
        panel=ui.DiagnosticPanel()
        for pct in ('0','37.5','100'):
            raw=diagnostic(pct)
            panel.show_result(raw);self.pump()
            bars=panel.views['Hardware'].content.findChildren(QProgressBar)
            self.assertEqual(len(bars),1);self.assertEqual(bars[0].value(),round(float(pct)*10))
            bar=panel.views['Armazenamento'].content.findChildren(QProgressBar)[0]
            self.assertEqual(bar.format(),pct+'% usado');self.assertEqual(bar.value(),round(float(pct)*10))
            # Intentionally inconsistent capacities prove UI does not recalculate percent.
            self.assertIn('187.5GB',labels(panel.views['Armazenamento']))
            self.assertIn('6 GB',labels(panel.views['Hardware']))
            self.assertEqual(panel.views['Texto técnico'].toPlainText(),raw)
            self.assertEqual(panel.views['Detalhes técnicos'].toPlainText(),raw)
            panel.copy.click();self.assertEqual(base.app.clipboard().text(),raw)
            self.assertNotIn('█',labels(panel.views['Hardware'].content))
        panel.deleteLater()
    def test_disks_status_and_unavailable_not_healthy(self):
        for status,display in [('Healthy','Saudável'),('Unknown','Indeterminado'),('Not available','Não disponível'),('Failed','Falha')]:
            panel=ui.ReadoutPanel();raw=diagnostic(health=status);panel.setPlainText(raw)
            disks=panel.content.findChildren(ui.DiskReadout);self.assertEqual(len(disks),2)
            self.assertIn('Saúde\n'+display,labels(disks[0]));self.assertIn('NVMe',labels(disks[1]))
            self.assertIn('Temperatura\nNão disponível',labels(disks[0]))
            self.assertIn('Unidades relacionadas\nNão disponível',labels(disks[0]))
            if status!='Healthy':self.assertNotIn('Saudável',labels(panel.content))
            self.assertEqual(panel.raw.toPlainText(),raw);panel.deleteLater()
    def test_collection_states_and_absence_outside_attention(self):
        states=['Disponível','Não disponível','Falha na coleta','Não suportado','Indeterminado']
        for state in states:
            card=ui.MetricCard('Coleta','—',state)
            badge=card.findChild(QLabel,'StatusBadge')
            self.assertEqual(badge.property('collectionState'),state);self.assertEqual(badge.property('tone'),'neutral')
            self.assertIn(state,badge.text());card.deleteLater()
        self.w._mostrar_sensores_hardware(r2.sensors())
        banners=self.w.abas_sensores_hardware.findChildren(QLabel,'ResultBanner')
        self.assertFalse(any('Não disponível' in x.text() for x in banners))
    def test_smart_health_translation_raw_and_clearing(self):
        w=self.w
        for value,shown in [('Healthy','Saudável'),('Unknown','Indeterminado'),('Not available','Não disponível'),('Failed','Falha')]:
            result=copy.deepcopy(r2.SMART);result['Discos'][0]['Saude']=value
            w._preencher_detalhes_saude_armazenamento(result)
            self.assertIn(shown,labels(w.texto_saude_resumo))
            self.assertEqual(json.loads(w.raw_saude_armazenamento.toPlainText()),result)
        w._limpar_saude_armazenamento('Falha simulada');self.pump()
        self.assertNotIn('LAB-SIMULADO',w.raw_saude_armazenamento.toPlainText())
    def test_order_network_raw_fallback_and_stale(self):
        p=ui.DiagnosticPanel();p.show_result(diagnostic(), 'Adaptador: Ethernet\nIPv4: 10.1.1.10\nDNS IPv6: fe80::1')
        self.assertEqual([p.tabs.tabText(i) for i in range(p.tabs.count())],['Resumo operacional','Hardware','Rede','Armazenamento','Detalhes técnicos','Dados brutos'])
        self.assertIn('fe80::1',labels(p.views['Rede']))
        for i in (4,5):self.assertTrue(p.tabs.sections[i].content.isHidden())
        p.show_result('Não foi possível obter os dados do sistema.');self.pump()
        self.assertNotIn('10.1.1.10',labels(p.views['Rede'].content))
        self.assertFalse(p.views['Armazenamento'].content.findChildren(ui.DiskReadout))
        self.assertFalse(p.views['Hardware'].content.findChildren(QProgressBar))
        p.views['Hardware'].setPlainText('[formato futuro] 101%');self.assertIn('101%',labels(p.views['Hardware'].content))
        p.deleteLater()
    def test_viewport_geometry_and_event_loop(self):
        w=self.w
        with patch.object(base.gui.core_logic,'registrar_log'):w._aplicar_snapshot_monitoramento((True,SNAPSHOT,'fixture'))
        w._mostrar_diagnostico_integrado(diagnostic())
        ticks=[];timer=QTimer(w);timer.setInterval(10);timer.timeout.connect(lambda:ticks.append(time.perf_counter()));timer.start()
        for width,height in ((1366,768),(1920,1080)):
            w.resize(round(width/w.devicePixelRatioF()),round(height/w.devicePixelRatioF()))
            for page in (5,0):
                w._set_nav(page);self.pump()
                area=w.pages.widget(page)
                self.assertIsInstance(area,QScrollArea)
                self.assertEqual(area.horizontalScrollBar().maximum(),0)
            w._mostrar_diagnostico_integrado(diagnostic());QTest.qWait(50)
        timer.stop();self.assertGreater(len(ticks),2)


def screenshots(out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    case=base.UxTests();case.setUp();w=case.w
    w.texto_detalhes_rede.setPlainText(w._formatar_detalhes_rede(r2.NETWORK))
    w._mostrar_diagnostico_integrado(diagnostic())
    with patch.object(base.gui.core_logic,'registrar_log'):w._aplicar_snapshot_monitoramento((True,SNAPSHOT,'fixture'))
    metrics=[]
    for width,height in ((1366,768),(1920,1080)):
        w.resize(round(width/w.devicePixelRatioF()),round(height/w.devicePixelRatioF()))
        for name,page,focus in [('dns',5,w.monitor_interface.parentWidget().parentWidget()),('ram',0,w.diagnostico_integrado.views['Hardware']),('disco',0,w.diagnostico_integrado.views['Armazenamento']),('raw',0,w.diagnostico_integrado.tabs.sections[5])]:
            w._set_nav(page)
            if name=='raw':w.diagnostico_integrado.tabs.setCurrentIndex(5)
            for _ in range(5):base.app.processEvents()
            area=w.pages.widget(page)
            area.verticalScrollBar().setValue(max(0,focus.mapTo(area.widget(),QPoint(0,0)).y()-45))
            for _ in range(5):base.app.processEvents()
            w.grab().save(str(out/f'{name}_{width}.png'))
            metrics.append(dict(scene=name,width=w.width(),height=w.height(),horizontal=area.horizontalScrollBar().maximum()))
    (out/'geometry.json').write_text(json.dumps(metrics,indent=2));case.tearDown()

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--screenshots':screenshots(sys.argv[2])
    else:unittest.main(verbosity=2)
