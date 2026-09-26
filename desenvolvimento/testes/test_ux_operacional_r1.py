"""Fixtures somente locais; nunca autentica, altera rede ou consulta hosts reais."""
import unittest,copy,tempfile,struct,socket,threading,time
from datetime import datetime,timezone
from unittest.mock import patch,MagicMock
import test_ux_global as base
import test_network_intelligence as previous
import hostname_identification as h
import operational_ui as ui
import network_intelligence as n
from PyQt6.QtWidgets import QTableWidget,QLabel
from PyQt6.QtCore import QTimer
from PyQt6.QtTest import QTest


def packet(names,transaction=7):
    data=bytes([len(names)])+b''.join(name.encode().ljust(15,b' ')+bytes([suffix])+struct.pack('!H',flags) for name,suffix,flags in names)
    return struct.pack('!6H',transaction,0x8400,0,1,0,0)+b'\x00'+struct.pack('!HHIH',33,1,0,len(data))+data


class IdentificationTests(unittest.TestCase):
    def test_netbios_real_wire_parser(self):
        self.assertEqual(h.parse_node_status(packet([('PC-FIN',0,0),('DOMAIN',0,0x8000),('SERVER',32,0)]),7),['PC-FIN'])
        for bad in (b'',packet([('PC',0,0)])[:-1],packet([('PC',0,0)],8)):
            with self.assertRaises(ValueError):h.parse_node_status(bad,7)
        self.assertEqual(h.valid_name('<img src=x>'),'')
    def test_transport_timeout_and_cancel(self):
        sock=MagicMock();sock.__enter__.return_value=sock;sock.recv.side_effect=socket.timeout()
        with patch.object(h.os,'name','nt'),patch.object(h.socket,'socket',return_value=sock):
            r=h.NetBIOSProvider().collect('10.1.1.50','10.1.1.10',lambda:False)
            self.assertEqual(r['status'],'unavailable');sock.settimeout.assert_called_with(.45)
            sock.connect.assert_called_once_with(('10.1.1.50',137))
            sent=sock.send.call_args.args[0];tx=struct.unpack('!H',sent[:2])[0]
            sock.recv.side_effect=None;sock.recv.return_value=packet([('PC-FIN',0,0)],tx)
            with patch.object(h.secrets,'randbits',return_value=tx):
                self.assertEqual(h.NetBIOSProvider().collect('10.1.1.50','10.1.1.10',lambda:False)['names'],['PC-FIN'])
        with patch.object(h.socket,'socket') as create:
            self.assertEqual(h.NetBIOSProvider().collect('10.1.1.50','10.1.1.10',lambda:True)['status'],'cancelled')
            create.assert_not_called()
    def test_ptr_netbios_conflict_and_no_state_effect(self):
        r=n.observe(previous.IP,previous.CTX,None,previous.silent());b=n.consolidate(r)
        stamp=n.utc();r['identifications']=h.metadata([],{'hostname':'PC-FIN.corp'},{'names':['PC-HR']},'',stamp)
        r['identification_checked']=stamp;r['alias']='Estação local';r['sector']='TI'
        a=n.consolidate(r)
        for key in ('state','score','confidence','last_online','last_seen','recommendation'):self.assertEqual(a.get(key),b.get(key))
        names,alert,items=h.identification(r)
        self.assertIn('PC-FIN',names);self.assertIn('divergente',alert);self.assertEqual(items[0]['source'],'DNS PTR')
        self.assertEqual(items[1]['confidence'],'Média')
        # No silent reassociation to a new MAC.
        r['mac']='00:11:22:33:44:99';r['identification_checked']='later'
        self.assertEqual(h.identification(r)[0],'Não identificado')
    def test_partial_source_failure_and_cancel_during_enrichment(self):
        with tempfile.TemporaryDirectory() as tmp:
            e=previous.EngineFixture(tmp,None)
            e.neighbor.collect=lambda *_:n.evidence('ARP/Neighbor',entries={previous.CTX['Gateway']:[{'mac':previous.MAC_A,'neighbor_state':'Reachable'}]})
            e.icmp.collect=lambda *args:n.evidence('ICMP',responded=False)
            e.tcp.collect=lambda *args:n.evidence('TCP',responded=False,ports=[])
            e.dns.collect=lambda *args:n.evidence('Reverse DNS',hostname='PTR-PRESERVADO')
            e.netbios.collect=MagicMock(side_effect=OSError('fixture failure'))
            result=e.run(previous.CTX,'Partial',focused_ip=previous.IP)
            self.assertTrue(result['Sucesso'])
            self.assertEqual(result['records'][0]['hostname'],'PTR-PRESERVADO')
            self.assertEqual(result['records'][0]['identification_status'],'unavailable')
            path=e.store.read()[1];data=path.read_bytes();stop=threading.Event()
            def cancel_nb(*args):
                stop.set();return {'status':'cancelled','names':[]}
            e.netbios.collect=cancel_nb
            result=e.run(previous.CTX,'Partial',focused_ip=previous.IP,cancel_callback=stop.is_set)
            self.assertFalse(result['Sucesso']);self.assertEqual(data,path.read_bytes())

    def test_254_bounded_and_legacy_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine=previous.EngineFixture(tmp,None)
            engine.neighbor.collect=lambda *_: n.evidence('ARP/Neighbor',entries={previous.CTX['Gateway']:[{'mac':previous.MAC_A,'neighbor_state':'Reachable'}]})
            engine.icmp.collect=lambda *args:n.evidence('ICMP',responded=True,strength=80)
            engine.tcp.collect=lambda *args:n.evidence('TCP',responded=False,ports=[])
            engine.dns.collect=lambda *args:n.evidence('Reverse DNS',hostname='PC-PTR')
            lock=threading.Lock();active=0;maximum=0
            def nb(*args):
                nonlocal active,maximum
                with lock:active+=1;maximum=max(maximum,active)
                time.sleep(.001)
                with lock:active-=1
                return {'status':'ok','names':['PC-NB']}
            engine.netbios.collect=nb
            start=time.perf_counter();result=engine.run(previous.CTX,'Fixture R1')
            self.assertEqual(len(result['records']),254);self.assertLessEqual(maximum,4)
            self.assertTrue(all(r.get('identifications') for r in result['records']))
            stored,path=engine.store.read();self.assertEqual(stored['schema'],1)
            print('R1 254 simulated enrichment seconds',round(time.perf_counter()-start,3),'concurrency',maximum)
            original=path.read_bytes();cancelled=engine.run(previous.CTX,'Fixture R1',cancel_callback=lambda:True)
            self.assertFalse(cancelled['Sucesso']);self.assertEqual(path.read_bytes(),original)
            # Old schema without extension remains readable.
            engine.store.transaction(lambda data:[r.pop('identifications',None) for s in data['scopes'].values() for r in s['records'].values()])
            self.assertEqual(engine.store.read()[0]['schema'],1)


class VisualTests(unittest.TestCase):
    def setUp(self):
        self.case=base.UxTests();self.case.setUp();self.w=self.case.w
    def tearDown(self):self.case.tearDown()
    def test_summary_structured_and_menu(self):
        self.w._mostrar_sensores_hardware(dict(Sucesso=True,Componentes=[dict(Componente='CPU',Medida='Uso total',Valor='12 %',Estado='Informativo',Origem='fixture')]))
        self.assertEqual(self.w.abas_sensores_hardware.tabText(0),'Resumo')
        text=' '.join(x.text() for x in self.w.abas_sensores_hardware.widget(0).findChildren(QLabel))
        self.assertIn('12 %',text);self.assertNotIn('throttling',text)
        self.assertFalse(self.w.nav_buttons[0].text().startswith('01'))
        raw='Adaptador: Ethernet\nIPv4: 10.1.1.50\nDescrição: <img src=x>'
        self.w.texto_detalhes_rede.setPlainText(raw)
        self.assertEqual(self.w.texto_detalhes_rede.toPlainText(),raw)
        self.assertNotIn('<img ',self.w.texto_detalhes_rede.toHtml())
    def test_local_timestamps(self):
        stamp=datetime.now(timezone.utc).isoformat()
        text,tip=ui.local_timestamp(stamp)
        self.assertIn('Hoje',text);self.assertIn('Original:',tip);self.assertIn(stamp,tip)
        self.assertEqual(ui.local_timestamp(None)[0],'—')
        self.assertEqual(ui.local_timestamp('bad')[0],'bad')
    def test_integrated_diagnostic_preserves_raw(self):
        raw='Computador: PC\nProcessador: CPU fixture\nMemória RAM:\nTotal: 8 GB\nArmazenamento Físico:\n• SSD 10 GB'
        self.w._mostrar_diagnostico_integrado(raw)
        p=self.w.diagnostico_integrado
        self.assertEqual(self.w.pages.count(),21);self.assertEqual(p.views['Texto técnico'].toPlainText(),raw)
        self.assertIn('CPU fixture',p.views['Resumo'].toPlainText())
        self.assertIn('não inclui dados de rede',p.views['Rede'].toPlainText())
    def test_modes_context_raw_search_without_cells(self):
        p=self.w.network_panel;record=n.consolidate(n.observe(previous.IP,previous.CTX,None,previous.silent()))
        record['identifications']=h.metadata([],{},dict(names=['PC-FIN']),'',n.utc());record['identification_checked']=record['identifications'][0]['observed_at']
        record['alias']='Alias fixture';record['sector']='Financeiro'
        p.receive(dict(Sucesso=True,records=[record],context=previous.CTX,scope='a'*64,history_ok=True,message='fixture'))
        cell=p.table.item(0,0);self.assertEqual(p.table.horizontalScrollMode(),QTableWidget.ScrollMode.ScrollPerPixel)
        with patch.object(p.table,'setItem',side_effect=AssertionError('rebuild')),patch.object(p.table,'setRowCount',side_effect=AssertionError('rebuild')):
            p.view_mode.setCurrentIndex(1);p.view_mode.setCurrentIndex(0)
            for query in ('PC-FIN','Alias fixture','Financeiro'):
                p.search.setText(query);p.apply_filter();self.assertEqual(p.selected_ip(),previous.IP)
            p.detail_tabs.setCurrentIndex(1)
            self.assertIn(previous.IP,p.device_context.text())
            self.assertIn('PC-FIN',p.device_context.text())
            p.search.setText('absent');p.apply_filter();self.assertEqual(p.selected_ip(),None)
            self.assertIn('Nenhum IP',p.device_context.text())
        self.assertIs(cell,p.table.item(0,0));p.clear_filters();p.details()
        self.assertIn(record['identification_checked'],p.raw_detail.toPlainText())

if __name__=='__main__':unittest.main(verbosity=2)
