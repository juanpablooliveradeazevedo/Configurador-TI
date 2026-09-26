import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import network_intelligence as n

CTX = dict(Rede='10.1.1.0/24', IPv4='10.1.1.10', Alias='Ethernet', Gateway='10.1.1.1',
           InterfaceIndex=12, InterfaceGuid='fixture-guid', Profile='LAN', LocalMAC='00:11:22:33:44:10',
           DNS_servers=['10.1.1.1'])
MAC_A, MAC_B = '00:11:22:33:44:50', '00:11:22:33:44:51'
IP = '10.1.1.50'


def silent():
    return [n.evidence('ICMP', responded=False), n.evidence('TCP', responded=False, ports=[]), n.evidence('ARP/Neighbor')]


class EngineFixture(n.NetworkEngine):
    def context(self, interface):
        return dict(CTX)


class ModelTests(unittest.TestCase):
    def test_known_offline_never_free(self):
        first = n.observe(IP, CTX, None, [n.evidence('ICMP', strength=80, responded=True), n.evidence('ARP/Neighbor', mac=MAC_A), n.evidence('Reverse DNS', hostname='PC-01')])
        second = n.observe(IP, CTX, first, silent())
        self.assertEqual(n.consolidate(second)['state'], 'Conhecido, atualmente offline')
        self.assertEqual(first['last_online'], second['last_online'])
        self.assertEqual(second['macs'], [MAC_A])

    def test_unknown_and_provider_failure(self):
        record = n.observe(IP, CTX, None, silent())
        self.assertEqual(n.consolidate(record)['state'], 'Candidato a livre')
        self.assertIn('DHCP', n.consolidate(record)['limitations'][0])
        self.assertEqual(n.consolidate(record, history_ok=False)['state'], 'Desconhecido')
        record['evidence'][0]['status'] = 'error'
        self.assertEqual(n.consolidate(record)['state'], 'Desconhecido')

    def test_tcp_refusal_is_use(self):
        record = n.observe(IP, CTX, None, [n.evidence('TCP', strength=90, responded=True, ports=[])])
        self.assertEqual(n.consolidate(record)['state'], 'Em uso agora')

    def test_changed_mac_replacement_keeps_evidence(self):
        first = n.observe(IP, CTX, None, [n.evidence('ARP/Neighbor', mac=MAC_A)])
        second = n.observe(IP, CTX, first, [n.evidence('ARP/Neighbor', mac=MAC_B)])
        self.assertIn('possível conflito', second['identity_alert'])
        self.assertEqual(second['macs'], [MAC_A, MAC_B])
        self.assertNotIn('confirmado', second['identity_alert'])

    def test_scopes(self):
        self.assertNotEqual(n.scope_id(CTX, 'Empresa A'), n.scope_id(CTX, 'Empresa B'))
        self.assertEqual(n.scope_id(CTX, 'Empresa A'), n.scope_id(dict(CTX, GatewayMAC=MAC_A), 'Empresa A'))
        with self.assertRaises(ValueError): n.scope_id(CTX, '')

    def test_stale_not_current_candidate(self):
        record = n.observe(IP, CTX, None, silent(), now='2020-01-01T00:00:00+00:00')
        self.assertEqual(n.consolidate(record)['state'], 'Desconhecido')
        self.assertEqual(n.mac('FF:FF:FF:FF:FF:FF'), '')
        self.assertEqual(n.mac('01:00:5e:00:00:01'), '')

    def test_notes_sanitized(self):
        self.assertNotIn('abc123', n.clean('senha=abc123 http://example.invalid/a'))
        self.assertNotIn('\u202e', n.clean('A\u202eB'))

    def test_tcp_bound_interface_and_refused(self):
        class Sock:
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def settimeout(self,value): pass
            def bind(self,value): self.bound=value; self.outer.assertEqual(value,(CTX['IPv4'],0))
            def setsockopt(self,*args): self.outer.assertEqual(args,(socket.IPPROTO_IP,31,n.struct.pack('!I',12)))
            def connect(self,value): raise ConnectionRefusedError()
        sock=Sock();sock.outer=self
        with patch.object(n.socket,'socket',return_value=sock),patch.object(n.os,'name','nt'):
            result=n.TCPProvider().collect(IP,CTX['IPv4'],lambda:False,12)
        self.assertTrue(result['responded'])
        self.assertEqual(result['ports'],[])

    def test_native_icmp_reply_parsing_and_source(self):
        class Fn:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*a):return self.fn(*a)
        class API: pass
        api=API()
        api.IcmpCreateFile=Fn(lambda:123)
        closed=[]
        api.IcmpCloseHandle=Fn(lambda h:closed.append(h))
        def send(*args):
            self.assertEqual(args[4],n.struct.unpack('=I',socket.inet_aton(CTX['IPv4']))[0])
            self.assertEqual(args[-1],600)
            payload=n.struct.pack('=III',args[5],0,7)
            n.ctypes.memmove(args[9],payload,len(payload))
            return 1
        api.IcmpSendEcho2Ex=Fn(send)
        with patch.object(n.os,'name','nt'),patch.object(n.ctypes,'WinDLL',return_value=api,create=True):
            result=n.ICMPProvider().collect(IP,CTX['IPv4'],lambda:False)
        self.assertTrue(result['responded'])
        self.assertEqual(result['latency_ms'],7)
        self.assertEqual(closed,[123])


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = n.HistoryStore(self.tmp.name, fallback=self.tmp.name + '/fallback')
        self.scope = n.scope_id(CTX, 'Empresa A')

    def seed(self):
        self.store.transaction(lambda d: d['scopes'].update({self.scope: {'context': CTX, 'records': {IP: n.observe(IP, CTX, None, silent())}}}))

    def test_roundtrip_reserve_expire_remove_replace(self):
        self.seed()
        engine = n.NetworkEngine(self.tmp.name, None)
        engine.store = self.store
        item = engine.edit(self.scope, IP, 'reserve', 'Impressora RH', 1)
        self.assertEqual(item['state'], 'Reservado')
        self.assertEqual(n.HistoryStore(self.tmp.name).read()[0]['scopes'][self.scope]['records'][IP]['reservation']['description'], 'Impressora RH')
        future = n.datetime.fromtimestamp(time.time() + 7200, n.timezone.utc)
        self.assertIsNone(n.active_reservation(item, future))
        removed = engine.edit(self.scope, IP, 'remove')
        self.assertIsNone(removed['active_reservation'])
        original_events = len(removed['events'])
        after = engine.edit(self.scope, IP, 'replacement', 'Troca confirmada')
        self.assertGreater(len(after['events']), original_events)

    def test_corruption_preserved(self):
        p = self.store.paths[0]
        p.write_bytes(b'{corrupt')
        with self.assertRaises(ValueError): self.store.transaction(lambda d: None)
        self.assertEqual(p.read_bytes(), b'{corrupt')

    def test_lock_and_atomic_failure(self):
        self.seed()
        path = self.store.paths[0]
        original = path.read_bytes()
        lock = path.with_suffix('.lock')
        lock.write_text('other')
        with self.assertRaises(RuntimeError): self.store.transaction(lambda d: None)
        lock.unlink()
        with patch.object(n.os, 'replace', side_effect=OSError('disk error')):
            with self.assertRaises(OSError): self.store.transaction(lambda d: d.update(hello=1))
        self.assertEqual(original, path.read_bytes())
        self.assertFalse(lock.exists())
        self.assertFalse(list(path.parent.glob('.configurador_ti_net_*')))

    def test_limits_no_loss(self):
        self.seed()
        original = self.store.paths[0].read_bytes()
        with patch.object(n, 'MAX_BYTES', len(original) + 10):
            with self.assertRaises(ValueError): self.store.transaction(lambda d: d.update(big='x'*1000))
        self.assertEqual(self.store.paths[0].read_bytes(), original)

    def test_fallback_and_merge(self):
        blocked = Path(self.tmp.name) / 'notdir'
        blocked.write_text('file')
        store = n.HistoryStore(blocked, fallback=Path(self.tmp.name)/'writable')
        # Non-directory is not a legacy file; fallback may be used for initial write.
        with self.assertRaises(NotADirectoryError): store.read()
        self.seed()
        other = n.HistoryStore(self.tmp.name)
        other.transaction(lambda d: d['scopes'][self.scope]['records'][IP].update(note='other instance'))
        self.store.transaction(lambda d: d['scopes'][self.scope]['records'][IP].update(type='test'))
        self.assertEqual(other.read()[0]['scopes'][self.scope]['records'][IP]['note'], 'other instance')

    def test_read_only_primary_uses_fallback(self):
        original_open=n.os.open
        primary=self.store.paths[0].with_suffix('.lock')
        def deny(path,*a,**kw):
            if Path(path)==primary: raise PermissionError('fixture read-only')
            return original_open(path,*a,**kw)
        with patch.object(n.os,'open',side_effect=deny):
            self.store.transaction(lambda d: None)
        self.assertEqual(self.store.read()[1],self.store.paths[1])


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = EngineFixture(self.tmp.name, None)
        self.engine.store = n.HistoryStore(self.tmp.name, fallback=self.tmp.name+'/fallback')
        self.engine.neighbor.collect = lambda index: n.evidence('ARP/Neighbor', entries={'10.1.1.1': [{'mac':MAC_A, 'neighbor_state':'Reachable'}]})
        self.engine.icmp.collect = lambda ip, source, cancel: n.evidence('ICMP', responded=False)
        self.engine.tcp.collect = lambda *args: n.evidence('TCP', responded=False, ports=[])
        self.engine.dns.collect = lambda ip, server, cancel: n.evidence('Reverse DNS', 'unavailable', error='DNS fixture')

    def test_scan_focus_history_and_cancellation(self):
        self.engine.icmp.collect = lambda ip, source, cancel: n.evidence('ICMP', strength=80, responded=True)
        r = self.engine.run(CTX, 'A', focused_ip=IP)
        self.assertTrue(r['Sucesso'])
        self.assertEqual(r['records'][0]['state'], 'Em uso agora')
        self.engine.icmp.collect = lambda ip, source, cancel: n.evidence('ICMP', responded=False)
        r = self.engine.run(CTX, 'A', focused_ip=IP)
        self.assertEqual(r['records'][0]['state'], 'Conhecido, atualmente offline')
        path = self.engine.store.paths[0]
        original = path.read_bytes()
        self.assertFalse(self.engine.run(CTX, 'A', cancel_callback=lambda: True)['Sucesso'])
        self.assertEqual(path.read_bytes(), original)
        r = self.engine.run(CTX, 'A', history_only=True)
        self.assertEqual(len(r['records']), 1)
        with self.assertRaises(ValueError): self.engine.run(CTX, 'A', focused_ip='8.8.8.8')

    def test_24_complete_and_gateway_excluded(self):
        r = self.engine.run(CTX, 'A')
        self.assertEqual(len(r['records']), 254)
        ips = {v['ip']: v for v in r['records']}
        self.assertNotEqual(ips['10.1.1.1']['state'], 'Candidato a livre')
        self.assertEqual(ips[CTX['IPv4']]['state'], 'Em uso agora')
        self.assertEqual(ips[IP]['state'], 'Candidato a livre')

    def test_gateway_changed_reject_and_missing_unknown(self):
        self.engine.run(CTX, 'A', focused_ip=IP)
        self.engine.neighbor.collect = lambda index: n.evidence('ARP/Neighbor', entries={'10.1.1.1': [{'mac':MAC_B, 'neighbor_state':'Reachable'}]})
        with self.assertRaises(ValueError): self.engine.run(CTX, 'A', focused_ip=IP)
        self.engine.neighbor.collect = lambda index: n.evidence('ARP/Neighbor', entries={})
        result = self.engine.run(CTX, 'A', focused_ip=IP)
        self.assertEqual(result['records'][0]['state'], 'Desconhecido')

    def test_two_companies_do_not_share_history(self):
        self.engine.icmp.collect = lambda *args: n.evidence('ICMP', strength=80, responded=True)
        a = self.engine.run(CTX, 'Company A', focused_ip=IP)
        self.engine.icmp.collect = lambda *args: n.evidence('ICMP', responded=False)
        b = self.engine.run(CTX, 'Company B', focused_ip=IP)
        self.assertNotEqual(a['scope'], b['scope'])
        self.assertIsNone(b['records'][0]['last_online'])

    def test_changed_profile_not_new_free_history(self):
        self.engine.run(CTX, 'A', focused_ip=IP)
        self.engine.context = lambda _i: dict(CTX, Profile='Changed profile')
        for attempt in range(2):
            result=self.engine.run(CTX,'A',focused_ip=IP)
            self.assertEqual(result['records'][0]['state'],'Desconhecido')
            self.assertFalse(result['history_ok'])

    def test_provider_timeouts_controlled(self):
        def unavailable(*args, **kw): raise RuntimeError('PowerShell timeout fixture')
        neighbor = n.NeighborProvider(unavailable).collect(12)
        dns = n.DNSProvider(unavailable).collect(IP, '10.1.1.1', lambda: False)
        self.assertEqual(neighbor['status'], 'unavailable')
        self.assertEqual(dns['status'], 'unavailable')

    def test_native_context_revalidation_and_apipa(self):
        from subprocess import CompletedProcess
        def ps(script,timeout):
            return CompletedProcess([],0,json.dumps({'Status':'Up','Guid':'fixture-guid','MAC':MAC_A,'IPs':[{'IPAddress':CTX['IPv4'],'PrefixLength':24}],'DNS':['10.1.1.1'],'Gateway':'10.1.1.1','Profile':'LAN'}),'')
        engine=n.NetworkEngine(self.tmp.name,ps)
        self.assertEqual(engine.context(CTX)['IPv4'],CTX['IPv4'])
        for extra in ({'IPv4':'169.254.1.2'}, {'Rede':'10.8.8.0/24'}, {'InterfaceIndex':0}):
            with self.assertRaises(ValueError): engine.context(dict(CTX,**extra))

    def test_cancel_in_probe_does_not_commit(self):
        import threading
        cancelled=threading.Event()
        def probe(*args):
            cancelled.set()
            return n.evidence('ICMP','cancelled')
        self.engine.icmp.collect=probe
        r=self.engine.run(CTX,'A',cancel_callback=cancelled.is_set)
        self.assertFalse(r['Sucesso'])
        self.assertFalse(self.engine.store.paths[0].exists())

    def test_export_preserves_report_contract(self):
        path = Path(self.tmp.name)/'inventario.json'
        path.write_text(json.dumps({'Empresa':{'empresa':'fixture'},'Interfaces':[CTX]}))
        self.engine.inventory_path=path
        self.engine.run(CTX, 'A')
        data=json.loads(path.read_text())
        self.assertEqual(data['Empresa']['empresa'],'fixture')
        self.assertEqual(len(data['Hosts']),1)
        self.assertFalse(data['DisponibilidadeIPs']['Concluida'])



class PowerShellGenerationTests(unittest.TestCase):
    """Captura os argumentos REAIS de ps; não duplica os scripts de produção."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scripts = []
        self.data = dict(Status='Up', Guid='fixture-guid', MAC=MAC_A,
                         IPs=[dict(IPAddress=CTX['IPv4'], PrefixLength=24)],
                         Gateway=CTX['Gateway'], Profile='LAN', DNS=['10.1.1.1'])

    def ps(self, script, timeout):
        from types import SimpleNamespace
        self.scripts.append((script, timeout))
        return SimpleNamespace(returncode=0, stdout=json.dumps(self.data), stderr='')

    def context_script(self):
        result = n.NetworkEngine(self.tmp.name, self.ps).context(CTX)
        self.assertEqual(result['IPv4'], CTX['IPv4'])
        self.assertEqual(result['InterfaceGuid'], 'fixture-guid')
        self.assertEqual(result['DNS_servers'], ['10.1.1.1'])
        return self.scripts[-1][0]

    def assert_structure(self, script):
        # Verificação lexical limitada, NÃO substitui o parser oficial.
        stack, quote, i = [], None, 0
        pairs = {')':'(', ']':'[', '}':'{'}
        while i < len(script):
            ch = script[i]
            if quote:
                if ch == quote:
                    if i+1 < len(script) and script[i+1] == quote:
                        i += 2
                        continue
                    quote = None
                elif ch == '`' and quote == '"':
                    i += 2
                    continue
            elif ch in ("'", '"'):
                quote = ch
            elif ch in '([{':
                stack.append(ch)
            elif ch in ')]}':
                self.assertTrue(stack, 'Fechamento sem abertura')
                self.assertEqual(stack.pop(), pairs[ch])
            i += 1
        self.assertIsNone(quote, 'Literal aberto')
        self.assertEqual(stack, [], 'Delimitadores abertos')
        self.assertNotRegex(script, r'(?m)^\s*[+\-]+\s*\$\w+\s*=')
        self.assertIn('ConvertTo-Json', script)

    def test_real_context_first_assignment_and_contract(self):
        script = self.context_script()
        self.assertTrue(script.lstrip().startswith('$a=Get-NetAdapter'))
        self.assertEqual(script.lstrip().splitlines()[0],
                         '$a=Get-NetAdapter -InterfaceIndex 12 -ErrorAction Stop')
        self.assertNotIn('+$a=Get-NetAdapter', script)
        for cmd in ('Get-NetAdapter','Get-NetIPAddress','Get-NetRoute',
                    'Get-NetConnectionProfile','Get-DnsClientServerAddress'):
            self.assertIn(cmd, script)
        self.assertEqual(self.scripts[-1][1], 10)
        self.assertGreater(len(script.splitlines()), 5)
        self.assert_structure(script)

    def test_prefix_mutations_are_rejected(self):
        script = self.context_script()
        for prefix in ('+', '-', '++', 'x'):
            with self.subTest(prefix=prefix):
                self.assertFalse((prefix+script).lstrip().startswith('$a=Get-NetAdapter'))
        for prefix in ('+', '-', '++'):
            with self.assertRaises(AssertionError):
                self.assert_structure(prefix+script)

    def test_real_neighbor_dns_scripts_and_empty_returns(self):
        self.data = []
        result = n.NeighborProvider(self.ps).collect('12')
        self.assertEqual(result['entries'], {})
        self.assertTrue(self.scripts[-1][0].startswith('Get-NetNeighbor -InterfaceIndex 12 '))
        self.assertEqual(self.scripts[-1][1], 8)
        self.assert_structure(self.scripts[-1][0])
        result = n.DNSProvider(self.ps).collect(IP, '10.1.1.1', lambda:False)
        self.assertEqual(result['hostname'], '')
        script, timeout = self.scripts[-1]
        self.assertEqual(timeout, 4)
        self.assert_structure(script)
        for token in ('try {', 'catch {', '-ErrorAction Stop', '-Type PTR',
                      "-Name '10.1.1.50'", "-Server '10.1.1.1'", '-NoHostsFile'):
            self.assertIn(token, script)

    def test_untrusted_values_never_become_commands(self):
        engine = n.NetworkEngine(self.tmp.name, self.ps)
        for index in ("12;Get-Process", "'12'", 0, -1):
            with self.assertRaises(ValueError):
                engine.context(dict(CTX, InterfaceIndex=index))
        self.assertFalse(self.scripts)
        self.assertEqual(n.NeighborProvider(self.ps).collect("12;Get-Process")['status'], 'unavailable')
        for ip, server in (("10.1.1.1';x", '10.1.1.1'), (IP, "server';x")):
            with self.assertRaises(ValueError):
                n.DNSProvider(self.ps).collect(ip, server, lambda:False)
        self.assertFalse(self.scripts)
        self.data = []
        n.DNSProvider(self.ps).collect(IP, "fe80::1%a';Get-Process;'", lambda:False)
        script = self.scripts[-1][0]
        self.assertIn("-Server 'fe80::1%a'';Get-Process;'''", script)
        self.assert_structure(script)

    def test_real_passive_inventory_script(self):
        import ast
        tree = ast.parse((ROOT/'core_logic.py').read_text(encoding='utf-8-sig'))
        method = next(x for x in ast.walk(tree) if isinstance(x, ast.FunctionDef)
                      and x.name == 'coletar_inventario_rede')
        assignment = next(x for x in method.body if isinstance(x, ast.Assign)
                          and any(isinstance(t,ast.Name) and t.id=='script' for t in x.targets))
        script = ast.literal_eval(assignment.value)
        self.assertIn('Virtual=if ($adapter)', script)
        self.assert_structure(script)

    def test_failed_cmdlets_and_empty_context_do_not_succeed(self):
        from types import SimpleNamespace
        for stdout, stderr, code in [('', 'CommandNotFoundException', 1), ('', '', 0)]:
            def fail(script, timeout):
                return SimpleNamespace(stdout=stdout,stderr=stderr,returncode=code)
            with self.assertRaises((OSError, ValueError)):
                n.NetworkEngine(self.tmp.name, fail).context(CTX)
            if code:
                self.assertEqual(n.NeighborProvider(fail).collect(12)['status'], 'unavailable')
                self.assertEqual(n.DNSProvider(fail).collect(IP,'10.1.1.1',lambda:False)['status'], 'unavailable')

    def test_native_parser_when_available(self):
        import shutil
        import subprocess
        executable = shutil.which('pwsh') or shutil.which('powershell')
        if not executable:
            self.skipTest('VALIDAÇÃO NATIVA POWERSHELL/WINDOWS: PENDENTE')
        self.context_script()
        self.data = []
        n.NeighborProvider(self.ps).collect(12)
        n.DNSProvider(self.ps).collect(IP,'10.1.1.1',lambda:False)
        import ast
        tree = ast.parse((ROOT/'core_logic.py').read_text(encoding='utf-8-sig'))
        method = next(x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef)
                      and x.name=='coletar_inventario_rede')
        assignment = next(x for x in method.body if isinstance(x,ast.Assign)
                          and any(isinstance(t,ast.Name) and t.id=='script' for t in x.targets))
        self.scripts.append((ast.literal_eval(assignment.value),30))
        for index,(script,_) in enumerate(self.scripts):
            path = Path(self.tmp.name)/('generated%d.ps1'%index)
            path.write_text(script,encoding='utf-8-sig')
            literal = str(path).replace("'", "''")
            command = ("$t=$null;$e=$null;"
                       "[System.Management.Automation.Language.Parser]::ParseFile('"+
                       literal+"',[ref]$t,[ref]$e)|Out-Null;"
                       "if($e.Count){$e|ForEach-Object {$_.Message};exit 1}")
            response = subprocess.run([executable,'-NoProfile','-NonInteractive','-Command',command],
                                      capture_output=True,timeout=15,shell=False)
            self.assertEqual(response.returncode,0,response.stdout+response.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
