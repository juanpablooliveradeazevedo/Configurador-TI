"""Focal service enrollment contract; Win32 clipboard/SCM still need Windows QA."""
import io
import ctypes
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock,patch

from agent import windows_service as service
from licensing.contracts import Denied


class ServiceEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.code=secrets.token_urlsafe(32)

    def test_real_generator_contract_and_invalid_inputs(self):
        for _ in range(30):
            self.assertEqual(43,len(service.validate_enrollment_code(secrets.token_urlsafe(32))))
        for bad in ('',' ','\x16','\x00', '\r',self.code+'\n',' '+self.code,
                    self.code+' ',self.code[:-1],self.code+'a',self.code+'=',
                    self.code[:2]+'é'+self.code[3:]):
            with self.subTest(kind=repr(bad[:2]),length=len(bad)):
                with self.assertRaises(Denied) as context: service.validate_enrollment_code(bad)
                self.assertEqual('INVALID_ENROLLMENT_CODE',context.exception.code)
                if bad:self.assertNotIn(bad,str(context.exception))

    def _read_keys(self,keys,paste=None):
        stderr=io.StringIO();key_reader=Mock(side_effect=keys)
        with patch.object(service.os,'name','nt'),patch.object(service.sys,'stdin',Mock(isatty=lambda:True)), \
             patch.object(service.sys,'stderr',stderr),patch.dict(sys.modules,{'msvcrt':types.SimpleNamespace(getwch=key_reader)}), \
             patch.object(service,'_clipboard_text',return_value=paste) as clipboard:
            code=service.read_enrollment_code()
        return code,stderr.getvalue(),clipboard

    def test_ctrl_v_clipboard_and_host_paste_no_echo(self):
        result,output,clipboard=self._read_keys(['\x16','\r'],self.code)
        self.assertEqual(self.code,result);clipboard.assert_called_once()
        self.assertNotIn(self.code,output)
        result,output,clipboard=self._read_keys([*self.code,'\r'])
        self.assertEqual(self.code,result);clipboard.assert_not_called()
        self.assertNotIn(self.code,output)

    def test_clipboard_unavailable_falls_back_to_hidden_manual_typing(self):
        output=io.StringIO()
        with patch.object(service.os,'name','nt'),patch.object(service.sys,'stdin',Mock(isatty=lambda:True)), \
             patch.object(service.sys,'stderr',output), \
             patch.dict(sys.modules,{'msvcrt':types.SimpleNamespace(getwch=Mock(side_effect=['\x16',*self.code,'\r']))}), \
             patch.object(service,'_clipboard_text',side_effect=Denied('CLIPBOARD_UNAVAILABLE')):
            self.assertEqual(self.code,service.read_enrollment_code())
        self.assertIn('Clipboard indisponível',output.getvalue())
        self.assertNotIn(self.code,output.getvalue())

    def test_win32_clipboard_lock_copy_unlock_close_and_fail_closed(self):
        class WinFn:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        raw=ctypes.create_string_buffer(self.code.encode('utf-16-le')+b'\x00\x00')
        events=[]
        user=types.SimpleNamespace(
            OpenClipboard=WinFn(lambda *_:events.append('open') or True),
            GetClipboardData=WinFn(lambda *_:1),
            CloseClipboard=WinFn(lambda:events.append('close') or True))
        kernel=types.SimpleNamespace(
            GlobalSize=WinFn(lambda *_:len(raw)),
            GlobalLock=WinFn(lambda *_:events.append('lock') or ctypes.addressof(raw)),
            GlobalUnlock=WinFn(lambda *_:events.append('unlock') or True))
        with patch.object(service.ctypes,'WinDLL',side_effect=lambda name,**_:user if name=='user32' else kernel,create=True):
            self.assertEqual(self.code,service._clipboard_text())
            self.assertEqual(['open','lock','unlock','close'],events)
            user.GetClipboardData=WinFn(lambda *_:None)
            with self.assertRaises(Denied) as context:service._clipboard_text()
            self.assertEqual('CLIPBOARD_UNAVAILABLE',context.exception.code)
            self.assertEqual('close',events[-1])

    def test_backspace_extended_key_and_control_failure(self):
        result,_,_=self._read_keys([*self.code[:-1],'x','\b','\xe0','H',self.code[-1],'\r'])
        self.assertEqual(self.code,result)
        for keys in (['\r'],['\x16','\r'],['\t'],['\x01'],[*self.code,'\x16','\r']):
            with self.subTest(keys_count=len(keys)):
                with self.assertRaises(Denied):self._read_keys(keys,'\x16')
        with patch.object(service.os,'name','nt'),patch.object(service.sys,'stdin',Mock(isatty=lambda:False)):
            with self.assertRaises(Denied) as context: service.read_enrollment_code()
        self.assertEqual('INTERACTIVE_CONSOLE_REQUIRED',context.exception.code)

    def test_invalid_input_never_enters_install_or_creates_state(self):
        with patch.object(service,'state_root',side_effect=AssertionError('state created')), \
             patch.object(service,'system_tool',side_effect=AssertionError('SCM invoked')), \
             patch.object(service,'machine_protect',side_effect=AssertionError('persisted')):
            for bad in ('\x16','',self.code+'\r',' '+self.code):
                with self.assertRaises(Denied) as context:service.install({'qa':True},bad)
                self.assertEqual('INVALID_ENROLLMENT_CODE',context.exception.code)

    def test_valid_install_protects_bootstrap_and_failed_scm_cleans_state(self):
        for scm_exit in (0,1):
            with self.subTest(scm_exit=scm_exit),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp);program=parent/'Program Files';program.mkdir()
                exe=program/'ConfiguradorTIAgent.exe';exe.write_bytes(b'exe')
                state=parent/'ProgramData'/'ConfiguradorTI-Agent'
                state.parent.mkdir()
                system_calls=[]
                def system_tool(name,args):
                    system_calls.append((name,args));return scm_exit if name=='sc.exe' else 0
                fake_os=types.SimpleNamespace(name='nt',environ={'ProgramFiles':str(program)})
                with patch.object(service,'os',fake_os),patch.object(service.ctypes,'windll',types.SimpleNamespace(shell32=Mock(IsUserAnAdmin=lambda:True)),create=True), \
                     patch.object(service,'state_root',return_value=state),patch.object(service,'system_tool',side_effect=system_tool), \
                     patch.object(service,'machine_protect',return_value=b'DPAPI-encrypted-only'), \
                     patch.object(service.sys,'executable',str(exe)),patch.object(service.sys,'frozen',True,create=True):
                    if scm_exit:
                        with self.assertRaises(Denied) as context:service.install({'qa':True},self.code)
                        self.assertEqual('SERVICE_INSTALL_FAILED',context.exception.code)
                        self.assertFalse(state.exists())
                    else:
                        self.assertEqual('INSTALLED',service.install({'qa':True},self.code)['status'])
                        self.assertEqual(b'DPAPI-encrypted-only',(state/'enrollment.bootstrap').read_bytes())
                        self.assertNotIn(self.code.encode(),(state/'enrollment.bootstrap').read_bytes())
                self.assertEqual(['icacls.exe','sc.exe'],[name for name,_ in system_calls])
                self.assertIn('LocalService',repr(system_calls[-1]))

    def test_bootstrap_is_one_use_only_after_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            bootstrap=Path(tmp)/'enrollment.bootstrap';bootstrap.write_bytes(b'DPAPI-encrypted-only')
            agent=Mock();agent.enroll.side_effect=Denied('NOT_FOUND')
            with patch.object(service,'dpapi',return_value=self.code.encode()) as dpapi:
                with self.assertRaises(Denied):service.enroll_from_bootstrap(agent,bootstrap)
                dpapi.assert_called_with(b'DPAPI-encrypted-only',True)
            self.assertTrue(bootstrap.exists())
            agent.enroll.side_effect=None
            with patch.object(service,'dpapi',return_value=self.code.encode()):
                service.enroll_from_bootstrap(agent,bootstrap)
            self.assertFalse(bootstrap.exists())
            bootstrap.write_bytes(b'DPAPI-encrypted-only')
            with patch.object(service,'dpapi',return_value=b'\x16'):
                with self.assertRaises(Denied) as context:service.enroll_from_bootstrap(agent,bootstrap)
            self.assertEqual('INVALID_BOOTSTRAP',context.exception.code)
            self.assertTrue(bootstrap.exists())

    def test_diagnostic_contains_fixed_category_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            service.record_service_failure(root,'ENROLLMENT',Denied('NOT_FOUND'))
            payload=(root/'service-diagnostic.json').read_text()
            self.assertEqual({'status':'FAILED','stage':'ENROLLMENT','code':'ENROLLMENT_REJECTED'},json.loads(payload))
            self.assertNotIn(self.code,payload)
            service.record_service_failure(root,'BOOTSTRAP',Exception('secret '+self.code))
            payload=(root/'service-diagnostic.json').read_text()
            self.assertEqual('BOOTSTRAP_FAILED',json.loads(payload)['code'])
            self.assertNotIn(self.code,payload)

    def test_scm_wrapper_records_sanitized_enrollment_failure(self):
        class WinFn:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        class FakeAgent:
            def __init__(self,*args):self.state={'binding':None}
            def enroll(self,code):raise Denied('NOT_FOUND')
            def close(self):pass
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'agent-public.json').write_text('{}')
            bootstrap=root/'enrollment.bootstrap';bootstrap.write_bytes(b'DPAPI-encrypted-only')
            statuses=[]
            win32=types.SimpleNamespace(
                RegisterServiceCtrlHandlerW=WinFn(lambda *_:1),
                SetServiceStatus=WinFn(lambda _handle,status:statuses.append((status._obj.current_state,status._obj.win32_exit)) or True),
                StartServiceCtrlDispatcherW=WinFn(lambda table:table[0].main(0,None) or True))
            fake_os=types.SimpleNamespace(name='nt',fdopen=os.fdopen,fsync=os.fsync,replace=os.replace,
                                          path=os.path,unlink=os.unlink)
            with patch.object(service,'os',fake_os),patch.object(service,'state_root',return_value=root), \
                 patch.object(service.ctypes,'WinDLL',return_value=win32,create=True), \
                 patch.object(service.ctypes,'WINFUNCTYPE',service.ctypes.CFUNCTYPE,create=True), \
                 patch('agent.runtime.Agent',FakeAgent),patch.object(service,'dpapi',return_value=self.code.encode()):
                service.run_service()
            self.assertTrue(bootstrap.exists())
            self.assertEqual((1,1066),statuses[-1])
            diagnostic=(root/'service-diagnostic.json').read_text()
            self.assertEqual({'status':'FAILED','stage':'ENROLLMENT','code':'ENROLLMENT_REJECTED'},json.loads(diagnostic))
            self.assertNotIn(self.code,diagnostic)


if __name__=='__main__':unittest.main()
