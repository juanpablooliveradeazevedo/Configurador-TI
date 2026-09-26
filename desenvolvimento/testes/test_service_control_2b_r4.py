"""Deterministic SCM transition tests; native Win32 still needs Windows QA."""
import ctypes
import types
import unittest
from unittest.mock import patch
from agent import windows_service as service

class Clock:
    def __init__(self):self.now=0
    def monotonic(self):return self.now
    def sleep(self,duration):self.now+=duration

class ServiceControlTests(unittest.TestCase):
    def exercise(self,action,states,raw=0,timeout=2):
        clock=Clock();seen=[];calls=[]
        def query():
            state=states[min(len(seen),len(states)-1)];seen.append(state)
            return {'state':state,'win32_exit_code':0,'service_exit_code':0}
        def tool(name,args):calls.append((name,args));return raw
        with patch.object(service,'os',types.SimpleNamespace(name='nt')), \
             patch.object(service,'query_service',side_effect=query), \
             patch.object(service,'system_tool',side_effect=tool):
            result=service.control(action,timeout=timeout,clock=clock.monotonic,sleep=clock.sleep)
        return result,calls,seen

    def test_stop_zero_and_pending_to_stopped(self):
        r,calls,_=self.exercise('stop',['RUNNING','STOP_PENDING','STOPPED'])
        self.assertEqual('PASS',r['status']);self.assertEqual('STOPPED',r['state_after'])
        self.assertEqual(['RUNNING','STOP_PENDING','STOPPED'],r['transitions'])
        self.assertEqual(0,r['raw_control_code']);self.assertEqual(1,len(calls))

    def test_stop_1061_with_terminal_stopped_is_transient(self):
        r,_,_=self.exercise('stop',['RUNNING','STOP_PENDING','STOPPED'],raw=1061)
        self.assertEqual('PASS',r['status']);self.assertEqual(1061,r['exit_code'])
        self.assertEqual('TRANSIENT_CONTROL_RESULT',r['warning'])
        self.assertGreater(r['duration_ms'],0)

    def test_stop_1061_without_terminal_state_fails(self):
        r,_,_=self.exercise('stop',['RUNNING'],raw=1061,timeout=1)
        self.assertEqual('NEEDS_HUMAN',r['status']);self.assertEqual('RUNNING',r['state_after'])
        self.assertEqual('STATE_TIMEOUT',r['warning'])

    def test_stop_1061_with_service_error_is_not_success(self):
        clock=Clock()
        queries=iter(({'state':'RUNNING','win32_exit_code':0,'service_exit_code':0},
                      {'state':'STOPPED','win32_exit_code':1066,'service_exit_code':1}))
        with patch.object(service,'os',types.SimpleNamespace(name='nt')), \
             patch.object(service,'query_service',side_effect=lambda:next(queries)), \
             patch.object(service,'system_tool',return_value=1061):
            result=service.control('stop',clock=clock.monotonic,sleep=clock.sleep)
        self.assertEqual('NEEDS_HUMAN',result['status'])
        self.assertEqual('SERVICE_TERMINATED_WITH_ERROR',result['warning'])

    def test_pending_stop_is_idempotent_and_timeout_fails(self):
        r,calls,_=self.exercise('stop',['STOP_PENDING','STOPPED'])
        self.assertEqual('PASS',r['status']);self.assertIsNone(r['raw_control_code']);self.assertEqual([],calls)
        r,calls,_=self.exercise('stop',['STOP_PENDING'],timeout=1)
        self.assertEqual('NEEDS_HUMAN',r['status']);self.assertEqual('STATE_TIMEOUT',r['warning'])
        self.assertEqual([],calls)

    def test_start_pending_running_and_timeout(self):
        r,_,_=self.exercise('start',['STOPPED','START_PENDING','RUNNING'])
        self.assertEqual('PASS',r['status']);self.assertEqual('RUNNING',r['state_after'])
        r,calls,_=self.exercise('start',['START_PENDING','RUNNING'])
        self.assertEqual('PASS',r['status']);self.assertEqual([],calls)
        r,_,_=self.exercise('start',['STOPPED','START_PENDING'],timeout=1)
        self.assertEqual('NEEDS_HUMAN',r['status']);self.assertEqual('STATE_TIMEOUT',r['warning'])

    def test_absent_and_already_stopped(self):
        r,calls,_=self.exercise('stop',['ABSENT'])
        self.assertEqual('NEEDS_HUMAN',r['status']);self.assertEqual(1060,r['exit_code']);self.assertEqual([],calls)
        r,calls,_=self.exercise('stop',['STOPPED'])
        self.assertEqual('PASS',r['status']);self.assertEqual('ALREADY_IN_TARGET_STATE',r['warning'])
        self.assertEqual([],calls)

    def test_unexpected_raw_and_query_failure_not_masked(self):
        r,_,_=self.exercise('stop',['RUNNING','STOPPED'],raw=5)
        self.assertEqual('NEEDS_HUMAN',r['status']);self.assertEqual('CONTROL_REJECTED',r['warning'])
        with patch.object(service,'os',types.SimpleNamespace(name='nt')), \
             patch.object(service,'query_service',side_effect=service.Denied('SERVICE_QUERY_FAILED')), \
             patch.object(service,'system_tool',side_effect=AssertionError('no control without state')):
            r=service.control('stop')
        self.assertEqual('NEEDS_HUMAN',r['status']);self.assertEqual('STATE_QUERY_FAILED',r['warning'])

    def test_native_query_handles_closed_and_absent_without_locale_parsing(self):
        class WinFn:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        closed=[]
        def status(_service,_info,buf,_size,_needed):
            fields=ctypes.cast(buf,ctypes.POINTER(service.w.DWORD*9)).contents
            fields[1]=4;fields[3]=0;fields[4]=0
            return True
        api=types.SimpleNamespace(
            OpenSCManagerW=WinFn(lambda *_:11),OpenServiceW=WinFn(lambda *_:22),
            QueryServiceStatusEx=WinFn(status),CloseServiceHandle=WinFn(lambda handle:closed.append(handle) or True))
        with patch.object(service,'os',types.SimpleNamespace(name='nt')), \
             patch.object(service.ctypes,'WinDLL',return_value=api,create=True):
            self.assertEqual('RUNNING',service.query_service()['state'])
            self.assertEqual([22,11],closed)
            api.OpenServiceW=WinFn(lambda *_:0)
            with patch.object(service.ctypes,'get_last_error',return_value=1060,create=True):
                self.assertEqual({'state':'ABSENT'},service.query_service())
            self.assertEqual([22,11,11],closed)

if __name__=='__main__':unittest.main()
