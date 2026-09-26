"""Semantic identity continuity through public status; no DPAPI secret reads."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from desenvolvimento import agent_service_qa_2b_r4 as qa

class IdentityRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.state=self.root/'state';self.state.mkdir()
        self.exe=self.root/'ConfiguradorTIAgent.exe';self.exe.write_bytes(b'agent-test')
        self.identity=self.state/'identity.bin';self.identity.write_bytes(b'PRIVATE-KEY-NEVER-LOG')
        self.did=str(uuid.uuid4());self.fp='a'*64;self.report_dir=self.root/'reports'
        self.write_status('STOPPED')

    def write_status(self,status,*,did=None,fp=None):
        data={'status':status,'device_id':did or self.did,'updated_at':int(time.time()),'agent_version':'5.0.2'}
        if fp is not None:data['public_key_fingerprint']=fp
        (self.state/'status.json').write_text(json.dumps(data))

    def exercise(self,mutate=None,*,fingerprint=False):
        state={'scm':'STOPPED'};calls=[]
        self.write_status('STOPPED',fp=self.fp if fingerprint else None)
        def query(*,include_config=False):
            result={'state':state['scm']}
            if include_config: result.update(account_is_localservice=True,start_mode='MANUAL')
            return result
        def invoke(_exe,command,**kwargs):
            calls.append(command)
            if command=='smoke':return 0,{'status':'PASS','headless':True}
            if command=='service-status':return 0,{'status':'PASS','state':state['scm']}
            if command=='service-start':
                old=state['scm'];state['scm']='RUNNING'
                if old=='STOPPED' and calls.count('service-start')==2 and mutate:mutate()
                else:self.write_status('ONLINE',fp=self.fp if fingerprint else None)
                return 0,{'status':'PASS','state_before':old,'raw_control_code':0,'exit_code':0}
            if command=='service-stop':
                state['scm']='STOPPED';self.write_status('STOPPED',fp=self.fp if fingerprint else None)
                return 0,{'status':'PASS','state_before':'RUNNING','raw_control_code':0,'exit_code':0}
            raise AssertionError(command)
        with patch.object(qa.service,'state_root',return_value=self.state):
            report=qa.run_qa(self.exe,None,self.report_dir,native=True,query=query,
                             invoke=invoke,admin=lambda:True,acl=lambda _:True)
        report_json=next(self.report_dir.glob('*.json')).read_text()
        report_txt=next(self.report_dir.glob('*.txt')).read_text()
        return report,report_json+report_txt,calls

    def test_mtime_and_mutable_state_change_still_pass(self):
        def rewrite():
            self.identity.write_bytes(b'PRIVATE-KEY-NEVER-LOG / high_water=changed')
            os.utime(self.identity,(time.time()+100,time.time()+100))
            self.write_status('ONLINE')
        report,serialized,_=self.exercise(rewrite)
        self.assertEqual('PASS',report.value['summary']['final_status'])
        self.assertEqual('PASS',report.value['steps'][-1]['status'])
        self.assertNotIn('PRIVATE-KEY-NEVER-LOG',serialized)
        self.assertNotIn(self.did,serialized)

    def test_same_public_fingerprint_passes(self):
        report,_,_=self.exercise(fingerprint=True)
        self.assertEqual('PASS',report.value['steps'][-1]['status'])

    def test_changed_device_id_fails(self):
        report,_,_=self.exercise(lambda:self.write_status('ONLINE',did=str(uuid.uuid4())))
        self.assertEqual('FAIL',report.value['summary']['final_status'])
        self.assertEqual('IDENTITY_CHANGED',report.value['steps'][-1]['category'])

    def test_changed_public_fingerprint_fails(self):
        report,_,_=self.exercise(lambda:self.write_status('ONLINE',fp='b'*64),fingerprint=True)
        self.assertEqual('FAIL',report.value['steps'][-1]['status'])

    def test_missing_identity_fails(self):
        report,_,_=self.exercise(lambda:(self.identity.unlink(),self.write_status('ONLINE')))
        self.assertEqual('FAIL',report.value['steps'][-1]['status'])

    def test_bootstrap_reappears_fails(self):
        report,_,_=self.exercise(lambda:((self.state/'enrollment.bootstrap').write_bytes(b'SECRET-BOOTSTRAP'),self.write_status('ONLINE')))
        self.assertEqual('FAIL',report.value['steps'][-1]['status'])

    def test_reenrollment_required_fails(self):
        report,serialized,calls=self.exercise(lambda:self.write_status('ENROLLMENT_REQUIRED'))
        self.assertEqual('FAIL',report.value['steps'][-1]['status'])
        self.assertNotIn('service-install',calls)
        self.assertNotIn('PRIVATE-KEY-NEVER-LOG',serialized)

    def test_authentication_rejection_fails(self):
        report,_,_=self.exercise(lambda:self.write_status('AUTH_REQUIRED'))
        self.assertEqual('FAIL',report.value['steps'][-1]['status'])
        self.assertEqual('AUTH_REJECTED',report.value['steps'][-1]['category'])

    def test_offline_cannot_be_reported_as_verified_identity(self):
        self.write_status('OFFLINE')
        counter=[0]
        def clock():return counter[0]
        def sleep(delay):counter[0]+=delay
        result,observed=qa._await_public_status(self.state/'status.json','ONLINE',
                            not_before=int(time.time()),timeout=1,clock=clock,sleep=sleep)
        self.assertEqual('NEEDS_HUMAN',result)
        self.assertEqual('OFFLINE',observed['status'])
        self.assertEqual(1,counter[0])

    def test_default_and_explicit_report_paths(self):
        profile=self.root/'UserProfile'
        from types import SimpleNamespace
        with patch.object(qa,'os',SimpleNamespace(name='nt',environ={'USERPROFILE':str(profile)})):
            self.assertEqual(profile/'Documents'/'ConfiguradorTI-QA-Reports',qa.default_report_dir())
        with patch.object(qa.Path,'home',return_value=profile):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(2,qa.main(['--agent-exe',str(self.exe)]))
        self.assertEqual(1,len(list((profile/'Documents'/'ConfiguradorTI-QA-Reports').glob('*.json'))))
        self.assertEqual(1,len(list((profile/'Documents'/'ConfiguradorTI-QA-Reports').glob('*.txt'))))
        explicit=self.root/'custom reports'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(2,qa.main(['--agent-exe',str(self.exe),'--output-dir',str(explicit)]))
        self.assertEqual(1,len(list(explicit.glob('*.json'))))
        self.assertEqual(1,len(list(explicit.glob('*.txt'))))

if __name__=='__main__':unittest.main()
