"""Local runner/report tests with synthetic SCM; no native Windows claim."""
import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from desenvolvimento import agent_service_qa_2b_r4 as qa

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.exe=self.root/'ConfiguradorTIAgent.exe';self.exe.write_bytes(b'agent-test')
        self.state=self.root/'state';self.state.mkdir()
        self.did=str(uuid.uuid4())
        (self.state/'identity.bin').write_bytes(b'opaque-ciphertext')
        self.write_status('STOPPED')
        self.report_dir=self.root/'reports'

    def write_status(self,status,device_id=None,public_key_fingerprint=None):
        data={'status':status,'device_id':device_id or self.did,'updated_at':int(time.time()),'agent_version':'5.0.2'}
        if public_key_fingerprint is not None:data['public_key_fingerprint']=public_key_fingerprint
        (self.state/'status.json').write_text(json.dumps(data))

    def load(self,report):
        files=list(self.report_dir.glob('*.json'));self.assertEqual(1,len(files))
        txt=list(self.report_dir.glob('*.txt'));self.assertEqual(1,len(txt))
        obj=json.loads(files[0].read_text())
        self.assertEqual(report.value,obj)
        self.assertEqual('2B-R5',obj['phase'])
        self.assertTrue(all(row['duration_ms']>=0 and row['status'] in qa.STATUS for row in obj['steps']))
        return obj,txt[0].read_text()

    def test_report_whitelists_untrusted_fields_and_secrets(self):
        markers=['password=test-secret','private key: private-test-secret',
                 'cookie: session-test-secret','csrf=test-secret',
                 'Bearer '+secrets.token_urlsafe(32)]
        report=qa.Report()
        for marker in markers:
            report.add('platform','PASS',marker,qa.utc_now(),2,
                       state_before=marker,state_after=['RUNNING'],sha256=marker,exit_code=marker)
        report.save(self.report_dir)
        obj,text=self.load(report)
        for marker in markers:self.assertNotIn(marker,json.dumps(obj)+text)
        self.assertEqual('QA_STEP_FAILED',obj['steps'][0]['category'])
        self.assertEqual('PASS',obj['summary']['final_status'])

    def run_scenario(self,*,stop_state='STOPPED',stop_status='PASS',stop_raw=1061):
        current={'state':'STOPPED'};commands=[]
        def query(*,include_config=False):
            result={'state':current['state']}
            if include_config:result.update(account_is_localservice=True,start_mode='MANUAL')
            return result
        def invoke(exe,command,**kwargs):
            commands.append((command,kwargs))
            if command=='smoke':return 0,{'status':'PASS','headless':True}
            if command=='service-status':return 0,{'status':'PASS','state':current['state']}
            if command=='service-start':
                old=current['state'];current['state']='RUNNING'
                self.write_status('ONLINE')
                return 0,{'status':'PASS','state_before':old,'state':'RUNNING','raw_control_code':0,'exit_code':0}
            if command=='service-stop':
                old=current['state'];current['state']=stop_state
                self.write_status('STOPPED')
                return 0,{'status':stop_status,'state_before':old,'state':stop_state,
                          'warning':'TRANSIENT_CONTROL_RESULT','raw_control_code':stop_raw,
                          'exit_code':stop_raw}
            raise AssertionError('unexpected command')
        with patch.object(qa.service,'state_root',return_value=self.state):
            report=qa.run_qa(self.exe,None,self.report_dir,native=True,query=query,
                             invoke=invoke,admin=lambda:True,acl=lambda _:True)
        return report,commands

    def test_json_txt_warn_1061_only_after_stopped_and_no_cleanup(self):
        report,commands=self.run_scenario()
        data,text=self.load(report)
        self.assertEqual('WARN',data['summary']['final_status'])
        stop=next(s for s in data['steps'] if s['id']=='stop')
        self.assertEqual('WARN',stop['status']);self.assertEqual(1061,stop['raw_code'])
        self.assertEqual('STOPPED',stop['state_after']);self.assertIn('raw=1061',text)
        self.assertNotIn('service-remove',[cmd for cmd,_ in commands])
        self.assertTrue((self.state/'identity.bin').exists())

    def test_1061_without_stopped_writes_fail_report(self):
        report,_=self.run_scenario(stop_state='RUNNING',stop_status='NEEDS_HUMAN')
        data,_=self.load(report)
        self.assertEqual('FAIL',data['summary']['final_status'])
        self.assertEqual('FAIL',next(s for s in data['steps'] if s['id']=='stop')['status'])
        self.assertFalse(any(s['id']=='restart' for s in data['steps']))

    def test_needs_human_without_admin_writes_report_without_mutation(self):
        calls=[]
        def invoke(_exe,command,**kwargs):
            calls.append(command)
            return 0,{'status':'PASS','headless':True}
        with patch.object(qa.service,'state_root',return_value=self.state):
            report=qa.run_qa(self.exe,None,self.report_dir,native=True,
                 query=lambda **_: {'state':'ABSENT'},invoke=invoke,admin=lambda:False)
        data,_=self.load(report)
        self.assertEqual('NEEDS_HUMAN',data['summary']['final_status'])
        self.assertEqual(['smoke'],calls)
        self.assertEqual('ADMIN_REQUIRED',data['steps'][-1]['category'])

    def test_nonwindows_emits_two_reports(self):
        report=qa.run_qa(self.exe,None,self.report_dir,native=False)
        data,_=self.load(report)
        self.assertEqual('NEEDS_HUMAN',data['summary']['final_status'])
        self.assertEqual(1,len(data['steps']))

    def test_secret_install_prompt_remains_out_of_reports(self):
        secret=secrets.token_urlsafe(32)
        (self.state/'identity.bin').unlink()
        (self.state/'status.json').unlink()
        config=self.root/'agent-public.json';config.write_text('{"qa":true}')
        current={'state':'ABSENT'};calls=[]
        def query(*,include_config=False):
            value={'state':current['state']}
            if include_config and current['state']!='ABSENT':value.update(account_is_localservice=True,start_mode='MANUAL')
            return value
        def invoke(_exe,command,**kwargs):
            calls.append((command,kwargs))
            if command=='smoke':return 0,{'status':'PASS','headless':True}
            if command=='service-install':
                self.assertTrue(kwargs['secret']);self.assertEqual(config,kwargs['config'])
                current['state']='STOPPED';(self.state/'identity.bin').write_bytes(b'opaque')
                self.write_status('STOPPED')
                return 0,{}
            if command=='service-status':return 0,{'status':'PASS','state':current['state']}
            if command=='service-start':
                old=current['state'];current['state']='RUNNING'
                self.write_status('ONLINE')
                return 0,{'status':'PASS','state_before':old,'raw_control_code':0,'exit_code':0}
            if command=='service-stop':
                current['state']='STOPPED'
                self.write_status('STOPPED')
                return 0,{'status':'PASS','state_before':'RUNNING','raw_control_code':0,'exit_code':0}
            raise AssertionError(command)
        with patch.object(qa.service,'state_root',return_value=self.state),patch.object(qa.sys,'stdin') as stdin:
            stdin.isatty.return_value=True
            report=qa.run_qa(self.exe,config,self.report_dir,native=True,query=query,invoke=invoke,
                             admin=lambda:True,acl=lambda _:True,prompt=lambda _:secret)
        data,text=self.load(report)
        self.assertEqual('WARN',data['summary']['final_status'])
        self.assertIn('service-install',[cmd for cmd,_ in calls])
        self.assertNotIn(secret,json.dumps(data)+text)

if __name__=='__main__':unittest.main()
