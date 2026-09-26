"""Security and integration contracts for the 2B reference deployments."""
import copy
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from control_plane.repository import SqliteRepository
from control_plane.service import ControlPlane
from control_plane.signing import EntitlementSigner
from control_plane.fleet import FleetService
from licensing.contracts import Denied,new_id,canonical
from licensing.verification import b64
from licensing.device import DeviceIdentity
from agent.runtime import Agent
from fleet_protocol.contracts import *
from fleet_protocol.transport import Transport

class Clock:
    def __init__(self): self.value=int(time.time())
    def __call__(self): return self.value
    def advance(self,n): self.value+=n
class Direct:
    def __init__(self,f): self.f=f;self.offline=False
    def call(self,route,payload,token=None):
        if self.offline: raise ConnectionError('BACKEND_UNAVAILABLE')
        return {'/v1/agent/challenge':self.f.challenge,'/v1/agent/enroll':self.f.enroll,'/v1/agent/call':self.f.agent}[route](payload)
class Fixture:
    def setup(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.clock=Clock()
        self.p=ControlPlane(SqliteRepository(self.root/'backend.db'),EntitlementSigner(Ed25519PrivateKey.generate(),'ent'),self.clock)
        self.f=FleetService(self.p,EntitlementSigner(Ed25519PrivateKey.generate(),'cmd'));self.owner=self.p.bootstrap_owner()
        self.f.bootstrap_web_owner(self.owner,'owner','temporary-password-123');self.token=self.login('owner')
        self.w('plan_policy',id='QA',seat_limit=10,device_limit=10,validity_seconds=3600,offline_seconds=300,minimum_supported_version='5.0',fleet_enabled=True)
        self.tid=self.w('create_tenant',label='Empresa QA')['id'];self.uid=self.user('tech','TECHNICIAN');self.lid=self.w('create_license',tenant_id=self.tid,plan_id='QA')['id'];self.w('assign_seat',user_id=self.uid,license_id=self.lid)
        self.inv=self.invite();self.direct=Direct(self.f)
        self.config={'endpoint':'http://127.0.0.1:8765','qa':True,'command_keys':self.f.signer.public_keys(),'entitlement_keys':self.p.signer.public_keys(),'sync_minimal':True}
        self.a=Agent(self.root/'agent',self.config,clock=self.clock,transport=self.direct);self.a.enroll(self.inv['enrollment_code']);self.did=self.inv['device_id']
    def teardown(self): self.a.close();self.tmp.cleanup()
    def login(self,name): return self.f.login({'username':name,'password':'temporary-password-123'})['access_token']
    def w(self,op,**p): return self.f.web(self.token,{'operation':op,'payload':p})
    def as_user(self,token,op,**p): return self.f.web(token,{'operation':op,'payload':p})
    def user(self,name,role,tenant=None): return self.w('create_user',tenant_id=tenant or self.tid,display_name=name,login=name,password='temporary-password-123',role=role)['id']
    def invite(self): return self.w('invite',user_id=self.uid,label='Notebook QA',protocol_version=1,agent_version=AGENT_VERSION,capabilities=list(CATALOG))
    def queue(self,**changes):
        p={'device_id':self.did,'action_id':'SET_MONITORING_INTERVAL','parameters':{'interval_seconds':120},'idempotency_key':new_id(),'issued_at':self.clock(),'confirmed':True};p.update(changes);return self.w('queue',**p)
    def c(self,cid): return self.p.repo.get('fleet_command',cid)
    def claim(self): return self.a._request('poll',{})['command']
    def sign_request(self,op,payload,**changes):
        b=self.a.state['binding'];p={k:b[k] for k in ('tenant_id','device_id','protocol_version','agent_version','capabilities')}
        p.update(issued_at=self.clock(),expires_at=self.clock()+30,nonce=new_id(),operation=op,payload=payload);p.update(changes)
        return {'payload':p,'signature':b64(self.a.identity.key.sign(canonical(p)))}
    def restart(self):
        public=self.a.identity.public();self.a.close();self.a=Agent(self.root/'agent',self.config,clock=self.clock,transport=self.direct);return public
class FleetTests(Fixture,unittest.TestCase):
    def setUp(self): self.setup()
    def tearDown(self): self.teardown()
    def test_enrollment_identity_persists(self):
        public=self.restart();self.assertEqual(public,self.a.identity.public());self.assertEqual(self.did,self.a.state['binding']['device_id'])
    def test_enrollment_code_one_use(self):
        with self.assertRaises(Denied): self.f.challenge({'code':self.inv['enrollment_code'],'public_key':DeviceIdentity().public()})
    def test_enrollment_expires(self):
        i=self.invite();self.clock.advance(301)
        with self.assertRaises(Denied): self.f.challenge({'code':i['enrollment_code'],'public_key':DeviceIdentity().public()})
    def test_enrollment_challenge_bound_capabilities(self):
        i=self.invite();key=DeviceIdentity();r=self.f.challenge({'code':i['enrollment_code'],'public_key':key.public()})
        c=copy.deepcopy(r['challenge']);c['purpose']='login'
        with self.assertRaises(Denied): self.f.enroll({'code':i['enrollment_code'],'challenge_id':c['id'],'proof':key.prove(c)})
    def test_revocation_requires_fresh_key(self):
        self.w('revoke_device',id=self.did);i=self.invite();r=self.f.challenge({'code':i['enrollment_code'],'public_key':self.a.identity.public()})
        with self.assertRaises(Denied): self.f.enroll({'code':i['enrollment_code'],'challenge_id':r['challenge']['id'],'proof':self.a.identity.prove(r['challenge'])})
    def test_heartbeat_status_online_offline(self):
        f=self.p.repo.get('fleet_agent',self.did);self.assertEqual('OFFLINE',self.f.status(f));self.a.tick(force=True)
        f=self.p.repo.get('fleet_agent',self.did);self.assertEqual(self.clock(),f['last_seen']);self.assertEqual('ONLINE',self.f.status(f));self.clock.advance(90);self.assertEqual('OFFLINE',self.f.status(f))
    def test_heartbeat_storage_bounded(self):
        n=len(self.p.repo.list('audit'))
        for i in range(50): self.a._request('heartbeat',{'summary':self.a.engine.summary()})
        self.assertEqual(1,len(self.p.repo.list('fleet_agent')));self.assertEqual(n,len(self.p.repo.list('audit')))
        self.clock.advance(121);self.f.cleanup();self.assertEqual([],self.p.repo.list('fleet_nonce'))
    def test_revoked_status_not_offline(self):
        self.w('revoke_device',id=self.did);self.a.tick(force=True)
        self.assertEqual('DEVICE_REVOKED',self.a.status);self.assertEqual('REVOKED',self.f.status(self.p.repo.get('fleet_agent',self.did)))
    def test_suspended_status(self):
        self.w('suspend_agent',id=self.did);self.assertEqual('SUSPENDED',self.f.status(self.p.repo.get('fleet_agent',self.did)))
    def test_unlicensed_status(self):
        self.w('revoke_license',id=self.lid);self.assertEqual('UNLICENSED',self.f.status(self.p.repo.get('fleet_agent',self.did)))
    def test_valid_action_real_engine_proof(self):
        c=self.queue();self.a.tick(force=True);row=self.c(c['id']);p=row['proof']
        self.assertEqual('SUCCEEDED',row['state']);self.assertEqual(60,p['before']);self.assertEqual(120,p['after']);self.assertTrue(p['rollback_available']);self.assertEqual(120,self.a.engine.store.get_monitoring_configuration()['interval_seconds'])
        self.assertEqual('SUCCESS',self.a.engine.store.get_action_run(p['action_run_id'])['result'])
    def test_rollback_existing_engine(self):
        c=self.queue();self.a.tick(force=True);p=self.c(c['id'])['proof'];run=self.a.engine.store.get_action_run(p['action_run_id'])
        from licensing.runtime import execution_gate
        from agent.engine import VerifiedGate
        body=json.loads(self.a.db.execute('SELECT body FROM commands').fetchone()[0]);ent=body['entitlement']['payload']
        with execution_gate(VerifiedGate(ent,self.clock)): out=self.a.engine.store.rollback_action(run['action_run_id'],monitoring_service=self.a.engine.monitor)
        self.assertEqual('ROLLED_BACK',out['status']);self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_expired_command_not_dispatched(self):
        c=self.queue();self.clock.advance(301);self.assertIsNone(self.claim());self.assertEqual('EXPIRED',self.c(c['id'])['state'])
    def test_lease_retry_new_claim(self):
        c=self.queue();one=self.claim();self.clock.advance(31);two=self.claim();self.assertNotEqual(one['payload']['claim_id'],two['payload']['claim_id']);self.assertEqual(one['payload']['command_id'],two['payload']['command_id'])
        with self.assertRaises(Denied): self.a._execute(one)
    def test_running_never_requeued_after_timeout(self):
        c=self.queue();e=self.claim()['payload'];self.a._request('start',{'command_id':e['command_id'],'claim_id':e['claim_id']});self.clock.advance(121)
        self.assertIsNone(self.claim());self.assertEqual('FAILED',self.c(c['id'])['state']);self.assertEqual('INDETERMINATE',self.c(c['id'])['timeout_result'])
    def test_pending_cancel(self):
        c=self.queue();self.w('cancel',id=c['id']);self.a.tick(force=True);self.assertEqual('CANCELLED',self.c(c['id'])['state']);self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_running_cancel_at_engine_boundary(self):
        c=self.queue();e=self.claim();original=self.a.engine.prepare
        def prepare(*args): self.w('cancel',id=c['id']);return original(*args)
        with patch.object(self.a.engine,'prepare',side_effect=prepare): self.a._execute(e)
        self.assertEqual('CANCELLED',self.c(c['id'])['state']);self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_duplicate_command_blocked_after_restart(self):
        self.queue();e=self.claim();self.a._execute(e);self.restart()
        with self.assertRaises(Denied): self.a._execute(e)
        self.assertEqual(1,self.a.db.execute('SELECT count(*) FROM commands').fetchone()[0])
    def test_idempotency_and_conflict(self):
        key=new_id();one=self.queue(idempotency_key=key);two=self.queue(idempotency_key=key);self.assertEqual(one['id'],two['id'])
        with self.assertRaises(Denied): self.queue(idempotency_key=key,parameters={'interval_seconds':300})
    def test_idempotency_concurrent(self):
        key=new_id();ids=[];errors=[]
        def worker():
            try: ids.append(self.queue(idempotency_key=key)['id'])
            except Exception as e: errors.append(type(e).__name__)
        ts=[threading.Thread(target=worker) for _ in range(4)]
        for t in ts:t.start()
        for t in ts:t.join()
        self.assertFalse(errors);self.assertEqual(1,len(set(ids)))
    def test_nonce_replay_persists_backend_restart(self):
        req=self.sign_request('heartbeat',{'summary':self.a.engine.summary()});self.f.agent(req)
        fresh=FleetService(ControlPlane(SqliteRepository(self.root/'backend.db'),self.p.signer,self.clock),self.f.signer)
        with self.assertRaises(Denied): fresh.agent(req)
    def test_wrong_tenant_signed_command(self):
        self.queue();e=self.claim();e['payload']['tenant_id']=new_id();e=self.f.signer.sign(e['payload'])
        with self.assertRaises(Denied): self.a._execute(e)
        self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_wrong_device_request(self):
        r=self.sign_request('poll',{},device_id=new_id())
        with self.assertRaises(Denied): self.f.agent(r)
    def test_wrong_signature(self):
        r=self.sign_request('poll',{});r['signature']=b64(DeviceIdentity().key.sign(canonical(r['payload'])))
        with self.assertRaises(Denied): self.f.agent(r)
    def test_key_purpose_separation(self):
        with self.assertRaises(Denied): FleetService(self.p,self.p.signer)
    def test_capability_negotiation_rejects(self):
        for caps in ([],['shell'],list(CATALOG)*2):
            with self.subTest(caps=caps),self.assertRaises(Denied): negotiation(1,AGENT_VERSION,caps)
    def test_protocol_product_separate(self):
        for proto,version in ((2,AGENT_VERSION),(True,AGENT_VERSION),(1,'4.9')):
            with self.subTest(proto=proto,version=version),self.assertRaises(Denied): negotiation(proto,version,list(CATALOG))
    def test_unknown_action_denied(self):
        with self.assertRaises(Denied): self.queue(action_id='RUN_SHELL')
    def test_arbitrary_script_parameter_denied(self):
        for name in ('shell','script','powershell','command','upload'):
            with self.subTest(name=name),self.assertRaises(Denied): self.queue(parameters={'interval_seconds':120,name:'ignored-but-forbidden'})
    def test_parameter_types_closed(self):
        for value in ('120',True,0,61,100000):
            with self.subTest(value=value),self.assertRaises(Denied): self.queue(parameters={'interval_seconds':value})
    def test_revocation_after_lease_before_start(self):
        c=self.queue();e=self.claim();self.w('revoke_device',id=self.did)
        with self.assertRaises(Denied): self.a._execute(e)
        self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_entitlement_removed_before_poll(self):
        c=self.queue();plan=self.p.repo.get('plan','QA');plan['features'].remove('transactional_actions');self.p.repo.put('plan',plan)
        self.assertIsNone(self.claim());self.assertEqual('CANCELLED',self.c(c['id'])['state'])
    def test_expired_entitlement_rejected_agent(self):
        self.queue();e=self.claim();payload=e['payload']['entitlement']['payload'];payload['expires_at']=self.clock()-1;e['payload']['entitlement']=self.p.signer.sign(payload);e=self.f.signer.sign(e['payload'])
        with self.assertRaises(Denied): self.a._execute(e)
    def test_cross_tenant_admin_cannot_read_mutate(self):
        tid=self.w('create_tenant',label='B')['id'];u=self.user('adminb','TENANT_ADMIN',tid);token=self.login('adminb')
        snap=self.as_user(token,'snapshot',offset=0);self.assertFalse(snap['fleet_agent']);self.assertTrue(all(x['tenant_id']==tid for x in snap['user']))
        for op,p in [('revoke_device',{'id':self.did}),('force_logout',{'user_id':self.uid}),('queue',{'device_id':self.did,'action_id':'SET_MONITORING_INTERVAL','parameters':{'interval_seconds':120},'idempotency_key':new_id(),'issued_at':self.clock(),'confirmed':True})]:
            with self.subTest(op=op),self.assertRaises(Denied): self.as_user(token,op,**p)
    def test_technician_cannot_administer_license(self):
        token=self.login('tech')
        with self.assertRaises(Denied): self.as_user(token,'create_license',tenant_id=self.tid,plan_id='QA')
    def test_viewer_cannot_mutate(self):
        self.user('view','VIEWER');token=self.login('view')
        for op in ('create_tenant','cancel','invite','queue'):
            with self.subTest(op=op),self.assertRaises(Denied): self.as_user(token,op)
    def test_owner_independent_of_tenant(self):
        self.w('suspend_tenant',id=self.tid);self.assertEqual('OWNER',self.w('snapshot',offset=0)['principal']['role'])
    def test_force_logout_web_and_2a_boundary(self):
        token=self.login('tech');self.p.admin(self.owner,'force_logout',{'user_id':self.uid})
        with self.assertRaises(Denied): self.as_user(token,'snapshot',offset=0)
    def test_role_change_revokes_web(self):
        token=self.login('tech');self.w('role',user_id=self.uid,role='VIEWER')
        with self.assertRaises(Denied): self.as_user(token,'snapshot',offset=0)
    def test_password_never_persisted_plaintext(self):
        rows=self.p.repo.list('qa_login');self.assertTrue(all('verifier' in r and 'password' not in r for r in rows));self.assertNotIn('temporary-password',json.dumps(rows))
    def test_privacy_schema_rejects_hostname_secret(self):
        s=self.a.engine.summary();s['inventory']['hostname']='sensitive'
        with self.assertRaises(Denied): self.a._request('heartbeat',{'summary':s})
    def test_proof_rejects_evidence_blob(self):
        c=self.queue();self.a.tick(force=True);pr=self.c(c['id'])['proof'];pr['raw_evidence']='secret'
        with self.assertRaises(Denied): proof(pr)
    def test_audit_filtered_no_cross_tenant(self):
        self.user('admin','TENANT_ADMIN');token=self.login('admin');rows=self.as_user(token,'audit',tenant='',actor='',action='',result='')['rows'];self.assertTrue(all(r['tenant_id']==self.tid for r in rows))
    def test_retry_backoff_offline_reconnect(self):
        self.direct.offline=True;self.a.tick(force=True);self.assertEqual('OFFLINE',self.a.status);first=self.a.next_attempt;self.a.tick(force=True);self.assertGreater(self.a.next_attempt,first)
        self.direct.offline=False;self.a.tick(force=True);self.assertEqual('ONLINE',self.a.status)
    def test_result_delivery_loss_does_not_reexecute(self):
        c=self.queue();original=self.direct.call;failed=[False]
        def call(route,p,token=None):
            if p.get('payload',{}).get('operation')=='result' and not failed[0]: failed[0]=True;raise ConnectionError('lost')
            return original(route,p,token)
        self.direct.call=call;self.a.tick(force=True);self.assertEqual('OFFLINE',self.a.status);self.assertEqual(120,self.a.engine.monitor.interval_seconds)
        self.restart();self.a.tick(force=True);self.assertEqual('SUCCEEDED',self.c(c['id'])['state']);self.assertEqual(1,self.a.db.execute('SELECT count(*) FROM commands').fetchone()[0])
    def test_crash_after_start_recovery_uncertain_not_rerun(self):
        c=self.queue();envelope=self.claim();e=envelope['payload'];self.a._request('start',{'command_id':c['id'],'claim_id':e['claim_id']})
        self.a.db.execute('INSERT INTO commands VALUES(?,?,?,?,?,?,?)',(c['id'],e['nonce'],json.dumps(e),'EXECUTING',None,self.clock(),None));self.a.db.commit();self.restart();self.a.tick(force=True)
        self.assertEqual('INDETERMINATE',self.c(c['id'])['proof']['result']);self.assertEqual(60,self.a.engine.monitor.interval_seconds)
    def test_single_instance_lock(self):
        with self.assertRaises(Denied): Agent(self.root/'agent',self.config,clock=self.clock,transport=self.direct)
    def test_clock_rollback_denied(self):
        self.clock.advance(-121)
        with self.assertRaises(Denied): self.a._request('poll',{})
    def test_minimum_release_version_enforced(self):
        plan=self.p.repo.get('plan','QA');plan['minimum_supported_version']='6.0';self.p.repo.put('plan',plan)
        with self.assertRaises(Denied): self.queue()
    def test_empty_unconfirmed_queue_denied(self):
        with self.assertRaises(Denied): self.queue(confirmed=False)
    def test_stale_idempotency_cannot_reexecute_after_retention(self):
        c=self.queue();self.a.tick(force=True);self.clock.advance(86401);self.f.cleanup();self.assertFalse(self.p.repo.list('fleet_command'))
        with self.assertRaises(Denied): self.queue(idempotency_key=c['idempotency_key'],issued_at=c['issued_at'])
    def test_read_only_session_absolute_expiry(self):
        self.clock.advance(1801)
        with self.assertRaises(Denied): self.w('snapshot',offset=0)
    def test_public_snapshot_no_credentials(self):
        data=json.dumps(self.w('snapshot',offset=0));self.assertNotIn('verifier',data);self.assertNotIn('public_key',data);self.assertNotIn('access_hash',data);self.assertNotIn(self.token,data)
    def test_http_remote_plaintext_rejected(self):
        for endpoint,qa in [('http://example.com',True),('http://localhost',True),('http://127.0.0.1',False),('https://user:password@example.com',False),('https://example.com/?token=x',False)]:
            with self.subTest(endpoint=endpoint),self.assertRaises(Denied): Transport(endpoint,qa=qa)
    def test_late_proof_after_network_loss_is_reconciled(self):
        c=self.queue();original=self.direct.call
        def call(route,p,token=None):
            if p.get('payload',{}).get('operation')=='result': raise ConnectionError('lost')
            return original(route,p,token)
        self.direct.call=call;self.a.tick(force=True);self.clock.advance(121);self.f.sweep()
        self.assertEqual('FAILED',self.c(c['id'])['state']);self.direct.call=original;self.restart();self.a.tick(force=True)
        row=self.c(c['id']);self.assertEqual('SUCCEEDED',row['state']);self.assertTrue(row['late_proof'])
    def test_forged_success_must_match_requested_postcondition(self):
        c=self.queue();e=self.claim()['payload'];self.a._request('start',{'command_id':c['id'],'claim_id':e['claim_id']})
        pr={k:e[k] for k in ('command_id','correlation_id','tenant_id','device_id','actor','action_id','playbook_id')}
        pr.update(action_run_id=new_id(),before=60,after=300,dry_run=True,preconditions=True,execution='EXECUTED',validator=True,rollback_available=True,result='SUCCESS',started_at=self.clock(),completed_at=self.clock())
        with self.assertRaises(Denied):self.a._request('result',{'command_id':c['id'],'claim_id':e['claim_id'],'proof':pr})
    def test_action_does_not_modify_desktop_feature_gate(self):
        from licensing.runtime import _execution_gate
        self.queue();self.a.tick(force=True);self.assertIsNone(_execution_gate.get())
if __name__=='__main__': unittest.main()
