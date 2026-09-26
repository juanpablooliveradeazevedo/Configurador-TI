"""2A: real Ed25519, persistent SQLite, HTTP and client trust-boundary tests."""
import copy,json,os,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from licensing.contracts import Denied,canonical,FEATURES,SAFE_FEATURES
from licensing.verification import EntitlementVerifier
from licensing.device import DeviceIdentity
from licensing.secure_store import SecureStore
from licensing.client import LicensingClient
from licensing.runtime import RuntimeGate
from licensing.transport import HttpAdapter
from licensing.build_guard import validate_public_config,inspect_client_tree,inspect_executable
from control_plane.repository import SqliteRepository
from control_plane.signing import EntitlementSigner
from control_plane.service import ControlPlane
from control_plane.http_service import QaServer
class Clock:
    def __init__(self):self.now=1800000000
    def __call__(self):return self.now
class Adapter:
    def __init__(self,plane):self.plane=plane;self.offline=False;self.calls=0
    def call(self,op,p,access_token=None):
        self.calls+=1
        if self.offline:raise ConnectionError('SERVER_UNAVAILABLE')
        return self.plane.client(op,p,access_token)
class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.clock=Clock()
        self.repo=SqliteRepository(self.root/'server'/'admin.db');self.signer=EntitlementSigner(Ed25519PrivateKey.generate(),'test-v1');self.cp=ControlPlane(self.repo,self.signer,self.clock)
        self.owner=self.cp.bootstrap_owner();self.tenant=self.admin('create_tenant',label='A');self.user=self.admin('create_user',tenant_id=self.tenant['id'],role='TECHNICIAN')
        self.lic=self.admin('create_license',tenant_id=self.tenant['id'],plan_id='QA');self.seat=self.admin('assign_seat',user_id=self.user['id'],license_id=self.lic['id'])
        self.adapter=Adapter(self.cp);self.client=self.new_client('client')
    def admin(self,op,**p):return self.cp.admin(self.owner,op,p)
    def new_client(self,name):return LicensingClient(self.adapter,SecureStore(self.root/name/'state.bin',qa=True),self.signer.public_keys(),clock=self.clock)
    def code(self,user=None):return self.admin('login_code',user_id=(user or self.user)['id'])['authorization_code']
    def login(self,client=None,user=None):
        c=client or self.client;self.assertEqual(c.login(self.code(user))['state'],'ONLINE_OK');return c
    def denied(self,fn,code=None):
        with self.assertRaises(Denied) as e:fn()
        if code:self.assertEqual(e.exception.code,code)
class IdentityTests(Fixture):
    def test_login_logout_refresh_rotation(self):
        self.login();old=self.client.data['refresh_token'];sid=self.client.data['session_id'];self.clock.now+=280
        self.assertEqual(self.client.renew()['state'],'ONLINE_OK');self.assertNotEqual(old,self.client.data['refresh_token']);self.denied(lambda:self.cp.identity.session(old,refresh=True))
        self.client.logout();self.assertEqual(self.repo.get('session',sid)['state'],'REVOKED');self.assertNotIn('refresh_token',self.client.data)
    def test_access_and_absolute_refresh_expiry(self):
        self.login();access=self.client.data['access_token'];self.clock.now+=301;self.denied(lambda:self.cp.identity.session(access));self.assertEqual(self.client.renew()['state'],'ONLINE_OK')
        self.clock.now+=86401;self.assertEqual(self.client.renew()['state'],'AUTH_REQUIRED')
    def test_one_use_and_expired_code(self):
        code=self.code();self.assertEqual(self.client.login(code)['state'],'ONLINE_OK');self.assertEqual(self.new_client('b').login(code)['state'],'AUTH_REQUIRED')
        code=self.code();self.clock.now+=121;self.assertEqual(self.client.login(code)['state'],'AUTH_REQUIRED')
    def test_force_logout_all_sessions_and_refresh(self):
        a=self.login();b=self.login(self.new_client('b'));self.admin('force_logout',user_id=self.user['id'])
        self.assertEqual(a.renew()['state'],'AUTH_REQUIRED');self.assertEqual(b.renew()['state'],'AUTH_REQUIRED');self.assertTrue(all(r['revoked'] for r in self.repo.list('refresh')))
    def test_suspended_user_denies_new_login_and_existing_session(self):
        self.login();code=self.code();self.admin('suspend_user',id=self.user['id']);self.assertEqual(self.client.renew()['state'],'AUTH_REQUIRED');self.assertEqual(self.new_client('b').login(code)['state'],'AUTH_REQUIRED')
    def test_revoke_session_and_refresh(self):
        for op,field in [('revoke_session','id'),('revoke_refresh','session_id')]:
            with self.subTest(op=op):
                self.login();self.admin(op,**{field:self.client.data['session_id']});self.assertEqual(self.client.renew()['state'],'AUTH_REQUIRED')
    def test_owner_is_independent_and_random(self):
        self.assertIsNone(self.repo.list('admin')[0]['tenant_id']);self.denied(self.cp.bootstrap_owner,'ALREADY_INITIALIZED');self.denied(lambda:self.cp.admin('wrong','list',{'kind':'tenant'}))
    def test_logout_offline_clears_local_cache_after_restart(self):
        self.login();self.adapter.offline=True;self.assertFalse(self.client.logout()['remote_logout']);self.assertFalse(self.new_client('client').is_allowed('guided_actions'))
    def test_injectable_identity_boundary(self):
        class Provider:
            def exchange(_,code):return {'subject':self.user['id']}
        self.cp.identity.provider=Provider();self.assertEqual(self.client.login('external-adapter-fixture')['state'],'ONLINE_OK')
class SignatureTests(Fixture):
    def setUp(self):super().setUp();self.login()
    def verify(self,e=None,keys=None):
        return EntitlementVerifier(keys or self.signer.public_keys()).verify(e or self.client.data['entitlement'],self.clock(),device_id=self.client.data['device_id'],public_key=self.client.device.public(),user_id=self.user['id'],tenant_id=self.tenant['id'])
    def test_valid_and_deterministic(self):
        p=self.verify();self.assertEqual(p['plan_id'],'QA');self.assertEqual(canonical(p),canonical(dict(reversed(list(p.items())))))
    def test_tampered_fields(self):
        for k,v in [('features',[]),('offline_until',9999999999),('tenant_id','other')]:
            with self.subTest(k=k):
                e=copy.deepcopy(self.client.data['entitlement']);e['payload'][k]=v;self.denied(lambda:self.verify(e))
    def test_wrong_and_unknown_key(self):
        other=EntitlementSigner(Ed25519PrivateKey.generate(),'test-v1');self.denied(lambda:self.verify(keys=other.public_keys()))
        e=copy.deepcopy(self.client.data['entitlement']);e['payload']['key_id']='unknown';self.denied(lambda:self.verify(e),'UNKNOWN_KEY')
    def test_signed_wrong_audience_issuer_not_before_and_expired(self):
        for field,value,code in [('audience','other','INVALID_ISSUER_AUDIENCE'),('issuer','other','INVALID_ISSUER_AUDIENCE'),('not_before',self.clock()+60,'NOT_YET_VALID')]:
            with self.subTest(field=field):
                p=copy.deepcopy(self.client.data['entitlement']['payload']);p[field]=value;self.denied(lambda:self.verify(self.signer.sign(p)),code)
        self.clock.now+=2592001;self.denied(self.verify,'OFFLINE_LEASE_EXPIRED')
    def test_revocation_cache(self):
        self.client.data['revoked']=[self.client.data['entitlement']['payload']['jti']];self.assertFalse(self.client.is_allowed('guided_actions'))
    def test_channel_and_session_binding(self):
        for field,value in [('channel','STABLE'),('session_id','other')]:
            p=copy.deepcopy(self.client.data['entitlement']['payload']);p[field]=value;e=self.signer.sign(p)
            self.denied(lambda:self.client._accept({'entitlement':e}),'INVALID_BINDING')
    def test_minimum_version(self):
        self.admin('plan_policy',id='QA',minimum_supported_version='5.1');self.assertEqual(self.client.renew()['state'],'OUTDATED_VERSION')
    def test_key_rotation_coexistence(self):
        other=EntitlementSigner(Ed25519PrivateKey.generate(),'test-v2');p=copy.deepcopy(self.client.data['entitlement']['payload']);p['key_id']='test-v2'
        self.verify(other.sign(p),dict(self.signer.public_keys(),**other.public_keys()))
class OfflineTests(Fixture):
    def test_network_failure_valid_lease_and_safe_reads(self):
        self.login();self.adapter.offline=True;self.assertEqual(self.client.renew()['state'],'OFFLINE_LEASE_VALID');self.assertTrue(self.client.is_allowed('guided_actions'))
        self.clock.now+=86401;self.assertEqual(self.client.snapshot()['state'],'OFFLINE_LEASE_EXPIRED')
        for feature in SAFE_FEATURES:self.assertTrue(self.client.is_allowed(feature))
        self.assertFalse(self.client.is_allowed('guided_actions'))
    def test_online_flag_cannot_extend_lease(self):
        self.login();self.clock.now+=86401;self.assertFalse(self.client.is_allowed('guided_actions'))
    def test_unavailable_without_session(self):
        self.adapter.offline=True;self.assertEqual(self.client.login(self.code())['state'],'SERVER_UNAVAILABLE')
    def test_backoff_and_bounded_retry(self):
        self.login();self.adapter.offline=True;self.client.renew();n=self.adapter.calls;self.client.renew();self.assertEqual(n,self.adapter.calls)
        for _ in range(12):self.clock.now+=301;self.client.renew();self.assertLessEqual(self.client.next_retry-self.clock(),300)
    def test_clock_rollback_and_persisted_high_water(self):
        self.login();self.clock.now-=121;self.assertEqual(self.client.snapshot()['state'],'CLOCK_SUSPECT');self.assertFalse(self.client.is_allowed('guided_actions'))
        restored=self.new_client('client');self.assertEqual(restored.snapshot()['state'],'CLOCK_SUSPECT')
    def test_restart_uses_cache_offline_and_preserves_key(self):
        self.login();old=self.client.device.public();restored=self.new_client('client');self.assertEqual(restored.device.public(),old);self.assertEqual(restored.snapshot()['state'],'OFFLINE_LEASE_VALID')
    def test_snapshot_does_not_wait_for_network_lock(self):
        self.login();entered=threading.Event();release=threading.Event();original=self.adapter.call
        def blocked(*a,**k):entered.set();release.wait(2);return original(*a,**k)
        with patch.object(self.adapter,'call',side_effect=blocked):
            worker=threading.Thread(target=self.client.renew);worker.start();self.assertTrue(entered.wait(1));start=time.monotonic();self.client.snapshot();self.assertLess(time.monotonic()-start,.2);release.set();worker.join(3);self.assertFalse(worker.is_alive())
class DeviceTests(Fixture):
    def test_enrollment_random_opaque_ids(self):
        import uuid
        self.login()
        for k in ('user_id','device_id','tenant_id','session_id'):uuid.UUID(self.client.data[k])
        self.assertEqual(len(self.repo.list('enrollment')),1)
    def test_device_limit_and_controlled_reenroll(self):
        self.login();self.login(self.new_client('b'));self.assertEqual(self.new_client('c').login(self.code())['reason'],'DEVICE_LIMIT')
        old=self.client.device.public();self.admin('revoke_device',id=self.client.data['device_id']);self.assertEqual(self.client.renew()['state'],'DEVICE_REVOKED')
        self.assertEqual(self.client.reenroll(self.code())['state'],'ONLINE_OK');self.assertNotEqual(old,self.client.device.public())
    def test_copied_entitlement_without_device_key_rejected(self):
        self.login();other=self.new_client('other');other.data.update({k:v for k,v in self.client.data.items() if k!='device_private'})
        self.assertFalse(other.is_allowed('guided_actions'))
    def test_challenge_replay_and_wrong_purpose(self):
        key=self.client.device;c=self.cp.client('challenge',{'purpose':'login','public_key':key.public()});proof=key.prove(c)
        self.denied(lambda:self.cp.devices.verify(c['id'],proof,key.public(),'renew'),'INVALID_CHALLENGE')
        self.cp.devices.verify(c['id'],proof,key.public(),'login');self.denied(lambda:self.cp.devices.verify(c['id'],proof,key.public(),'login'),'INVALID_CHALLENGE')
    def test_expired_challenge_and_wrong_key(self):
        key=self.client.device;c=self.cp.devices.challenge(key.public(),'login');other=DeviceIdentity()
        self.denied(lambda:self.cp.devices.verify(c['id'],other.prove(c),key.public(),'login'),'INVALID_DEVICE_PROOF')
        self.clock.now+=61;self.denied(lambda:self.cp.devices.verify(c['id'],key.prove(c),key.public(),'login'),'INVALID_CHALLENGE')
    def test_revoked_key_is_not_silently_reenabled(self):
        self.login();self.admin('revoke_device',id=self.client.data['device_id']);self.assertEqual(self.client.login(self.code())['state'],'DEVICE_REVOKED')
class AdministrationTests(Fixture):
    def test_all_seven_plans_are_backend_policy(self):
        self.assertEqual(len(self.repo.list('plan')),7);self.admin('plan_policy',id='QA',features=['reports.basic']);self.login();self.assertFalse(self.client.is_allowed('guided_actions'));self.assertTrue(self.client.is_allowed('reports.basic'))
    def test_seat_limit_release_and_usage(self):
        other=self.admin('create_user',tenant_id=self.tenant['id']);self.denied(lambda:self.admin('assign_seat',user_id=other['id'],license_id=self.lic['id']),'SEAT_LIMIT')
        self.login();self.admin('release_seat',id=self.seat['id']);self.assertEqual(self.client.renew()['reason'],'SEAT_REQUIRED')
        self.admin('assign_seat',user_id=other['id'],license_id=self.lic['id']);self.assertEqual(sum(s['state']=='ACTIVE' for s in self.repo.list('seat')),1)
    def test_concurrent_seat_assignment_never_overbooks(self):
        self.admin('release_seat',id=self.seat['id']);users=[self.admin('create_user',tenant_id=self.tenant['id']) for _ in range(4)]
        def assign(u):
            try:self.admin('assign_seat',user_id=u['id'],license_id=self.lic['id']);return True
            except Denied:return False
        with ThreadPoolExecutor(4) as pool:self.assertEqual(sum(pool.map(assign,users)),1)
    def test_tenant_admin_cannot_cross_tenant_or_create_owner(self):
        self.admin('role',user_id=self.user['id'],role='TENANT_ADMIN');self.login();token=self.client.data['access_token'];other=self.admin('create_tenant')
        self.assertEqual(len(self.cp.admin(token,'list',{'kind':'tenant'})),1)
        for op,p in [('create_user',{'tenant_id':other['id']}),('create_user',{'tenant_id':self.tenant['id'],'role':'OWNER'}),('plan_policy',{'id':'QA','seat_limit':100}),('create_tenant',{})]:self.denied(lambda:self.cp.admin(token,op,p))
    def test_technician_cannot_admin_and_viewer_has_no_mutation(self):
        self.login();self.denied(lambda:self.cp.admin(self.client.data['access_token'],'list',{'kind':'tenant'}),'FORBIDDEN')
        self.admin('role',user_id=self.user['id'],role='VIEWER');self.assertEqual(self.client.renew()['state'],'AUTH_REQUIRED');self.login();self.assertFalse(self.client.is_allowed('transactional_actions'))
    def test_tenant_suspension_bulk_revokes(self):
        self.login();code=self.code();self.admin('suspend_tenant',id=self.tenant['id'],revoke_devices=True)
        self.assertEqual(self.client.renew()['state'],'TENANT_SUSPENDED');self.assertEqual(self.client.login(code)['state'],'TENANT_SUSPENDED');self.assertTrue(all(d['state']=='REVOKED' for d in self.repo.list('device')))
    def test_license_and_entitlement_revocation(self):
        self.login();eid=self.client.data['entitlement']['payload']['jti'];self.admin('revoke_entitlement',id=eid);self.assertFalse(self.client.renew()['state']=='ONLINE_OK')
        self.login();self.admin('revoke_license',id=self.lic['id']);self.assertEqual(self.client.renew()['state'],'LICENSE_SUSPENDED')
    def test_audit_has_actions_ids_and_no_secrets(self):
        self.login();token=self.client.data['access_token'];refresh=self.client.data['refresh_token'];self.clock.now+=280;self.client.renew();self.client.logout()
        rows=self.repo.list('audit');actions={r['action'] for r in rows}
        self.assertTrue({'LOGIN_SUCCESS','SESSION_REFRESH','LOGOUT','TENANT_CREATED','USER_CREATED','LICENSE_CREATED','SEAT_ASSIGNED','ENTITLEMENT_ISSUED','DEVICE_ENROLLED'}<=actions)
        body=json.dumps(rows)
        for secret in (token,refresh,self.owner,self.client.device.private()):self.assertNotIn(secret,body)
        self.assertTrue(all(r['correlation_id'] and r['metadata']=={} for r in rows))
    def test_admin_listing_omits_token_hashes(self):
        self.login();rows=self.admin('list',kind='session');self.assertNotIn('access_hash',rows[0]);self.denied(lambda:self.admin('list',kind='refresh'))
class BoundaryTests(Fixture):
    def test_real_loopback_http_flow(self):
        with QaServer(('127.0.0.1',0),self.cp) as server:
            t=threading.Thread(target=server.serve_forever);t.start()
            try:
                adapter=HttpAdapter('http://127.0.0.1:'+str(server.server_port),qa=True)
                c=LicensingClient(adapter,SecureStore(self.root/'http'/'state.bin',qa=True),self.signer.public_keys(),clock=self.clock)
                self.login(c);self.admin('revoke_device',id=c.data['device_id']);self.assertEqual(c.renew()['state'],'DEVICE_REVOKED')
            finally:server.shutdown();t.join(2)
    def test_transport_refuses_plain_production_nonlocal_qa_and_credentials(self):
        for url,qa in [('http://127.0.0.1',False),('http://example.test',True),('https://secret@example.test',False),('https://example.test?secret=x',False)]:self.denied(lambda:HttpAdapter(url,qa=qa))
        self.denied(lambda:HttpAdapter('https://example.test').call('login',{'inventory':'forbidden'}),'INVALID_REQUEST')
    def test_atomic_store_failure_preserves_previous_bytes(self):
        store=SecureStore(self.root/'atomic.bin',qa=True);store.write({'before':1});old=store.path.read_bytes()
        with patch('licensing.secure_store.os.replace',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):store.write({'after':2})
        self.assertEqual(store.path.read_bytes(),old);self.assertFalse(list(self.root.glob('.license-*.tmp')))
    def test_store_rejects_symlink_corruption_and_nonqa_posix(self):
        target=self.root/'target';target.write_text('{}');link=self.root/'link';link.symlink_to(target)
        self.denied(lambda:SecureStore(link,qa=True).read(),'INVALID_STORE_PATH')
        store=SecureStore(self.root/'bad',qa=True);store.write({'x':1});store.path.write_text('invalid');self.denied(store.read,'INVALID_CACHE')
        if os.name!='nt':self.denied(lambda:SecureStore(self.root/'production'),'WINDOWS_SECURE_STORE_REQUIRED')
    def test_source_dev_never_enables_frozen(self):
        config=dict(config_version=1,source_mode='DEV_UNMANAGED',mode='PRODUCTION',endpoint='',public_keys={},channel='INTERNAL');(self.root/'licensing_public.json').write_text(json.dumps(config))
        self.assertTrue(RuntimeGate(self.root,self.root,frozen=False).is_allowed('guided_actions'));gate=RuntimeGate(self.root,self.root,frozen=True)
        self.assertFalse(gate.is_allowed('guided_actions'));self.assertTrue(gate.is_allowed('local.export'))
    def test_production_config_secret_and_qa_rejection(self):
        root=Path(__file__).resolve().parents[2];config=json.loads((root/'licensing_public.json').read_text());validate_public_config(config,'PRODUCTION')
        for key in ('private_key','refresh_token','owner_credential','password'):self.denied(lambda:validate_public_config(dict(config,**{key:'fixture'}),'PRODUCTION'))
        self.denied(lambda:validate_public_config(dict(config,mode='QA'),'PORTABLE'))
    def test_client_has_no_signing_key_or_backend_import(self):
        root=Path(__file__).resolve().parents[2];inspect_client_tree(root)
        p=self.root/'licensing';p.mkdir();(p/'bad.py').write_text('import control_plane.signing\n');self.denied(lambda:inspect_client_tree(self.root))
    def test_archive_guard_checks_pyz_and_embedded_config(self):
        import types
        config=json.loads((Path(__file__).resolve().parents[2]/'licensing_public.json').read_text());modules={'licensing.runtime','licensing.client','licensing.verification','licensing.device','licensing.gui'}
        class Archive:
            toc={'PYZ.pyz':(),'licensing_public.json':()}
            def __init__(self,*args):pass
            def open_embedded_archive(self,name):return types.SimpleNamespace(toc={x:() for x in modules})
            def extract(self,name):return json.dumps(config).encode()
        reader=types.ModuleType('PyInstaller.archive.readers');reader.CArchiveReader=Archive
        with patch.dict(sys.modules,{'PyInstaller.archive.readers':reader}):
            self.assertTrue(inspect_executable('fixture.exe','PRODUCTION',config)['backend_excluded']);modules.add('control_plane.signing');self.denied(lambda:inspect_executable('fixture.exe','PRODUCTION',config))
    def test_manifest_metadata_contains_only_public_contract(self):
        from release_metadata import build_metadata
        for channel in ('INTERNAL','BETA','STABLE'):
            m=build_metadata(profile='QA',release_channel=channel);self.assertEqual(m['release_channel'],channel);self.assertNotIn('token',json.dumps(m))
    def test_unknown_feature_denied_explanation_present(self):
        self.login();self.assertFalse(self.client.is_allowed('arbitrary'));self.assertIn('Requer licença',self.client.explain('arbitrary'));self.denied(lambda:self.client.require('arbitrary'),'FEATURE_DENIED')
if __name__=='__main__':unittest.main(verbosity=2)
