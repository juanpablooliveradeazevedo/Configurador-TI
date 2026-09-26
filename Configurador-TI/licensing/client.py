"""Central client state/feature gates. Network operations are explicit Worker calls."""
import copy,threading,time
from .contracts import State,Denied,FEATURES,SAFE_FEATURES,version_tuple
from .device import DeviceIdentity
from .verification import EntitlementVerifier
class LicensingClient:
    def __init__(self,adapter,store,public_keys,*,version='5.0',channel='INTERNAL',clock=time.time):
        self.adapter,self.store,self.clock=adapter,store,clock;self.verifier=EntitlementVerifier(public_keys)
        self.version,self.channel=version,channel;self.lock=threading.RLock();self.operation_lock=threading.RLock()
        self.state=State.AUTH_REQUIRED;self.online=False;self.unavailable=False;self.failures=0;self.next_retry=0
        self.data=store.read();self.device=DeviceIdentity(self.data.get('device_private'));self.data['device_private']=self.device.private();self.data.setdefault('max_seen',0)
        self._evaluate();self._save()
    def _save(self): self.store.write(self.data)
    def _payload(self):
        p=self.verifier.verify(self.data['entitlement'],int(self.clock()),device_id=self.data['device_id'],public_key=self.device.public(),user_id=self.data['user_id'],tenant_id=self.data['tenant_id'],revoked=self.data.get('revoked',[]))
        if p['channel']!=self.channel or p['session_id']!=self.data['session_id']: raise Denied('INVALID_BINDING')
        return p
    def _evaluate(self):
        now=int(self.clock())
        if now+120<self.data.get('max_seen',0): self.state=State.CLOCK_SUSPECT;return None
        self.data['max_seen']=max(now,self.data.get('max_seen',0))
        if self.data.get('denied'): self.state=State(self.data['denied']);return None
        if 'entitlement' not in self.data: self.state=State.SERVER_UNAVAILABLE if self.unavailable else State.AUTH_REQUIRED;return None
        try:
            p=self._payload()
            if version_tuple(self.version)<version_tuple(p['minimum_supported_version']): self.state=State.OUTDATED_VERSION;return None
            if now>=p['offline_until']: self.state=State.OFFLINE_LEASE_EXPIRED;return None
            self.state=State.ONLINE_OK if self.online else State.OFFLINE_LEASE_VALID;return p
        except Denied as exc: self.state=State.OFFLINE_LEASE_EXPIRED if exc.code=='OFFLINE_LEASE_EXPIRED' else State.INDETERMINATE
        except (KeyError,TypeError,ValueError): self.state=State.INDETERMINATE
        return None
    def _request(self,op,p): return self.adapter.call(op,p,self.data.get('access_token'))
    def _challenge(self,purpose):
        p={'purpose':purpose}
        if purpose=='login': p['public_key']=self.device.public()
        if purpose=='refresh': p['refresh_token']=self.data['refresh_token']
        c=self._request('challenge',p)
        if c.get('purpose')!=purpose or c.get('public_key')!=self.device.public() or (purpose!='login' and c.get('session_id')!=self.data.get('session_id')): raise Denied('INVALID_CHALLENGE')
        return {'challenge_id':c['id'],'proof':self.device.prove(c)}
    def _accept(self,reply):
        with self.lock:
            candidate=dict(self.data)
            for f in ('access_token','refresh_token','session_id','device_id','user_id','tenant_id','expires','entitlement'):
                if f in reply: candidate[f]=reply[f]
            p=self.verifier.verify(candidate['entitlement'],int(self.clock()),device_id=candidate['device_id'],public_key=self.device.public(),user_id=candidate['user_id'],tenant_id=candidate['tenant_id'])
            if p['session_id']!=candidate['session_id'] or p['channel']!=self.channel: raise Denied('INVALID_BINDING')
            candidate.pop('denied',None);candidate.pop('last_error',None)
            self.data=candidate;self.online=True;self.unavailable=False;self.failures=0;self.next_retry=0
            self._evaluate();self._save();return self.snapshot()
    def _failure(self,exc):
        with self.lock:
            self.online=False;self.unavailable=isinstance(exc,ConnectionError)
            if self.unavailable: self.failures+=1;self.next_retry=self.clock()+min(300,2**min(self.failures,8))
            else:
                code=getattr(exc,'code','INDETERMINATE');self.data['last_error']=code
                self.data['denied']=code if code in {s.value for s in State} else State.AUTH_REQUIRED.value
                for f in ('access_token','refresh_token','entitlement'): self.data.pop(f,None)
            self._evaluate();self._save();return self.snapshot()
    def login(self,code):
        with self.operation_lock:
            try:
                proof=self._challenge('login')
                return self._accept(self._request('login',dict(proof,authorization_code=code,public_key=self.device.public(),version=self.version,channel=self.channel)))
            except (Denied,ConnectionError) as e: return self._failure(e)
    def renew(self,*,force=False):
        with self.operation_lock:
            if not force and self.clock()<self.next_retry: return self.snapshot()
            if not self.data.get('refresh_token'): return self.snapshot()
            try:
                op='refresh' if self.clock()>=self.data.get('expires',0)-30 else 'renew'
                p=dict(self._challenge(op),version=self.version,channel=self.channel)
                if op=='refresh': p['refresh_token']=self.data['refresh_token']
                return self._accept(self._request(op,p))
            except (Denied,ConnectionError) as e: return self._failure(e)
    def logout(self):
        with self.operation_lock:
            remote=False
            try: self._request('logout',{});remote=True
            except (Denied,ConnectionError): pass
            with self.lock:
                self.data={'device_private':self.device.private(),'max_seen':self.data.get('max_seen',0)};self.online=False;self.unavailable=False;self._save()
            return dict(self.snapshot(),remote_logout=remote)
    def reenroll(self,code):
        with self.operation_lock:
            self.logout()
            with self.lock:
                self.device=DeviceIdentity();self.data={'device_private':self.device.private(),'max_seen':self.data.get('max_seen',0)};self._save()
            return self.login(code)
    def current_entitlement(self):
        with self.lock: return copy.deepcopy(self._evaluate())
    def licensing_state(self):
        with self.lock: self._evaluate();return self.state.value
    def is_allowed(self,feature):
        if feature in SAFE_FEATURES: return True
        with self.lock:
            p=self._evaluate();return bool(feature in FEATURES and p and feature in p['features'])
    def explain(self,feature): return 'Disponível' if self.is_allowed(feature) else 'Requer licença válida: '+self.licensing_state()
    def require(self,feature):
        if not self.is_allowed(feature): raise Denied('FEATURE_DENIED')
    def snapshot(self):
        with self.lock:
            p=self._evaluate() or {}
            return dict(state=self.state.value,reason=self.data.get('last_error'),online=self.online,tenant=p.get('tenant_id'),plan=p.get('plan_id'),expires_at=p.get('expires_at'),offline_until=p.get('offline_until'),device_id=self.data.get('device_id'),session_id=self.data.get('session_id'),features=p.get('features',[]),next_retry=self.next_retry,degraded=self.state not in (State.ONLINE_OK,State.OFFLINE_LEASE_VALID))
FeatureGate=LicensingClient
