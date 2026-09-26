"""Transactional QA authority; identity, device, entitlement and administration layers."""
import hashlib,secrets,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from licensing.contracts import Denied,Principal,new_id,canonical,PLANS,ROLES,FEATURES,EXISTING_FEATURES,ISSUER,AUDIENCE,version_tuple,CHANNELS
from licensing.verification import unb64,thumbprint
ACCESS_TTL=300
REFRESH_TTL=86400

def digest(value):
    if not isinstance(value,str) or not 1<=len(value)<=1024: raise Denied()
    return hashlib.sha256(value.encode()).hexdigest()
class AdminAudit:
    def __init__(self,repo,clock): self.repo,self.clock=repo,clock
    def add(self,action,actor=None,target=None,tenant=None,result='SUCCESS'):
        self.repo.put('audit',dict(id=new_id(),actor=actor,target=target,tenant_id=tenant,time=int(self.clock()),action=action,result=result,correlation_id=new_id(),metadata={}))
        self.repo.retain('audit',5000)
class QaIdentityProvider:
    """One-use code, backend only; explicitly not a production IdP."""
    def __init__(self,repo,clock): self.repo,self.clock=repo,clock
    def exchange(self,authorization_code):
        row=self.repo.get('code',digest(authorization_code))
        if row['used'] or self.clock()>=row['expires']: raise Denied()
        row['used']=True;self.repo.put('code',row)
        return {'subject':row['user_id'],'provider':'QA_ONLY'}
class DeviceService:
    def __init__(self,repo,clock,audit): self.repo,self.clock,self.audit=repo,clock,audit
    def challenge(self,public_key,purpose,session_id=None):
        try: Ed25519PublicKey.from_public_bytes(unb64(public_key))
        except (ValueError,TypeError): raise Denied('INVALID_DEVICE_KEY') from None
        value=dict(id=new_id(),nonce=secrets.token_urlsafe(32),purpose=purpose,session_id=session_id,public_key=public_key,expires=int(self.clock())+60)
        self.repo.put('challenge',dict(id=value['id'],value=value,used=False));return value
    def verify(self,cid,signature,public,purpose,sid=None):
        row=self.repo.get('challenge',cid);c=row['value']
        if row['used'] or self.clock()>=c['expires'] or (c['public_key'],c['purpose'],c['session_id'])!=(public,purpose,sid): raise Denied('INVALID_CHALLENGE')
        try: Ed25519PublicKey.from_public_bytes(unb64(public)).verify(unb64(signature),canonical(c))
        except Exception: raise Denied('INVALID_DEVICE_PROOF') from None
        row['used']=True;self.repo.put('challenge',row)
    def enroll(self,user,public,plan,*,device_id=None):
        devices=[d for d in self.repo.list('device') if d['user_id']==user['id']]
        for d in devices:
            if d['public_key']==public:
                if d['state']!='ACTIVE': raise Denied('DEVICE_REVOKED')
                d['last_seen']=int(self.clock());self.repo.put('device',d);return d
        if sum(d['state']=='ACTIVE' for d in devices)>=plan['device_limit']: raise Denied('DEVICE_LIMIT')
        d=dict(id=device_id or new_id(),user_id=user['id'],tenant_id=user['tenant_id'],public_key=public,state='ACTIVE',created_at=int(self.clock()),last_seen=int(self.clock()),revoked_at=None)
        self.repo.put('device',d)
        self.repo.put('enrollment',dict(id=new_id(),device_id=d['id'],tenant_id=user['tenant_id'],state='ENROLLED',created_at=int(self.clock())))
        self.audit.add('DEVICE_ENROLLED',user['id'],d['id'],user['tenant_id']);return d
class IdentityService:
    def __init__(self,plane): self.p=plane;self.provider=QaIdentityProvider(plane.repo,plane.clock)
    def create(self,u,d):
        access,refresh=secrets.token_urlsafe(32),secrets.token_urlsafe(48);now=int(self.p.clock());sid=new_id()
        s=dict(id=sid,user_id=u['id'],tenant_id=u['tenant_id'],device_id=d['id'],access_hash=digest(access),expires=now+ACCESS_TTL,refresh_expires=now+REFRESH_TTL,state='ACTIVE',created_at=now)
        self.p.repo.put('session',s)
        self.p.repo.put('refresh',dict(id=digest(refresh),session_id=sid,tenant_id=u['tenant_id'],used=False,revoked=False,expires=now+REFRESH_TTL))
        return dict(access_token=access,refresh_token=refresh,session_id=sid,user_id=u['id'],tenant_id=u['tenant_id'],device_id=d['id'],expires=s['expires'])
    def session(self,token,*,refresh=False):
        if refresh:
            r=self.p.repo.get('refresh',digest(token));s=self.p.repo.get('session',r['session_id'])
            if r['used'] or r['revoked'] or self.p.clock()>=r['expires']: raise Denied()
        else:
            key=digest(token);s=next((x for x in self.p.repo.list('session') if secrets.compare_digest(x['access_hash'],key)),None)
            if s is None or self.p.clock()>=s['expires']: raise Denied()
        u=self.p.repo.get('user',s['user_id']);self.p.active_user(u)
        d=self.p.repo.get('device',s['device_id'])
        if d['state']!='ACTIVE': raise Denied('DEVICE_REVOKED')
        self.p.effective_license(u)
        if s['state']!='ACTIVE': raise Denied()
        return s,u,d
    def revoke(self,s,actor,action='SESSION_REVOKED'):
        s['state']='REVOKED';self.p.repo.put('session',s)
        for r in self.p.repo.list('refresh'):
            if r['session_id']==s['id']: r['revoked']=True;self.p.repo.put('refresh',r)
        self.p.audit.add(action,actor,s['id'],s['tenant_id'])
    def refresh(self,token,cid,proof):
        s,u,d=self.session(token,refresh=True)
        self.p.devices.verify(cid,proof,d['public_key'],'refresh',s['id'])
        old=self.p.repo.get('refresh',digest(token));old['used']=True;self.p.repo.put('refresh',old)
        access,refresh=secrets.token_urlsafe(32),secrets.token_urlsafe(48)
        s['access_hash']=digest(access);s['expires']=int(self.p.clock())+ACCESS_TTL;self.p.repo.put('session',s)
        self.p.repo.put('refresh',dict(id=digest(refresh),session_id=s['id'],tenant_id=u['tenant_id'],used=False,revoked=False,expires=s['refresh_expires']))
        self.p.audit.add('SESSION_REFRESH',u['id'],s['id'],u['tenant_id'])
        return dict(access_token=access,refresh_token=refresh,session_id=s['id'],user_id=u['id'],tenant_id=u['tenant_id'],device_id=d['id'],expires=s['expires'])
class EntitlementIssuer:
    def __init__(self,plane): self.p=plane
    def issue(self,s,u,d,version,channel,*,maximum_validity=None):
        lic,plan=self.p.effective_license(u)
        if channel not in CHANNELS: raise Denied('INVALID_CHANNEL')
        if version_tuple(version)<version_tuple(plan['minimum_supported_version']): raise Denied('OUTDATED_VERSION')
        if any(r.get('session_id')==s['id'] for r in self.p.repo.list('revocation')): raise Denied('LICENSE_SUSPENDED')
        now=int(self.p.clock());expiry=min(lic['expires'],now+plan['validity_seconds'],now+maximum_validity if maximum_validity is not None else lic['expires']);until=min(expiry,now+plan['offline_seconds']);eid,lease=new_id(),new_id()
        features=[f for f in plan['features'] if f in {'monitoring.basic','reports.basic'}] if u['role']=='VIEWER' else plan['features']
        payload=dict(entitlement_id=eid,jti=eid,tenant_id=u['tenant_id'],license_id=lic['id'],plan_id=plan['id'],user_id=u['id'],role=u['role'],features=features,seats={'limit':plan['seat_limit']},device_policy={'limit':plan['device_limit']},device_id=d['id'],device_key=thumbprint(d['public_key']),session_id=s['id'],issued_at=now,not_before=now,expires_at=expiry,offline_until=until,issuer=ISSUER,audience=AUDIENCE,key_id=self.p.signer.kid,entitlement_version=1,lease={'id':lease,'version':1,'offline_until':until},channel=channel,minimum_supported_version=plan['minimum_supported_version'],release_version=version)
        self.p.repo.put('entitlement',dict(id=eid,tenant_id=u['tenant_id'],session_id=s['id'],license_id=lic['id'],device_id=d['id'],state='ACTIVE',expires=expiry))
        self.p.repo.put('lease',dict(id=lease,tenant_id=u['tenant_id'],entitlement_id=eid,offline_until=until))
        self.p.audit.add('ENTITLEMENT_ISSUED',u['id'],eid,u['tenant_id']);return self.p.signer.sign(payload)
class ControlPlane:
    def __init__(self,repo,signer,clock=time.time,identity_provider=None):
        self.repo,self.signer,self.clock=repo,signer,clock;self.audit=AdminAudit(repo,clock);self.devices=DeviceService(repo,clock,self.audit)
        self.identity=IdentityService(self);self.entitlements=EntitlementIssuer(self)
        if identity_provider is not None: self.identity.provider=identity_provider
    def bootstrap_owner(self):
        with self.repo.transaction():
            if self.repo.list('admin'): raise Denied('ALREADY_INITIALIZED')
            credential=secrets.token_urlsafe(48)
            self.repo.put('admin',dict(id=new_id(),credential_hash=digest(credential),role='OWNER',tenant_id=None,state='ACTIVE',mfa_required_for_production=True))
            for name in PLANS: self.repo.put('plan',dict(id=name,features=sorted(EXISTING_FEATURES),seat_limit=1,device_limit=2,validity_seconds=2592000,offline_seconds=86400,minimum_supported_version='5.0',state='ACTIVE'))
            return credential
    def active_user(self,u):
        if u['state']!='ACTIVE': raise Denied('AUTH_REQUIRED')
        if self.repo.get('tenant',u['tenant_id'])['state']!='ACTIVE': raise Denied('TENANT_SUSPENDED')
    def effective_license(self,u):
        self.active_user(u)
        seat=next((x for x in self.repo.list('seat') if x['user_id']==u['id'] and x['state']=='ACTIVE'),None)
        if seat is None: raise Denied('SEAT_REQUIRED')
        lic=self.repo.get('license',seat['license_id']);plan=self.repo.get('plan',lic['plan_id'])
        if lic['state']!='ACTIVE' or self.clock()>=lic['expires'] or plan['state']!='ACTIVE': raise Denied('LICENSE_SUSPENDED')
        return lic,plan
    def principal(self,credential):
        key=digest(credential)
        for a in self.repo.list('admin'):
            if a['state']=='ACTIVE' and secrets.compare_digest(a['credential_hash'],key): return Principal(a['id'],'OWNER',None)
        s,u,d=self.identity.session(credential)
        if u['role']!='TENANT_ADMIN': raise Denied('FORBIDDEN')
        return Principal(u['id'],u['role'],u['tenant_id'])
    def scope(self,a,tenant):
        if a.role!='OWNER' and a.tenant_id!=tenant: raise Denied('FORBIDDEN')
    def entity(self,kind,oid,a):
        row=self.repo.get(kind,oid);self.scope(a,row.get('tenant_id',row['id'] if kind=='tenant' else None));return row
    def admin(self,credential,op,payload=None):
        try:
            with self.repo.transaction(): return self._admin(self.principal(credential),op,payload or {})
        except Denied: self.audit.add('ADMIN_DENIED',result='DENIED');raise
    def _admin(self,a,op,p):
        if op=='list':
            kind=p['kind']
            if kind not in {'tenant','user','license','plan','seat','device','session','entitlement','audit'}: raise Denied('FORBIDDEN')
            rows=self.repo.list(kind)
            if a.role!='OWNER': rows=[r for r in rows if r.get('tenant_id',r['id'] if kind=='tenant' else None)==a.tenant_id]
            return [{k:v for k,v in r.items() if k not in {'access_hash','credential_hash'}} for r in rows]
        if op=='plan_policy':
            if a.role!='OWNER': raise Denied('FORBIDDEN')
            if p['id'] not in PLANS: raise Denied('INVALID_PLAN')
            row=self.repo.get('plan',p['id'])
            if not set(p)<=set(row): raise Denied('INVALID_POLICY')
            row.update(p)
            if not isinstance(row['features'],list) or not set(row['features'])<=FEATURES or row['state'] not in ('ACTIVE','SUSPENDED'): raise Denied('INVALID_POLICY')
            for k,limit in [('seat_limit',100000),('device_limit',1000),('validity_seconds',31536000),('offline_seconds',604800)]:
                if type(row[k]) is not int or not 1<=row[k]<=limit: raise Denied('INVALID_POLICY')
            if row['offline_seconds']>row['validity_seconds']: raise Denied('INVALID_POLICY')
            version_tuple(row['minimum_supported_version']);self.repo.put('plan',row);self.audit.add('PLAN_CHANGED',a.account_id,row['id']);return row
        if op=='create_tenant':
            if a.role!='OWNER': raise Denied('FORBIDDEN')
            row=dict(id=new_id(),state='ACTIVE',label=str(p.get('label','Tenant'))[:120]);self.repo.put('tenant',row);self.audit.add('TENANT_CREATED',a.account_id,row['id'],row['id']);return row
        if op in {'create_user','create_license'}:
            tid=p['tenant_id'];self.scope(a,tid)
            if self.repo.get('tenant',tid)['state']!='ACTIVE': raise Denied('TENANT_SUSPENDED')
            row=dict(id=new_id(),tenant_id=tid,state='ACTIVE')
            if op=='create_user':
                role=p.get('role','TECHNICIAN')
                if role not in ROLES[1:] or (a.role!='OWNER' and role=='TENANT_ADMIN'): raise Denied('FORBIDDEN')
                row['role']=role;kind,event='user','USER_CREATED'
            else:
                if a.role!='OWNER': raise Denied('FORBIDDEN')
                plan=self.repo.get('plan',p['plan_id']);row.update(plan_id=plan['id'],expires=int(self.clock())+plan['validity_seconds']);kind,event='license','LICENSE_CREATED'
            self.repo.put(kind,row);self.audit.add(event,a.account_id,row['id'],tid);return row
        if op=='login_code':
            u=self.entity('user',p['user_id'],a);self.active_user(u);code=secrets.token_urlsafe(32)
            self.repo.put('code',dict(id=digest(code),user_id=u['id'],used=False,expires=int(self.clock())+120))
            self.audit.add('QA_CODE_ISSUED',a.account_id,u['id'],u['tenant_id']);return {'authorization_code':code,'expires_in':120,'provider':'QA_ONLY'}
        if op=='issue_entitlement':
            s=self.entity('session',p['session_id'],a);u=self.repo.get('user',s['user_id']);d=self.repo.get('device',s['device_id'])
            if s['state']!='ACTIVE' or self.clock()>=s['expires']: raise Denied()
            if d['state']!='ACTIVE': raise Denied('DEVICE_REVOKED')
            return self.entitlements.issue(s,u,d,p['version'],p['channel'])
        if op=='assign_seat':
            u=self.entity('user',p['user_id'],a);self.active_user(u);lic=self.entity('license',p['license_id'],a)
            if lic['tenant_id']!=u['tenant_id']: raise Denied('FORBIDDEN')
            if lic['state']!='ACTIVE' or self.clock()>=lic['expires']: raise Denied('LICENSE_SUSPENDED')
            seats=[s for s in self.repo.list('seat') if s['state']=='ACTIVE']
            if any(s['user_id']==u['id'] for s in seats): raise Denied('SEAT_ALREADY_ASSIGNED')
            if sum(s['license_id']==lic['id'] for s in seats)>=self.repo.get('plan',lic['plan_id'])['seat_limit']: raise Denied('SEAT_LIMIT')
            row=dict(id=new_id(),tenant_id=u['tenant_id'],user_id=u['id'],license_id=lic['id'],state='ACTIVE');self.repo.put('seat',row);self.audit.add('SEAT_ASSIGNED',a.account_id,row['id'],u['tenant_id']);return row
        if op=='role':
            u=self.entity('user',p['user_id'],a)
            if a.role!='OWNER' or p['role'] not in ROLES[1:]: raise Denied('FORBIDDEN')
            u['role']=p['role'];self.repo.put('user',u)
            for s in self.repo.list('session'):
                if s['user_id']==u['id']: self.identity.revoke(s,a.account_id)
            self.audit.add('ROLE_CHANGED',a.account_id,u['id'],u['tenant_id']);return u
        ops={'suspend_tenant':('tenant','SUSPENDED','TENANT_SUSPENDED'),'suspend_user':('user','SUSPENDED','USER_SUSPENDED'),'revoke_license':('license','REVOKED','LICENSE_REVOKED'),'revoke_device':('device','REVOKED','DEVICE_REVOKED'),'revoke_entitlement':('entitlement','REVOKED','ENTITLEMENT_REVOKED'),'release_seat':('seat','RELEASED','SEAT_RELEASED')}
        if op in ops:
            kind,state,event=ops[op];r=self.entity(kind,p['id'],a)
            if kind in {'tenant','license'} and a.role!='OWNER': raise Denied('FORBIDDEN')
            r['state']=state
            if kind=='device': r['revoked_at']=int(self.clock())
            self.repo.put(kind,r);tid=r.get('tenant_id',r['id'])
            self.repo.put('revocation',dict(id=new_id(),target_id=r['id'],tenant_id=tid,session_id=r.get('session_id'),created_at=int(self.clock())))
            for s in self.repo.list('session'):
                affected=(kind=='tenant' and s['tenant_id']==r['id'] or kind=='user' and s['user_id']==r['id'] or kind=='device' and s['device_id']==r['id'] or kind=='entitlement' and s['id']==r['session_id'] or kind=='seat' and s['user_id']==r['user_id'] or kind=='license' and any(e['session_id']==s['id'] and e['license_id']==r['id'] for e in self.repo.list('entitlement')))
                if affected: self.identity.revoke(s,a.account_id)
            if kind=='tenant' and p.get('revoke_devices',False):
                for d in self.repo.list('device'):
                    if d['tenant_id']==tid: d['state']='REVOKED';d['revoked_at']=int(self.clock());self.repo.put('device',d);self.audit.add('DEVICE_REVOKED',a.account_id,d['id'],tid)
            self.audit.add(event,a.account_id,r['id'],tid);return r
        if op in {'revoke_session','force_logout','revoke_refresh'}:
            if op=='force_logout':
                u=self.entity('user',p['user_id'],a)
                for ws in self.repo.list('web_session'):
                    if ws.get('account_id')==u['id']: self.repo.delete('web_session',ws['id'])
            if op in ('revoke_session','revoke_refresh'): sessions=[self.entity('session',p['id'] if op=='revoke_session' else p['session_id'],a)]
            else:
                u=self.entity('user',p['user_id'],a);sessions=[s for s in self.repo.list('session') if s['user_id']==u['id']]
            for s in sessions: self.identity.revoke(s,a.account_id,'FORCE_LOGOUT' if op=='force_logout' else 'SESSION_REVOKED')
            return {'revoked':len(sessions)}
        raise Denied('UNKNOWN_OPERATION')
    def client(self,op,p,token=None):
        try:
            with self.repo.transaction(): return self._client(op,p,token)
        except Denied:
            if op=='login': self.audit.add('LOGIN_FAILURE',result='DENIED')
            raise
    def _client(self,op,p,token):
        if op=='challenge':
            purpose=p['purpose']
            if purpose=='login': return self.devices.challenge(p['public_key'],'login')
            if purpose not in ('renew','refresh'): raise Denied('INVALID_CHALLENGE')
            s,u,d=self.identity.session(p['refresh_token'] if purpose=='refresh' else token,refresh=purpose=='refresh')
            return self.devices.challenge(d['public_key'],purpose,s['id'])
        if op=='login':
            subject=self.identity.provider.exchange(p['authorization_code']);u=self.repo.get('user',subject['subject']);lic,plan=self.effective_license(u)
            self.devices.verify(p['challenge_id'],p['proof'],p['public_key'],'login');d=self.devices.enroll(u,p['public_key'],plan)
            reply=self.identity.create(u,d);s=self.repo.get('session',reply['session_id']);reply['entitlement']=self.entitlements.issue(s,u,d,p['version'],p['channel'])
            self.audit.add('LOGIN_SUCCESS',u['id'],s['id'],u['tenant_id']);return reply
        if op=='refresh':
            reply=self.identity.refresh(p['refresh_token'],p['challenge_id'],p['proof']);s,u,d=self.identity.session(reply['access_token'])
            reply['entitlement']=self.entitlements.issue(s,u,d,p['version'],p['channel']);return reply
        s,u,d=self.identity.session(token)
        if op=='logout': self.identity.revoke(s,u['id'],'LOGOUT');return {'logged_out':True}
        if op=='renew':
            self.devices.verify(p['challenge_id'],p['proof'],d['public_key'],'renew',s['id']);d['last_seen']=int(self.clock());self.repo.put('device',d)
            return {'entitlement':self.entitlements.issue(s,u,d,p['version'],p['channel'])}
        raise Denied('UNKNOWN_OPERATION')
