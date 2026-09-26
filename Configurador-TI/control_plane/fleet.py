"""Fleet authority. All mutations serialize in the administrative repository.

QA password adapter shares the 2A account/tenant/role authority; deployment
production must replace this adapter with OIDC/MFA, never export its verifier.
"""
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from licensing.contracts import Denied, Principal, new_id, canonical, version_tuple
from licensing.verification import unb64
from .service import digest
from fleet_protocol.contracts import (closed,identifier,label,integer,action,negotiation,
    fingerprint,summary,proof,CATALOG,AGENT_VERSION,PROTOCOL_VERSION,ONLINE_SECONDS,
    COMMAND_TTL,LEASE_SECONDS,EXECUTION_SECONDS,TERMINAL)

class FleetService:
    def __init__(self,plane,command_signer):
        self.p,self.repo,self.clock,self.signer=plane,plane.repo,plane.clock,command_signer
        if set(command_signer.public_keys().values()) & set(plane.signer.public_keys().values()): raise Denied('KEY_PURPOSE_CONFLICT')
    def sign(self,p,purpose): return self.signer.sign(dict(p,purpose=purpose,key_id=self.signer.kid))
    def _account(self,uid,owner=False):
        u=self.repo.get('admin' if owner else 'user',uid)
        if u['state']!='ACTIVE': raise Denied('AUTH_REQUIRED')
        if not owner: self.p.active_user(u)
        return Principal(u['id'],u['role'],u['tenant_id'])
    @staticmethod
    def _password(password,salt):
        if not isinstance(password,str) or not 12<=len(password)<=256: raise Denied('INVALID_PASSWORD')
        return hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
    def set_login(self,a,username,password,uid,owner=False):
        name=label(username).casefold(); key=digest(name)
        if any(r['id']==key for r in self.repo.list('qa_login')): raise Denied('LOGIN_EXISTS')
        if owner:
            if a.role!='OWNER' or uid!=a.account_id: raise Denied('FORBIDDEN')
        else: self.p.entity('user',uid,a)
        salt=secrets.token_hex(16); verifier=self._password(password,salt)
        self.repo.put('qa_login',dict(id=key,account_id=uid,owner=owner,salt=salt,verifier=verifier))
    def bootstrap_web_owner(self,credential,username,password):
        with self.repo.transaction():
            a=self.p.principal(credential)
            if a.role!='OWNER' or any(x['owner'] for x in self.repo.list('qa_login')): raise Denied('ALREADY_INITIALIZED')
            self.set_login(a,username,password,a.account_id,True)
    def login(self,p):
        closed(p,'username password')
        with self.repo.transaction():
            self.cleanup()
            key=digest(label(p['username']).casefold())
            row=next((r for r in self.repo.list('qa_login') if r['id']==key),None)
            salt=row['salt'] if row else '00'*16
            candidate=self._password(p['password'],salt)
            if not row or not secrets.compare_digest(candidate,row['verifier']): raise Denied('AUTH_REQUIRED')
            a=self._account(row['account_id'],row['owner']); token=secrets.token_urlsafe(48)
            if len(self.repo.list('web_session'))>=1000: raise Denied('CAPACITY_REACHED')
            self.repo.put('web_session',dict(id=digest(token),account_id=a.account_id,owner=row['owner'],tenant_id=a.tenant_id,expires=int(self.clock())+1800,created_at=int(self.clock())))
            self.p.audit.add('WEB_LOGIN',a.account_id,tenant=a.tenant_id)
            return {'access_token':token,'expires_in':1800,'provider':'QA_ONLY'}
    def principal(self,token):
        s=self.repo.get('web_session',digest(token))
        if self.clock()>=s['expires']: raise Denied('AUTH_REQUIRED')
        return self._account(s['account_id'],s['owner'])
    def _license(self,u):
        lic,plan=self.p.effective_license(u)
        if not {'central.agent','fleet.management'}<=set(plan['features']): raise Denied('FEATURE_DENIED')
        return lic,plan
    def _active(self,did):
        f=self.repo.get('fleet_agent',did);d=self.repo.get('device',did)
        if d['state']!='ACTIVE': raise Denied('DEVICE_REVOKED')
        if f['state']!='ACTIVE': raise Denied('AGENT_SUSPENDED')
        u=self.repo.get('user',d['user_id']);lic,plan=self._license(u)
        if u['role']=='VIEWER': raise Denied('FORBIDDEN')
        negotiation(f['protocol_version'],f['agent_version'],f['capabilities'])
        if version_tuple(f['agent_version'])<version_tuple(plan['minimum_supported_version']): raise Denied('AGENT_OUTDATED')
        return f,d,u,plan
    def _authorize(self,c):
        f,d,u,plan=self._active(c['device_id'])
        if f['tenant_id']!=c['tenant_id']: raise Denied('FORBIDDEN')
        a=self._account(c['actor'],c['actor_owner']);self.p.scope(a,f['tenant_id'])
        if a.role not in ('OWNER','TENANT_ADMIN','TECHNICIAN'): raise Denied('FORBIDDEN')
        spec=action(c['action_id'],c['parameters'])
        if c['action_id'] not in f['capabilities'] or not set(spec['features'])<=set(plan['features']): raise Denied('FEATURE_DENIED')
        if a.role!='OWNER':
            _,ap=self._license(self.repo.get('user',a.account_id))
            if not set(spec['features'])<=set(ap['features']): raise Denied('FEATURE_DENIED')
        return f,d,u,plan
    def status(self,f):
        try: self._active(f['id'])
        except Denied as e:
            if e.code=='DEVICE_REVOKED': return 'REVOKED'
            if e.code in ('AGENT_SUSPENDED','TENANT_SUSPENDED'): return 'SUSPENDED'
            if e.code in ('SEAT_REQUIRED','LICENSE_SUSPENDED','FEATURE_DENIED'): return 'UNLICENSED'
            return 'AUTH_FAILED'
        return 'ONLINE' if f['last_seen'] is not None and self.clock()-f['last_seen']<ONLINE_SECONDS else 'OFFLINE'
    def _scoped(self,a,kind):
        rows=self.repo.list(kind)
        if a.role!='OWNER': rows=[r for r in rows if r.get('tenant_id',r['id'] if kind=='tenant' else None)==a.tenant_id]
        if a.role in ('TECHNICIAN','VIEWER') and kind in ('session','web_session'): rows=[r for r in rows if r.get('user_id',r.get('account_id'))==a.account_id]
        return rows
    def snapshot(self,a,offset=0):
        result={'principal':dict(account_id=a.account_id,role=a.role,tenant_id=a.tenant_id),'catalog':CATALOG,'counts':{},'offset':offset}
        for kind in ('tenant','user','license','seat','device','session','web_session','fleet_agent','fleet_command','audit'):
            rows=self._scoped(a,kind)
            if kind=='audit': rows.sort(key=lambda r:r['time'],reverse=True)
            if kind=='fleet_command': rows.sort(key=lambda r:r['issued_at'],reverse=True)
            result['counts'][kind]=len(rows)
            rows=rows[offset:offset+20]
            result[kind]=[{k:v for k,v in r.items() if k not in ('access_hash','credential_hash','public_key','nonce','request_hash','actor_owner','claim_id','idempotency_key')} for r in rows]
            if kind=='fleet_agent':
                for r in result[kind]: r['status']=self.status(r)
        result['plan']=self.repo.list('plan')
        return result
    def web(self,token,p):
        closed(p,'operation payload');op=p['operation'];v=p['payload']
        if not isinstance(op,str) or not isinstance(v,dict): raise Denied('INVALID_SCHEMA')
        with self.repo.transaction():
            self.cleanup();self.sweep();a=self.principal(token)
            if op=='snapshot': closed(v,'offset');return self.snapshot(a,integer(v['offset'],0,1000000))
            if op=='logout': closed(v,'');self.repo.delete('web_session',digest(token));return {'ok':True}
            if op=='audit':
                closed(v,'tenant actor action result')
                for value in v.values():
                    if value: identifier(value)
                rows=self._scoped(a,'audit')
                fields={'tenant':'tenant_id','actor':'actor','action':'action','result':'result'}
                return {'rows':sorted([r for r in rows if all(not val or r[fields[k]]==val for k,val in v.items())],key=lambda r:r['time'],reverse=True)[:100]}
            if a.role=='VIEWER': raise Denied('FORBIDDEN')
            if op in ('preview','queue'): return self._queue(a,op,v)
            if op=='cancel':
                closed(v,'id');c=self.p.entity('fleet_command',identifier(v['id']),a)
                if c['state'] not in TERMINAL:
                    c['cancel_requested']=True
                    if c['state']!='RUNNING': c['state']='CANCELLED'
                    self.repo.put('fleet_command',c);self.p.audit.add('COMMAND_CANCELLED',a.account_id,c['id'],c['tenant_id'])
                return c
            if a.role not in ('OWNER','TENANT_ADMIN'): raise Denied('FORBIDDEN')
            if op=='invite': return self._invite(a,v)
            if op=='agent_tags':
                closed(v,'id tags assigned_technician');f=self.p.entity('fleet_agent',identifier(v['id']),a)
                if not isinstance(v['tags'],list) or len(v['tags'])>8: raise Denied('INVALID_VALUE')
                tags=[label(x,30) for x in v['tags']]
                if v['assigned_technician']:
                    u=self.p.entity('user',identifier(v['assigned_technician']),a)
                    if u['tenant_id']!=f['tenant_id'] or u['role'] not in ('TECHNICIAN','TENANT_ADMIN'): raise Denied('FORBIDDEN')
                f.update(tags=tags,assigned_technician=v['assigned_technician'] or None);self.repo.put('fleet_agent',f)
                self.p.audit.add('AGENT_TAGS',a.account_id,f['id'],f['tenant_id']);return f
            if op=='suspend_agent':
                closed(v,'id');f=self.p.entity('fleet_agent',identifier(v['id']),a);f['state']='SUSPENDED';self.repo.put('fleet_agent',f)
                self.p.audit.add('AGENT_SUSPENDED',a.account_id,f['id'],f['tenant_id']);return f
            if op=='suspend_license':
                closed(v,'id')
                if a.role!='OWNER': raise Denied('FORBIDDEN')
                r=self.p.entity('license',identifier(v['id']),a);r['state']='SUSPENDED';self.repo.put('license',r)
                self.p.audit.add('LICENSE_SUSPENDED',a.account_id,r['id'],r['tenant_id']);return r
            if op=='create_user':
                closed(v,'tenant_id role display_name login password');name=label(v['display_name']);login=label(v['login'])
                u=self.p._admin(a,op,{'tenant_id':identifier(v['tenant_id']),'role':identifier(v['role'])})
                self.set_login(a,login,v['password'],u['id']);u.update(display_name=name,login=login);self.repo.put('user',u);return u
            schemas={'create_tenant':'label','create_license':'tenant_id plan_id','assign_seat':'user_id license_id','release_seat':'id','role':'user_id role','force_logout':'user_id','revoke_session':'id','suspend_user':'id','suspend_tenant':'id','revoke_device':'id','revoke_license':'id','login_code':'user_id'}
            if op=='plan_policy':
                closed(v,'id seat_limit device_limit validity_seconds offline_seconds minimum_supported_version fleet_enabled')
                if type(v['fleet_enabled']) is not bool: raise Denied('INVALID_SCHEMA')
                row=self.repo.get('plan',identifier(v['id']));features=set(row['features'])-{'central.agent','fleet.management'}
                if v['fleet_enabled']: features.update(('central.agent','fleet.management'))
                policy={k:val for k,val in v.items() if k!='fleet_enabled'};policy['features']=sorted(features)
                return self.p._admin(a,op,policy)
            if op not in schemas: raise Denied('UNKNOWN_OPERATION')
            closed(v,schemas[op])
            for k,val in v.items(): label(val) if k=='label' else identifier(val)
            if op=='revoke_session':
                ws=next((r for r in self.repo.list('web_session') if r['id']==v['id']),None)
                if ws:
                    if ws['owner']: raise Denied('FORBIDDEN')
                    self.p.scope(a,ws['tenant_id']);self.repo.delete('web_session',ws['id']);self.p.audit.add('WEB_SESSION_REVOKED',a.account_id,ws['account_id'],ws['tenant_id']);return {'revoked':1}
            out=self.p._admin(a,op,v)
            if op in ('role','suspend_user'):
                uid=v.get('user_id',v.get('id'))
                for ws in self.repo.list('web_session'):
                    if ws['account_id']==uid: self.repo.delete('web_session',ws['id'])
            return out
    def _invite(self,a,v):
        closed(v,'user_id label protocol_version agent_version capabilities')
        negotiation(v['protocol_version'],v['agent_version'],v['capabilities'])
        u=self.p.entity('user',identifier(v['user_id']),a);self._license(u)
        if u['role']=='VIEWER': raise Denied('FORBIDDEN')
        if len(self.repo.list('fleet_invite'))>=1000 or len(self.repo.list('fleet_agent'))>=1000: raise Denied('CAPACITY_REACHED')
        binding={k:v[k] for k in ('protocol_version','agent_version','capabilities')}
        binding.update(tenant_id=u['tenant_id'],user_id=u['id'],device_id=new_id())
        code=secrets.token_urlsafe(32)
        row=dict(id=digest(code),binding=binding,label=label(v['label']),expires=int(self.clock())+300,used=False,challenge_id=None)
        self.repo.put('fleet_invite',row);self.p.audit.add('AGENT_INVITED',a.account_id,binding['device_id'],u['tenant_id'])
        return {'enrollment_code':code,'expires_in':300,'device_id':binding['device_id']}
    def challenge(self,v):
        closed(v,'code public_key')
        with self.repo.transaction():
            i=self.repo.get('fleet_invite',digest(v['code']))
            if i['used'] or self.clock()>=i['expires']: raise Denied('ENROLLMENT_EXPIRED')
            self._license(self.repo.get('user',i['binding']['user_id']))
            purpose='agent-enroll:'+fingerprint(i['binding'])
            if i['challenge_id']: self.repo.delete('challenge',i['challenge_id'])
            c=self.p.devices.challenge(v['public_key'],purpose)
            i.update(challenge_id=c['id'],public_key=v['public_key'],purpose=purpose);self.repo.put('fleet_invite',i)
            return {'challenge':c,'binding':i['binding']}
    def enroll(self,v):
        closed(v,'code challenge_id proof')
        with self.repo.transaction():
            i=self.repo.get('fleet_invite',digest(v['code']))
            if i['used'] or self.clock()>=i['expires'] or v['challenge_id']!=i['challenge_id']: raise Denied('ENROLLMENT_EXPIRED')
            u=self.repo.get('user',i['binding']['user_id']);_,plan=self._license(u)
            if u['role']=='VIEWER': raise Denied('FORBIDDEN')
            if any(d['public_key']==i['public_key'] for d in self.repo.list('device')): raise Denied('FRESH_KEY_REQUIRED')
            self.p.devices.verify(v['challenge_id'],v['proof'],i['public_key'],i['purpose'])
            d=self.p.devices.enroll(u,i['public_key'],plan,device_id=i['binding']['device_id'])
            f=dict(i['binding'],id=d['id'],label=i['label'],state='ACTIVE',enrollment='ENROLLED',last_seen=None,summary=None,tags=[],assigned_technician=None,policy_version=1,drift_state='NOT_EVALUATED')
            self.repo.put('fleet_agent',f);i['used']=True;self.repo.put('fleet_invite',i)
            return i['binding']
    def _queue(self,a,op,v):
        closed(v,'device_id action_id parameters' if op=='preview' else 'device_id action_id parameters idempotency_key issued_at confirmed')
        f=self.p.entity('fleet_agent',identifier(v['device_id']),a)
        c=dict(tenant_id=f['tenant_id'],device_id=f['id'],actor=a.account_id,actor_owner=a.role=='OWNER',action_id=v['action_id'],parameters=v['parameters'])
        self._authorize(c)
        if op=='preview': return {'allowed':True,'privilege':'STANDARD_USER','action_id':v['action_id'],'parameters':v['parameters'],'dry_run_at_agent':True}
        integer(v['issued_at'],0,2**53);identifier(v['idempotency_key'])
        now=int(self.clock())
        if v['confirmed'] is not True or not now-COMMAND_TTL<v['issued_at']<=now+30: raise Denied('COMMAND_EXPIRED')
        key=fingerprint([c['tenant_id'],c['device_id'],v['idempotency_key']]);request_hash=fingerprint(v)
        old=next((r for r in self.repo.list('fleet_idempotency') if r['id']==key),None)
        if old:
            if old['request_hash']!=request_hash: raise Denied('IDEMPOTENCY_CONFLICT')
            return self.repo.get('fleet_command',old['command_id'])
        if len(self.repo.list('fleet_command'))>=2000: raise Denied('CAPACITY_REACHED')
        c.update(id=new_id(),correlation_id=new_id(),issued_at=now,expires_at=now+COMMAND_TTL,nonce=new_id(),idempotency_key=v['idempotency_key'],state='PENDING',claim_id=None,lease_until=0,attempts=0,cancel_requested=False,proof=None)
        self.repo.put('fleet_command',c);self.repo.put('fleet_idempotency',dict(id=key,command_id=c['id'],request_hash=request_hash,expires=now+86400))
        self.p.audit.add('COMMAND_QUEUED',a.account_id,c['id'],c['tenant_id']);return c
    def agent(self,envelope):
        closed(envelope,'payload signature');v=closed(envelope['payload'],'protocol_version agent_version capabilities tenant_id device_id issued_at expires_at nonce operation payload')
        negotiation(v['protocol_version'],v['agent_version'],v['capabilities'])
        for k in ('tenant_id','device_id','nonce'): identifier(v[k])
        for k in ('issued_at','expires_at'): integer(v[k],0,2**53)
        now=int(self.clock())
        if not now-60<=v['issued_at']<=now+30 or not now<v['expires_at']<=v['issued_at']+60: raise Denied('REQUEST_EXPIRED')
        with self.repo.transaction():
            f=self.repo.get('fleet_agent',v['device_id']);d=self.repo.get('device',v['device_id'])
            for k in ('tenant_id','protocol_version','agent_version','capabilities'):
                if v[k]!=f[k]: raise Denied('WRONG_BINDING')
            try: Ed25519PublicKey.from_public_bytes(unb64(d['public_key'])).verify(unb64(envelope['signature']),canonical(v))
            except Exception: raise Denied('INVALID_DEVICE_PROOF') from None
            self._active(f['id']);self.cleanup();self.sweep()
            nonce=fingerprint([f['id'],v['nonce']])
            if any(x['id']==nonce for x in self.repo.list('fleet_nonce')): raise Denied('REPLAY_DETECTED')
            if len(self.repo.list('fleet_nonce'))>=10000: raise Denied('CAPACITY_REACHED')
            self.repo.put('fleet_nonce',dict(id=nonce,expires=v['expires_at']+60))
            op,p=v['operation'],v['payload']
            if op=='heartbeat':
                closed(p,'summary');f.update(last_seen=now,summary=summary(p['summary']));self.repo.put('fleet_agent',f)
                return {'status':self.status(f),'server_time':now,'policy_version':1,'drift_state':'NOT_EVALUATED'}
            if op=='poll':
                closed(p,'')
                for c in sorted(self.repo.list('fleet_command'),key=lambda c:c['issued_at']):
                    if c['device_id']!=f['id'] or c['state']!='PENDING': continue
                    try: _,d,u,_=self._authorize(c)
                    except Denied:
                        c['state']='CANCELLED';self.repo.put('fleet_command',c);self.p.audit.add('COMMAND_AUTH_REJECTED',c['actor'],c['id'],c['tenant_id'],'DENIED');continue
                    c.update(state='LEASED',claim_id=new_id(),lease_until=min(now+LEASE_SECONDS,c['expires_at']),attempts=c['attempts']+1);self.repo.put('fleet_command',c)
                    ent=self.p.entitlements.issue({'id':'agent-'+f['id']},u,d,f['agent_version'],'INTERNAL',maximum_validity=300)
                    out={k:c[k] for k in ('tenant_id','device_id','actor','correlation_id','issued_at','expires_at','nonce','idempotency_key','action_id','parameters','claim_id','lease_until')}
                    out.update(command_id=c['id'],user_id=u['id'],protocol_version=f['protocol_version'],agent_version=f['agent_version'],capabilities=f['capabilities'],playbook_id=CATALOG[c['action_id']]['playbook_id'],resource=CATALOG[c['action_id']]['resource'],entitlement=ent)
                    self.p.audit.add('COMMAND_LEASED',c['actor'],c['id'],c['tenant_id'])
                    return {'command':self.sign(out,'fleet-command')}
                return {'command':None}
            if op not in ('start','cancel_check','result'): raise Denied('UNKNOWN_OPERATION')
            closed(p,'command_id claim_id proof' if op=='result' else 'command_id claim_id')
            c=self.repo.get('fleet_command',identifier(p['command_id']))
            if c['device_id']!=f['id'] or c['tenant_id']!=f['tenant_id'] or c['claim_id']!=p['claim_id']: raise Denied('WRONG_BINDING')
            if op=='cancel_check':
                try: self._authorize(c);allowed=True
                except Denied: allowed=False
                return {'cancel_requested':not allowed or c['cancel_requested'] or c['state']!='RUNNING'}
            if op=='start':
                self._authorize(c)
                if c['cancel_requested'] or c['state'] not in ('LEASED','RUNNING'): raise Denied('COMMAND_NOT_READY')
                if c['state']=='LEASED':
                    if now>=c['lease_until']: raise Denied('CLAIM_EXPIRED')
                    c.update(state='RUNNING',run_until=now+EXECUTION_SECONDS,permit_until=min(now+30,c['expires_at']));self.repo.put('fleet_command',c)
                    self.p.audit.add('COMMAND_RUNNING',c['actor'],c['id'],c['tenant_id'])
                if now>=c['permit_until']: raise Denied('COMMAND_EXPIRED')
                return self.sign(dict(command_id=c['id'],claim_id=c['claim_id'],tenant_id=f['tenant_id'],device_id=f['id'],expires_at=c['permit_until']),'execution-permit')
            pr=proof(p['proof'])
            for k in ('correlation_id','tenant_id','device_id','actor','action_id'):
                if pr[k]!=c[k]: raise Denied('INVALID_PROOF')
            if pr['command_id']!=c['id'] or pr['started_at']<c['issued_at'] or pr['completed_at']>now+30: raise Denied('INVALID_PROOF')
            if pr['result']=='SUCCESS' and pr['after']!=c['parameters']['interval_seconds']: raise Denied('INVALID_PROOF')
            if c['proof'] is not None:
                if c['proof']!=pr: raise Denied('RESULT_CONFLICT')
                return {'accepted':True}
            if c['state']!='RUNNING':
                if c['state']!='FAILED' or c.get('timeout_result')!='INDETERMINATE' or (pr['result']!='INDETERMINATE' and pr['completed_at']>c['run_until']): raise Denied('COMMAND_NOT_READY')
                c['late_proof']=True
            c.update(proof=pr,state='SUCCEEDED' if pr['result']=='SUCCESS' else 'CANCELLED' if pr['result']=='CANCELLED' else 'FAILED')
            self.repo.put('fleet_command',c);self.p.audit.add('COMMAND_RESULT',c['actor'],c['id'],c['tenant_id'],pr['result']);return {'accepted':True}
    def sweep(self):
        now=int(self.clock())
        for c in self.repo.list('fleet_command'):
            if c['state'] in TERMINAL: continue
            old=c['state']
            if old=='RUNNING' and now>=c['run_until']: c.update(state='FAILED',timeout_result='INDETERMINATE')
            elif old!='RUNNING' and now>=c['expires_at']: c['state']='EXPIRED'
            elif old=='LEASED' and now>=c['lease_until']: c['state']='PENDING' if c['attempts']<3 else 'EXPIRED'
            if c['state']!=old:
                self.repo.put('fleet_command',c);self.p.audit.add('COMMAND_'+c['state'],c['actor'],c['id'],c['tenant_id'])
    def cleanup(self):
        now=int(self.clock())
        for kind in ('fleet_nonce','fleet_invite','web_session','fleet_idempotency'):
            for row in self.repo.list(kind):
                if row['expires']<=now: self.repo.delete(kind,row['id'])
        for c in self.repo.list('fleet_command'):
            if c['state'] in TERMINAL and c['issued_at']<now-86400: self.repo.delete('fleet_command',c['id'])
        for e in self.repo.list('entitlement'):
            # Synthetic Agent leases are short-lived command evidence, never desktop leases.
            if e['session_id'].startswith('agent-') and e['expires']<now:
                self.repo.delete('entitlement',e['id'])
                for l in self.repo.list('lease'):
                    if l['entitlement_id']==e['id']: self.repo.delete('lease',l['id'])
        for r in self.repo.list('challenge'):
            if r['value']['expires']<now: self.repo.delete('challenge',r['id'])
