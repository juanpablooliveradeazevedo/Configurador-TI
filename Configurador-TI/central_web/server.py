"""Local BFF: opaque browser session and synchronizer CSRF token.
Backend access tokens stay in server memory, never HTML/JS/localStorage/URLs.
"""
import secrets
import threading
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from licensing.contracts import Denied,new_id
from fleet_protocol.contracts import AGENT_VERSION,CATALOG
from fleet_protocol.http_support import LocalServer,LocalHandler
from .views import page,CSS
from .messages import msg
class CentralServer(LocalServer):
    def __init__(self,address,transport):
        self.transport=transport;self.sessions={};self.session_lock=threading.Lock();super().__init__(address,Handler)
    def browser_session(self,cookie):
        jar=SimpleCookie()
        try: jar.load(cookie or '');sid=jar['configurador_ti_session'].value if 'configurador_ti_session' in jar else ''
        except Exception: sid=''
        with self.session_lock:
            for key,s in list(self.sessions.items()):
                if s['expires']<=time.monotonic(): self.sessions.pop(key,None)
            s=self.sessions.get(sid)
            if s is None:
                if len(self.sessions)>=256: raise Denied('CAPACITY_REACHED')
                sid=secrets.token_urlsafe(32);s={'csrf':secrets.token_urlsafe(32),'token':None,'expires':time.monotonic()+1800,'pending':None,'offset':0,'lock':threading.RLock()};self.sessions[sid]=s
            return sid,s
    def rotate(self,sid,s):
        with self.session_lock:
            self.sessions.pop(sid,None);sid=secrets.token_urlsafe(32);s['csrf']=secrets.token_urlsafe(32);s['expires']=time.monotonic()+1800;self.sessions[sid]=s;return sid
class Handler(LocalHandler):
    # HTML forms navigate within this origin; no referrer is sent elsewhere.
    referrer_policy='same-origin'
    def backend(self,s,op,p): return self.server.transport.call('/v1/web/call',{'operation':op,'payload':p},s['token'])
    def render(self,sid,s,notice='',error='',preview=None,special=None,audit=None):
        snapshot=None
        if s['token']:
            try: snapshot=self.backend(s,'snapshot',{'offset':s['offset']})
            except (Denied,ConnectionError) as e:
                error=getattr(e,'code','BACKEND_UNAVAILABLE')
                if error in ('AUTH_REQUIRED','NOT_FOUND','TENANT_SUSPENDED'): s['token']=None;s['pending']=None
        self.respond(200,page(s['csrf'],snapshot,notice,error,preview,special,audit),'text/html; charset=utf-8','configurador_ti_session='+sid+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800')
    def do_GET(self):
        try:
            self.origin_check(True,safe_navigation=True)
            if self.path=='/style.css': self.respond(200,CSS,'text/css');return
            if self.path!='/': raise Denied('UNKNOWN_OPERATION')
            sid,s=self.server.browser_session(self.headers.get('Cookie'))
            with s['lock']: self.render(sid,s)
        except Denied as e: self.respond(403,e.code.encode(),'text/plain')
    def do_POST(self):
        sid=s=None
        try:
            self.origin_check(True)
            if self.path!='/': raise Denied('UNKNOWN_OPERATION')
            raw=self.body(8192,'application/x-www-form-urlencoded').decode('utf-8')
            values=parse_qs(raw,keep_blank_values=True,max_num_fields=20,strict_parsing=True)
            if any(len(v)!=1 for v in values.values()): raise Denied('INVALID_SCHEMA')
            v={k:val[0] for k,val in values.items()};op=v.pop('operation','');csrf=v.pop('csrf','')
            if self.server.limited('login' if op=='login' else 'admin',15 if op=='login' else 120): raise Denied('RATE_LIMITED')
            sid,s=self.server.browser_session(self.headers.get('Cookie'))
            with s['lock']:
                if not secrets.compare_digest(csrf,s['csrf']): raise Denied('CSRF_DENIED')
                special=preview=audit=None
                if op=='login':
                    if set(v)!={'username','password'}: raise Denied('INVALID_SCHEMA')
                    r=self.server.transport.call('/v1/web/login',v);s['token']=r['access_token'];sid=self.server.rotate(sid,s)
                else:
                    if not s['token']: raise Denied('AUTH_REQUIRED')
                    if op=='logout':
                        self.backend(s,'logout',{});s['token']=None;s['pending']=None;sid=self.server.rotate(sid,s)
                    elif op=='page':
                        if set(v)!={'offset'}: raise Denied('INVALID_SCHEMA')
                        s['offset']=max(0,min(1000000,int(v['offset'])))
                    elif op=='prepare':
                        if set(v)!={'device_id','action_id','interval_seconds'}: raise Denied('INVALID_SCHEMA')
                        p={'device_id':v['device_id'],'action_id':v['action_id'],'parameters':{'interval_seconds':int(v['interval_seconds'])}}
                        preview=self.backend(s,'preview',p);s['pending']=dict(p,idempotency_key=new_id(),issued_at=int(time.time()),confirmed=True)
                    elif op=='send':
                        if v!={'confirmed':'yes'} or s['pending'] is None: raise Denied('CONFIRMATION_REQUIRED')
                        self.backend(s,'queue',s['pending']);s['pending']=None
                    else:
                        if op=='invite':
                            v.update(protocol_version=1,agent_version=AGENT_VERSION,capabilities=list(CATALOG))
                        elif op=='plan_policy':
                            v['fleet_enabled']=v.get('fleet_enabled')=='yes'
                            for k in ('seat_limit','device_limit','validity_seconds','offline_seconds'): v[k]=int(v[k])
                        elif op=='agent_tags': v['tags']=[x.strip() for x in v['tags'].split(',') if x.strip()]
                        result=self.backend(s,op,v)
                        if op in ('invite','login_code'): special=result
                        if op=='audit': audit=result['rows']
                self.render(sid,s,notice=msg('success'),preview=preview,special=special,audit=audit)
        except (Denied,ConnectionError,ValueError,KeyError,UnicodeError) as e:
            code=getattr(e,'code','BACKEND_UNAVAILABLE' if isinstance(e,ConnectionError) else 'INVALID_SCHEMA')
            if s is not None:
                with s['lock']: self.render(sid,s,error=code)
            else: self.respond(403,code.encode(),'text/plain')
