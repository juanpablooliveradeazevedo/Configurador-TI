"""Loopback-only reference API. Central communicates server-to-server (no CORS)."""
import json
from licensing.contracts import Denied,canonical
from fleet_protocol.contracts import MAX_PAYLOAD
from fleet_protocol.http_support import LocalServer,LocalHandler

def unique_object(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise Denied('INVALID_SCHEMA')
        out[k]=v
    return out
class Handler(LocalHandler):
    def do_GET(self):
        try:
            self.origin_check()
            if self.path!='/health': raise Denied('UNKNOWN_OPERATION')
            self.respond(200,canonical({'status':'QA_ONLY','api_version':1}))
        except Denied as e: self.respond(403,canonical({'error':e.code}))
    def do_POST(self):
        try:
            self.origin_check();route=self.path
            group='login' if route=='/v1/web/login' else 'web' if route.startswith('/v1/web/') else 'agent'
            if self.server.limited(group,20 if group=='login' else 240): raise Denied('RATE_LIMITED')
            p=json.loads(self.body(MAX_PAYLOAD,'application/json'),object_pairs_hook=unique_object,parse_constant=lambda _: (_ for _ in ()).throw(Denied('INVALID_SCHEMA')))
            f=self.server.fleet
            if route=='/v1/web/login': result=f.login(p)
            elif route=='/v1/web/call':
                auth=self.headers.get('Authorization','')
                if not auth.startswith('Bearer '): raise Denied('AUTH_REQUIRED')
                result=f.web(auth[7:],p)
            elif route=='/v1/agent/challenge': result=f.challenge(p)
            elif route=='/v1/agent/enroll': result=f.enroll(p)
            elif route=='/v1/agent/call': result=f.agent(p)
            elif route.startswith('/v1/client/'):
                op=route.removeprefix('/v1/client/');auth=self.headers.get('Authorization','')
                result=f.p.client(op,p,auth[7:] if auth.startswith('Bearer ') else None)
            else: raise Denied('UNKNOWN_OPERATION')
            raw=canonical(result)
            if len(raw)>MAX_PAYLOAD: raise Denied('RESPONSE_TOO_LARGE')
            self.respond(200,raw)
        except Denied as e:
            self.server.fleet.p.audit.add('API_DENIED',result='DENIED');self.respond(403,canonical({'error':e.code}))
        except (ValueError,KeyError,TypeError,UnicodeError,RecursionError): self.respond(400,canonical({'error':'INVALID_SCHEMA'}))
        except Exception: self.respond(503,canonical({'error':'INDETERMINATE'}))
class QaServer(LocalServer):
    def __init__(self,address,fleet): self.fleet=fleet;super().__init__(address,Handler)
