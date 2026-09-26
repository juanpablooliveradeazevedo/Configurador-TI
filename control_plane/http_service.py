"""Loopback-only QA reference HTTP server; no deployment claim."""
import json,time,threading
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from licensing.contracts import Denied,canonical
from licensing.transport import FIELDS
class QaServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,plane):
        if address[0] not in ('127.0.0.1','localhost'): raise ValueError('QA loopback only')
        self.plane=plane;self.rate_lock=threading.Lock();self.requests=[]
        super().__init__(address,Handler)
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def setup(self): super().setup();self.connection.settimeout(5)
    def respond(self,status,payload):
        data=canonical(payload);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        try:
            with self.server.rate_lock:
                now=time.monotonic();self.server.requests=[x for x in self.server.requests if now-x<60]
                if len(self.server.requests)>=120: self.respond(429,{'error':'RATE_LIMITED'});return
                self.server.requests.append(now)
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=32768: raise Denied('INVALID_REQUEST')
            p=json.loads(self.rfile.read(size))
            if not isinstance(p,dict): raise Denied('INVALID_REQUEST')
            header=self.headers.get('Authorization','');token=header[7:] if header.startswith('Bearer ') else None
            if self.path.startswith('/v1/client/'):
                op=self.path.removeprefix('/v1/client/')
                if op not in FIELDS or not set(p)<=FIELDS[op]: raise Denied('INVALID_REQUEST')
                result=self.server.plane.client(op,p,token)
            elif self.path=='/v1/admin' and set(p)=={'operation','payload'}: result=self.server.plane.admin(token,p['operation'],p['payload'])
            else: raise Denied('INVALID_REQUEST')
            self.respond(200,result)
        except Denied as e: self.respond(403,{'error':e.code})
        except (ValueError,TypeError,KeyError,UnicodeError): self.respond(400,{'error':'INVALID_REQUEST'})
        except (BrokenPipeError,ConnectionError,TimeoutError): pass
        except Exception: self.respond(503,{'error':'SERVER_UNAVAILABLE'})
