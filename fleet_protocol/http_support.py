"""Bounded local QA HTTP support. Not a production HTTP server."""
import collections
import threading
import time
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from urllib.parse import urlsplit
from licensing.contracts import Denied
class LocalServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True
    def __init__(self,address,handler):
        if address[0]!='127.0.0.1': raise Denied('QA_LOOPBACK_ONLY')
        self.slots=threading.BoundedSemaphore(24);self.rates={};self.rate_lock=threading.Lock()
        super().__init__(address,handler)
    def process_request(self,request,address):
        if not self.slots.acquire(False): request.close();return
        try: super().process_request(request,address)
        except BaseException: self.slots.release();raise
    def process_request_thread(self,request,address):
        try: super().process_request_thread(request,address)
        finally: self.slots.release()
    def limited(self,key,limit):
        now=time.monotonic()
        with self.rate_lock:
            times=self.rates.setdefault(key,collections.deque())
            while times and times[0]<now-60: times.popleft()
            if len(times)>=limit: return True
            times.append(now);return False
class LocalHandler(BaseHTTPRequestHandler):
    server_version='ConfiguradorTI-QA'
    sys_version=''
    referrer_policy='no-referrer'
    def setup(self): super().setup();self.connection.settimeout(5)
    def log_message(self,*args): pass
    def origin_check(self,browser=False,*,safe_navigation=False):
        host='127.0.0.1:'+str(self.server.server_port)
        if self.headers.get_all('Host')!=[host]: raise Denied('INVALID_ORIGIN')
        sites=self.headers.get_all('Sec-Fetch-Site',[])
        if len(sites)>1: raise Denied('INVALID_ORIGIN')
        if safe_navigation:
            # A cross-site link is a legitimate top-level GET. Subresource
            # requests from another site still do not need access to this UI.
            if sites==['cross-site'] and (self.headers.get('Sec-Fetch-Mode')!='navigate' or self.headers.get('Sec-Fetch-Dest')!='document'):
                raise Denied('INVALID_ORIGIN')
            return
        origins=self.headers.get_all('Origin',[])
        if len(origins)>1: raise Denied('INVALID_ORIGIN')
        if origins:
            if not browser: raise Denied('INVALID_ORIGIN')
            try: origin=urlsplit(origins[0])
            except ValueError: raise Denied('INVALID_ORIGIN') from None
            if (origin.scheme!='http' or origin.netloc!=host or origin.path or origin.query or origin.fragment
                    or origin.username or origin.password or origin.hostname!='127.0.0.1' or origin.port!=self.server.server_port):
                raise Denied('INVALID_ORIGIN')
        if sites==['cross-site']: raise Denied('INVALID_ORIGIN')
    def body(self,maximum,content_type):
        lengths=self.headers.get_all('Content-Length')
        if not lengths or len(lengths)!=1 or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type')!=content_type: raise Denied('INVALID_REQUEST')
        try: size=int(lengths[0])
        except ValueError: raise Denied('INVALID_REQUEST') from None
        if not 0<size<=maximum: raise Denied('PAYLOAD_TOO_LARGE')
        data=self.rfile.read(size)
        if len(data)!=size: raise Denied('INVALID_REQUEST')
        return data
    def respond(self,status,data,content_type='application/json',cookie=None):
        self.send_response(status)
        for key,val in {'Content-Type':content_type,'Content-Length':str(len(data)),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':self.referrer_policy,'Content-Security-Policy':"default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",'Connection':'close'}.items(): self.send_header(key,val)
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(data);self.close_connection=True
