"""Validated outbound HTTPS. Explicit QA permits only literal 127.0.0.1."""
import json
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from licensing.contracts import Denied, canonical
from .contracts import MAX_PAYLOAD
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise Denied('REDIRECT_DENIED')
class Transport:
    def __init__(self, endpoint, *, qa=False, timeout=5):
        try: u=urlsplit(endpoint); port=u.port
        except (ValueError,TypeError): raise Denied('INVALID_ENDPOINT') from None
        if not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/') or (u.scheme!='https' and not (qa and u.scheme=='http' and u.hostname=='127.0.0.1')): raise Denied('TLS_REQUIRED')
        self.endpoint=endpoint.rstrip('/'); self.timeout=max(1,min(10,timeout))
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def call(self,route,payload,token=None):
        if route not in ('/v1/web/login','/v1/web/call','/v1/agent/challenge','/v1/agent/enroll','/v1/agent/call'): raise Denied('UNKNOWN_OPERATION')
        body=canonical(payload)
        if len(body)>MAX_PAYLOAD: raise Denied('PAYLOAD_TOO_LARGE')
        headers={'Content-Type':'application/json'}
        if token: headers['Authorization']='Bearer '+token
        request=urllib.request.Request(self.endpoint+route,data=body,headers=headers,method='POST')
        try:
            with self.opener.open(request,timeout=self.timeout) as r: data=r.read(MAX_PAYLOAD+1)
        except urllib.error.HTTPError as e:
            data=e.read(MAX_PAYLOAD+1)
            try: code=json.loads(data).get('error','AUTH_REQUIRED')
            except (ValueError,AttributeError): code='AUTH_REQUIRED'
            raise Denied(code) from None
        except (urllib.error.URLError,OSError,TimeoutError): raise ConnectionError('BACKEND_UNAVAILABLE') from None
        if len(data)>MAX_PAYLOAD: raise Denied('PAYLOAD_TOO_LARGE')
        try: return json.loads(data)
        except (ValueError,RecursionError): raise Denied('INVALID_RESPONSE') from None
