"""Narrow HTTPS API. Loopback HTTP is only available in explicit QA."""
import json
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,HTTPRedirectHandler,ProxyHandler
from urllib.error import HTTPError,URLError
from .contracts import Denied,canonical
FIELDS={'challenge':{'purpose','public_key','refresh_token'},'login':{'authorization_code','public_key','challenge_id','proof','version','channel'},'renew':{'challenge_id','proof','version','channel'},'refresh':{'refresh_token','challenge_id','proof','version','channel'},'logout':set()}
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
class HttpAdapter:
    def __init__(self,endpoint,*,qa=False,timeout=3):
        p=urlsplit(endpoint)
        if p.username or p.password or p.query or p.fragment or p.path not in ('','/') or not p.hostname: raise Denied('INVALID_ENDPOINT')
        if p.scheme!='https' and not (qa and p.scheme=='http' and p.hostname in ('127.0.0.1','localhost','::1')): raise Denied('HTTPS_REQUIRED')
        self.endpoint=endpoint.rstrip('/');self.timeout=min(5,max(.1,timeout));self.opener=build_opener(ProxyHandler({}),NoRedirect())
    def call(self,op,payload,access_token=None):
        if op not in FIELDS or not set(payload)<=FIELDS[op]: raise Denied('INVALID_REQUEST')
        headers={'Content-Type':'application/json'}
        if access_token: headers['Authorization']='Bearer '+access_token
        req=Request(self.endpoint+'/v1/client/'+op,data=canonical(payload),headers=headers,method='POST')
        try:
            with self.opener.open(req,timeout=self.timeout) as response: data=response.read(65537)
            if len(data)>65536: raise Denied('INVALID_RESPONSE')
            result=json.loads(data)
            if not isinstance(result,dict): raise Denied('INVALID_RESPONSE')
            return result
        except HTTPError as e:
            if e.code>=500 or e.code==429: raise ConnectionError('SERVER_UNAVAILABLE') from None
            try: code=json.loads(e.read(4096)).get('error','AUTH_REQUIRED')
            except (ValueError,AttributeError): code='AUTH_REQUIRED'
            raise Denied(code) from None
        except (URLError,TimeoutError,OSError): raise ConnectionError('SERVER_UNAVAILABLE') from None
        except (ValueError,UnicodeError): raise Denied('INVALID_RESPONSE') from None
