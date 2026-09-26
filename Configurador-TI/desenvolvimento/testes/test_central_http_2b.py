import http.client
import json
import re
import ssl
import threading
import unittest
from urllib.parse import urlencode
from control_plane.fleet_http import QaServer
from central_web.server import CentralServer
from central_web.views import page
from fleet_protocol.transport import Transport
from fleet_protocol.contracts import MAX_PAYLOAD
from licensing.contracts import Denied,canonical
from test_fleet_2b import Fixture

class HttpTests(Fixture,unittest.TestCase):
    def setUp(self):
        self.setup();self.api=QaServer(('127.0.0.1',0),self.f);self.bt=threading.Thread(target=self.api.serve_forever,daemon=True);self.bt.start()
        self.transport=Transport('http://127.0.0.1:'+str(self.api.server_port),qa=True)
        self.central=CentralServer(('127.0.0.1',0),self.transport);self.ct=threading.Thread(target=self.central.serve_forever,daemon=True);self.ct.start()
        self.cookie=None;self.csrf=None
    def tearDown(self):
        self.central.shutdown();self.central.server_close();self.ct.join();self.api.shutdown();self.api.server_close();self.bt.join();self.teardown()
    def api_call(self,body,headers=None,path='/v1/web/login'):
        c=http.client.HTTPConnection('127.0.0.1',self.api.server_port,timeout=5);h={'Content-Type':'application/json'};h.update(headers or {})
        c.request('POST',path,body=body,headers=h);r=c.getresponse();data=r.read();status=r.status;heads=dict(r.getheaders());c.close();return status,heads,data
    def browser(self,fields=None,headers=None,path='/'):
        c=http.client.HTTPConnection('127.0.0.1',self.central.server_port,timeout=5);h={};h.update(headers or {})
        if self.cookie:h['Cookie']=self.cookie
        if fields is not None:
            h['Content-Type']='application/x-www-form-urlencoded';method='POST';body=urlencode(fields)
        else: method='GET';body=None
        c.request(method,path,body=body,headers=h);r=c.getresponse();data=r.read().decode();status=r.status;heads=dict(r.getheaders());c.close()
        if 'Set-Cookie' in heads:self.cookie=heads['Set-Cookie'].split(';')[0]
        found=re.search(r'name="csrf" value="([^"]+)"',data)
        if found:self.csrf=found.group(1)
        return status,heads,data
    def login_browser(self):
        self.browser();return self.browser({'operation':'login','csrf':self.csrf,'username':'owner','password':'temporary-password-123'})
    def post(self,op,**v): return self.browser(dict(v,operation=op,csrf=self.csrf))
    def test_real_http_auth_snapshot(self):
        r=self.transport.call('/v1/web/login',{'username':'owner','password':'temporary-password-123'})
        out=self.transport.call('/v1/web/call',{'operation':'snapshot','payload':{'offset':0}},r['access_token'])
        self.assertEqual(self.did,out['fleet_agent'][0]['id'])
    def test_real_agent_http_engine(self):
        self.a.transport=self.transport;c=self.queue();self.a.tick(force=True);self.assertEqual('SUCCEEDED',self.c(c['id'])['state'])
    def test_schema_duplicate_keys_denied(self):
        status,_,data=self.api_call(b'{"username":"owner","username":"evil","password":"temporary-password-123"}')
        self.assertEqual(403,status);self.assertIn(b'INVALID_SCHEMA',data)
    def test_payload_limit(self):
        status,_,data=self.api_call(b'x'*(MAX_PAYLOAD+1));self.assertEqual(403,status)
    def test_cors_denied(self):
        status,heads,data=self.api_call(b'{}',{'Origin':'https://evil.example'})
        self.assertEqual(403,status);self.assertNotIn('Access-Control-Allow-Origin',heads)
    def test_host_header_rebinding_denied(self):
        status,_,_=self.api_call(b'{}',{'Host':'evil.example'});self.assertEqual(403,status)
    def test_bearer_required(self):
        status,_,data=self.api_call(canonical({'operation':'snapshot','payload':{'offset':0}}),path='/v1/web/call')
        self.assertEqual(403,status);self.assertIn(b'AUTH_REQUIRED',data)
    def test_plaintext_listener_not_exposed(self):
        with self.assertRaises(Denied):QaServer(('0.0.0.0',0),self.f)
        with self.assertRaises(Denied):CentralServer(('0.0.0.0',0),self.transport)
    def test_login_rate_limited(self):
        for _ in range(20):self.api_call(b'{"username":"bad","password":"temporary-password-123"}')
        status,_,data=self.api_call(b'{}');self.assertIn(b'RATE_LIMITED',data)
    def test_browser_headers_and_cookie(self):
        status,headers,data=self.browser();self.assertEqual(200,status)
        self.assertEqual('same-origin',headers['Referrer-Policy'])
        self.assertNotIn(headers['Referrer-Policy'],('no-referrer','unsafe-url'))
        self.assertIn('HttpOnly',headers['Set-Cookie']);self.assertIn('SameSite=Strict',headers['Set-Cookie']);self.assertEqual('no-store',headers['Cache-Control'])
        self.assertEqual('nosniff',headers['X-Content-Type-Options']);self.assertEqual('DENY',headers['X-Frame-Options'])
        self.assertIn("default-src 'none'",headers['Content-Security-Policy'])
        self.assertIn("form-action 'self'",headers['Content-Security-Policy'])
        self.assertIn("base-uri 'none'",headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin',headers)
        self.assertIn('<form method="post" action="/">',data)
    def test_backend_retains_no_referrer_policy(self):
        status,headers,_=self.api_call(b'{}')
        self.assertEqual(403,status)
        self.assertEqual('no-referrer',headers['Referrer-Policy'])
    def test_chromium_direct_get_reload_and_cross_site_top_level_navigation(self):
        direct={'Sec-Fetch-Site':'none','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'}
        status,headers,html=self.browser(headers=direct)
        self.assertEqual(200,status);self.assertIn('Login / e-mail',html)
        status,_,html=self.browser(headers={**direct,'Sec-Fetch-Site':'same-origin'})
        self.assertEqual(200,status);self.assertIn('Login / e-mail',html)
        tenants_before=len(self.p.repo.list('tenant'))
        external={**direct,'Sec-Fetch-Site':'cross-site','Origin':'https://example.org'}
        status,headers,html=self.browser(headers=external)
        self.assertEqual(200,status);self.assertIn('Login / e-mail',html)
        self.assertEqual(tenants_before,len(self.p.repo.list('tenant')))
        self.assertNotIn('Access-Control-Allow-Origin',headers)
        self.assertEqual('no-store',headers['Cache-Control'])
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        status,_,_=self.browser(headers={**external,'Sec-Fetch-Mode':'no-cors','Sec-Fetch-Dest':'style'},path='/style.css')
        self.assertEqual(403,status)
    def test_chromium_same_origin_login_and_admin_post(self):
        headers={'Origin':'http://127.0.0.1:'+str(self.central.server_port),
                 'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document','Sec-Fetch-User':'?1'}
        status,initial,html=self.browser(headers={'Sec-Fetch-Site':'none','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'})
        self.assertEqual(200,status);self.assertEqual('same-origin',initial['Referrer-Policy'])
        old_cookie=self.cookie
        status,response,html=self.browser({'operation':'login','csrf':self.csrf,'username':'owner',
                                           'password':'temporary-password-123'},headers=headers)
        self.assertEqual(200,status);self.assertIn('Endpoints',html);self.assertNotEqual(old_cookie,self.cookie)
        self.assertIn('HttpOnly',response['Set-Cookie']);self.assertIn('SameSite=Strict',response['Set-Cookie'])
        self.assertEqual('same-origin',response['Referrer-Policy'])
        token=self.central.sessions[self.cookie.split('=',1)[1]]['token']
        self.assertNotIn(token,html)
        status,_,html=self.browser({'operation':'create_tenant','csrf':self.csrf,'label':'Chrome QA'},headers=headers)
        self.assertEqual(200,status);self.assertIn('Chrome QA',html)
        self.assertEqual(1,sum(t['label']=='Chrome QA' for t in self.p.repo.list('tenant')))
    def test_browser_cross_origin_post_rejected_before_mutation(self):
        self.login_browser();port=self.central.server_port
        good='http://127.0.0.1:'+str(port)
        fields={'operation':'create_tenant','csrf':self.csrf,'label':'Blocked'}
        before=len(self.p.repo.list('tenant'))
        variants=[{'Origin':'https://evil.example','Sec-Fetch-Site':'same-origin'},
                  {'Origin':good+'.evil','Sec-Fetch-Site':'same-origin'},
                  {'Origin':good+'@evil.example','Sec-Fetch-Site':'same-origin'},
                  {'Origin':'null','Sec-Fetch-Site':'same-origin'},
                  {'Origin':good,'Sec-Fetch-Site':'cross-site'},
                  {'Sec-Fetch-Site':'cross-site'}]
        for headers in variants:
            with self.subTest(headers=headers):
                status,_,_=self.browser(fields,headers=headers)
                self.assertEqual(403,status)
                self.assertEqual(before,len(self.p.repo.list('tenant')))
    def test_browser_duplicate_host_and_wrong_csrf_rejected(self):
        self.login_browser();port=self.central.server_port
        fields=urlencode({'operation':'create_tenant','csrf':self.csrf,'label':'Blocked'})
        before=len(self.p.repo.list('tenant'))
        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        connection.putrequest('POST','/',skip_host=True)
        connection.putheader('Host','127.0.0.1:'+str(port))
        connection.putheader('Host','evil.example')
        connection.putheader('Origin','http://127.0.0.1:'+str(port))
        connection.putheader('Content-Type','application/x-www-form-urlencoded')
        connection.putheader('Content-Length',str(len(fields)))
        connection.putheader('Cookie',self.cookie)
        connection.endheaders(fields.encode())
        reply=connection.getresponse();self.assertEqual(403,reply.status);reply.read();connection.close()
        status,_,html=self.browser({'operation':'create_tenant','csrf':'wrong','label':'Blocked'},
                                   headers={'Origin':'http://127.0.0.1:'+str(port),'Sec-Fetch-Site':'same-origin'})
        self.assertIn('CSRF_DENIED',html)
        self.assertEqual(before,len(self.p.repo.list('tenant')))
    def test_real_browser_null_origin_remains_denied_with_valid_csrf(self):
        status,initial,_=self.browser(headers={'Sec-Fetch-Site':'none','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'})
        self.assertEqual(200,status);self.assertEqual('same-origin',initial['Referrer-Policy'])
        before=len(self.p.repo.list('tenant'))
        real_headers={'Host':'127.0.0.1:'+str(self.central.server_port),'Origin':'null',
                      'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate',
                      'Sec-Fetch-Dest':'document','Sec-Fetch-User':'?1'}
        status,response,body=self.browser({'operation':'login','csrf':self.csrf,
            'username':'owner','password':'temporary-password-123'},headers=real_headers)
        self.assertEqual(403,status);self.assertIn('INVALID_ORIGIN',body)
        self.assertEqual('same-origin',response['Referrer-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin',response)
        self.assertFalse(self.central.sessions[self.cookie.split('=',1)[1]]['token'])
        status,_,body=self.browser({'operation':'create_tenant','csrf':self.csrf,'label':'Blocked'},headers=real_headers)
        self.assertEqual(403,status);self.assertIn('INVALID_ORIGIN',body)
        self.assertEqual(before,len(self.p.repo.list('tenant')))
    def test_central_duplicate_origin_and_host_rebinding_denied(self):
        self.login_browser();port=self.central.server_port
        fields=urlencode({'operation':'create_tenant','csrf':self.csrf,'label':'Blocked'})
        before=len(self.p.repo.list('tenant'))
        for extra_headers in ((('Host','127.0.0.1:'+str(port)),('Origin','http://127.0.0.1:'+str(port)),('Origin','https://evil.example')),
                              (('Host','evil.example'),('Origin','http://127.0.0.1:'+str(port)))):
            with self.subTest(extra_headers=extra_headers):
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                connection.putrequest('POST','/',skip_host=True)
                for name,value in extra_headers: connection.putheader(name,value)
                connection.putheader('Content-Type','application/x-www-form-urlencoded')
                connection.putheader('Content-Length',str(len(fields)))
                connection.putheader('Cookie',self.cookie)
                connection.endheaders(fields.encode())
                reply=connection.getresponse();self.assertEqual(403,reply.status)
                self.assertIn(b'INVALID_ORIGIN',reply.read());connection.close()
                self.assertEqual(before,len(self.p.repo.list('tenant')))
    def test_login_session_rotation_and_no_backend_token(self):
        self.browser();old=self.cookie;_,_,data=self.login_browser();self.assertNotEqual(old,self.cookie);self.assertIn('Endpoints',data)
        session=self.central.sessions[self.cookie.split('=',1)[1]];self.assertNotIn(session['token'],data)
    def test_csrf_missing_no_mutation(self):
        self.login_browser();before=len(self.p.repo.list('tenant'));_,_,data=self.browser({'operation':'create_tenant','label':'Denied'})
        self.assertIn('CSRF_DENIED',data);self.assertEqual(before,len(self.p.repo.list('tenant')))
    def test_cross_origin_form_denied(self):
        self.login_browser();status,_,_=self.browser({'operation':'create_tenant','csrf':self.csrf,'label':'Denied'},headers={'Origin':'http://evil.example'});self.assertEqual(403,status)
    def test_forms_administration_and_remote_confirmation(self):
        self.login_browser();_,_,data=self.post('create_tenant',label='Via formulário');self.assertIn('Via formulário',data)
        _,_,data=self.post('prepare',device_id=self.did,action_id='SET_MONITORING_INTERVAL',interval_seconds='120');self.assertIn('Confirmo a alteração',data);self.assertEqual([],self.p.repo.list('fleet_command'))
        _,_,data=self.post('send',confirmed='yes');self.assertEqual(1,len(self.p.repo.list('fleet_command')))
        self.a.transport=self.transport;self.a.tick(force=True);_,_,data=self.browser();self.assertIn('SUCCESS',data);self.assertIn('Estado anterior',data)
    def test_unknown_form_payload_not_shell(self):
        self.login_browser();_,_,data=self.post('queue',command='whoami');self.assertIn('INVALID_SCHEMA',data);self.assertEqual([],self.p.repo.list('fleet_command'))
    def test_login_xss_escaped(self):
        self.w('create_tenant',label='<script>alert(1)</script>');self.login_browser();_,_,data=self.browser();self.assertNotIn('<script>',data);self.assertIn('&lt;script&gt;',data)
    def test_url_tokens_rejected(self):
        status,_,_=self.browser(path='/?token=secret');self.assertEqual(403,status)
    def test_force_logout_seen_on_browser_refresh(self):
        self.browser();self.browser({'operation':'login','csrf':self.csrf,'username':'tech','password':'temporary-password-123'});self.w('force_logout',user_id=self.uid)
        _,_,data=self.browser();self.assertIn('Login / e-mail',data);self.assertNotIn('<h2>Endpoints',data)
    def test_redirect_denied(self):
        from fleet_protocol.transport import NoRedirect
        with self.assertRaises(Denied):NoRedirect().redirect_request(None,None,302,None,None,'http://evil.example')
    def test_tls_certificate_validation(self):
        # Validate the actual transport SSL context, never an insecure override.
        handler=next(h for h in self.transport.opener.handlers if isinstance(h,__import__('urllib.request',fromlist=['HTTPSHandler']).HTTPSHandler))
        self.assertEqual(ssl.CERT_REQUIRED,handler._context.verify_mode);self.assertTrue(handler._context.check_hostname)
if __name__=='__main__':unittest.main()
