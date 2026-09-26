"""Persistent device identity, durable duplicate journal, fail-closed execution."""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from licensing.contracts import Denied,canonical,new_id,version_tuple
from licensing.device import DeviceIdentity
from licensing.secure_store import SecureStore
from licensing.verification import EntitlementVerifier,b64
from fleet_protocol.contracts import closed,command,verify,fingerprint,negotiation,AGENT_VERSION
from fleet_protocol.transport import Transport
from .engine import AgentActionEngine,VerifiedGate

class InstanceLock:
    def __init__(self,path):
        self.file=open(path,'a+b');self.file.seek(0);self.file.write(b'0');self.file.flush();self.file.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.file,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.file.close();raise Denied('AGENT_ALREADY_RUNNING') from None
    def close(self): self.file.close()

class Agent:
    def __init__(self,root,config,*,clock=time.time,transport=None,engine=None):
        closed(config,'endpoint qa command_keys entitlement_keys sync_minimal')
        if type(config['qa']) is not bool or config['sync_minimal'] is not True: raise Denied('SYNC_CONSENT_REQUIRED')
        if not config['command_keys'] or not config['entitlement_keys'] or set(config['command_keys'].values())&set(config['entitlement_keys'].values()): raise Denied('KEY_PURPOSE_CONFLICT')
        SecureStore(Path(root)/'identity.bin',qa=config['qa'])._safe()
        self.root=Path(root).resolve();self.clock=clock;self.stop_event=threading.Event();self.next_attempt=0;self.failures=0;self.status='STARTING'
        self.secure=SecureStore(self.root/'identity.bin',qa=config['qa']);self.secure._safe();self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        for name in ('agent.lock','agent-journal.db','status.json','status.tmp','stop.request'):
            SecureStore(self.root/name,qa=config['qa'])._safe()
        self.lock=InstanceLock(self.root/'agent.lock')
        try:
            self.state=self.secure.read()
            self.identity=DeviceIdentity(self.state.get('private_key'))
            if not self.state:
                self.state={'private_key':self.identity.private(),'binding':None,'high_water':int(clock())};self.secure.write(self.state)
            self.keys=config['command_keys'];self.verifier=EntitlementVerifier(config['entitlement_keys'])
            self.transport=transport or Transport(config['endpoint'],qa=config['qa']);self.engine=engine or AgentActionEngine(self.root)
            self.db=sqlite3.connect(self.root/'agent-journal.db')
            self.db.execute('CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL,run_id TEXT,started INTEGER NOT NULL,proof TEXT)');self.db.commit()
            if os.name!='nt': os.chmod(self.root/'agent-journal.db',0o600)
            self._recover()
        except BaseException: self.lock.close();raise
    def _now(self):
        now=int(self.clock())
        if now<self.state['high_water']-120: raise Denied('CLOCK_ROLLBACK')
        if now>self.state['high_water']: self.state['high_water']=now;self.secure.write(self.state)
        return now
    def enroll(self,code):
        if self.state['binding']: raise Denied('ALREADY_ENROLLED')
        response=self.transport.call('/v1/agent/challenge',{'code':code,'public_key':self.identity.public()})
        closed(response,'challenge binding');b=response['binding'];closed(b,'tenant_id user_id device_id protocol_version agent_version capabilities')
        negotiation(b['protocol_version'],b['agent_version'],b['capabilities'])
        if b['agent_version']!=AGENT_VERSION: raise Denied('AGENT_OUTDATED')
        c=response['challenge']
        if c.get('purpose')!='agent-enroll:'+fingerprint(b) or c.get('public_key')!=self.identity.public() or not self._now()<c.get('expires',0)<=self._now()+60: raise Denied('INVALID_CHALLENGE')
        out=self.transport.call('/v1/agent/enroll',{'code':code,'challenge_id':c['id'],'proof':self.identity.prove(c)})
        if out!=b: raise Denied('WRONG_BINDING')
        self.state['binding']=b;self.secure.write(self.state);self.status='ENROLLED'
    def _request(self,op,payload):
        b=self.state['binding']
        if b is None: raise Denied('ENROLLMENT_REQUIRED')
        now=self._now();p={k:b[k] for k in ('tenant_id','device_id','protocol_version','agent_version','capabilities')}
        p.update(issued_at=now,expires_at=now+30,nonce=new_id(),operation=op,payload=payload)
        return self.transport.call('/v1/agent/call',{'payload':p,'signature':b64(self.identity.key.sign(canonical(p)))})
    def _recover(self):
        for cid,body,run_id,started in self.db.execute("SELECT id,body,run_id,started FROM commands WHERE state IN ('RESERVED','EXECUTING')").fetchall():
            c=json.loads(body);run=self.engine.store.get_action_run(run_id) if run_id else None
            pr=self.engine.make_proof(c,run,started,self._now(),True)
            self.db.execute("UPDATE commands SET state='RESULT_PENDING',proof=? WHERE id=?",(json.dumps(pr),cid))
        self.db.commit()
    def flush(self):
        for cid,body,pr in self.db.execute("SELECT id,body,proof FROM commands WHERE state='RESULT_PENDING' ORDER BY started LIMIT 10").fetchall():
            c=json.loads(body)
            r=self._request('result',{'command_id':cid,'claim_id':c['claim_id'],'proof':json.loads(pr)})
            if r!={'accepted':True}: raise Denied('INVALID_RESPONSE')
            self.db.execute("UPDATE commands SET state='ACKNOWLEDGED' WHERE id=?",(cid,));self.db.commit()
        self.db.execute("DELETE FROM commands WHERE state='ACKNOWLEDGED' AND started<?",(self._now()-86400,));self.db.commit()
    def _execute(self,envelope):
        c=verify(envelope,self.keys,'fleet-command');b=self.state['binding'];spec=command(c,b,self._now())
        ent=self.verifier.verify(c['entitlement'],self._now(),device_id=b['device_id'],public_key=self.identity.public(),user_id=b['user_id'],tenant_id=b['tenant_id'])
        if ent['session_id']!='agent-'+b['device_id'] or ent['channel']!='INTERNAL' or version_tuple(AGENT_VERSION)<version_tuple(ent['minimum_supported_version']): raise Denied('WRONG_BINDING')
        gate=VerifiedGate(ent,self._now)
        for feature in spec['features']: gate.require(feature)
        if self.db.execute('SELECT 1 FROM commands WHERE id=? OR nonce=?',(c['command_id'],c['nonce'])).fetchone(): raise Denied('DUPLICATE_COMMAND')
        if self.db.execute('SELECT count(*) FROM commands').fetchone()[0]>=2000: raise Denied('JOURNAL_FULL')
        request={'command_id':c['command_id'],'claim_id':c['claim_id']}
        permit=verify(self._request('start',request),self.keys,'execution-permit')
        closed(permit,'purpose key_id command_id claim_id tenant_id device_id expires_at')
        if any(permit[k]!=c[k] for k in ('command_id','claim_id','tenant_id','device_id')) or not self._now()<permit['expires_at']<=self._now()+30: raise Denied('PERMIT_INVALID')
        started=self._now();run=None;uncertain=False
        self.db.execute('INSERT INTO commands VALUES(?,?,?,?,?,?,?)',(c['command_id'],c['nonce'],json.dumps(c),'RESERVED',None,started,None));self.db.commit()
        def cancelled():
            if self.stop_event.is_set() or self._now()-started>=120 or self._now()>=c['expires_at']: return True
            try: return self._request('cancel_check',request)['cancel_requested'] is not False
            except (ConnectionError,Denied,KeyError): return True
        try:
            run=self.engine.prepare(c,gate);rid=run['action_run_id']
            self.db.execute('UPDATE commands SET run_id=? WHERE id=?',(rid,c['command_id']));self.db.commit()
            if run['status']=='READY':
                if cancelled() or self._now()>=permit['expires_at']: run=self.engine.store.cancel_action(rid)
                else:
                    self.db.execute("UPDATE commands SET state='EXECUTING' WHERE id=?",(c['command_id'],));self.db.commit()
                    run=self.engine.execute(rid,gate,cancelled)
        except Exception: uncertain=True
        pr=self.engine.make_proof(c,run,started,self._now(),uncertain)
        self.db.execute("UPDATE commands SET state='RESULT_PENDING',proof=? WHERE id=?",(json.dumps(pr),c['command_id']));self.db.commit();self.flush()
    def tick(self,*,force=False):
        if not force and self.clock()<self.next_attempt: return
        try:
            self._request('heartbeat',{'summary':self.engine.summary()});self.flush()
            r=self._request('poll',{});closed(r,'command')
            if r['command'] is not None: self._execute(r['command'])
            self.status='ONLINE';self.failures=0;self.next_attempt=self.clock()+30
        except ConnectionError:
            self.failures+=1;self.status='OFFLINE';self.next_attempt=self.clock()+min(300,2**min(self.failures,8))
        except Denied as e: self.status=e.code;self.next_attempt=self.clock()+60
        except Exception: self.status='INDETERMINATE';self.next_attempt=self.clock()+60
        self.write_status()
    def write_status(self):
        value={'status':self.status,'updated_at':int(self.clock()),'device_id':(self.state['binding'] or {}).get('device_id'),'agent_version':AGENT_VERSION}
        temp=self.root/'status.tmp';temp.write_text(json.dumps(value),encoding='utf-8');os.replace(temp,self.root/'status.json')
    def run(self):
        stop=self.root/'stop.request'
        while not self.stop_event.is_set() and not stop.exists():
            self.tick();self.stop_event.wait(1)
        stop.unlink(missing_ok=True);self.status='STOPPED';self.write_status()
    def close(self): self.db.close();self.lock.close()
