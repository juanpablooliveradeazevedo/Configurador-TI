"""Foreground/test lifecycle and explicit Windows service commands."""
import argparse
import getpass
import json
import signal
import sys
from pathlib import Path
from licensing.contracts import Denied
from licensing.secure_store import SecureStore
from fleet_protocol.contracts import AGENT_VERSION,closed
from fleet_protocol.transport import Transport

def main():
    p=argparse.ArgumentParser(description='Configurador TI Agent headless outbound-only')
    p.add_argument('command',choices=('enroll','run','once','stop','status','smoke','service-install','service-start','service-stop','service-status','service-remove','service-run'))
    p.add_argument('--state-dir');p.add_argument('--config');p.add_argument('--enrollment-stdin',action='store_true',help='QA automation only; secret is read from stdin, never argv')
    a=p.parse_args()
    if a.command=='smoke':
        from .engine import AgentActionEngine
        print(json.dumps({'status':'PASS','agent_version':AGENT_VERSION,'headless':True,'inbound_listener':False}));return
    if a.command.startswith('service-'):
        from . import windows_service as service
        if a.command=='service-run': service.run_service();return
        if a.command!='service-install':
            print(json.dumps(service.control({'service-start':'start','service-stop':'stop','service-status':'query','service-remove':'delete'}[a.command])));return
    if not a.state_dir and a.command!='service-install': p.error('--state-dir obrigatório')
    root=Path(a.state_dir).resolve() if a.state_dir else None
    if a.command=='status':
        value=json.loads((root/'status.json').read_text(encoding='utf-8')) if (root/'status.json').exists() else {'status':'NOT_STARTED'}
        import time
        if value.get('updated_at',0)<time.time()-120 and value.get('status')!='STOPPED': value['status']='STALE'
        print(json.dumps(value));return
    if a.command=='stop':
        SecureStore(root/'identity.bin',qa=True)._safe()
        if not root.is_dir(): raise Denied('NOT_STARTED')
        (root/'stop.request').touch();return
    if not a.config: p.error('--config público obrigatório')
    cp=Path(a.config)
    if cp.stat().st_size>65536: raise Denied('PAYLOAD_TOO_LARGE')
    config=json.loads(cp.read_text(encoding='utf-8'));closed(config,'endpoint qa command_keys entitlement_keys sync_minimal')
    Transport(config['endpoint'],qa=config['qa'])
    if a.command=='service-install':
        print(json.dumps(service.install(config,service.read_enrollment_code())));return
    from .runtime import Agent
    agent=Agent(root,config)
    try:
        if a.command=='enroll':
            if a.enrollment_stdin:
                if not config['qa']: raise Denied('QA_ONLY')
                code=sys.stdin.readline(256).strip()
            else: code=getpass.getpass('Código de enrollment (uso único): ')
            agent.enroll(code);print('ENROLLED')
        elif a.command=='once': agent.tick(force=True);print(agent.status)
        else:
            (root/'stop.request').unlink(missing_ok=True)
            for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:agent.stop_event.set())
            agent.run()
    finally: agent.close()
if __name__=='__main__':
    try: main()
    except (Denied,OSError,ValueError,KeyError) as e: raise SystemExit(getattr(e,'code','AGENT_STATE_UNAVAILABLE')) from None
