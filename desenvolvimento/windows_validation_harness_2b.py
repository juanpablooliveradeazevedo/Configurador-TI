"""Isolated, repeatable 2B QA validation. No hardcoded credentials or UAC tricks.

Runs on Windows and POSIX QA. Native SCM/desktop review is NEEDS_HUMAN until
performed on Windows. Machine-readable evidence contains statuses, no secrets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from control_plane.fleet_cli import initialize
from fleet_protocol.transport import Transport
from fleet_protocol.contracts import AGENT_VERSION,CATALOG
from licensing.contracts import new_id

def free_port():
    with socket.socket() as s: s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait_until(fn,seconds=12):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            value=fn()
            if value: return value
        except (ConnectionError,OSError,ValueError): pass
        time.sleep(.1)
    raise RuntimeError('WAIT_TIMEOUT')

def run(output,agent_exe=None,build_agent=False):
    report={'phase':'2B','platform':sys.platform,'status':'RUNNING','checks':[],'cleanup':'PENDING'};processes=[]
    def record(name,status='PASS',detail=None):
        r={'name':name,'status':status}
        if detail:r['detail']=detail
        report['checks'].append(r)
    def spawn(args):
        child=subprocess.Popen(args,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False);processes.append(child);return child
    def stop(child):
        if child.poll() is None:
            child.terminate()
            try:child.wait(10)
            except subprocess.TimeoutExpired:child.kill();child.wait(5)
    def command(args,input=None):
        r=subprocess.run(args,input=input,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,shell=False,timeout=30)
        if r.returncode: raise RuntimeError('CHILD_PROCESS_FAILED')
        return r.stdout.strip()
    temp=None
    try:
        temp=tempfile.TemporaryDirectory(prefix='configurador-ti-2b-harness-');root=Path(temp.name);backend=root/'backend';agent=root/'agent';port=free_port()
        username='qa-'+secrets.token_hex(8);password=secrets.token_urlsafe(32)
        initialize(backend,username,password,port);record('isolated_setup')
        config=backend/'agent-public.json';api=Transport('http://127.0.0.1:'+str(port),qa=True)
        backend_args=[sys.executable,'-m','control_plane.fleet_cli','serve','--state-dir',str(backend),'--port',str(port)]
        b=spawn(backend_args)
        token=wait_until(lambda:api.call('/v1/web/login',{'username':username,'password':password})['access_token']);record('backend_process_start')
        def web(op,**p):return api.call('/v1/web/call',{'operation':op,'payload':p},token)
        web('plan_policy',id='QA',seat_limit=2,device_limit=2,validity_seconds=3600,offline_seconds=300,minimum_supported_version='5.0',fleet_enabled=True)
        tid=web('create_tenant',label='Harness isolado')['id']
        uid=web('create_user',tenant_id=tid,display_name='Técnico QA',login='qa-'+secrets.token_hex(8),password=secrets.token_urlsafe(32),role='TECHNICIAN')['id']
        lid=web('create_license',tenant_id=tid,plan_id='QA')['id'];web('assign_seat',user_id=uid,license_id=lid)
        invite=web('invite',user_id=uid,label='Endpoint QA',protocol_version=1,agent_version=AGENT_VERSION,capabilities=list(CATALOG));did=invite['device_id']
        if build_agent:
            if os.name=='nt':
                from desenvolvimento.package_deployments_2b import agent_build
                agent_exe=agent_build(root/'build');record('native_agent_build')
            else:record('native_agent_build','NEEDS_HUMAN','Windows real necessário')
        if agent_exe:
            exe=Path(agent_exe).resolve();manifest=json.loads((exe.parent/'release-manifest.json').read_text(encoding='utf-8'))
            if manifest.get('deployment')!='Agent' or manifest.get('artifact_sha256')!=hashlib.sha256(exe.read_bytes()).hexdigest():raise RuntimeError('EXE_TRUST_MISMATCH')
            for line in (exe.parent/'SHA256SUMS.txt').read_text().splitlines():
                digest,name=line.split('  ',1);file=(exe.parent/name).resolve()
                if exe.parent not in file.parents or hashlib.sha256(file.read_bytes()).hexdigest()!=digest:raise RuntimeError('PACKAGE_TRUST_MISMATCH')
            entry=[str(exe)];record('native_exe_trust')
        else:entry=[sys.executable,'-m','agent']
        smoke=json.loads(command(entry+['smoke']));assert smoke['status']=='PASS';record('headless_entry_smoke')
        args=['--state-dir',str(agent),'--config',str(config)]
        assert command(entry+['enroll',*args,'--enrollment-stdin'],invite['enrollment_code']+'\n')=='ENROLLED';record('enrollment_process')
        assert command(entry+['once',*args])=='ONLINE';record('heartbeat')
        c=web('queue',device_id=did,action_id='SET_MONITORING_INTERVAL',parameters={'interval_seconds':120},idempotency_key=new_id(),issued_at=int(time.time()),confirmed=True)
        assert command(entry+['once',*args])=='ONLINE'
        row=next(x for x in web('snapshot',offset=0)['fleet_command'] if x['id']==c['id'])
        assert row['state']=='SUCCEEDED' and row['proof']['before']==60 and row['proof']['after']==120;record('remote_action_real_engine_proof')
        assert command(entry+['once',*args])=='ONLINE';record('agent_restart_identity_journal')
        (agent/'status.json').unlink(missing_ok=True)
        runner=spawn(entry+['run',*args]);wait_until(lambda:(agent/'status.json').exists() and json.loads((agent/'status.json').read_text())['status']=='ONLINE')
        command(entry+['stop','--state-dir',str(agent)]);runner.wait(12);assert runner.returncode==0;record('foreground_start_stop')
        stop(b);assert command(entry+['once',*args])=='OFFLINE';record('backend_offline_agent_fail_closed')
        b=spawn(backend_args)
        token=wait_until(lambda:api.call('/v1/web/login',{'username':username,'password':password})['access_token'])
        assert command(entry+['once',*args])=='ONLINE';record('backend_restart_agent_reconnect')
        web('revoke_device',id=did);assert command(entry+['once',*args])=='DEVICE_REVOKED';record('revocation')
        record('service_install_lifecycle','NEEDS_HUMAN','Instalação explícita como LocalService; validar SCM/DPAPI/ACL no Windows')
        record('technician_windows_gui','NEEDS_HUMAN','Smoke fonte/EXE e GUI responsiva no Windows; sem instalar updates')
        if not agent_exe:record('agent_windows_exe','NEEDS_HUMAN','Executar --build-agent no Windows ou fornecer --agent-exe com manifesto')
        report['status']='PASS_WITH_NATIVE_PENDING' if any(x['status']=='NEEDS_HUMAN' for x in report['checks']) else 'PASS'
    except Exception as e:
        # Never serialize exception text: it may contain credentials/URLs/paths.
        record('harness_failure','FAIL',type(e).__name__);report['status']='FAIL'
    finally:
        for child in reversed(processes): stop(child)
        if temp:
            try:temp.cleanup();report['cleanup']='PASS'
            except OSError: report['cleanup']='FAIL';report['status']='FAIL'
        out=Path(output).resolve();out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--agent-exe');p.add_argument('--build-agent',action='store_true');a=p.parse_args()
    result=run(a.output,a.agent_exe,a.build_agent);print(result['status']);raise SystemExit(1 if result['status']=='FAIL' else 0)
