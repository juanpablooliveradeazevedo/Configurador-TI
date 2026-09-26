"""Local Windows Agent Service QA runner. No cleanup, elevation or secret capture."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from agent import windows_service as service
from fleet_protocol.contracts import AGENT_VERSION
from licensing.contracts import Denied

STATUS=frozenset(('PASS','FAIL','WARN','SKIP','NEEDS_HUMAN'))
STATES=frozenset(('ABSENT','STOPPED','START_PENDING','STOP_PENDING','RUNNING','OTHER','UNKNOWN'))
NAMES={'platform':'Windows availability','files':'Agent EXE and QA config','checksum':'Agent EXE SHA-256',
       'smoke':'Agent headless smoke','scm_before':'Initial SCM state','admin':'Administrator gate',
       'install':'Interactive service installation','scm_config':'LocalService and manual start',
       'state_dir':'Restricted ProgramData presence','acl':'ProgramData ACL',
       'status_before':'Agent service-status','start':'Start and verify RUNNING',
    'state_files':'Identity, bootstrap and status','identity_before':'Enrolled identity before restart',
    'identity_stopped':'Identity at service stop','stop':'Stop and verify STOPPED',
       'restart':'Restart and verify RUNNING','identity':'Persistent identity'}
MESSAGES={
    'OK':'Verificação concluída.', 'WINDOWS_REQUIRED':'Execute em Windows real.',
    'FILES_MISSING':'Informe Agent EXE e, para instalação nova, config QA pública.',
    'INVALID_AGENT_EXE':'Agent EXE ausente ou inválido.', 'HASH_OK':'SHA-256 calculado.',
    'SMOKE_FAILED':'Smoke do Agent não passou.', 'SCM_ABSENT':'Serviço ausente.',
    'SCM_FOUND':'Serviço consultado no SCM.', 'SCM_QUERY_FAILED':'Consulta SCM falhou.',
    'ADMIN_REQUIRED':'Reabra o terminal como Administrador; não há autoelevação.',
    'INPUT_REQUIRED':'Gere um código na Central e execute em console interativo.',
    'INSTALL_FAILED':'Instalação não concluiu; consulte o diagnóstico local.',
    'CONFIG_MISMATCH':'Conta/start mode divergem de LocalService/MANUAL.',
    'STATE_MISSING':'ProgramData do Agent não está disponível.',
    'ACL_MISMATCH':'ACL/owner da pasta não confere com o contrato QA.',
    'ACL_UNAVAILABLE':'Não foi possível consultar a ACL; verifique localmente.',
    'COMMAND_FAILED':'Comando ou estado final falhou; consulte SCM/diagnóstico local.',
    'TRANSIENT_CONTROL_RESULT':'Código transitório; estado terminal confirmado.',
    'STATE_FILES_INVALID':'Identity/bootstrap/status não conferem após enrollment.',
    'IDENTITY_CHANGED':'Identidade mudou durante restart.',
    'AUTH_REJECTED':'O Agent não autenticou após o restart.',
    'AUTH_UNVERIFIED':'Autenticação não confirmada; verifique a conectividade local.',
    'QA_STEP_FAILED':'Etapa falhou; revisar localmente sem enviar segredos.'}

def utc_now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')

class Report:
    def __init__(self):
        self.value={'schema_version':1,'run_id':secrets.token_hex(8),
                    'generated_at_utc':utc_now(),'component':'Configurador TI Agent Service',
                    'app_version':AGENT_VERSION,'phase':'2B-R5',
                    'environment':{'platform':'Windows' if os.name=='nt' else 'non-Windows'},
                    'steps':[],'summary':{}}
    def add(self,ident,status,category,started,duration_ms,**evidence):
        category=category if category in MESSAGES else 'QA_STEP_FAILED'
        row={'id':ident if ident in NAMES else 'unknown','name':NAMES.get(ident,'QA step'),
             'status':status if status in STATUS else 'FAIL',
             'started_at_utc':started,'duration_ms':max(0,round(duration_ms)),
             'category':category,'message':MESSAGES[category]}
        for key in ('exit_code','raw_code'):
            val=evidence.get(key)
            if type(val) is int and -1<=val<=65535: row[key]=val
        for key in ('state_before','state_after'):
            val=evidence.get(key)
            if isinstance(val,str) and val in STATES:row[key]=val
        digest=evidence.get('sha256')
        if isinstance(digest,str) and re.fullmatch('[a-f0-9]{64}',digest):row['sha256']=digest
        self.value['steps'].append(row)
        return row
    def finish(self):
        count=Counter(s['status'] for s in self.value['steps'])
        final=('FAIL' if count['FAIL'] else 'NEEDS_HUMAN' if count['NEEDS_HUMAN'] else
               'WARN' if count['WARN'] or count['SKIP'] else 'PASS')
        self.value['summary']={k.lower():count[k] for k in ('PASS','FAIL','WARN','SKIP','NEEDS_HUMAN')}
        self.value['summary']['final_status']=final
        return self.value
    def save(self,directory):
        directory=Path(directory).expanduser().resolve()
        if os.name=='nt':
            state=service.state_root().resolve()
            if directory==state or state in directory.parents: raise ValueError('INVALID_REPORT_DESTINATION')
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        data=self.finish()
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        name=f'CONFIGURADOR_TI_AGENT_SERVICE_QA_{stamp}_{data["run_id"]}'
        json_path=directory/(name+'.json');txt_path=directory/(name+'.txt')
        with json_path.open('x',encoding='utf-8') as out:json.dump(data,out,indent=2,ensure_ascii=False)
        lines=[f'Configurador TI Agent Service QA / 2B-R5 / {data["summary"]["final_status"]}',
               f'run_id: {data["run_id"]}',f'generated_at_utc: {data["generated_at_utc"]}']
        for item in data['steps']:
            lines.append(f'{item["id"]}: {item["status"]} / {item["category"]} / {item["duration_ms"]} ms'
                         +(f' / raw={item["raw_code"]}' if 'raw_code' in item else '')
                         +(f' / {item["state_before"]}->{item["state_after"]}' if 'state_before' in item and 'state_after' in item else '')
                         +(f' / sha256={item["sha256"]}' if 'sha256' in item else ''))
        with txt_path.open('x',encoding='utf-8') as out:out.write('\n'.join(lines)+'\n')
        return json_path,txt_path

def _admin():
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())

def _invoke(exe,command,*,config=None,secret=False):
    args=[str(exe),command]
    if config is not None:args.extend(('--config',str(config)))
    if secret:
        # The EXE owns the hidden R3 prompt. Do not capture its output/input.
        result=subprocess.run(args,shell=False,timeout=90)
        return result.returncode,{}
    result=subprocess.run(args,shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=45)
    if len(result.stdout)>4096:return result.returncode,{}
    try: value=json.loads(result.stdout)
    except (ValueError,UnicodeError):value={}
    return result.returncode,value if isinstance(value,dict) else {}

_ACL_PS=r'''$ErrorActionPreference='Stop'
$a=Get-Acl -LiteralPath $env:CONFIGURADOR_TI_QA_ACL_PATH
$s=@{}
foreach($r in $a.Access){
 if($r.AccessControlType -ne 'Allow'){continue}
 try{$sid=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{continue}
 if(-not $s.ContainsKey($sid)){$s[$sid]=0}
 $s[$sid]=$s[$sid] -bor [int]$r.FileSystemRights
}
function hasRights($sid,$mask){return $s.ContainsKey($sid) -and (($s[$sid] -band $mask) -eq $mask)}
$owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
[pscustomobject]@{protected=$a.AreAccessRulesProtected;owner_admin=($owner -eq 'S-1-5-32-544');
 system=(hasRights 'S-1-5-18' 2032127);admins=(hasRights 'S-1-5-32-544' 2032127);
 localservice=(hasRights 'S-1-5-19' 197055);
 broad=($s.ContainsKey('S-1-1-0') -or $s.ContainsKey('S-1-5-32-545'))} | ConvertTo-Json -Compress'''

def _acl(root):
    ps=Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
    env=dict(os.environ,CONFIGURADOR_TI_QA_ACL_PATH=str(root))
    result=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-Command',_ACL_PS],env=env,
                          shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,timeout=20)
    if result.returncode or len(result.stdout)>4096:return None
    try: flags=json.loads(result.stdout)
    except (ValueError,UnicodeError):return None
    if not isinstance(flags,dict) or set(flags)!={'protected','owner_admin','system','admins','localservice','broad'}:return None
    if any(type(val) is not bool for val in flags.values()):return None
    return all(flags[k] for k in ('protected','owner_admin','system','admins','localservice')) and not flags['broad']

def default_report_dir():
    """Per-user documents, including when an elevated process has a different cwd."""
    profile=os.environ.get('USERPROFILE') if os.name=='nt' else None
    return (Path(profile) if profile else Path.home())/'Documents'/'ConfiguradorTI-QA-Reports'

def _public_status(path):
    """Only the Agent's public status. Never decrypt or inspect identity.bin."""
    if path.stat().st_size>4096: raise ValueError('INVALID_STATUS')
    data=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data,dict): raise ValueError('INVALID_STATUS')
    did=data.get('device_id')
    if not isinstance(did,str) or str(uuid.UUID(did))!=did: raise ValueError('INVALID_DEVICE_ID')
    if not isinstance(data.get('status'),str) or type(data.get('updated_at')) is not int:
        raise ValueError('INVALID_STATUS')
    # A future public-only status can include this; current Agent exposes the
    # device ID and proves key continuity via authenticated ONLINE heartbeat.
    fp=data.get('public_key_fingerprint')
    if fp is not None and (not isinstance(fp,str) or not re.fullmatch('[a-f0-9]{64}',fp)):
        raise ValueError('INVALID_PUBLIC_FINGERPRINT')
    return {'device_id':did,'public_key_fingerprint':fp,
            'status':data['status'],'updated_at':data['updated_at']}

def _same_public_identity(before,after):
    return (before['device_id']==after['device_id'] and
            before['public_key_fingerprint']==after['public_key_fingerprint'])

def _await_public_status(path,expected,*,not_before,timeout=20,clock=time.monotonic,sleep=time.sleep):
    deadline=clock()+timeout
    while True:
        try: observed=_public_status(path)
        except FileNotFoundError: observed=None
        if observed is not None:
            fresh=observed['updated_at']>=not_before
            if observed['status'] in ('ENROLLMENT_REQUIRED','AUTH_REQUIRED','WRONG_BINDING',
                                      'DEVICE_REVOKED','INVALID_SIGNATURE') and fresh:
                return 'FAIL',observed
            if observed['status']==expected and fresh:
                return 'PASS',observed
        if clock()>=deadline: return 'NEEDS_HUMAN',observed
        sleep(min(0.5,max(0,deadline-clock())))

def run_qa(exe,config,output_dir,*,native=None,query=None,invoke=None,admin=None,acl=None,prompt=None):
    """Run bounded local QA, always write sanitized reports, never delete state."""
    native=os.name=='nt' if native is None else native
    query=service.query_service if query is None else query
    invoke=_invoke if invoke is None else invoke
    admin=_admin if admin is None else admin
    acl=_acl if acl is None else acl
    prompt=input if prompt is None else prompt
    exe=Path(exe);config=Path(config) if config else None
    report=Report()
    def step(ident,fn):
        started=utc_now();begin=time.monotonic()
        try:status,category,evidence=fn()
        except Exception:
            # Error text may include paths, command output or private data.
            status,category,evidence='FAIL','QA_STEP_FAILED',{}
        report.add(ident,status,category,started,(time.monotonic()-begin)*1000,**evidence)
        return status
    def command(ident,cmd,target):
        def action():
            code,data=invoke(exe,cmd)
            state=query()['state']
            good=code==0 and data.get('status')=='PASS' and state==target
            transient=data.get('warning')=='TRANSIENT_CONTROL_RESULT' and good
            evidence={'exit_code':data.get('exit_code',code),'raw_code':data.get('raw_control_code'),
                      'state_before':data.get('state_before'),'state_after':state}
            return ('WARN' if transient else 'PASS') if good else 'FAIL', \
                   'TRANSIENT_CONTROL_RESULT' if transient else 'OK' if good else 'COMMAND_FAILED',evidence
        return step(ident,action)
    try:
        if step('platform',lambda:('PASS','OK',{}) if native else ('NEEDS_HUMAN','WINDOWS_REQUIRED',{}))!='PASS':return report
        if step('files',lambda:('PASS','OK',{}) if exe.is_file() and exe.name.lower()=='configuradortiagent.exe'
                else ('FAIL','INVALID_AGENT_EXE',{}))!='PASS':return report
        if step('checksum',lambda:('PASS','HASH_OK',{'sha256':hashlib.sha256(exe.read_bytes()).hexdigest()}))!='PASS':return report
        if step('smoke',lambda:(lambda code,data:('PASS','OK',{}) if code==0 and data.get('status')=='PASS'
                and data.get('headless') is True else ('FAIL','SMOKE_FAILED',{}))(*invoke(exe,'smoke')))!='PASS':return report
        state={}
        def initial():
            state.update(query(include_config=True))
            return ('PASS','SCM_FOUND',{'state_after':state['state']}) if state['state']!='ABSENT' else \
                   ('WARN','SCM_ABSENT',{'state_after':'ABSENT'})
        if step('scm_before',initial)=='FAIL':return report
        if step('admin',lambda:('PASS','OK',{}) if admin() else ('NEEDS_HUMAN','ADMIN_REQUIRED',{}))!='PASS':return report
        if state['state']=='ABSENT':
            def install():
                if config is None or not config.is_file() or not sys.stdin.isatty():
                    return 'NEEDS_HUMAN','INPUT_REQUIRED',{}
                payload=json.loads(config.read_text(encoding='utf-8'))
                if payload.get('qa') is not True:return 'FAIL','FILES_MISSING',{}
                try: prompt('Gere um novo código na Central. Pressione Enter para instalar pelo prompt secreto do Agent: ')
                except (EOFError,KeyboardInterrupt):return 'NEEDS_HUMAN','INPUT_REQUIRED',{}
                code,_=invoke(exe,'service-install',config=config,secret=True)
                return (('PASS','OK',{'exit_code':code}) if code==0 and query()['state']!='ABSENT' else
                        ('FAIL','INSTALL_FAILED',{'exit_code':code}))
            if step('install',install)!='PASS':return report
        def check_config():
            if state['state']=='ABSENT':
                state.clear();state.update(query(include_config=True))
            ok=state.get('account_is_localservice') is True and state.get('start_mode')=='MANUAL'
            return ('PASS','OK',{}) if ok else ('FAIL','CONFIG_MISMATCH',{})
        if step('scm_config',check_config)!='PASS':return report
        root=service.state_root()
        if step('state_dir',lambda:('PASS','OK',{}) if root.is_dir() else ('FAIL','STATE_MISSING',{}))!='PASS':return report
        def check_acl():
            result=acl(root)
            return ('PASS','OK',{}) if result is True else ('FAIL','ACL_MISMATCH',{}) if result is False else ('NEEDS_HUMAN','ACL_UNAVAILABLE',{})
        if step('acl',check_acl)!='PASS':return report
        def status_before():
            code,data=invoke(exe,'service-status')
            ok=code==0 and data.get('status')=='PASS' and data.get('state')==query()['state']
            return ('PASS','OK',{'exit_code':code,'state_after':data.get('state')}) if ok else ('FAIL','COMMAND_FAILED',{'exit_code':code})
        if step('status_before',status_before)!='PASS':return report
        start_at=int(time.time())
        if command('start','service-start','RUNNING') not in ('PASS','WARN'):return report
        identity=root/'identity.bin';bootstrap=root/'enrollment.bootstrap';status_file=root/'status.json'
        def state_files():
            ok=identity.is_file() and not bootstrap.exists() and status_file.is_file()
            return ('PASS','OK',{}) if ok else ('FAIL','STATE_FILES_INVALID',{})
        if step('state_files',state_files)!='PASS':return report
        original={}
        def binding_before():
            result,observed=_await_public_status(status_file,'ONLINE',not_before=start_at)
            if result=='PASS': original.update(observed);return 'PASS','OK',{}
            return result,'AUTH_REJECTED' if result=='FAIL' else 'AUTH_UNVERIFIED',{}
        if step('identity_before',binding_before)!='PASS':return report
        stop_at=int(time.time())
        if command('stop','service-stop','STOPPED') not in ('PASS','WARN'):return report
        stopped={}
        def binding_stopped():
            if not identity.is_file() or bootstrap.exists():return 'FAIL','IDENTITY_CHANGED',{}
            result,observed=_await_public_status(status_file,'STOPPED',not_before=stop_at)
            if result!='PASS':return result,'AUTH_REJECTED' if result=='FAIL' else 'AUTH_UNVERIFIED',{}
            if not _same_public_identity(original,observed):return 'FAIL','IDENTITY_CHANGED',{}
            stopped.update(observed)
            return 'PASS','OK',{}
        if step('identity_stopped',binding_stopped)!='PASS':return report
        restart_at=int(time.time())
        if command('restart','service-start','RUNNING') not in ('PASS','WARN'):return report
        def identity_persists():
            if not identity.is_file() or bootstrap.exists():return 'FAIL','IDENTITY_CHANGED',{}
            result,observed=_await_public_status(status_file,'ONLINE',not_before=restart_at)
            if result!='PASS':
                category='IDENTITY_CHANGED' if observed and observed['status']=='ENROLLMENT_REQUIRED' else \
                         'AUTH_REJECTED' if result=='FAIL' else 'AUTH_UNVERIFIED'
                return result,category,{}
            if not _same_public_identity(original,observed) or not _same_public_identity(stopped,observed):
                return 'FAIL','IDENTITY_CHANGED',{}
            return 'PASS','OK',{}
        step('identity',identity_persists)
        return report
    finally:
        report.save(output_dir)

def main(argv=None):
    parser=argparse.ArgumentParser(description='Configurador TI Agent Service QA local; no cleanup or auto-UAC')
    parser.add_argument('--agent-exe',required=True);parser.add_argument('--config')
    parser.add_argument('--output-dir',default=str(default_report_dir()))
    args=parser.parse_args(argv)
    report=run_qa(args.agent_exe,args.config,args.output_dir)
    summary=report.value['summary']
    print(json.dumps({'final_status':summary['final_status'],'run_id':report.value['run_id'],
                      'report_directory':str(Path(args.output_dir).expanduser().resolve())}))
    return 1 if summary['final_status']=='FAIL' else 2 if summary['final_status']=='NEEDS_HUMAN' else 0

if __name__=='__main__':raise SystemExit(main())
