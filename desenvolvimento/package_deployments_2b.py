"""Repeatable separated source deployments + optional native Agent EXE.

Static local dependency closure fails closed on cross-deployment imports.
No production claim: reference Backend/Central bind QA loopback only.
"""
import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from release_metadata import build_metadata
from licensing.contracts import Denied
from desenvolvimento.scan_branding import require_clean
PROFILE_ENTRY={'Technician':['main_gui.py','main_gui.pyw'],'Agent':['agent_entry.py','agent/__main__.py','agent/windows_service.py'],'Backend':['control_plane/fleet_cli.py'],'Central':['central_web/__main__.py']}
FORBIDDEN={'Technician':('control_plane','agent','agent_entry','central_web','fleet_protocol'), 'Agent':('control_plane','central_web','PyQt6','main_gui','licensing.gui'),'Backend':('agent','central_web','PyQt6','main_gui'),'Central':('control_plane','agent','PyQt6','main_gui','sqlite3')}

def module_file(module):
    path=ROOT.joinpath(*module.split('.'))
    if path.with_suffix('.py').is_file(): return path.with_suffix('.py')
    if (path/'__init__.py').is_file(): return path/'__init__.py'
    return None

def imports(path):
    relative=path.relative_to(ROOT);parts=list(relative.with_suffix('').parts)
    package=parts[:-1]
    names=[]
    for n in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
        if isinstance(n,ast.Import): names.extend(a.name for a in n.names)
        elif isinstance(n,ast.ImportFrom):
            prefix=package[:len(package)-n.level+1] if n.level else []
            base='.'.join(prefix+((n.module or '').split('.') if n.module else []))
            if base: names.append(base)
            names.extend((base+'.' if base else '')+a.name for a in n.names if a.name!='*')
    return names

def prohibited(profile,name): return any(name==p or name.startswith(p+'.') for p in FORBIDDEN[profile])
def source_files(profile):
    pending=[ROOT/p for p in PROFILE_ENTRY[profile]];seen=set()
    while pending:
        path=pending.pop()
        if path in seen: continue
        seen.add(path)
        rel=path.relative_to(ROOT)
        for parent in rel.parents:
            init=ROOT/parent/'__init__.py'
            if parent!=Path('.') and init.is_file(): pending.append(init)
        for name in imports(path):
            if prohibited(profile,name): raise Denied('DEPLOYMENT_BOUNDARY_VIOLATION')
            target=module_file(name)
            if target: pending.append(target)
    if profile=='Technician':
        seen.update(ROOT/p for p in ('style.qss','licensing_public.json','distribuicao/LEIA-ME.txt'))
    return sorted(seen)
def inspect_files(profile,paths):
    for p in paths:
        relative=p.relative_to(ROOT);name='.'.join(relative.with_suffix('').parts)
        if prohibited(profile,name) or p.suffix in ('.db','.bin','.pem','.key','.log') or p.is_symlink(): raise Denied('DEPLOYMENT_BOUNDARY_VIOLATION')
        if (b'-----BEGIN ' + b'PRIVATE KEY-----') in p.read_bytes(): raise Denied('PRIVATE_MATERIAL_FOUND')
    return True

def inventory(profile,files):
    dependencies=[{'name':n,'version':importlib.metadata.version(n),'source':'https://pypi.org/project/'+n+'/'} for n in ('cryptography','cffi','pycparser')]
    if profile=='Technician':
        dependencies.extend({'name':n,'version':v,'source':'https://pypi.org/project/'+n+'/','version_basis':'validated Qt regression environment'} for n,v in [('PyQt6','6.11.0'),('PyQt6-Qt6','6.11.2'),('PyQt6-sip','13.12.0')])
    return {'format':'configurador-ti-source-inventory-v1','deployment':profile,'phase':'2B','python':platform.python_version(),'dependencies':dependencies, 'files':[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files], 'note':'Source/dependency inventory; not a complete SPDX attestation. Native build records actual build environment.'}
def zip_entry(z,name,data):
    info=zipfile.ZipInfo(name,(2026,9,25,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;z.writestr(info,data)
def package(profile,out):
    files=source_files(profile);inspect_files(profile,files);out=Path(out);out.mkdir(parents=True,exist_ok=True)
    for source in files:require_clean(source)
    target=out/f'Configurador_TI_2B_{profile}_SOURCE_QA.zip'
    meta=build_metadata(profile=profile.upper(),release_channel='INTERNAL');meta.update(deployment=profile,agent_protocol_version=1,api_version=1,minimum_agent_version='5.0.2',source_only=True)
    with zipfile.ZipFile(target,'w') as z:
        for p in files: zip_entry(z,p.relative_to(ROOT).as_posix(),p.read_bytes())
        zip_entry(z,'release-manifest.json',json.dumps(meta,indent=2).encode())
        zip_entry(z,'source-inventory.json',json.dumps(inventory(profile,files),indent=2).encode())
        zip_entry(z,'SHA256SUMS.txt',''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(ROOT).as_posix()+'\n' for p in files).encode())
        zip_entry(z,'requirements-runtime.txt',b'cryptography==46.0.0\ncffi==1.17.1\npycparser==2.23\n'+(b'PyQt6==6.11.0\nPyQt6-Qt6==6.11.2\nPyQt6-sip==13.12.0\n' if profile=='Technician' else b''))
        zip_entry(z,'DEPLOYMENT.txt',('Configurador TI 2B '+profile+' source deployment. QA_ONLY. See complete candidate LEIA-ME_2B.md. No private keys or runtime data included.').encode())
    with zipfile.ZipFile(target) as z:
        if z.testzip(): raise Denied('ZIP_CORRUPT')
    require_clean(target)
    return target

def agent_build(out):
    if os.name!='nt': raise Denied('WINDOWS_BUILD_REQUIRED')
    version=importlib.metadata.version('pyinstaller')
    if version!='6.22.1': raise Denied('PINNED_BUILD_TOOL_REQUIRED')
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    if (out/'ConfiguradorTIAgent.exe').exists(): raise Denied('EXISTING_ARTIFACT_PRESERVED')
    with tempfile.TemporaryDirectory(prefix='configurador-ti-agent-build-') as tmp:
        t=Path(tmp);files=source_files('Agent');inspect_files('Agent',files)
        stage=t/'source';stage.mkdir()
        for f in files:
            dest=stage/f.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,dest)
        metadata=build_metadata(profile='AGENT_QA',pyinstaller_version=version,release_channel='INTERNAL');metadata.update(deployment='Agent',agent_protocol_version=1,api_version=1,minimum_agent_version='5.0.2')
        mp=t/'configurador_ti_build_metadata.json';mp.write_text(json.dumps(metadata),encoding='utf-8')
        cmd=[sys.executable,'-m','PyInstaller','--clean','--noconfirm','--onedir','--console','--name','ConfiguradorTIAgent','--distpath',str(t/'dist'),'--workpath',str(t/'work'),'--specpath',str(t),'--add-data',str(mp)+os.pathsep+'.']
        for name in FORBIDDEN['Agent']: cmd.extend(['--exclude-module',name])
        cmd.append(str(stage/'agent_entry.py'))
        subprocess.run(cmd,cwd=stage,shell=False,check=True,timeout=600)
        exe=t/'dist'/'ConfiguradorTIAgent'/'ConfiguradorTIAgent.exe'
        from PyInstaller.archive.readers import CArchiveReader
        archive=CArchiveReader(str(exe));modules=set()
        for name in archive.toc:
            if name.endswith('.pyz'): modules.update(archive.open_embedded_archive(name).toc)
        if any(prohibited('Agent',n) for n in modules) or not {'agent.runtime','agent.engine','agent.windows_service','assist'}<=modules: raise Denied('DEPLOYMENT_BOUNDARY_VIOLATION')
        subprocess.run([str(exe),'smoke'],shell=False,check=True,timeout=30)
        shutil.copytree(exe.parent,out,dirs_exist_ok=True)
    artifacts=[p for p in out.rglob('*') if p.is_file()]
    metadata['artifact_sha256']=hashlib.sha256((out/'ConfiguradorTIAgent.exe').read_bytes()).hexdigest();metadata['artifact_name']='ConfiguradorTIAgent.exe'
    (out/'release-manifest.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    (out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(out).as_posix()+'\n' for p in sorted(artifacts)),encoding='utf-8')
    (out/'source-inventory.json').write_text(json.dumps(inventory('Agent',files),indent=2),encoding='utf-8')
    require_clean(out)
    return out/'ConfiguradorTIAgent.exe'
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--agent-exe',action='store_true');a=p.parse_args()
    if a.agent_exe: print(agent_build(a.output))
    else:
        for profile in PROFILE_ENTRY: print(package(profile,a.output))
