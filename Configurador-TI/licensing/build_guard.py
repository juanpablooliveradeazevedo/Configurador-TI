"""Public release boundary guards, with native archive inspection after build."""
import ast,json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .contracts import Denied,CHANNELS
from .verification import unb64

def validate_public_config(value,profile):
    allowed={'config_version','source_mode','mode','endpoint','public_keys','channel'}
    if not isinstance(value,dict) or not set(value)<=allowed or value.get('config_version')!=1: raise Denied('INVALID_PUBLIC_CONFIG')
    if value.get('mode') not in ('QA','PRODUCTION') or value.get('channel') not in CHANNELS: raise Denied('INVALID_PUBLIC_CONFIG')
    if profile in ('PRODUCTION','PORTABLE') and value['mode']!='PRODUCTION': raise Denied('QA_NOT_ALLOWED_IN_PRODUCTION')
    keys=value.get('public_keys',{})
    if not isinstance(keys,dict): raise Denied('INVALID_PUBLIC_CONFIG')
    for kid,key in keys.items():
        if not isinstance(kid,str) or not 1<=len(kid)<=80: raise Denied('INVALID_PUBLIC_CONFIG')
        Ed25519PublicKey.from_public_bytes(unb64(key))
    if value.get('endpoint'):
        from .transport import HttpAdapter
        HttpAdapter(value['endpoint'],qa=value['mode']=='QA')
        if not keys: raise Denied('PUBLIC_KEYS_REQUIRED')
    return value

def inspect_client_tree(root):
    for p in (Path(root)/'licensing').rglob('*.py'):
        source=p.read_text(encoding='utf-8');tree=ast.parse(source)
        for node in ast.walk(tree):
            names=[n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
            if any(n.startswith('control_plane') for n in names): raise Denied('BACKEND_MATERIAL_IN_CLIENT')
        if ('-----BEGIN '+'PRIVATE KEY-----') in source: raise Denied('BACKEND_MATERIAL_IN_CLIENT')
    return {'client_boundary':'verified','signing_private_material':'absent'}

def inspect_executable(executable,profile,expected_config):
    from PyInstaller.archive.readers import CArchiveReader
    archive=CArchiveReader(str(executable));names=set(archive.toc)
    forbidden=('agent','central_web','fleet_protocol','control_plane','backend-key','owner-credential','state.bin','control-plane.db')
    if any(any(part in name.casefold() for part in forbidden) for name in names): raise Denied('BACKEND_MATERIAL_IN_CLIENT')
    pyzs=[n for n in names if n.lower().endswith('.pyz')]
    if not pyzs: raise Denied('PYZ_MISSING')
    modules=set()
    for n in pyzs: modules.update(archive.open_embedded_archive(n).toc)
    if any(n==p or n.startswith(p+'.') for n in modules for p in ('control_plane','agent','central_web','fleet_protocol')): raise Denied('BACKEND_MATERIAL_IN_CLIENT')
    if not {'licensing.runtime','licensing.client','licensing.verification','licensing.device','licensing.gui'}<=modules: raise Denied('CLIENT_MODULE_MISSING')
    candidates=[n for n in names if n.replace('\\','/').split('/')[-1]=='licensing_public.json']
    if len(candidates)==1: config=json.loads(archive.extract(candidates[0]))
    elif profile=='DEV':
        paths=[Path(executable).parent/'_internal'/'licensing_public.json',Path(executable).parent/'licensing_public.json']
        p=next((p for p in paths if p.is_file()),None)
        if p is None: raise Denied('PUBLIC_CONFIG_MISSING')
        config=json.loads(p.read_text(encoding='utf-8'))
    else: raise Denied('PUBLIC_CONFIG_MISSING')
    validate_public_config(config,profile)
    if config!=expected_config: raise Denied('PUBLIC_CONFIG_MISMATCH')
    return {'backend_excluded':True,'public_config_verified':True}
