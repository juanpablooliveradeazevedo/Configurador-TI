"""QA bootstrap only. Normal administration happens in Central Web."""
import argparse
import getpass
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
from licensing.secure_store import SecureStore
from licensing.verification import b64,unb64
from licensing.contracts import Denied
from .repository import SqliteRepository
from .signing import EntitlementSigner
from .service import ControlPlane
from .fleet import FleetService

def key_store(root,name): return SecureStore(Path(root)/name,qa=True)
def load(root):
    root=Path(root)
    key=Ed25519PrivateKey.from_private_bytes(unb64(key_store(root,'backend-key.bin').read()['key']))
    cmd=Ed25519PrivateKey.from_private_bytes(unb64(key_store(root,'command-key.bin').read()['key']))
    p=ControlPlane(SqliteRepository(root/'control-plane.db'),EntitlementSigner(key,'qa-v1'))
    return FleetService(p,EntitlementSigner(cmd,'fleet-command-qa-v1'))
def initialize(root,username,password,port=8765):
    key_store(root,'backend-key.bin')._safe()
    root=Path(root).resolve();project=Path(__file__).resolve().parents[1]
    if root==project or project in root.parents: raise Denied('INVALID_STORE_PATH')
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Validate before creating persistent authority. Existing 2A keys are reused.
    FleetService._password(password,'00'*16)
    from fleet_protocol.contracts import label
    label(username)
    backend=key_store(root,'backend-key.bin')
    if not backend.path.exists():
        if (root/'control-plane.db').exists(): raise Denied('AUTHORITY_KEY_MISSING')
        key=Ed25519PrivateKey.generate();backend.write({'key':b64(key.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption()))})
    command=key_store(root,'command-key.bin')
    if not command.path.exists():
        key=Ed25519PrivateKey.generate();command.write({'key':b64(key.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption()))})
    f=load(root);owner=key_store(root,'owner-credential.bin')
    if not f.repo.list('admin'): owner.write({'owner_credential':f.p.bootstrap_owner()})
    f.bootstrap_web_owner(owner.read()['owner_credential'],username,password)
    config={'endpoint':f'http://127.0.0.1:{port}','qa':True,'command_keys':f.signer.public_keys(),'entitlement_keys':f.p.signer.public_keys(),'sync_minimal':True}
    (root/'agent-public.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
    (root/'licensing_public.json').write_text(json.dumps(dict(config_version=1,source_mode='MANAGED',mode='QA',channel='INTERNAL',endpoint=config['endpoint'],public_keys=f.p.signer.public_keys()),indent=2),encoding='utf-8')
    return f

def main():
    parser=argparse.ArgumentParser(description='Configurador TI Backend LOCAL QA ONLY')
    parser.add_argument('command',choices=('init','serve'));parser.add_argument('--state-dir',required=True);parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    if args.command=='init':
        initialize(args.state_dir,input('Login owner QA: '),getpass.getpass('Senha QA (mínimo 12 caracteres): '),args.port)
        print('QA inicializado; copie somente agent-public.json para o Agent.')
    else:
        from .fleet_http import QaServer
        with QaServer(('127.0.0.1',args.port),load(args.state_dir)) as server: server.serve_forever()
if __name__=='__main__':
    try: main()
    except (Denied,KeyError,OSError) as e: raise SystemExit(getattr(e,'code','BACKEND_STATE_UNAVAILABLE')) from None
