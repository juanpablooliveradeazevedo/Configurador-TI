"""LOCAL QA harness. Credentials come from hidden input, never argv."""
import argparse,getpass,json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
from licensing.secure_store import SecureStore
from licensing.verification import b64,unb64
from licensing.contracts import Denied
from .repository import SqliteRepository
from .signing import EntitlementSigner
from .service import ControlPlane

def main():
    parser=argparse.ArgumentParser(description='Configurador TI Control Plane LOCAL QA ONLY')
    parser.add_argument('command',choices=('init','serve','admin'));parser.add_argument('--state-dir',required=True);parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--operation',default='list');parser.add_argument('--data',default='{}',help='Public JSON fields only');parser.add_argument('--data-file',help='Public JSON file; never credentials')
    args=parser.parse_args();root=Path(args.state_dir).resolve();project=Path(__file__).resolve().parents[1]
    if root==project or project in root.parents: parser.error('Backend state must be outside source tree.')
    store=SecureStore(root/'backend-key.bin',qa=True)
    if args.command=='init':
        root.mkdir(parents=True,exist_ok=True,mode=0o700)
        if store.path.exists() or (root/'control-plane.db').exists(): parser.error('Existing state preserved. Use serve/admin.')
        key=Ed25519PrivateKey.generate();store.write({'key':b64(key.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption()))})
    else:
        if not store.path.exists(): parser.error('Run init first.')
        key=Ed25519PrivateKey.from_private_bytes(unb64(store.read()['key']))
    plane=ControlPlane(SqliteRepository(root/'control-plane.db'),EntitlementSigner(key,'qa-v1'))
    if args.command=='init':
        SecureStore(root/'owner-credential.bin',qa=True).write({'owner_credential':plane.bootstrap_owner()})
        config=dict(config_version=1,source_mode='MANAGED',mode='QA',channel='INTERNAL',endpoint=f'http://127.0.0.1:{args.port}',public_keys=plane.signer.public_keys())
        (root/'licensing_public.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
        print('QA initialized. Public config and protected owner credential are in backend directory.')
    elif args.command=='serve':
        from .http_service import QaServer
        print('LOCAL QA ONLY: http://127.0.0.1:'+str(args.port))
        with QaServer(('127.0.0.1',args.port),plane) as server: server.serve_forever()
    else:
        credential=getpass.getpass('Admin credential (Enter: protected local owner store): ') or SecureStore(root/'owner-credential.bin',qa=True).read()['owner_credential']
        data=json.loads(Path(args.data_file).read_text(encoding='utf-8') if args.data_file else args.data)
        print(json.dumps(plane.admin(credential,args.operation,data),indent=2,ensure_ascii=False))
if __name__=='__main__':
    try: main()
    except Denied as e: raise SystemExit(e.code)
