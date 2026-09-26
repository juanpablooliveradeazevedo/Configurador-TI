"""Explicit source DEV policy. Frozen clients never bypass licensing."""
import json,sys
from pathlib import Path
from .contracts import Denied,FEATURES,SAFE_FEATURES
class RuntimeGate:
    def __init__(self,root,assets,*,frozen=None):
        self.root,self.assets=Path(root),Path(assets);self.frozen=getattr(sys,'frozen',False) if frozen is None else frozen
        self.client=None;self.error=None
        try:
            self.config=json.loads((self.assets/'licensing_public.json').read_text(encoding='utf-8'))
            if not isinstance(self.config,dict): raise ValueError()
        except (OSError,ValueError): self.config={}
        self.dev=not self.frozen and self.config.get('source_mode')=='DEV_UNMANAGED' and not self.config.get('endpoint')
    def initialize(self):
        if self.dev: return self.snapshot()
        try:
            from .transport import HttpAdapter
            from .secure_store import SecureStore
            from .client import LicensingClient
            from release_metadata import RUNTIME_BUILD_METADATA,PRODUCT_VERSION
            mode=self.config.get('mode','PRODUCTION');profile=RUNTIME_BUILD_METADATA.get('profile');qa=mode=='QA' and (not self.frozen or profile in ('DEV','QA'))
            if mode=='QA' and not qa: raise Denied('QA_NOT_ALLOWED_IN_PRODUCTION')
            if not self.config.get('endpoint'): raise Denied('AUTH_REQUIRED')
            self.client=LicensingClient(HttpAdapter(self.config['endpoint'],qa=qa),SecureStore(self.root/'dados'/'licenciamento'/'state.bin',qa=qa),self.config.get('public_keys',{}),version=PRODUCT_VERSION,channel=self.config.get('channel','INTERNAL'))
        except (Denied,OSError,ValueError,ImportError) as e: self.error=getattr(e,'code','INDETERMINATE')
        return self.snapshot()
    def is_allowed(self,feature):
        if feature in SAFE_FEATURES: return True
        return feature in FEATURES if self.dev else bool(self.client and self.client.is_allowed(feature))
    def require(self,feature):
        if not self.is_allowed(feature): raise Denied('FEATURE_DENIED')
    def explain(self,feature):
        if self.dev: return 'DEV explícito — somente fonte, sem habilitação comercial'
        return self.client.explain(feature) if self.client else 'Conecte a conta em Licença & Conta.'
    def snapshot(self):
        if self.dev: return {'state':'DEV_UNMANAGED','online':False,'degraded':False,'features':sorted(FEATURES)}
        return self.client.snapshot() if self.client else {'state':self.error or 'AUTH_REQUIRED','online':False,'degraded':True,'features':[]}
    def login(self,code):
        if not self.client: self.initialize()
        return self.client.login(code) if self.client else self.snapshot()
    def reenroll(self,code):
        if not self.client: self.initialize()
        return self.client.reenroll(code) if self.client else self.snapshot()
    def renew(self):
        if not self.client: self.initialize()
        return self.client.renew() if self.client else self.snapshot()
    def logout(self): return self.client.logout() if self.client else self.snapshot()
    def current_entitlement(self): return self.client.current_entitlement() if self.client else None
    def licensing_state(self): return self.snapshot()['state']
_runtime=None
def get_runtime():
    global _runtime
    if _runtime is None:
        from app_paths import runtime_root,asset_root
        _runtime=RuntimeGate(runtime_root(),asset_root())
    return _runtime
# Scoped gate for headless engine calls; never changes the desktop global gate.
from contextvars import ContextVar
from contextlib import contextmanager
_execution_gate=ContextVar('configurador_ti_execution_gate',default=None)
@contextmanager
def execution_gate(gate):
    token=_execution_gate.set(gate)
    try: yield
    finally: _execution_gate.reset(token)
def require_feature(feature):
    gate=_execution_gate.get()
    (gate if gate is not None else get_runtime()).require(feature)
