"""Versioned public identity/licensing contracts; no operational evidence."""
import json
import re
import uuid
from enum import Enum
from dataclasses import dataclass
from typing import Protocol
ISSUER='configurador-ti-control-plane'
AUDIENCE='configurador-ti-client'
CHANNELS=('INTERNAL','BETA','STABLE')
PLANS=('INTERNAL','QA','NFR','TRIAL','TECHNICIAN','BUSINESS','ENTERPRISE')
ROLES=('OWNER','TENANT_ADMIN','TECHNICIAN','VIEWER')
FEATURES=frozenset(('monitoring.basic','monitoring.advanced','endpoint_posture','assist.playbooks','guided_actions','transactional_actions','reports.basic','reports.advanced','fleet.management','central.agent','integrations.service_desk','branding.custom'))
EXISTING_FEATURES=FEATURES-{'fleet.management','central.agent','integrations.service_desk','branding.custom'}
SAFE_FEATURES=frozenset(('local.read','local.export','reports.existing','support','account'))
class State(str,Enum):
    ONLINE_OK='ONLINE_OK'
    OFFLINE_LEASE_VALID='OFFLINE_LEASE_VALID'
    OFFLINE_LEASE_EXPIRED='OFFLINE_LEASE_EXPIRED'
    AUTH_REQUIRED='AUTH_REQUIRED'
    LICENSE_SUSPENDED='LICENSE_SUSPENDED'
    DEVICE_REVOKED='DEVICE_REVOKED'
    TENANT_SUSPENDED='TENANT_SUSPENDED'
    SERVER_UNAVAILABLE='SERVER_UNAVAILABLE'
    CLOCK_SUSPECT='CLOCK_SUSPECT'
    INDETERMINATE='INDETERMINATE'
    OUTDATED_VERSION='OUTDATED_VERSION'
class Denied(RuntimeError):
    def __init__(self,code='AUTH_REQUIRED'):
        self.code=code if isinstance(code,str) and re.fullmatch('[A-Z_]{1,64}',code) else 'INDETERMINATE'
        super().__init__(self.code)
def new_id(): return str(uuid.uuid4())
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
def version_tuple(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d{1,5}(\.\d{1,5}){1,3}',value): raise Denied('INVALID_VERSION')
    v=tuple(map(int,value.split('.')))
    return v+(0,)*(4-len(v))
@dataclass(frozen=True)
class Principal:
    account_id:str
    role:str
    tenant_id:str|None
@dataclass(frozen=True)
class FeatureDefinition:
    id:str
    implemented:bool
FEATURE_DEFINITIONS=tuple(FeatureDefinition(f,f in EXISTING_FEATURES) for f in sorted(FEATURES))
class IdentityProvider(Protocol):
    def exchange(self,authorization_code:str)->dict: ...
class Repository(Protocol):
    def get(self,kind:str,identifier:str)->dict: ...
    def put(self,kind:str,row:dict)->None: ...
    def list(self,kind:str)->list: ...
    def transaction(self): ...
class ClientAdapter(Protocol):
    def call(self,operation:str,payload:dict,access_token:str|None=None)->dict: ...
