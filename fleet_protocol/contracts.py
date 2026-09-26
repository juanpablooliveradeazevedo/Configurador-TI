"""Fleet v1. Closed schemas; technical identifiers never become executable text."""
import hashlib
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from licensing.contracts import Denied, canonical, version_tuple
from licensing.verification import unb64
API_VERSION = 1
PROTOCOL_VERSION = 1
AGENT_VERSION = '5.0.2'
MAX_PAYLOAD = 65536
ONLINE_SECONDS = 90
COMMAND_TTL = 300
LEASE_SECONDS = 30
EXECUTION_SECONDS = 120
TERMINAL = {'SUCCEEDED', 'FAILED', 'CANCELLED', 'EXPIRED'}
CATALOG = {'SET_MONITORING_INTERVAL': {
    'playbook_id': 'MONITORING_SETTINGS_REVIEW', 'resource': 'LOCAL:MONITORING:INTERVAL',
    'privilege': 'STANDARD_USER', 'rollback': True,
    'features': ['central.agent', 'fleet.management', 'assist.playbooks', 'guided_actions', 'transactional_actions']}}

def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise Denied('INVALID_SCHEMA')
    try:
        if len(canonical(value)) > MAX_PAYLOAD: raise Denied('PAYLOAD_TOO_LARGE')
    except (ValueError, TypeError, RecursionError): raise Denied('INVALID_SCHEMA') from None
    return value

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', value): raise Denied('INVALID_IDENTIFIER')
    return value

def label(value, limit=120):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= limit or any(ord(c) < 32 for c in value): raise Denied('INVALID_LABEL')
    return value.strip()

def integer(value, low, high):
    if type(value) is not int or not low <= value <= high: raise Denied('INVALID_VALUE')
    return value

def action(aid, parameters):
    if not isinstance(aid,str) or aid not in CATALOG: raise Denied('ACTION_NOT_ALLOWED')
    closed(parameters, 'interval_seconds')
    if type(parameters['interval_seconds']) is not int or parameters['interval_seconds'] not in (30,60,120,300): raise Denied('INVALID_PARAMETERS')
    return CATALOG[aid]

def negotiation(protocol, product, capabilities):
    if type(protocol) is not int or protocol != PROTOCOL_VERSION: raise Denied('PROTOCOL_UNSUPPORTED')
    if version_tuple(product) < version_tuple(AGENT_VERSION): raise Denied('AGENT_OUTDATED')
    if not isinstance(capabilities,list) or not capabilities or any(not isinstance(c,str) or c not in CATALOG for c in capabilities) or len(set(capabilities)) != len(capabilities): raise Denied('CAPABILITY_UNSUPPORTED')

def fingerprint(value): return hashlib.sha256(canonical(value)).hexdigest()

def verify(envelope, keys, purpose):
    closed(envelope, 'payload signature')
    p = envelope['payload']
    if not isinstance(p,dict) or p.get('purpose') != purpose or p.get('key_id') not in keys: raise Denied('SIGNATURE_INVALID')
    try: Ed25519PublicKey.from_public_bytes(unb64(keys[p['key_id']])).verify(unb64(envelope['signature']), canonical(p))
    except Exception: raise Denied('SIGNATURE_INVALID') from None
    return p

def summary(value):
    closed(value, 'inventory posture monitoring')
    i = closed(value['inventory'], 'os architecture')
    if i['os'] not in ('Windows','Linux','Darwin','Other') or i['architecture'] not in ('x64','arm64','Other'): raise Denied('INVALID_SUMMARY')
    p = closed(value['posture'], 'assessment checks')
    if p['assessment'] not in ('NOT_COLLECTED','OK','ATTENTION','INDETERMINATE'): raise Denied('INVALID_SUMMARY')
    integer(p['checks'],0,6)
    m = closed(value['monitoring'], 'interval_seconds retention_days state')
    action('SET_MONITORING_INTERVAL', {'interval_seconds': m['interval_seconds']})
    if type(m['retention_days']) is not int or m['retention_days'] not in (7,14,30,60,90) or m['state'] not in ('STOPPED','RUNNING','PAUSED','ERROR'): raise Denied('INVALID_SUMMARY')
    return value

COMMAND_FIELDS = 'purpose key_id protocol_version agent_version capabilities tenant_id device_id user_id actor command_id correlation_id issued_at expires_at nonce idempotency_key action_id playbook_id parameters resource claim_id lease_until entitlement'
def command(p, binding, now):
    closed(p, COMMAND_FIELDS)
    negotiation(p['protocol_version'],p['agent_version'],p['capabilities'])
    for k in ('tenant_id','device_id','user_id','actor','command_id','correlation_id','nonce','idempotency_key','claim_id'): identifier(p[k])
    for k in ('tenant_id','device_id','user_id','protocol_version','agent_version','capabilities'):
        if p[k] != binding[k]: raise Denied('WRONG_BINDING')
    spec = action(p['action_id'],p['parameters'])
    if p['action_id'] not in binding['capabilities'] or p['playbook_id'] != spec['playbook_id'] or p['resource'] != spec['resource']: raise Denied('ACTION_NOT_ALLOWED')
    for k in ('issued_at','expires_at','lease_until'): integer(p[k],0,2**53)
    if not p['issued_at'] <= now < min(p['expires_at'],p['lease_until']) or p['expires_at']-p['issued_at'] > COMMAND_TTL: raise Denied('COMMAND_EXPIRED')
    return spec

PROOF_FIELDS = 'command_id correlation_id tenant_id device_id actor action_id playbook_id action_run_id before dry_run preconditions execution validator after rollback_available result started_at completed_at'
def proof(p):
    closed(p, PROOF_FIELDS)
    for k in ('command_id','correlation_id','tenant_id','device_id','actor','action_id','playbook_id'): identifier(p[k])
    if p['action_run_id'] is not None: identifier(p['action_run_id'])
    if p['action_id'] not in CATALOG or p['playbook_id'] != CATALOG[p['action_id']]['playbook_id']: raise Denied('INVALID_PROOF')
    for k in ('before','after'):
        if p[k] is not None: action('SET_MONITORING_INTERVAL',{'interval_seconds':p[k]})
    for k in ('dry_run','preconditions','validator','rollback_available'):
        if type(p[k]) is not bool: raise Denied('INVALID_PROOF')
    if p['execution'] not in ('NOT_STARTED','EXECUTED','RECOVERY_REQUIRED') or p['result'] not in ('SUCCESS','FAILURE','INDETERMINATE','CANCELLED','ROLLED_BACK'): raise Denied('INVALID_PROOF')
    integer(p['started_at'],0,2**53); integer(p['completed_at'],p['started_at'],2**53)
    if p['result']=='SUCCESS' and (not p['validator'] or p['execution']!='EXECUTED' or not p['dry_run'] or not p['preconditions']): raise Denied('INVALID_PROOF')
    return p
