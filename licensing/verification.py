"""Public Ed25519 verification; private entitlement keys are backend-only."""
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .contracts import canonical,Denied,ISSUER,AUDIENCE,FEATURES,CHANNELS,version_tuple

def b64(data): return base64.b64encode(data).decode('ascii')
def unb64(value): return base64.b64decode(value,validate=True)
def thumbprint(public): return hashlib.sha256(unb64(public)).hexdigest()
class EntitlementVerifier:
    def __init__(self,public_keys): self.keys=dict(public_keys)
    def verify(self,envelope,now,*,device_id,public_key,user_id,tenant_id,revoked=()):
        try:
            if set(envelope)!={'payload','signature'}: raise ValueError()
            p=envelope['payload']
            if len(canonical(p))>32768: raise ValueError()
            if p['key_id'] not in self.keys: raise Denied('UNKNOWN_KEY')
            Ed25519PublicKey.from_public_bytes(unb64(self.keys[p['key_id']])).verify(unb64(envelope['signature']),canonical(p))
            if p['issuer']!=ISSUER or p['audience']!=AUDIENCE: raise Denied('INVALID_ISSUER_AUDIENCE')
            if p['entitlement_version']!=1 or p['lease']['version']!=1: raise ValueError()
            if any(type(p[k]) is not int for k in ('issued_at','not_before','expires_at','offline_until')): raise ValueError()
            if not p['issued_at']<=p['not_before']<=p['offline_until']<=p['expires_at']: raise ValueError()
            if now<p['not_before']: raise Denied('NOT_YET_VALID')
            if now>=p['expires_at']: raise Denied('OFFLINE_LEASE_EXPIRED')
            if (p['device_id'],p['device_key'],p['user_id'],p['tenant_id'])!=(device_id,thumbprint(public_key),user_id,tenant_id): raise Denied('DEVICE_BINDING_MISMATCH')
            if any(p[k] in revoked for k in ('jti','license_id','device_id')): raise Denied('LICENSE_SUSPENDED')
            if not isinstance(p['features'],list) or not set(p['features'])<=FEATURES: raise ValueError()
            if p['channel'] not in CHANNELS: raise ValueError()
            for k in ('jti','entitlement_id','license_id','plan_id','tenant_id','user_id','session_id'):
                if not isinstance(p[k],str) or not p[k]: raise ValueError()
            if p['jti']!=p['entitlement_id'] or p['lease']['offline_until']!=p['offline_until']: raise ValueError()
            version_tuple(p['minimum_supported_version'])
            return dict(p)
        except Denied: raise
        except (KeyError,ValueError,TypeError,InvalidSignature): raise Denied('INVALID_ENTITLEMENT') from None
