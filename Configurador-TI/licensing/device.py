"""Per-device proof key: not an entitlement signing authority."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
from .verification import b64,unb64
from .contracts import canonical,Denied
class DeviceIdentity:
    def __init__(self,private=None): self.key=Ed25519PrivateKey.from_private_bytes(unb64(private)) if private else Ed25519PrivateKey.generate()
    def private(self): return b64(self.key.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption()))
    def public(self): return b64(self.key.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw))
    def prove(self,challenge):
        if set(challenge)!={'id','nonce','purpose','session_id','public_key','expires'} or len(canonical(challenge))>2048: raise Denied('INVALID_CHALLENGE')
        return b64(self.key.sign(canonical(challenge)))
