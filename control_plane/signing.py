"""Backend signing boundary. Keys are injected, never static source material."""
from licensing.contracts import canonical
from licensing.verification import b64
from cryptography.hazmat.primitives import serialization as s
class EntitlementSigner:
    def __init__(self,key,kid): self.key,self.kid=key,kid
    def sign(self,payload): return {'payload':payload,'signature':b64(self.key.sign(canonical(payload)))}
    def public_keys(self): return {self.kid:b64(self.key.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw))}
