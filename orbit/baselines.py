"""Common-substrate B1--B3 abstractions.
B1 verifies a signed profile. B2 adds a class-key Schnorr transcript; B3 adds
local profile version state. No baseline fabricates per-device status semantics.
"""
import secrets
from .crypto import enc,H,commit,respond,verify_pop,verify_sig

class Baseline:
    def __init__(self,mode,manufacturer_pub,class_pub):
        if mode not in ('B1','B2','B3'):raise ValueError('baseline')
        self.mode=mode;self.pub=manufacturer_pub;self.class_pub=class_pub;self.version=0
    def admit(self,file,claimed_url,class_secret,xid=1,claimed_id=0):
        if not verify_sig(self.pub,file.body(),file.signature) or claimed_url!=file.url:return False
        if self.mode=='B3' and file.version<self.version:return False
        if self.mode!='B1':
            r,R=commit();nonce=secrets.token_bytes(32)
            # Stronger claimed-ID binding is included, but no individual key is required.
            msg=enc('CLASS-POP-BASELINE-v2',R,self.class_pub,nonce,H(file.url.encode()),xid,claimed_id)
            z=respond(class_secret,r,msg)
            if not verify_pop(self.class_pub,R,z,msg):return False
        self.version=max(self.version,file.version)
        return True
