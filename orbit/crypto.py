"""Canonical encoding and P-256 Schnorr reference implementation.
Native EC arithmetic uses system OpenSSL libcrypto.
"""
from __future__ import annotations
import ctypes as C
import ctypes.util
import hashlib
import secrets
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def enc(*fields) -> bytes:
    """Tagged, injective encoding. Integers are unsigned 64-bit, byte lengths u32."""
    out = bytearray()
    for v in fields:
        if isinstance(v, bool): out += b't' + bytes([v])
        elif isinstance(v, int): out += b'i' + struct.pack('!Q', v)
        elif isinstance(v, bytes): out += b'b' + struct.pack('!I', len(v)) + v
        elif isinstance(v, str):
            b = v.encode('utf-8'); out += b's' + struct.pack('!I', len(b)) + b
        else: raise TypeError(f'Unsupported canonical field {type(v)}')
    return bytes(out)

_lib = C.CDLL(ctypes.util.find_library('crypto') or 'libcrypto.so.3')
_p = C.c_void_p
for name, restype, argtypes in [
    ('EC_GROUP_new_by_curve_name',_p,[C.c_int]), ('EC_GROUP_free',None,[_p]),
    ('EC_POINT_new',_p,[_p]), ('EC_POINT_free',None,[_p]),
    ('BN_CTX_new',_p,[]), ('BN_CTX_free',None,[_p]),
    ('BN_bin2bn',_p,[C.c_void_p,C.c_int,_p]), ('BN_clear_free',None,[_p]),
    ('EC_POINT_oct2point',C.c_int,[_p,_p,C.c_void_p,C.c_size_t,_p]),
    ('EC_POINT_point2oct',C.c_size_t,[_p,_p,C.c_int,C.c_void_p,C.c_size_t,_p]),
    ('EC_POINT_is_on_curve',C.c_int,[_p,_p,_p]),
    ('EC_POINT_is_at_infinity',C.c_int,[_p,_p]),
    ('EC_POINT_mul',C.c_int,[_p,_p,_p,_p,_p,_p]),
    ('EC_POINT_add',C.c_int,[_p,_p,_p,_p,_p]),
    ('EC_POINT_cmp',C.c_int,[_p,_p,_p,_p])]:
    f = getattr(_lib,name); f.restype=restype; f.argtypes=argtypes

def _point_op(scalar: int, point: bytes|None=None, add: bytes|None=None) -> bytes:
    if not 0 <= scalar < ORDER: raise ValueError('scalar out of range')
    group = _lib.EC_GROUP_new_by_curve_name(415) # OpenSSL NID_X9_62_prime256v1
    ctx = _lib.BN_CTX_new(); pts=[]; bn=None
    try:
        def newpoint():
            p=_lib.EC_POINT_new(group)
            if not p: raise RuntimeError('EC allocation')
            pts.append(p); return p
        def parse(b):
            if not isinstance(b,bytes) or len(b)!=33 or b[0] not in (2,3):
                raise ValueError('noncanonical compressed point')
            p=newpoint()
            if (_lib.EC_POINT_oct2point(group,p,b,len(b),ctx)!=1 or
                _lib.EC_POINT_is_on_curve(group,p,ctx)!=1 or
                _lib.EC_POINT_is_at_infinity(group,p)==1):
                raise ValueError('invalid point')
            return p
        r=newpoint(); bn=_lib.BN_bin2bn(scalar.to_bytes(32,'big'),32,None)
        q=parse(point) if point is not None else None
        if _lib.EC_POINT_mul(group,r,bn if q is None else None,q,bn if q else None,ctx)!=1:
            raise RuntimeError('EC multiplication')
        if add is not None:
            a=parse(add)
            if _lib.EC_POINT_add(group,r,r,a,ctx)!=1: raise RuntimeError('EC addition')
        out=C.create_string_buffer(33)
        n=_lib.EC_POINT_point2oct(group,r,2,out,33,ctx)
        if n!=33: raise ValueError('point at infinity')
        return out.raw
    finally:
        if bn: _lib.BN_clear_free(bn)
        for p in pts: _lib.EC_POINT_free(p)
        _lib.BN_CTX_free(ctx); _lib.EC_GROUP_free(group)

def scalar() -> int: return secrets.randbelow(ORDER-1)+1
def public(k:int) -> bytes: return _point_op(k)
def commit() -> tuple[int,bytes]:
    r=scalar(); return r,public(r)
def respond(k:int,r:int,message:bytes) -> int:
    return (r+int.from_bytes(H(message),'big')%ORDER*k)%ORDER

def verify_pop(P:bytes,R:bytes,z:int,message:bytes) -> bool:
    try:
        if not isinstance(z,int) or not 0 < z < ORDER: return False
        t=int.from_bytes(H(message),'big')%ORDER
        return secrets.compare_digest(public(z),_point_op(t,P,R))
    except (ValueError, TypeError, OverflowError): return False

def signing_key(): return ec.generate_private_key(ec.SECP256R1())
def signing_public(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
def sign(k, body:bytes) -> bytes: return k.sign(body,ec.ECDSA(hashes.SHA256()))
def verify_sig(pub:bytes, body:bytes, sig:bytes) -> bool:
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),pub).verify(sig,body,ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature,ValueError,TypeError): return False
