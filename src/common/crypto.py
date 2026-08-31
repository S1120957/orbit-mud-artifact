"""Cryptographic primitives for ORBIT-MUD.

Curve arithmetic and ECDSA come from the `ecdsa` library (secp256r1 /
NIST256p); we do not implement elliptic-curve arithmetic ourselves.
Schnorr proof-of-possession is the textbook interactive scheme over the
library's point arithmetic, with the challenge scalar derived from the
canonical transcript encoding (Fiat-Shamir is NOT used: the Controller
nonce inside the transcript provides interactivity, matching FIDEM's
interactive design).
"""
from __future__ import annotations
import os
from dataclasses import dataclass

from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.ellipticcurve import Point, INFINITY
from ecdsa.util import sigencode_der, sigdecode_der

from .encoding import H, Henc

CURVE = NIST256p
G = CURVE.generator
ORDER = CURVE.order
POINT_LEN = 33  # compressed SEC1


def point_to_bytes(p: Point) -> bytes:
    return VerifyingKey.from_public_point(p, curve=CURVE).to_string("compressed")


def bytes_to_point(b: bytes) -> Point:
    return VerifyingKey.from_string(b, curve=CURVE).pubkey.point


def rand_scalar() -> int:
    while True:
        k = int.from_bytes(os.urandom(32), "big") % ORDER
        if k != 0:
            return k


# ---------------- Schnorr proof of possession ----------------

@dataclass
class SchnorrCommitment:
    r: int          # secret nonce (device-side only)
    R: bytes        # compressed commitment point


def schnorr_commit() -> SchnorrCommitment:
    r = rand_scalar()
    return SchnorrCommitment(r=r, R=point_to_bytes(r * G))


def _challenge_scalar(transcript: bytes) -> int:
    # hash-to-scalar; 2^256 mod n bias is negligible for secp256r1
    return int.from_bytes(H(b"ORBIT-SCHNORR-CH" + transcript), "big") % ORDER


def schnorr_respond(k: int, com: SchnorrCommitment, transcript: bytes) -> bytes:
    c = _challenge_scalar(transcript)
    s = (com.r + c * k) % ORDER
    return s.to_bytes(32, "big")


def schnorr_verify(P: bytes, R: bytes, s_bytes: bytes, transcript: bytes) -> bool:
    try:
        s = int.from_bytes(s_bytes, "big")
        if not (0 < s < ORDER):
            return False
        c = _challenge_scalar(transcript)
        lhs = s * G
        rhs = bytes_to_point(R) + c * bytes_to_point(P)
        if rhs == INFINITY:
            return False
        return lhs == rhs
    except Exception:
        return False


# ---------------- ECDSA signer (manufacturer / witnesses) ----------------

class Signer:
    """ECDSA-P256/SHA-256 signer with a stable identifier."""

    def __init__(self, ident: str):
        self.ident = ident
        self._sk = SigningKey.generate(curve=CURVE)
        self.public_bytes = self._sk.get_verifying_key().to_string("compressed")

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign_deterministic(msg, hashfunc=__import__("hashlib").sha256,
                                           sigencode=sigencode_der)


def verify_sig(public_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(public_bytes, curve=CURVE)
        return vk.verify(sig, msg, hashfunc=__import__("hashlib").sha256,
                         sigdecode=sigdecode_der)
    except Exception:
        return False
