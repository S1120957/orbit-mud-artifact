"""Baselines.

B1: RFC 8520 DHCP MUD selection without binding: the Controller fetches the
    file named by the URL, verifies the manufacturer signature, installs.
B2: FIDEM-spec baseline reproduction (from the FIDEM paper's protocol
    description; the original source code was unavailable): shared class
    secret K_c, X_c published in the signed MUD file, interactive Schnorr
    with H = SHA256(R || X_c || C || URL).
B3: B2 plus a persistent local cache of (manufacturer, class) ->
    (last_update, profile_digest); files older than the cached last_update
    are rejected.
"""
from __future__ import annotations
import hashlib
import os

from ..common.crypto import rand_scalar, point_to_bytes, bytes_to_point, \
    verify_sig, G, ORDER
from ecdsa.ellipticcurve import INFINITY


class FidemClass:
    """Class credential material for B2/B3."""
    def __init__(self):
        self.Kc = rand_scalar()
        self.Xc = point_to_bytes(self.Kc * G)


class FidemDevice:
    def __init__(self, cls: FidemClass, url: str):
        self.Kc = cls.Kc          # shared class secret
        self.url = url

    def commit(self):
        self.r = rand_scalar()
        return point_to_bytes(self.r * G)

    def respond(self, R: bytes, Xc: bytes, C: bytes) -> bytes:
        h = int.from_bytes(hashlib.sha256(R + Xc + C +
                                          self.url.encode()).digest(),
                           "big") % ORDER
        return ((self.r + h * self.Kc) % ORDER).to_bytes(32, "big")


def b1_verify(controller_trust, mud_file, url) -> bool:
    pub = controller_trust.get(mud_file.manufacturer_id)
    return (pub is not None and mud_file.mud_url == url and
            verify_sig(pub, mud_file.canonical(), mud_file.signature))


def b2_verify(controller_trust, mud_file, url, Xc: bytes, R: bytes,
              respond_fn) -> bool:
    if not b1_verify(controller_trust, mud_file, url):
        return False
    C = os.urandom(32)
    Z = respond_fn(R, Xc, C)
    h = int.from_bytes(hashlib.sha256(R + Xc + C + url.encode()).digest(),
                       "big") % ORDER
    z = int.from_bytes(Z, "big")
    if not (0 < z < ORDER):
        return False
    lhs = z * G
    rhs = bytes_to_point(R) + h * bytes_to_point(Xc)
    return rhs != INFINITY and lhs == rhs


class B3Cache:
    def __init__(self):
        self.cache = {}

    def check_and_update(self, mud_file) -> bool:
        key = (mud_file.manufacturer_id, mud_file.class_id)
        prev = self.cache.get(key)
        if prev is not None and mud_file.last_update < prev:
            return False
        self.cache[key] = max(prev or 0, mud_file.last_update)
        return True


# --- B2': the variant found in the released FIDEM implementation -------------
# FIDEM's Fig. 3 specifies h = [R || X_c || C || URL].  The authors' released
# controller (cu_ec_compute_challenge_e_with_url) additionally binds a device
# identifier into the challenge.  We implement that stronger variant to check
# whether device-identifier binding confers per-device entitlement.
class FidemDeviceRel(FidemDevice):
    def respond_rel(self, R: bytes, Xc: bytes, C: bytes,
                    device_id: bytes) -> bytes:
        h = int.from_bytes(hashlib.sha256(R + Xc + C + self.url.encode()
                                          + device_id).digest(),
                           "big") % ORDER
        return ((self.r + h * self.Kc) % ORDER).to_bytes(32, "big")


def b2rel_verify(controller_trust, mud_file, url, Xc: bytes, R: bytes,
                 device_id: bytes, respond_fn) -> bool:
    """As b2_verify, but the challenge also binds the claimed device id."""
    if not b1_verify(controller_trust, mud_file, url):
        return False
    C = os.urandom(32)
    Z = respond_fn(R, Xc, C, device_id)
    h = int.from_bytes(hashlib.sha256(R + Xc + C + url.encode()
                                      + device_id).digest(), "big") % ORDER
    z = int.from_bytes(Z, "big")
    if not (0 < z < ORDER):
        return False
    lhs = z * G
    rhs = bytes_to_point(R) + h * bytes_to_point(Xc)
    return rhs != INFINITY and lhs == rhs
