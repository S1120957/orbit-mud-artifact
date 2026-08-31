"""ORBIT-MUD device and DHCP-equivalent message encoding."""
from __future__ import annotations
import os
import struct
from dataclasses import dataclass

from ..common.crypto import rand_scalar, point_to_bytes, schnorr_commit, \
    schnorr_respond, G
from ..common.encoding import encode, H


def lifecycle_digest(cp_digest: bytes, status_root: bytes, profile_digest:
                     bytes, version: int, epoch: int) -> bytes:
    return H(encode("ORBIT-LIFECYCLE-DIGEST", cp_digest, status_root,
                    profile_digest, version, epoch))


def transcript(xid: int, nonce: bytes, R: bytes, P: bytes, leaf_index: int,
               url: str, profile_digest: bytes, man_id: str, class_id: str,
               version: int, epoch: int, ldigest: bytes,
               status_root: bytes) -> bytes:
    return encode("ORBIT-ONBOARD-TRANSCRIPT", xid, nonce, R, P, leaf_index,
                  H(url.encode()), profile_digest, man_id, class_id,
                  version, epoch, ldigest, status_root)


@dataclass
class Device:
    man_id: str
    class_id: str
    epoch: int
    leaf_index: int
    k: int = 0
    P: bytes = b""
    mud_url: str = ""

    def __post_init__(self):
        if self.k == 0:
            self.k = rand_scalar()
            self.P = point_to_bytes(self.k * G)

    # --- protocol steps ---
    def discover_payload(self):
        """DHCP Discover contribution: URL + (R, leaf_index, epoch)."""
        self._com = schnorr_commit()
        return dict(url=self.mud_url, R=self._com.R,
                    leaf_index=self.leaf_index, epoch=self.epoch, P=self.P)

    def request_payload(self, xid: int, nonce: bytes, profile_digest: bytes,
                        version: int, ldigest: bytes, status_root: bytes):
        tau = transcript(xid, nonce, self._com.R, self.P, self.leaf_index,
                         self.mud_url, profile_digest, self.man_id,
                         self.class_id, version, self.epoch, ldigest,
                         status_root)
        return schnorr_respond(self.k, self._com, tau)


# ---------------- DHCP option encoding (byte-accurate) ----------------
# Layout of the experimental extension (subject to IANA allocation):
#   Option 161 : MUDstring  = URL || 0x20 || reserved("O:224,225")
#   Option 224 : R(33) || leaf_index u32 || epoch u32          [Discover]
#   Option 225 : P (33, compressed device public key)          [Discover]
#   Option 226 : nonce(32) || lifecycle_digest(32)             [Offer]
#   Option 227 : s (32, Schnorr response)                      [Request]

def opt(code: int, payload: bytes) -> bytes:
    assert len(payload) <= 255, f"option {code} exceeds 255 bytes"
    return bytes([code, len(payload)]) + payload


def discover_options(url: str, R: bytes, leaf_index: int, epoch: int,
                     P: bytes) -> bytes:
    mudstring = url.encode() + b"\x20" + b"O:224,225"
    o224 = R + struct.pack(">II", leaf_index, epoch)
    return opt(161, mudstring) + opt(224, o224) + opt(225, P)


def offer_options(nonce: bytes, ldigest: bytes) -> bytes:
    return opt(226, nonce + ldigest)


def request_options(url: str, s: bytes) -> bytes:
    mudstring = url.encode() + b"\x20" + b"O:227"
    return opt(161, mudstring) + opt(227, s)


def fidem_discover_options(url: str, R: bytes) -> bytes:
    mudstring = url.encode() + b"\x20" + b"O:224"
    return opt(161, mudstring) + opt(224, R)
