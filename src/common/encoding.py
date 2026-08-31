"""Canonical, unambiguous encoding for all ORBIT-MUD authenticated structures.

Encoding rule (documented in the paper, Sec. Protocol Operation):
  encode(tag, f1, ..., fk) =
      u32be(len(tag)) || tag || u32be(len(f1)) || f1 || ... || u32be(len(fk)) || fk
where every field is first mapped to bytes:
  - bytes    -> as-is
  - str      -> UTF-8
  - int >= 0 -> 8-byte big-endian
Each authenticated structure uses a distinct ASCII domain-separation tag, so no
two structures of different types can collide byte-wise, and no field boundary
is ambiguous. Hash is SHA-256 throughout.
"""
from __future__ import annotations
import hashlib
import struct


def _to_bytes(x) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode("utf-8")
    if isinstance(x, bool):
        return struct.pack(">Q", int(x))
    if isinstance(x, int):
        if x < 0:
            raise ValueError("negative integers not allowed in canonical encoding")
        return struct.pack(">Q", x)
    raise TypeError(f"unsupported field type {type(x)}")


def encode(tag: str, *fields) -> bytes:
    out = bytearray()
    for item in (tag, *fields):
        b = _to_bytes(item)
        out += struct.pack(">I", len(b))
        out += b
    return bytes(out)


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def Henc(tag: str, *fields) -> bytes:
    """SHA-256 over the canonical encoding."""
    return H(encode(tag, *fields))
