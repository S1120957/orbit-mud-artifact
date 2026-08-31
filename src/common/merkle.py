"""Merkle structures used by ORBIT-MUD.

Hashing follows the RFC 6962 domain separation:
    leaf hash  = SHA-256(0x00 || leaf_data)
    node hash  = SHA-256(0x01 || left || right)

Two uses:
  * DeviceStatusTree: a Merkle tree over device-status leaves; membership
    proof (audit path) simultaneously authenticates key, manufacturer,
    class, epoch and status because all are inside the leaf preimage.
  * AppendOnlyLog: Merkle history tree over lifecycle-record digests with
    RFC 6962 inclusion and consistency proofs.
"""
from __future__ import annotations
import hashlib
from typing import List, Tuple

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _h(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(NODE_PREFIX + left + right)


def _mth(leaves: List[bytes]) -> bytes:
    """Merkle tree head over leaf hashes (RFC 6962 Sec. 2.1)."""
    n = len(leaves)
    if n == 0:
        return _h(b"")
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _audit_path(m: int, leaves: List[bytes]) -> List[bytes]:
    """RFC 6962 Sec. 2.1.1 PATH(m, D)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return _audit_path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _audit_path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def verify_audit_path(leaf: bytes, index: int, size: int, path: List[bytes],
                      root: bytes) -> bool:
    """RFC 6962 Sec. 2.1.3 style verification."""
    if index >= size or size <= 0:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


class DeviceStatusTree:
    """Mutable-leaf Merkle tree; rebuilt on status change (sizes used here
    make full rebuild cheap; an incremental update is an optimization,
    not a correctness requirement)."""

    def __init__(self, leaves_data: List[bytes]):
        self.set_leaves(leaves_data)

    def set_leaves(self, leaves_data: List[bytes]):
        self.leaves_data = list(leaves_data)
        self.leaf_hashes = [leaf_hash(d) for d in self.leaves_data]
        self.root = _mth(self.leaf_hashes)
        self.size = len(self.leaf_hashes)

    def update_leaf(self, index: int, data: bytes):
        self.leaves_data[index] = data
        self.leaf_hashes[index] = leaf_hash(data)
        self.root = _mth(self.leaf_hashes)

    def membership_proof(self, index: int) -> List[bytes]:
        return _audit_path(index, self.leaf_hashes)

    @staticmethod
    def verify_membership(leaf_data: bytes, index: int, size: int,
                          path: List[bytes], root: bytes) -> bool:
        return verify_audit_path(leaf_hash(leaf_data), index, size, path, root)


class AppendOnlyLog:
    """RFC 6962-style history tree over entry digests."""

    def __init__(self):
        self.entries: List[bytes] = []          # raw entry bytes
        self.leaf_hashes: List[bytes] = []

    def append(self, entry: bytes) -> int:
        self.entries.append(entry)
        self.leaf_hashes.append(leaf_hash(entry))
        return len(self.entries) - 1

    @property
    def size(self) -> int:
        return len(self.leaf_hashes)

    def root(self, size: int | None = None) -> bytes:
        size = self.size if size is None else size
        return _mth(self.leaf_hashes[:size])

    def inclusion_proof(self, index: int, size: int | None = None) -> List[bytes]:
        size = self.size if size is None else size
        return _audit_path(index, self.leaf_hashes[:size])

    def consistency_proof(self, m: int, n: int | None = None) -> List[bytes]:
        """RFC 6962 Sec. 2.1.2 PROOF(m, D[n])."""
        n = self.size if n is None else n
        if m == 0 or m > n:
            raise ValueError("bad consistency bounds")
        return self._subproof(m, self.leaf_hashes[:n], True)

    def _subproof(self, m: int, D: List[bytes], b: bool) -> List[bytes]:
        n = len(D)
        if m == n:
            return [] if b else [_mth(D)]
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            return self._subproof(m, D[:k], b) + [_mth(D[k:])]
        return self._subproof(m - k, D[k:], False) + [_mth(D[:k])]


def verify_consistency(m: int, n: int, old_root: bytes, new_root: bytes,
                       proof: List[bytes]) -> bool:
    """RFC 6962 Sec. 2.1.4 consistency verification (verifier side)."""
    if m == 0 or m > n:
        return False
    if m == n:
        return old_root == new_root and proof == []
    path = list(proof)
    # If m is an exact power of two, MTH(D[0:m]) == old_root is known to the
    # verifier and omitted by the prover; prepend it.
    if m & (m - 1) == 0:
        path = [old_root] + path
    if not path:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0
