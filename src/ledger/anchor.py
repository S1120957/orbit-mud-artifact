"""Permissioned consortium ledger for ORBIT-MUD anchoring.

Design (aligned with the off-chain aggregation model of our prior work):
  * Complete MUD files and lifecycle records stay OFF-CHAIN.
  * Only compact commitments go ON-CHAIN. A batch of B lifecycle checkpoints
    is aggregated off-chain into ONE Merkle root; that root is the anchor
    transaction payload. This is the off-chain aggregation step: on-chain
    bytes per checkpoint fall as 1/B.
  * Blocks are ordered, hash-chained, and endorsed by q-of-n consortium
    organisations (manufacturers, hospital operators, regulators).
  * A controller verifies that the checkpoint it was shown is committed to
    the ledger by checking an inclusion proof against an endorsed block
    header. Because the ledger is totally ordered, two conflicting
    checkpoints for the same log size cannot both be anchored: the second is
    refused at anchoring time, so the unanchored fork is REJECTED at
    admission rather than merely detected afterwards.

SCOPE / HONESTY: this module implements the cryptographic and data-structure
layer of a permissioned ledger and its verification path. It does NOT
implement network consensus, peer gossip, or transaction ordering latency;
no consensus-latency or energy figure is produced anywhere in this artifact.
Measured quantities are computation and storage only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..common.crypto import Signer, verify_sig
from ..common.encoding import encode, H
from ..common.merkle import _mth, _audit_path, verify_audit_path, leaf_hash


def anchor_leaf(manufacturer_id: str, cp_digest: bytes, log_root: bytes,
                log_size: int) -> bytes:
    """Canonical, domain-separated anchor payload for one checkpoint."""
    return encode("ORBIT-ANCHOR", manufacturer_id, cp_digest, log_root,
                  log_size)


@dataclass
class BlockHeader:
    height: int
    prev_hash: bytes
    tx_root: bytes
    n_tx: int
    timestamp: int

    def signed_body(self) -> bytes:
        return encode("ORBIT-BLOCK", self.height, self.prev_hash,
                      self.tx_root, self.n_tx, self.timestamp)

    def digest(self) -> bytes:
        return H(self.signed_body())


@dataclass
class Block:
    header: BlockHeader
    payloads: List[bytes] = field(default_factory=list)
    endorsements: List[Tuple[str, bytes]] = field(default_factory=list)

    def size_bytes(self) -> int:
        """On-chain footprint: header + endorsements (payload commitments are
        the aggregated roots already inside tx_root)."""
        return (len(self.header.signed_body())
                + sum(len(s) + len(o) for o, s in self.endorsements))


class Organisation:
    """A consortium member that endorses blocks (manufacturer, provider,
    regulator, operator)."""

    def __init__(self, oid: str):
        self.oid = oid
        self.signer = Signer(f"org:{oid}")
        self.public_bytes = self.signer.public_bytes
        self.available = True
        self.height = -1

    def endorse(self, block: Block, prev_hash: bytes) -> Optional[Tuple[str, bytes]]:
        if not self.available:
            return None
        # refuse a block that does not extend the chain the org has seen
        if block.header.height <= self.height:
            return None
        if block.header.prev_hash != prev_hash:
            return None
        self.height = block.header.height
        return (self.oid, self.signer.sign(
            encode("ORBIT-ENDORSE", self.oid, block.header.digest())))


def verify_org_endorsement(pub: bytes, oid: str, header_digest: bytes,
                           sig: bytes) -> bool:
    return verify_sig(pub, encode("ORBIT-ENDORSE", oid, header_digest), sig)


class ConsortiumLedger:
    """Ordered, hash-chained, q-of-n endorsed anchor ledger."""

    def __init__(self, orgs: List[Organisation], q: int = 2):
        self.orgs = orgs
        self.q = q
        self.blocks: List[Block] = []
        self.pending: List[bytes] = []          # off-chain aggregation buffer
        self.pending_meta: List[tuple] = []
        # manufacturer_id -> {log_size: cp_digest} committed order
        self.committed: Dict[str, Dict[int, bytes]] = {}
        self.refused: List[tuple] = []

    # ---- off-chain aggregation -------------------------------------
    def submit(self, manufacturer_id: str, cp) -> bool:
        """Buffer a checkpoint for anchoring. Refuses an equivocating
        checkpoint: same manufacturer and log_size, different digest."""
        seen = self.committed.setdefault(manufacturer_id, {})
        d = cp.digest()
        if cp.log_size in seen and seen[cp.log_size] != d:
            self.refused.append((manufacturer_id, cp.log_size, "equivocation"))
            return False
        for mid, size, dg in self.pending_meta:
            if mid == manufacturer_id and size == cp.log_size and dg != d:
                self.refused.append(
                    (manufacturer_id, cp.log_size, "equivocation-in-batch"))
                return False
        self.pending.append(anchor_leaf(manufacturer_id, d, cp.log_root,
                                        cp.log_size))
        self.pending_meta.append((manufacturer_id, cp.log_size, d))
        return True

    def seal_block(self, timestamp: int = 0) -> Optional[Block]:
        """Aggregate all buffered anchors into ONE block."""
        if not self.pending:
            return None
        leaves = [leaf_hash(p) for p in self.pending]
        prev = self.blocks[-1].header.digest() if self.blocks else b"\x00" * 32
        hdr = BlockHeader(height=len(self.blocks), prev_hash=prev,
                          tx_root=_mth(leaves), n_tx=len(leaves),
                          timestamp=timestamp)
        blk = Block(header=hdr, payloads=list(self.pending))
        for org in self.orgs:
            e = org.endorse(blk, prev)
            if e:
                blk.endorsements.append(e)
        # commit only if the q-of-n threshold of DISTINCT orgs is met
        if len({o for o, _ in blk.endorsements}) < self.q:
            return None
        self.blocks.append(blk)
        for mid, size, dg in self.pending_meta:
            self.committed.setdefault(mid, {})[size] = dg
        self.pending, self.pending_meta = [], []
        return blk

    # ---- verification path -----------------------------------------
    def anchor_proof(self, manufacturer_id: str, cp) -> Optional[dict]:
        payload = anchor_leaf(manufacturer_id, cp.digest(), cp.log_root,
                              cp.log_size)
        for blk in reversed(self.blocks):
            if payload in blk.payloads:
                idx = blk.payloads.index(payload)
                leaves = [leaf_hash(p) for p in blk.payloads]
                return dict(payload=payload, index=idx, size=len(leaves),
                            path=_audit_path(idx, leaves), header=blk.header,
                            endorsements=list(blk.endorsements))
        return None

    def on_chain_bytes(self) -> int:
        return sum(b.size_bytes() for b in self.blocks)


def verify_anchor(org_pubs: Dict[str, bytes], q: int, manufacturer_id: str,
                  cp, proof: Optional[dict]) -> bool:
    """Controller-side check: the checkpoint is committed to a q-of-n
    endorsed block. Counts DISTINCT organisation identities."""
    if not proof:
        return False
    expected = anchor_leaf(manufacturer_id, cp.digest(), cp.log_root,
                           cp.log_size)
    if proof["payload"] != expected:
        return False
    if not verify_audit_path(leaf_hash(expected), proof["index"],
                             proof["size"], proof["path"],
                             proof["header"].tx_root):
        return False
    hd = proof["header"].digest()
    good = set()
    for oid, sig in proof["endorsements"]:
        if oid in good:
            continue
        pub = org_pubs.get(oid)
        if pub and verify_org_endorsement(pub, oid, hd, sig):
            good.add(oid)
    return len(good) >= q
