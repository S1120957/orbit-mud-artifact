"""Witness services.

A witness endorses a manufacturer checkpoint only if:
  (1) the manufacturer signature verifies;
  (2) the checkpoint is consistent (append-only) with the checkpoint the
      witness itself last endorsed for this manufacturer, proven by a log
      consistency proof;
  (3) the log size is non-decreasing relative to the witness's view.

Security statement (used verbatim in the paper): if at least q of n
witnesses are honest and reachable, a checkpoint that regresses or forks
the log relative to those witnesses' views cannot collect q endorsements;
conflicting q-endorsed checkpoints for overlapping views constitute
transferable evidence of misbehavior. Witnesses do NOT make equivocation
impossible and do NOT prove global latestness.
"""
from __future__ import annotations
from typing import Optional, Tuple

from ..common.crypto import Signer, verify_sig
from ..common.merkle import verify_consistency
from ..common.encoding import encode


class Witness:
    def __init__(self, wid: str):
        self.wid = wid
        self.signer = Signer(f"witness:{wid}")
        self.public_bytes = self.signer.public_bytes
        self.view = {}          # manufacturer_id -> (size, root)
        self.available = True

    def endorse(self, cp, manufacturer) -> Optional[Tuple[str, bytes]]:
        if not self.available:
            return None
        if not verify_sig(manufacturer.signer.public_bytes, cp.signed_body(),
                          cp.signature):
            return None
        prev = self.view.get(cp.manufacturer_id)
        if prev is not None:
            old_size, old_root = prev
            if cp.log_size < old_size:
                return None                      # regression: refuse
            proof = manufacturer.consistency(old_size)
            if not verify_consistency(old_size, cp.log_size, old_root,
                                      cp.log_root, proof):
                return None                      # fork: refuse
        self.view[cp.manufacturer_id] = (cp.log_size, cp.log_root)
        sig = self.signer.sign(encode("ORBIT-WITNESS-ENDORSE", self.wid,
                                      cp.signed_body()))
        return (self.wid, sig)


def verify_endorsement(witness_pub: bytes, wid: str, cp_body: bytes,
                       sig: bytes) -> bool:
    return verify_sig(witness_pub, encode("ORBIT-WITNESS-ENDORSE", wid,
                                          cp_body), sig)
