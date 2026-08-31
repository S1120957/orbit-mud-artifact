"""Lifecycle log: records, device-status tree, and signed checkpoints."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..common.encoding import encode, Henc, H
from ..common.crypto import Signer, verify_sig
from ..common.merkle import AppendOnlyLog, DeviceStatusTree

ACTIVE, REVOKED, SUSPENDED = "active", "revoked", "suspended"


def status_leaf(P: bytes, man_id: str, class_id: str, epoch: int,
                status: str, metadata_digest: bytes) -> bytes:
    """leaf_i = H(P_i || M || C || e || status_i || metadata_digest_i),
    canonically encoded."""
    return encode("ORBIT-STATUS-LEAF", P, man_id, class_id, epoch, status,
                  metadata_digest)


@dataclass
class LifecycleRecord:
    manufacturer_id: str
    class_id: str
    profile_version: int
    profile_digest: bytes
    credential_epoch: int
    device_status_root: bytes
    status_tree_size: int
    is_supported: bool
    emergency_status: bool
    valid_from: int
    valid_until: int
    predecessor_record_digest: bytes
    sequence_number: int

    def canonical(self) -> bytes:
        return encode("ORBIT-LIFECYCLE-RECORD",
                      self.manufacturer_id, self.class_id,
                      self.profile_version, self.profile_digest,
                      self.credential_epoch, self.device_status_root,
                      self.status_tree_size,
                      self.is_supported, self.emergency_status,
                      self.valid_from, self.valid_until,
                      self.predecessor_record_digest, self.sequence_number)

    def digest(self) -> bytes:
        return H(self.canonical())


@dataclass
class Checkpoint:
    log_root: bytes
    log_size: int
    latest_record_digest: bytes
    issued_at: int
    manufacturer_id: str
    signature: bytes = b""
    endorsements: List[tuple] = field(default_factory=list)  # (witness_id, sig)

    def signed_body(self) -> bytes:
        return encode("ORBIT-CHECKPOINT", self.manufacturer_id, self.log_root,
                      self.log_size, self.latest_record_digest, self.issued_at)

    def digest(self) -> bytes:
        return H(self.signed_body())


@dataclass
class MUDFile:
    """Simplified MUD file: RFC 8520 metadata subset + ORBIT extension."""
    mud_url: str
    manufacturer_id: str
    class_id: str
    profile_version: int
    last_update: int
    is_supported: bool
    acl_summary: str          # stands in for the full ACL body
    signature: bytes = b""

    def canonical(self) -> bytes:
        return encode("ORBIT-MUD-FILE", self.mud_url, self.manufacturer_id,
                      self.class_id, self.profile_version, self.last_update,
                      self.is_supported, self.acl_summary)

    def digest(self) -> bytes:
        return H(self.canonical())


class ManufacturerLog:
    """Manufacturer M: device enrollment, status tree, lifecycle records,
    append-only log, checkpoint issuance, MUD file signing."""

    def __init__(self, man_id: str):
        self.man_id = man_id
        self.signer = Signer(f"manufacturer:{man_id}")
        self.log = AppendOnlyLog()
        self.records: List[LifecycleRecord] = []
        # per class: device registry and status tree
        self.class_devices: Dict[str, list] = {}      # class -> [dict per device]
        self.class_trees: Dict[str, DeviceStatusTree] = {}
        self.class_epoch: Dict[str, int] = {}
        self.class_version: Dict[str, int] = {}
        self.mud_files: Dict[str, MUDFile] = {}       # url -> current file
        self.mud_history: Dict[str, List[MUDFile]] = {}
        self.seq = 0
        self.checkpoints: List[Checkpoint] = []

    # ---------- enrollment ----------
    def enroll_class(self, class_id: str, mud_url: str, acl_summary: str,
                     epoch: int = 1, version: int = 1):
        self.class_devices[class_id] = []
        self.class_epoch[class_id] = epoch
        self.class_version[class_id] = version
        f = MUDFile(mud_url, self.man_id, class_id, version,
                    int(time.time()), True, acl_summary)
        f.signature = self.signer.sign(f.canonical())
        self.mud_files[mud_url] = f
        self.mud_history.setdefault(mud_url, []).append(f)

    def enroll_device(self, class_id: str, P: bytes,
                      metadata_digest: bytes = b"\x00" * 32) -> int:
        idx = len(self.class_devices[class_id])
        self.class_devices[class_id].append(dict(
            P=P, status=ACTIVE, metadata=metadata_digest))
        return idx

    def _rebuild_tree(self, class_id: str):
        e = self.class_epoch[class_id]
        leaves = [status_leaf(d["P"], self.man_id, class_id, e, d["status"],
                              d["metadata"]) for d in self.class_devices[class_id]]
        self.class_trees[class_id] = DeviceStatusTree(leaves)

    # ---------- lifecycle publication ----------
    def publish_record(self, class_id: str, mud_url: str,
                       is_supported: bool = True, emergency: bool = False,
                       validity: int = 3600) -> LifecycleRecord:
        self._rebuild_tree(class_id)
        t = self.class_trees[class_id]
        now = int(time.time())
        pred = self.records[-1].digest() if self.records else b"\x00" * 32
        rec = LifecycleRecord(
            manufacturer_id=self.man_id, class_id=class_id,
            profile_version=self.class_version[class_id],
            profile_digest=self.mud_files[mud_url].digest(),
            credential_epoch=self.class_epoch[class_id],
            device_status_root=t.root, status_tree_size=t.size,
            is_supported=is_supported, emergency_status=emergency,
            valid_from=now, valid_until=now + validity,
            predecessor_record_digest=pred, sequence_number=self.seq)
        self.seq += 1
        self.records.append(rec)
        self.log.append(rec.canonical())
        return rec

    def issue_checkpoint(self, witnesses=None, issued_at: int | None = None
                         ) -> Checkpoint:
        cp = Checkpoint(log_root=self.log.root(), log_size=self.log.size,
                        latest_record_digest=self.records[-1].digest(),
                        issued_at=issued_at or int(time.time()),
                        manufacturer_id=self.man_id)
        cp.signature = self.signer.sign(cp.signed_body())
        if witnesses:
            for w in witnesses:
                e = w.endorse(cp, self)
                if e is not None:
                    cp.endorsements.append(e)
        self.checkpoints.append(cp)
        return cp

    # ---------- lifecycle events ----------
    def update_profile(self, class_id: str, mud_url: str, acl_summary: str):
        self.class_version[class_id] += 1
        f = MUDFile(mud_url, self.man_id, class_id,
                    self.class_version[class_id], int(time.time()), True,
                    acl_summary)
        f.signature = self.signer.sign(f.canonical())
        self.mud_files[mud_url] = f
        self.mud_history.setdefault(mud_url, []).append(f)

    def set_device_status(self, class_id: str, index: int, status: str):
        self.class_devices[class_id][index]["status"] = status

    def rotate_epoch(self, class_id: str):
        self.class_epoch[class_id] += 1

    # ---------- proof serving ----------
    def latest_record_proofs(self):
        idx = len(self.records) - 1
        return dict(record=self.records[idx],
                    inclusion=self.log.inclusion_proof(idx),
                    index=idx, size=self.log.size)

    def consistency(self, old_size: int):
        return self.log.consistency_proof(old_size)

    def membership(self, class_id: str, index: int):
        t = self.class_trees[class_id]
        d = self.class_devices[class_id][index]
        e = self.class_epoch[class_id]
        leaf = status_leaf(d["P"], self.man_id, class_id, e, d["status"],
                           d["metadata"])
        return dict(leaf=leaf, index=index, size=t.size,
                    path=t.membership_proof(index), status=d["status"],
                    P=d["P"], metadata=d["metadata"])
