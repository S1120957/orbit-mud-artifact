"""ORBIT-MUD Controller (reference prototype).

Verification pipeline (each step is a named check so experiments can log the
exact rejection reason):

  C1  MUD file signature (manufacturer key from configured trust store)
  C2  checkpoint signature
  C3  witness endorsements: q-of-n on first contact when policy=strong
  C4  log inclusion of the latest lifecycle record
  C5  log consistency with the Controller's cached checkpoint
  C6  local monotonicity: sequence, profile_version, credential_epoch
  C7  freshness: issued_at within accept_window (+ grace when log offline)
  C8  record semantics: profile digest matches file; supported; no emergency
  C9  device-status membership: leaf(P,M,C,e,active) in device_status_root
  C10 Schnorr proof of possession over the bound transcript

The device proves possession of k_i over the exact lifecycle state the
Controller selected and verified; binding the lifecycle digest prevents
cross-state transcript reuse but does NOT itself prove freshness (C7 does,
up to the policy bound).
"""
from __future__ import annotations
import json
import os
import struct
import time
from dataclasses import dataclass, field

from ..common.crypto import schnorr_verify, verify_sig
from ..common.merkle import verify_audit_path, verify_consistency, \
    DeviceStatusTree, leaf_hash
from ..common.encoding import encode, H
from ..device.device import lifecycle_digest, transcript
from ..lifecycle_log.log import ACTIVE
from ..witness.witness import verify_endorsement


@dataclass
class Decision:
    accepted: bool
    reason: str
    checks: dict = field(default_factory=dict)
    installed_policy: str | None = None


class Controller:
    def __init__(self, name: str, trust_store: dict, witness_pubs: dict,
                 policy: dict | None = None, state_path: str | None = None):
        self.name = name
        self.trust_store = trust_store            # man_id -> pubkey bytes
        self.witness_pubs = witness_pubs          # wid -> pubkey bytes
        self.policy = dict(first_contact="strong", q=2,
                           accept_window=3600, grace=600,
                           fail_closed_classes=set())
        if policy:
            self.policy.update(policy)
        self.state_path = state_path
        self.state = {"classes": {}, "checkpoints": {}, "seen_R": []}
        self.installed = {}                       # mac -> policy summary
        if state_path and os.path.exists(state_path):
            self._load()

    # ---------- persistence ----------
    def _load(self):
        with open(self.state_path) as f:
            raw = json.load(f)
        self.state = {"classes": raw["classes"],
                      "checkpoints": {k: (v[0], bytes.fromhex(v[1]))
                                      for k, v in raw["checkpoints"].items()},
                      "seen_R": raw.get("seen_R", [])}

    def persist(self):
        if not self.state_path:
            return
        raw = {"classes": self.state["classes"],
               "checkpoints": {k: [v[0], v[1].hex()]
                               for k, v in self.state["checkpoints"].items()},
               "seen_R": self.state["seen_R"][-10000:]}
        with open(self.state_path, "w") as f:
            json.dump(raw, f)

    # ---------- verification ----------
    def verify_onboarding(self, mac: str, xid: int, disc: dict, mud_file,
                          cp, record_bundle, membership, consistency_proof,
                          device_response_fn, now: int | None = None,
                          log_reachable: bool = True) -> Decision:
        now = now or int(time.time())
        checks = {}
        rec = record_bundle["record"]
        man = rec.manufacturer_id
        key = f"{man}/{rec.class_id}"

        def fail(step, why):
            checks[step] = False
            return Decision(False, f"{step}:{why}", checks)

        # C1 MUD file signature + URL sanity
        pub = self.trust_store.get(man)
        if pub is None or not verify_sig(pub, mud_file.canonical(),
                                         mud_file.signature):
            return fail("C1", "mud-file-signature")
        if mud_file.mud_url != disc["url"]:
            return fail("C1", "url-mismatch")
        checks["C1"] = True

        # C2 checkpoint signature
        if not verify_sig(pub, cp.signed_body(), cp.signature):
            return fail("C2", "checkpoint-signature")
        checks["C2"] = True

        # C3 witness endorsements on first contact under strong policy
        first_contact = man not in self.state["checkpoints"]
        if first_contact and self.policy["first_contact"] == "strong":
            good = 0
            for wid, sig in cp.endorsements:
                wp = self.witness_pubs.get(wid)
                if wp and verify_endorsement(wp, wid, cp.signed_body(), sig):
                    good += 1
            if good < self.policy["q"]:
                return fail("C3", f"witness-quorum:{good}<{self.policy['q']}")
        checks["C3"] = True

        # C4 inclusion of latest record
        if cp.latest_record_digest != rec.digest():
            return fail("C4", "record-not-latest-in-checkpoint")
        if not verify_audit_path(leaf_hash(rec.canonical()),
                                 record_bundle["index"],
                                 record_bundle["size"],
                                 record_bundle["inclusion"], cp.log_root) \
                or record_bundle["size"] != cp.log_size:
            return fail("C4", "log-inclusion")
        checks["C4"] = True

        # C5 consistency with cached checkpoint
        cached = self.state["checkpoints"].get(man)
        if cached is not None:
            old_size, old_root = cached
            if cp.log_size < old_size:
                return fail("C5", "log-size-regression")
            if not verify_consistency(old_size, cp.log_size, old_root,
                                      cp.log_root, consistency_proof or []):
                return fail("C5", "log-consistency")
        checks["C5"] = True

        # C6 local monotonicity
        st = self.state["classes"].get(key)
        if st is not None:
            if rec.sequence_number < st["seq"]:
                return fail("C6", "sequence-rollback")
            if rec.profile_version < st["version"]:
                return fail("C6", "profile-version-rollback")
            if rec.credential_epoch < st["epoch"]:
                return fail("C6", "epoch-rollback")
        checks["C6"] = True

        # C7 freshness / bounded staleness
        window = self.policy["accept_window"]
        if not log_reachable:
            window += self.policy["grace"]
            if rec.class_id in self.policy["fail_closed_classes"]:
                return fail("C7", "log-unreachable-fail-closed")
        if now > cp.issued_at + window:
            return fail("C7", "checkpoint-stale")
        rec_window = rec.valid_until + (self.policy["grace"]
                                        if not log_reachable else 0)
        if now < rec.valid_from or now > rec_window:
            return fail("C7", "record-window")
        checks["C7"] = True

        # C8 record semantics
        if rec.profile_digest != mud_file.digest():
            return fail("C8", "profile-digest-mismatch")
        if not rec.is_supported:
            return fail("C8", "end-of-support")
        if rec.emergency_status:
            return fail("C8", "emergency-suspension")
        if rec.credential_epoch != disc["epoch"]:
            return fail("C8", "epoch-mismatch")
        checks["C8"] = True

        # C9 device-status membership (key, M, C, epoch, ACTIVE all in leaf)
        from ..lifecycle_log.log import status_leaf
        leaf = status_leaf(disc["P"], man, rec.class_id,
                           rec.credential_epoch, ACTIVE, membership.get(
                               "metadata", b"\x00" * 32))
        if membership["status"] != ACTIVE:
            # serve the true leaf so the proof verifies but status check fails
            return fail("C9", f"device-status:{membership['status']}")
        if membership["P"] != disc["P"]:
            return fail("C9", "public-key-mismatch")
        if not DeviceStatusTree.verify_membership(
                leaf, membership["index"], membership["size"],
                membership["path"], rec.device_status_root):
            return fail("C9", "membership-proof")
        checks["C9"] = True

        # C10 Schnorr PoP over bound transcript
        if disc["R"].hex() in set(self.state["seen_R"]):
            return fail("C10", "commitment-reuse")
        nonce = os.urandom(32)
        ldig = lifecycle_digest(cp.digest(), rec.device_status_root,
                                rec.profile_digest, rec.profile_version,
                                rec.credential_epoch)
        s = device_response_fn(xid, nonce, rec.profile_digest,
                               rec.profile_version, ldig,
                               rec.device_status_root)
        tau = transcript(xid, nonce, disc["R"], disc["P"],
                         disc["leaf_index"], disc["url"], rec.profile_digest,
                         man, rec.class_id, rec.profile_version,
                         rec.credential_epoch, ldig, rec.device_status_root)
        if not schnorr_verify(disc["P"], disc["R"], s, tau):
            return fail("C10", "schnorr-verify")
        checks["C10"] = True
        self.state["seen_R"].append(disc["R"].hex())

        # accept: update persistent state, install policy
        self.state["checkpoints"][man] = (cp.log_size, cp.log_root)
        self.state["classes"][key] = dict(seq=rec.sequence_number,
                                          version=rec.profile_version,
                                          epoch=rec.credential_epoch)
        self.installed[mac] = f"ACLs[{mud_file.acl_summary}] v{rec.profile_version}"
        self.persist()
        return Decision(True, "accepted", checks, self.installed[mac])

    def observe_checkpoint(self, man: str, cp, consistency_proof) -> bool:
        """Cross-controller / gossip equivocation detection: returns True if
        the observed checkpoint conflicts with local state (fork evidence)."""
        cached = self.state["checkpoints"].get(man)
        if cached is None:
            return False
        old_size, old_root = cached
        if cp.log_size == old_size:
            return cp.log_root != old_root
        if cp.log_size > old_size:
            return not verify_consistency(old_size, cp.log_size, old_root,
                                          cp.log_root,
                                          consistency_proof or [])
        return True  # smaller log than already proven: regression evidence

    def revalidate(self, mac: str, rec, mud_file) -> bool:
        """Post-admission lifecycle re-check (revocation / emergency /
        end-of-support propagation on the polling path). Returns True if the
        installed policy was withdrawn."""
        key = f"{rec.manufacturer_id}/{rec.class_id}"
        withdraw = rec.emergency_status or (not rec.is_supported)
        if withdraw and mac in self.installed:
            del self.installed[mac]
            return True
        return False
