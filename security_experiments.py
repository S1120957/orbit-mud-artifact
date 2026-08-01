"""Executable security experiments E1..E15.

Each experiment returns a dict:
  {id, name, expected, actual, pass (actual==expected), baseline_note, detail}
"actual" is derived from real protocol execution, never asserted.
"""
from __future__ import annotations
import os
import sys
import time
import json
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

from world import build_world, onboard, CLASS, URL, MAN
from src.controller.controller import Controller
from src.lifecycle_log.log import REVOKED, SUSPENDED, ACTIVE
from src.device.device import Device
from src.common.crypto import rand_scalar, point_to_bytes, G
from src.baselines.baselines import FidemClass, FidemDevice, b2_verify


def fresh_controller(w, policy=None):
    m = w["m"]
    return Controller("FRESH", {m.man_id: m.signer.public_bytes},
                      {x.wid: x.public_bytes for x in w["witnesses"]},
                      policy=policy)


def E1_replay_old_signed_file():
    # An old, still validly signed MUD file (v1) replayed after v2 published.
    w = build_world(10)
    m = w["m"]
    old_file = copy.deepcopy(m.mud_files[URL])          # v1, valid signature
    # Controller first accepts v1 world normally
    onboard(w, w["devices"][0])
    # publish v2
    m.update_profile(CLASS, URL, "dns:telemetry.mfr.example;tcp/443;NEWCAP")
    m.publish_record(CLASS, URL)
    cp2 = m.issue_checkpoint(witnesses=w["witnesses"])
    # attacker serves OLD file + OLD record bundle but must present a checkpoint
    # the controller will consistency-check; the honest latest record is v2.
    # Attacker replays v1 file against the new checkpoint:
    rb2 = m.latest_record_proofs()
    dec = onboard(w, w["devices"][1], cp=cp2, mud_file=old_file,
                  record_bundle=rb2)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E1", name="Replay old signed MUD file",
                expected="rejected", actual=actual, passed=actual == "rejected",
                detail=dec.reason,
                baseline_note="B1/B2 accept: signature valid, no version check")


def E2_rollback_returning_controller():
    w = build_world(10)
    m = w["m"]
    ctrl = w["controllers"][0]
    m.update_profile(CLASS, URL, "v2caps")
    m.publish_record(CLASS, URL)
    cp2 = m.issue_checkpoint(witnesses=w["witnesses"])
    onboard(w, w["devices"][0], cp=cp2)                 # controller now at v2
    # attacker crafts a record claiming version 1 with a fresh-looking cp
    from src.lifecycle_log.log import LifecycleRecord
    old = m.records[0]
    dec = onboard(w, w["devices"][1], cp=cp2,
                  record_bundle=dict(record=old,
                                     inclusion=m.log.inclusion_proof(0),
                                     index=0, size=cp2.log_size))
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E2", name="Profile rollback v+1->v (returning controller)",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="B3 also rejects via last_update cache; B1/B2 accept")


def E3_first_contact_old_but_valid_checkpoint():
    # A first-contact controller shown an OLD but still time-valid checkpoint.
    # Strong policy requires q-of-n witnesses on the CURRENT checkpoint; the
    # old checkpoint only carries witness endorsements matching its own view.
    w = build_world(10, validity=100000)
    m = w["m"]
    old_cp = w["cp"]                                    # endorsed at size s0
    old_rb = m.latest_record_proofs()                  # record consistent w/ old_cp
    old_mem = m.membership(CLASS, 3)                    # proof vs current status root
    # log advances (an unrelated device revoked, tree rebuilt); witnesses
    # endorse the new checkpoint.
    m.set_device_status(CLASS, 0, REVOKED)
    m.publish_record(CLASS, URL)
    m.issue_checkpoint(witnesses=w["witnesses"])
    # first-contact strong controller: present the OLD cp (still time-valid)
    # with the membership proof matching the OLD record's status root. It IS
    # validly signed+endorsed for its size; strong policy alone cannot tell it
    # is not the newest -> honest result: ACCEPTED but stale.
    ctrl = fresh_controller(w, policy=dict(first_contact="strong", q=2))
    dec = onboard(w, w["devices"][3], ctrl=ctrl, cp=old_cp,
                  record_bundle=old_rb, membership=old_mem)
    actual = "accepted" if dec.accepted else "rejected"
    # Property actually provided: witness quorum on first contact; NOT
    # global-latest. So expected == accepted for a still-valid endorsed cp.
    return dict(id="E3",
                name="First-contact old-but-time-valid endorsed checkpoint",
                expected="accepted", actual=actual,
                passed=actual == "accepted", detail=dec.reason,
                baseline_note=("Honest result: witnesses bound freshness to the "
                               "endorsed view, not global latestness. Freshness "
                               "still bounded by valid_until/accept_window."))


def E3b_first_contact_expired_checkpoint():
    w = build_world(10, validity=1)
    m = w["m"]
    old_cp = w["cp"]
    old_rb = m.latest_record_proofs()
    ctrl = fresh_controller(w, policy=dict(first_contact="strong", q=2))
    dec = onboard(w, w["devices"][3], ctrl=ctrl, cp=old_cp,
                  record_bundle=old_rb, now=int(time.time()) + 10000)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E3b",
                name="First-contact checkpoint beyond freshness window",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="Bounded staleness enforces rejection past window")


def E4_revoked_device():
    w = build_world(10)
    m = w["m"]
    m.set_device_status(CLASS, 2, REVOKED)
    m.publish_record(CLASS, URL)
    cp = m.issue_checkpoint(witnesses=w["witnesses"])
    dec = onboard(w, w["devices"][2], cp=cp)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E4", name="Join with revoked device key",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="B1/B2/B3 have no per-device status: accept")


def E5_suspended_device():
    w = build_world(10)
    m = w["m"]
    m.set_device_status(CLASS, 3, SUSPENDED)
    m.publish_record(CLASS, URL)
    cp = m.issue_checkpoint(witnesses=w["witnesses"])
    dec = onboard(w, w["devices"][3], cp=cp)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E5", name="Join with suspended device key",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="No baseline models suspension")


def E6_replay_old_transcript():
    # Capture the exact commitment R the controller saw, then replay it.
    w = build_world(10)
    d = w["devices"][0]
    m = w["m"]
    ctrl = w["controllers"][0]
    disc1 = d.discover_payload()                    # fixes d._com
    captured_R = disc1["R"]
    rb = m.latest_record_proofs()
    mem = m.membership(CLASS, d.leaf_index)
    dec1 = ctrl.verify_onboarding("02:00:00:aaaaaa", 123, disc1,
                                  m.mud_files[URL], w["cp"], rb, mem, None,
                                  d.request_payload)
    assert dec1.accepted, dec1.reason               # R now recorded in seen_R
    # Attacker replays the identical Discover payload (same R).
    disc2 = {"url": URL, "R": captured_R, "leaf_index": d.leaf_index,
             "epoch": d.epoch, "P": d.P}
    dec2 = ctrl.verify_onboarding("02:00:00:aaaaab", 124, disc2,
                                  m.mud_files[URL], w["cp"], rb, mem, None,
                                  d.request_payload)
    actual = "rejected" if not dec2.accepted else "accepted"
    return dict(id="E6", name="Replay old onboarding transcript (reused R)",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec2.reason,
                baseline_note="Commitment-reuse tracking (as in FIDEM) rejects")


def E7_transcript_under_different_checkpoint():
    # A response computed for checkpoint A verified against checkpoint B fails
    # because H(CP) is inside the transcript.
    w = build_world(10)
    d = w["devices"][0]
    m = w["m"]
    ctrl = w["controllers"][0]
    cpA = w["cp"]
    # advance log to get a different checkpoint B
    m.publish_record(CLASS, URL)
    cpB = m.issue_checkpoint(witnesses=w["witnesses"])
    disc = d.discover_payload()
    rbB = m.latest_record_proofs()
    memB = m.membership(CLASS, d.leaf_index)
    # device computes response bound to A's lifecycle digest, controller uses B
    from src.device.device import lifecycle_digest, transcript
    recB = rbB["record"]
    ldA = lifecycle_digest(cpA.digest(), recB.device_status_root,
                           recB.profile_digest, recB.profile_version,
                           recB.credential_epoch)

    def wrong_response(xid, nonce, pd, ver, ldig_ignored, sr):
        # device signs using A's checkpoint digest instead of the one B sends
        return d.request_payload(xid, nonce, pd, ver, ldA, sr)

    dec = ctrl.verify_onboarding("02:00:00:bbbbbb",
                                 99, disc, m.mud_files[URL], cpB, rbB, memB,
                                 m.consistency(ctrl.state["checkpoints"].get(
                                     m.man_id, (cpB.log_size, cpB.log_root))[0])
                                 if m.man_id in ctrl.state["checkpoints"] else None,
                                 wrong_response)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E7", name="Replay transcript under a different checkpoint",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="Checkpoint digest bound in transcript")


def E8_leaked_fidem_class_secret():
    # With FIDEM's shared K_c leaked, ANY device of the class can be
    # impersonated (B2). Demonstrated by producing a valid B2 proof from the
    # leaked secret alone.
    w = build_world(10)
    m = w["m"]
    trust = {m.man_id: m.signer.public_bytes}
    cls = FidemClass()
    # attacker learns cls.Kc -> builds a device with it, no enrollment needed
    attacker = FidemDevice(cls, URL)
    R = attacker.commit()
    ok = b2_verify(trust, m.mud_files[URL], URL, cls.Xc, R, attacker.respond)
    actual = "class-wide-impersonation" if ok else "blocked"
    return dict(id="E8", name="Leaked FIDEM class secret K_c",
                expected="class-wide-impersonation", actual=actual,
                passed=actual == "class-wide-impersonation",
                detail="B2 accepts any holder of K_c",
                baseline_note="ORBIT-MUD has no class-wide shared secret")


def E9_leaked_orbit_device_key():
    # Leaking one k_i lets the attacker pass AS THAT device only, until revoked.
    w = build_world(10)
    d = w["devices"][0]
    leaked_k = d.k
    clone = Device(MAN, CLASS, epoch=1, leaf_index=0, k=leaked_k,
                   P=point_to_bytes(leaked_k * G), mud_url=URL)
    dec_before = onboard(w, clone)
    # now revoke that identity
    m = w["m"]
    m.set_device_status(CLASS, 0, REVOKED)
    m.publish_record(CLASS, URL)
    cp = m.issue_checkpoint(witnesses=w["witnesses"])
    dec_after = onboard(w, clone, cp=cp)
    actual = ("impersonates-self-until-revoked"
              if dec_before.accepted and not dec_after.accepted else "other")
    return dict(id="E9", name="Leaked ORBIT-MUD device key k_i",
                expected="impersonates-self-until-revoked", actual=actual,
                passed=actual == "impersonates-self-until-revoked",
                detail=f"before={dec_before.reason};after={dec_after.reason}",
                baseline_note="Blast radius = one revocable identity, not class")


def E10_impersonate_other_after_one_leak():
    # With only k_0 leaked, try to pass as device index 1 (different key).
    w = build_world(10)
    victim = w["devices"][1]
    leaked_k = w["devices"][0].k
    # attacker presents victim's leaf/index but can only sign with leaked_k
    forged = Device(MAN, CLASS, epoch=1, leaf_index=1, k=leaked_k,
                    P=point_to_bytes(leaked_k * G), mud_url=URL)
    m = w["m"]
    ctrl = w["controllers"][0]
    disc = forged.discover_payload()
    disc["leaf_index"] = 1                 # claim victim's slot
    disc["P"] = w["devices"][1].P          # claim victim's key (can't sign it)
    rb = m.latest_record_proofs()
    mem = m.membership(CLASS, 1)
    dec = ctrl.verify_onboarding("02:00:00:cccccc", 7, disc,
                                 m.mud_files[URL], w["cp"], rb, mem, None,
                                 forged.request_payload)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E10", name="Impersonate another device after one k_i leak",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="Per-device PoP: cannot sign for a key not held")


def E11_split_view_detected():
    w = build_world(10, n_controllers=2)
    m = w["m"]
    c1, c2 = w["controllers"]
    onboard(w, w["devices"][0], ctrl=c1)
    onboard(w, w["devices"][1], ctrl=c2)
    # Fork: build an alternate log head of the SAME size but different root by
    # replaying an equivocating checkpoint to c2.
    forked_root = os.urandom(32)
    from src.lifecycle_log.log import Checkpoint
    good = w["cp"]
    fake = Checkpoint(log_root=forked_root, log_size=good.log_size,
                      latest_record_digest=good.latest_record_digest,
                      issued_at=good.issued_at, manufacturer_id=m.man_id)
    detected = c2.observe_checkpoint(m.man_id, fake, None)
    actual = "detected" if detected else "undetected"
    return dict(id="E11", name="Inconsistent checkpoints to two controllers",
                expected="detected", actual=actual,
                passed=actual == "detected",
                detail="same size, different root at equal seq",
                baseline_note="Detection via checkpoint comparison, not prevention")


def E12_witness_availability():
    results = {}
    for k in range(4):
        w = build_world(6, validity=100000)
        for i in range(3):
            w["witnesses"][i].available = (i < k)
        m = w["m"]
        m.publish_record(CLASS, URL)
        cp = m.issue_checkpoint(witnesses=w["witnesses"])
        ctrl = fresh_controller(w, policy=dict(first_contact="strong", q=2))
        dec = onboard(w, w["devices"][0], ctrl=cp and ctrl, cp=cp)
        results[k] = "accepted" if dec.accepted else f"rejected:{dec.reason}"
    # expected: 0,1 witnesses -> rejected (q=2); 2,3 -> accepted
    ok = (results[0].startswith("rejected") and results[1].startswith("rejected")
          and results[2] == "accepted" and results[3] == "accepted")
    return dict(id="E12", name="Witnesses available in {0,1,2,3} (q=2 strong)",
                expected="reject<2, accept>=2", actual=results, passed=ok,
                baseline_note="2-of-3 quorum on first contact")


def E13_stale_within_grace():
    w = build_world(6)
    ctrl = w["controllers"][0]
    onboard(w, w["devices"][0])                    # establish cached state
    t = w["cp"].issued_at + ctrl.policy["accept_window"] + \
        ctrl.policy["grace"] - 5
    dec = onboard(w, w["devices"][1], now=t, log_reachable=False)
    actual = "accepted" if dec.accepted else f"rejected:{dec.reason}"
    return dict(id="E13", name="Stale cached checkpoint within grace, log down",
                expected="accepted", actual=actual,
                passed=dec.accepted, detail=actual,
                baseline_note="Bounded-staleness grace for returning controller")


def E14_stale_after_grace():
    w = build_world(6)
    ctrl = w["controllers"][0]
    onboard(w, w["devices"][0])
    t = w["cp"].issued_at + ctrl.policy["accept_window"] + \
        ctrl.policy["grace"] + 60
    dec = onboard(w, w["devices"][1], now=t, log_reachable=False)
    actual = "rejected" if not dec.accepted else "accepted"
    return dict(id="E14", name="Stale checkpoint after grace interval",
                expected="rejected", actual=actual,
                passed=actual == "rejected", detail=dec.reason,
                baseline_note="Past grace -> reject")


def E15_emergency_suspension_healthcare():
    w = build_world(8)
    m = w["m"]
    ctrl = w["controllers"][0]
    dec0 = onboard(w, w["devices"][0])
    assert dec0.accepted
    installed_before = "02:00:00:000000" in ctrl.installed
    # emergency suspend the whole class (incident), propagate via re-validate
    m.publish_record(CLASS, URL, emergency=True)
    rec = m.records[-1]
    withdrew = ctrl.revalidate("02:00:00:000000", rec, m.mud_files[URL])
    # a new join attempt during emergency:
    cp = m.issue_checkpoint(witnesses=w["witnesses"])
    dec1 = onboard(w, w["devices"][1], cp=cp)
    actual = ("suspended" if withdrew and not dec1.accepted else "not-suspended")
    return dict(id="E15", name="Emergency suspension of healthcare gateway",
                expected="suspended", actual=actual,
                passed=actual == "suspended",
                detail=f"withdrew={withdrew};newjoin={dec1.reason}",
                baseline_note="Emergency flag in signed record; withdraw+deny")


EXPERIMENTS = [E1_replay_old_signed_file, E2_rollback_returning_controller,
               E3_first_contact_old_but_valid_checkpoint,
               E3b_first_contact_expired_checkpoint, E4_revoked_device,
               E5_suspended_device, E6_replay_old_transcript,
               E7_transcript_under_different_checkpoint,
               E8_leaked_fidem_class_secret, E9_leaked_orbit_device_key,
               E10_impersonate_other_after_one_leak, E11_split_view_detected,
               E12_witness_availability, E13_stale_within_grace,
               E14_stale_after_grace, E15_emergency_suspension_healthcare]


def run_all():
    out = []
    for fn in EXPERIMENTS:
        try:
            out.append(fn())
        except Exception as e:
            import traceback
            out.append(dict(id=fn.__name__, name=fn.__name__,
                            expected="run", actual="EXCEPTION", passed=False,
                            detail=f"{e}\n{traceback.format_exc()}"))
    return out


if __name__ == "__main__":
    res = run_all()
    with open(os.path.join(os.path.dirname(__file__), "..", "results",
                           "security_experiments.json"), "w") as f:
        json.dump(res, f, indent=2, default=str)
    npass = sum(1 for r in res if r["passed"])
    for r in res:
        print(f"[{'PASS' if r['passed'] else 'FAIL'}] {r['id']:4} "
              f"{r['name'][:52]:52} exp={r['expected']}")
    print(f"\n{npass}/{len(res)} experiments matched expected outcome")
