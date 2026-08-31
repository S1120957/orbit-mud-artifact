import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

from src.common.encoding import encode, Henc
from src.common.crypto import schnorr_commit, schnorr_respond, \
    schnorr_verify, rand_scalar, point_to_bytes, G, Signer, verify_sig
from src.common.merkle import AppendOnlyLog, verify_consistency
from src.lifecycle_log.log import REVOKED, SUSPENDED
from src.baselines.baselines import FidemClass, FidemDevice, b1_verify, \
    b2_verify, B3Cache
from src.device.device import discover_options, offer_options, \
    request_options
from world import build_world, onboard, CLASS, URL


def test_encoding_unambiguous():
    assert encode("T", b"ab", b"c") != encode("T", b"a", b"bc")
    assert encode("T1", b"x") != encode("T2", b"x")
    assert Henc("T", 1, "a") != Henc("T", 1, "b")


def test_schnorr_roundtrip_and_reject():
    k = rand_scalar()
    P = point_to_bytes(k * G)
    com = schnorr_commit()
    tau = encode("T", os.urandom(32))
    s = schnorr_respond(k, com, tau)
    assert schnorr_verify(P, com.R, s, tau)
    assert not schnorr_verify(P, com.R, s, encode("T", os.urandom(32)))
    k2 = rand_scalar()
    s2 = schnorr_respond(k2, com, tau)
    assert not schnorr_verify(P, com.R, s2, tau)


def test_ecdsa_signer():
    s = Signer("x")
    m = b"hello"
    sig = s.sign(m)
    assert verify_sig(s.public_bytes, m, sig)
    assert not verify_sig(s.public_bytes, b"hellp", sig)


def test_log_consistency_negative():
    log = AppendOnlyLog()
    for i in range(10):
        log.append(os.urandom(8))
    r5, r10 = log.root(5), log.root(10)
    p = log.consistency_proof(5, 10)
    assert verify_consistency(5, 10, r5, r10, p)
    assert not verify_consistency(5, 10, r10, r5, p)


def test_happy_path_onboarding():
    w = build_world(20)
    d = w["devices"][3]
    dec = onboard(w, d)
    assert dec.accepted, dec.reason
    assert all(dec.checks.values())


def test_wrong_key_rejected():
    w = build_world(10)
    d = w["devices"][0]
    d.k = rand_scalar()          # key not matching enrolled P? P stays enrolled
    dec = onboard(w, d)
    assert not dec.accepted and dec.reason.startswith("C10")


def test_revoked_and_suspended_rejected():
    w = build_world(10)
    m = w["m"]
    m.set_device_status(CLASS, 4, REVOKED)
    m.publish_record(CLASS, URL)
    cp = m.issue_checkpoint(witnesses=w["witnesses"])
    dec = onboard(w, w["devices"][4], cp=cp)
    assert not dec.accepted and "C9" in dec.reason
    m.set_device_status(CLASS, 5, SUSPENDED)
    m.publish_record(CLASS, URL)
    cp = m.issue_checkpoint(witnesses=w["witnesses"])
    dec = onboard(w, w["devices"][5], cp=cp)
    assert not dec.accepted and "C9" in dec.reason
    dec = onboard(w, w["devices"][6], cp=cp)
    assert dec.accepted


def test_witness_quorum_first_contact():
    w = build_world(5)
    for wit in w["witnesses"][:2]:
        wit.available = False
    m = w["m"]
    m.publish_record(CLASS, URL)
    cp = m.issue_checkpoint(witnesses=w["witnesses"])   # only 1 endorsement
    from src.controller.controller import Controller
    fresh = Controller("FRESH", {m.man_id: m.signer.public_bytes},
                       {x.wid: x.public_bytes for x in w["witnesses"]})
    dec = onboard(w, w["devices"][0], ctrl=fresh, cp=cp)
    assert not dec.accepted and dec.reason.startswith("C3")


def test_stale_checkpoint_rejected():
    w = build_world(5)
    dec = onboard(w, w["devices"][0], now=int(time.time()) + 999999)
    assert not dec.accepted and dec.reason.startswith("C7")


def test_dhcp_option_limits():
    d_opts = discover_options(URL, b"\x02" * 33, 1, 1, b"\x03" * 33)
    o_opts = offer_options(os.urandom(32), os.urandom(32))
    r_opts = request_options(URL, os.urandom(32))
    for blob in (d_opts, o_opts, r_opts):
        i = 0
        while i < len(blob):
            code, ln = blob[i], blob[i + 1]
            assert ln <= 255
            i += 2 + ln


def test_baselines():
    w = build_world(5)
    m = w["m"]
    f = m.mud_files[URL]
    trust = {m.man_id: m.signer.public_bytes}
    assert b1_verify(trust, f, URL)
    cls = FidemClass()
    dv = FidemDevice(cls, URL)
    R = dv.commit()
    assert b2_verify(trust, f, URL, cls.Xc, R, dv.respond)
    c = B3Cache()
    assert c.check_and_update(f)
    class Old:  # older last_update, same class
        manufacturer_id, class_id, last_update = m.man_id, CLASS, f.last_update - 10
    assert not c.check_and_update(Old)
