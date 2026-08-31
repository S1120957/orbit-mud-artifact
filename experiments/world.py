"""Construct a reproducible experimental world.

World = one manufacturer, one or more MUD classes, N devices in the class
under test, three logical witness services, and one or more Controllers.
All components run in one process on one host: this evaluates protocol
behavior and performance, not organizational independence or network
latency.
"""
from __future__ import annotations
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.lifecycle_log.log import ManufacturerLog, ACTIVE, REVOKED, SUSPENDED
from src.witness.witness import Witness
from src.controller.controller import Controller
from src.device.device import Device

URL = "https://mfr.example/mud/gw-monitor-v1.json"
CLASS = "patient-monitoring-gateway"
MAN = "ACME-MED-0042"


def build_world(n_devices=100, seed=1, policy=None, state_path=None,
                n_controllers=1, validity=3600):
    random.seed(seed)
    m = ManufacturerLog(MAN)
    m.enroll_class(CLASS, URL, "dns:telemetry.mfr.example;tcp/443")
    devices = []
    for i in range(n_devices):
        d = Device(MAN, CLASS, epoch=1, leaf_index=i, mud_url=URL)
        m.enroll_device(CLASS, d.P)
        devices.append(d)
    m.publish_record(CLASS, URL, validity=validity)
    witnesses = [Witness(f"W{i+1}") for i in range(3)]
    cp = m.issue_checkpoint(witnesses=witnesses)
    wp = {w.wid: w.public_bytes for w in witnesses}
    trust = {MAN: m.signer.public_bytes}
    ctrls = [Controller(f"CTRL{i+1}", trust, wp, policy=policy,
                        state_path=(state_path and f"{state_path}.{i}"))
             for i in range(n_controllers)]
    return dict(m=m, devices=devices, witnesses=witnesses, cp=cp,
                controllers=ctrls, url=URL, cls=CLASS)


def onboard(world, dev, ctrl=None, cp=None, mud_file=None, now=None,
            log_reachable=True, mac=None, record_bundle=None,
            consistency=None, membership=None, xid=None):
    """Run one complete onboarding of `dev` against a Controller."""
    m = world["m"]
    ctrl = ctrl or world["controllers"][0]
    cp = cp or world["cp"]
    mud_file = mud_file or m.mud_files[world["url"]]
    rb = record_bundle or m.latest_record_proofs()
    mem = membership or m.membership(world["cls"], dev.leaf_index)
    cached = ctrl.state["checkpoints"].get(m.man_id)
    if consistency is None and cached is not None and cached[0] < cp.log_size:
        consistency = m.consistency(cached[0])
    disc = dev.discover_payload()
    xid = xid if xid is not None else random.getrandbits(32)
    return ctrl.verify_onboarding(
        mac or f"02:00:00:{dev.leaf_index:06x}", xid, disc, mud_file, cp, rb,
        mem, consistency, dev.request_payload, now=now,
        log_reachable=log_reachable)
