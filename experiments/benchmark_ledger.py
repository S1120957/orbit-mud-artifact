"""Blockchain anchoring benchmarks (computation and storage only).

Measures:
  1. off-chain aggregation: on-chain bytes per anchored checkpoint vs batch B
  2. anchor verification latency at the controller vs batch size B
  3. ledger storage growth vs number of anchored checkpoints
  4. onboarding latency with and without the ledger anchor check

NOT measured (and never claimed anywhere): consensus latency, block
propagation, peer gossip, transaction throughput of a real network, or
energy. Those require a deployed ledger network.
"""
from __future__ import annotations
import csv, os, statistics as st, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from world import build_world, onboard, CLASS, URL
from src.ledger.anchor import (ConsortiumLedger, Organisation, verify_anchor)

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results")
N_RUNS = 200
BATCHES = [1, 2, 5, 10, 20, 50, 100]


def timer(fn, runs=N_RUNS):
    xs = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e3)
    return xs


def make_checkpoints(k):
    """k distinct, validly signed checkpoints from one manufacturer."""
    w = build_world(8, validity=1000000)
    m = w["m"]
    cps = [w["cp"]]
    for _ in range(k - 1):
        m.publish_record(CLASS, URL)
        cps.append(m.issue_checkpoint(witnesses=w["witnesses"]))
    return w, m, cps


def bench_aggregation():
    rows = []
    for B in BATCHES:
        w, m, cps = make_checkpoints(B)
        orgs = [Organisation(f"ORG{i}") for i in range(3)]
        led = ConsortiumLedger(orgs, q=2)
        for cp in cps:
            led.submit(m.man_id, cp)
        led.seal_block(timestamp=1)
        on_chain = led.on_chain_bytes()
        rows.append([B, on_chain, round(on_chain / B, 2), len(led.blocks)])
    with open(os.path.join(RESULTS, "ledger_aggregation.csv"), "w",
              newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["batch_B", "on_chain_bytes_total",
                      "on_chain_bytes_per_checkpoint", "blocks"])
        wtr.writerows(rows)
    return rows


def bench_verify():
    rows = []
    for B in BATCHES:
        w, m, cps = make_checkpoints(B)
        orgs = [Organisation(f"ORG{i}") for i in range(3)]
        led = ConsortiumLedger(orgs, q=2)
        for cp in cps:
            led.submit(m.man_id, cp)
        led.seal_block(timestamp=1)
        pubs = {o.oid: o.public_bytes for o in orgs}
        target = cps[B // 2]
        proof = led.anchor_proof(m.man_id, target)
        assert verify_anchor(pubs, 2, m.man_id, target, proof)
        xs = timer(lambda: verify_anchor(pubs, 2, m.man_id, target, proof))
        rows.append([B, len(proof["path"]),
                     round(st.median(xs), 4), round(st.pstdev(xs), 4)])
    with open(os.path.join(RESULTS, "ledger_verify.csv"), "w", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["batch_B", "inclusion_path_nodes", "verify_median_ms",
                      "verify_stdev_ms"])
        wtr.writerows(rows)
    return rows


def bench_storage():
    """Ledger storage vs number of anchored checkpoints at fixed batch B=10."""
    rows = []
    B = 10
    for total in [10, 50, 100, 500, 1000]:
        w, m, cps = make_checkpoints(1)
        orgs = [Organisation(f"ORG{i}") for i in range(3)]
        led = ConsortiumLedger(orgs, q=2)
        cp0 = cps[0]
        # synthesise distinct anchors by advancing log size
        from src.lifecycle_log.log import Checkpoint
        anchored = 0
        for j in range(total):
            c = Checkpoint(log_root=cp0.log_root, log_size=j + 1,
                           latest_record_digest=cp0.latest_record_digest,
                           issued_at=cp0.issued_at,
                           manufacturer_id=m.man_id)
            c.signature = m.signer.sign(c.signed_body())
            if led.submit(m.man_id, c):
                anchored += 1
            if (j + 1) % B == 0:
                led.seal_block(timestamp=j)
        led.seal_block(timestamp=total)
        rows.append([total, anchored, len(led.blocks), led.on_chain_bytes(),
                     round(led.on_chain_bytes() / max(anchored, 1), 2)])
    with open(os.path.join(RESULTS, "ledger_storage.csv"), "w", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["checkpoints_total", "anchored", "blocks",
                      "on_chain_bytes", "bytes_per_checkpoint"])
        wtr.writerows(rows)
    return rows


def bench_onboarding_delta():
    """Returning-controller onboarding with vs without the anchor check."""
    w = build_world(1000)
    m = w["m"]
    ctrl = w["controllers"][0]
    orgs = [Organisation(f"ORG{i}") for i in range(3)]
    led = ConsortiumLedger(orgs, q=2)
    led.submit(m.man_id, w["cp"]); led.seal_block(timestamp=1)
    pubs = {o.oid: o.public_bytes for o in orgs}
    proof = led.anchor_proof(m.man_id, w["cp"])
    import random
    onboard(w, w["devices"][0])

    def plain():
        onboard(w, w["devices"][random.randrange(1000)], ctrl=ctrl)

    def with_anchor():
        onboard(w, w["devices"][random.randrange(1000)], ctrl=ctrl)
        verify_anchor(pubs, 2, m.man_id, w["cp"], proof)

    a = timer(plain); b = timer(with_anchor)
    rows = [["returning_onboarding_no_ledger", round(st.median(a), 4)],
            ["returning_onboarding_with_ledger", round(st.median(b), 4)],
            ["ledger_check_overhead", round(st.median(b) - st.median(a), 4)]]
    with open(os.path.join(RESULTS, "ledger_onboarding.csv"), "w",
              newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["metric", "median_ms"])
        wtr.writerows(rows)
    return rows


if __name__ == "__main__":
    os.makedirs(RESULTS, exist_ok=True)
    print("== off-chain aggregation ==")
    for r in bench_aggregation():
        print(f"B={r[0]:>4} total={r[1]:>7}B  per-checkpoint={r[2]:>8}B")
    print("\n== anchor verification ==")
    for r in bench_verify():
        print(f"B={r[0]:>4} path={r[1]:>2} nodes  median={r[2]}ms")
    print("\n== ledger storage (B=10) ==")
    for r in bench_storage():
        print(f"cps={r[0]:>5} blocks={r[2]:>4} on-chain={r[3]:>8}B  "
              f"per-cp={r[4]}B")
    print("\n== onboarding delta ==")
    for r in bench_onboarding_delta():
        print(f"{r[0]:<38} {r[1]} ms")
