"""Performance benchmarks. Software-only, single host. No hardware energy,
RAM, flash, or TEE numbers are produced (no embedded hardware available).

Outputs:
  results/raw_results.csv      one row per (metric, population, run)
  results/summary_results.csv  aggregated statistics per (metric, population)
  results/sizes.csv            deterministic byte sizes
  results/scalability.csv      proof sizes / verify time vs N
  results/throughput.csv       concurrent-join throughput
"""
from __future__ import annotations
import csv
import os
import platform
import statistics as st
import sys
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from world import build_world, CLASS, URL, MAN
from src.device.device import (discover_options, offer_options,
                               request_options, fidem_discover_options,
                               lifecycle_digest, transcript)
from src.common.crypto import schnorr_commit, schnorr_respond, \
    schnorr_verify, rand_scalar, point_to_bytes, G
from src.common.merkle import DeviceStatusTree

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results")
N_RUNS = 200          # >=100 as required
POPULATIONS = [100, 1000, 10000, 100000]


def timer(fn, runs=N_RUNS):
    xs = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e3)   # ms
    return xs


def bootstrap_ci(xs, iters=2000, alpha=0.05):
    n = len(xs)
    means = []
    for _ in range(iters):
        s = [xs[random.randrange(n)] for _ in range(n)]
        means.append(sum(s) / n)
    means.sort()
    lo = means[int((alpha / 2) * iters)]
    hi = means[int((1 - alpha / 2) * iters)]
    return lo, hi


def summarize(name, population, xs):
    lo, hi = bootstrap_ci(xs)
    return dict(metric=name, population=population, runs=len(xs),
                mean=st.mean(xs), median=st.median(xs),
                stdev=st.pstdev(xs), iqr=(st.quantiles(xs, n=4)[2] -
                                          st.quantiles(xs, n=4)[0]),
                min=min(xs), max=max(xs), ci95_lo=lo, ci95_hi=hi)


def run_latency(raw_writer, summ_rows):
    # Build one representative world at N=1000 for latency microbenchmarks.
    w = build_world(1000)
    m = w["m"]
    ctrl = w["controllers"][0]
    dev = w["devices"][7]
    cp = w["cp"]
    rec = m.records[-1]
    mem = m.membership(CLASS, dev.leaf_index)
    mud = m.mud_files[URL]

    # device proof generation
    def dev_proof():
        com = schnorr_commit()
        tau = transcript(1, b"n" * 32, com.R, dev.P, dev.leaf_index, URL,
                         rec.profile_digest, MAN, CLASS, rec.profile_version,
                         rec.credential_epoch, b"l" * 32,
                         rec.device_status_root)
        schnorr_respond(dev.k, com, tau)

    # controller schnorr verify
    com = schnorr_commit()
    tau = transcript(1, b"n" * 32, com.R, dev.P, dev.leaf_index, URL,
                     rec.profile_digest, MAN, CLASS, rec.profile_version,
                     rec.credential_epoch, b"l" * 32, rec.device_status_root)
    s = schnorr_respond(dev.k, com, tau)

    def ctrl_verify():
        schnorr_verify(dev.P, com.R, s, tau)

    # merkle membership proof gen + verify
    def mem_gen():
        m.membership(CLASS, dev.leaf_index)

    leaf = mem["leaf"]

    def mem_verify():
        DeviceStatusTree.verify_membership(leaf, mem["index"], mem["size"],
                                           mem["path"], rec.device_status_root)

    # full onboarding (returning controller, warm state)
    from world import onboard
    onboard(w, dev)   # warm

    def full_onboard():
        onboard(w, w["devices"][random.randrange(1000)])

    benches = {
        "device_proof_gen_ms": dev_proof,
        "controller_schnorr_verify_ms": ctrl_verify,
        "membership_proof_gen_ms": mem_gen,
        "membership_proof_verify_ms": mem_verify,
        "full_onboarding_ms": full_onboard,
    }
    for name, fn in benches.items():
        xs = timer(fn)
        for i, v in enumerate(xs):
            raw_writer.writerow([name, 1000, i, f"{v:.6f}"])
        summ_rows.append(summarize(name, 1000, xs))


def run_first_vs_returning(raw_writer, summ_rows):
    w = build_world(1000)
    m = w["m"]
    from world import onboard
    from src.controller.controller import Controller

    # first-contact: strong policy, fresh controller each run (witness quorum)
    def first_contact():
        c = Controller("FC", {m.man_id: m.signer.public_bytes},
                       {x.wid: x.public_bytes for x in w["witnesses"]},
                       policy=dict(first_contact="strong", q=2))
        onboard(w, w["devices"][random.randrange(1000)], ctrl=c)

    ctrl = w["controllers"][0]
    onboard(w, w["devices"][0])  # warm

    def returning():
        onboard(w, w["devices"][random.randrange(1000)], ctrl=ctrl)

    for name, fn in [("first_contact_onboarding_ms", first_contact),
                     ("returning_onboarding_ms", returning)]:
        xs = timer(fn, runs=N_RUNS)
        for i, v in enumerate(xs):
            raw_writer.writerow([name, 1000, i, f"{v:.6f}"])
        summ_rows.append(summarize(name, 1000, xs))


def run_sizes():
    rows = []
    # DHCP-equivalent encoded message sizes (bytes), ORBIT vs FIDEM-style vs RFC8520
    R = b"\x02" * 33
    P = b"\x03" * 33
    s = b"\x04" * 32
    orbit_disc = discover_options(URL, R, 1, 1, P)
    orbit_offer = offer_options(b"\x00" * 32, b"\x00" * 32)
    orbit_req = request_options(URL, s)
    fidem_disc = fidem_discover_options(URL, R)
    rfc8520 = len(URL.encode()) + 3 + 2  # option 161 header + mudstring + 0x20+res
    rows.append(("orbit_discover_bytes", len(orbit_disc)))
    rows.append(("orbit_offer_bytes", len(orbit_offer)))
    rows.append(("orbit_request_bytes", len(orbit_req)))
    rows.append(("orbit_total_dhcp_bytes",
                 len(orbit_disc) + len(orbit_offer) + len(orbit_req)))
    rows.append(("fidem_discover_bytes", len(fidem_disc)))
    rows.append(("rfc8520_mudstring_bytes", rfc8520))
    rows.append(("mud_url_len_bytes", len(URL)))
    rows.append(("max_single_option_limit", 255))
    rows.append(("dhcp_min_message_capacity", 576))
    # each option <=255 and each message well under 576
    rows.append(("orbit_discover_fits_576", int(len(orbit_disc) < 576)))
    rows.append(("orbit_request_fits_576", int(len(orbit_req) < 576)))
    with open(os.path.join(RESULTS, "sizes.csv"), "w", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["quantity", "value_bytes"])
        wtr.writerows(rows)
    return dict(rows)


def run_scalability():
    rows = []
    for N in POPULATIONS:
        w = build_world(N, seed=7)
        m = w["m"]
        idx = N // 2
        mem = m.membership(CLASS, idx)
        # membership proof size = number of path nodes * 32
        mp_nodes = len(mem["path"])
        mp_bytes = mp_nodes * 32
        # inclusion proof for latest record in the append-only log
        rb = m.latest_record_proofs()
        inc_bytes = len(rb["inclusion"]) * 32
        # consistency proof from size 1 -> current
        cons_nodes = len(m.consistency(1)) if m.log.size > 1 else 0
        cons_bytes = cons_nodes * 32
        # membership verify time
        leaf = mem["leaf"]
        t0 = time.perf_counter()
        for _ in range(50):
            DeviceStatusTree.verify_membership(leaf, mem["index"], mem["size"],
                                               mem["path"],
                                               m.records[-1].device_status_root)
        verify_ms = (time.perf_counter() - t0) / 50 * 1e3
        rows.append([N, mp_nodes, mp_bytes, len(rb["inclusion"]), inc_bytes,
                     cons_nodes, cons_bytes, f"{verify_ms:.6f}"])
    with open(os.path.join(RESULTS, "scalability.csv"), "w", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["population_N", "membership_path_nodes",
                      "membership_bytes", "inclusion_nodes", "inclusion_bytes",
                      "consistency_nodes", "consistency_bytes",
                      "membership_verify_ms"])
        wtr.writerows(rows)
    return rows


def run_throughput():
    rows = []
    w = build_world(2000)
    m = w["m"]
    ctrl = w["controllers"][0]
    from world import onboard
    onboard(w, w["devices"][0])  # warm cached state
    for batch in [1, 10, 50, 100, 200]:
        picks = [w["devices"][random.randrange(2000)] for _ in range(batch)]
        t0 = time.perf_counter()
        for d in picks:
            onboard(w, d, ctrl=ctrl)
        dt = time.perf_counter() - t0
        rows.append([batch, f"{dt*1e3:.4f}", f"{batch/dt:.2f}"])
    with open(os.path.join(RESULTS, "throughput.csv"), "w", newline="") as f:
        wtr = csv.writer(f)
        wtr.writerow(["sequential_joins", "wall_ms", "joins_per_sec"])
        wtr.writerows(rows)
    return rows


def main():
    os.makedirs(RESULTS, exist_ok=True)
    summ_rows = []
    with open(os.path.join(RESULTS, "raw_results.csv"), "w", newline="") as f:
        raw = csv.writer(f)
        raw.writerow(["metric", "population", "run", "value_ms"])
        run_latency(raw, summ_rows)
        run_first_vs_returning(raw, summ_rows)
    with open(os.path.join(RESULTS, "summary_results.csv"), "w",
              newline="") as f:
        cols = ["metric", "population", "runs", "mean", "median", "stdev",
                "iqr", "min", "max", "ci95_lo", "ci95_hi"]
        wtr = csv.DictWriter(f, fieldnames=cols)
        wtr.writeheader()
        for r in summ_rows:
            wtr.writerow(r)
    sizes = run_sizes()
    scal = run_scalability()
    thr = run_throughput()
    # environment manifest
    with open(os.path.join(RESULTS, "environment.txt"), "w") as f:
        f.write(f"python={platform.python_version()}\n")
        f.write(f"platform={platform.platform()}\n")
        f.write(f"processor={platform.processor()}\n")
        import ecdsa
        f.write(f"ecdsa={ecdsa.__version__}\n")
        f.write("curve=secp256r1 (NIST256p)\nhash=SHA-256\n")
        f.write("process_model=single-process, single-thread, in-memory\n")
        f.write(f"n_runs_per_latency_metric={N_RUNS}\n")
    print("== summary ==")
    for r in summ_rows:
        print(f"{r['metric']:34} median={r['median']:.4f}ms "
              f"CI95=[{r['ci95_lo']:.4f},{r['ci95_hi']:.4f}]")
    print("\n== sizes (bytes) ==")
    for k in ["orbit_discover_bytes", "orbit_request_bytes",
              "orbit_total_dhcp_bytes", "fidem_discover_bytes",
              "rfc8520_mudstring_bytes"]:
        print(f"{k:28} {sizes[k]}")
    print("\n== scalability (N, path_nodes, membership_bytes) ==")
    for row in scal:
        print(f"N={row[0]:>7}  path={row[1]:>3} nodes  {row[2]:>4} B  "
              f"verify={row[7]}ms")
    print("\n== throughput ==")
    for row in thr:
        print(f"{row[0]:>4} joins  {row[1]} ms  {row[2]} joins/s")


if __name__ == "__main__":
    main()
