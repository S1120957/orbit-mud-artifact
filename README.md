# ORBIT-MUD

**Lifecycle-Aware Binding of MUD Profiles to Individual IoT Devices**

Research artifact: prototype, experiments, and manuscript source.

ORBIT-MUD extends MUD (RFC 8520) onboarding with three elements:

1. a **per-device Schnorr proof of possession** (no class-wide shared secret);
2. a **single authenticated device-status Merkle tree**, whose one membership
   proof simultaneously binds device key, manufacturer, class, credential
   epoch, and status (`active` / `revoked` / `suspended`);
3. **manufacturer-signed lifecycle checkpoints** over an append-only
   (RFC 6962-style) log, endorsed by a configurable *q*-of-*n* witness quorum
   (2-of-3 in the prototype).

It provides replay resistance, local rollback resistance, bounded-freshness
first-contact protection, individual revocation, end-of-support and emergency
signalling, and **detectable** equivocation. It explicitly does **not** claim
to prove globally latest state, does not provide privacy, and was evaluated in
software only. See `CLAIMS_EVIDENCE_MATRIX.md` for the full claim-by-claim
account of what is demonstrated, argued, assumed, or disclaimed.

## Quick start

```bash
pip install -r requirements.txt
make all
```

Or step by step — see `REPRODUCIBILITY.md`.

## Headline results

- **22/22** executable security scenarios matched their expected outcome.
- Device proof generation **0.62 ms** median; returning-Controller onboarding
  **9.66 ms**; first-contact onboarding **17.45 ms** (200 runs each, single
  Xeon vCPU).
- Device-side DHCP-equivalent payloads are **fixed size** — 132 B Discover,
  84 B Request — **independent of population size**. Merkle proofs travel
  Controller↔log, not over DHCP.
- Membership proofs grow logarithmically: **224 B** at *N* = 10² to
  **544 B** at *N* = 10⁵, verified in under **12.85 µs**.
- A leaked FIDEM class secret yields class-wide impersonation; a leaked
  ORBIT-MUD device key compromises **only that revocable identity**.

## Layout

```
src/common/        canonical encoding, Schnorr + ECDSA, Merkle tree & log
src/device/        device state, DHCP option encoders, transcript binding
src/controller/    C1-C10 verification pipeline, persistent state, revalidation
src/lifecycle_log/ lifecycle records, checkpoints, manufacturer log
src/witness/       witness endorsement (append-only consistency checked)
src/baselines/     B1 RFC 8520, B2 FIDEM-spec reproduction, B3 version cache
attacks/           security_experiments.py  -> E1-E15 + E3b
experiments/       world.py, benchmark.py, make_figures.py
tests/             11 pytest unit tests
results/           raw + summary CSVs, sizes, scalability, throughput, JSON
formal/            ProVerif + Tamarin models and RUN_LOG (NOT executed)
paper-lncs/        main.tex, references.bib, figures (Springer LNCS)
logs/              captured stdout of the reported runs
configs/           deployment policy (quorum, windows, fail-closed classes)
```

## Honesty notes

- Throughput (92–99 joins/s) is **serial on one core**, reported as a
  single-core lower bound rather than a deployment target.
- An old-but-still-time-valid endorsed checkpoint **is accepted** on first
  contact (experiment E3). This is a deliberate, reported negative result: the
  witness quorum bounds freshness, it does not prove latestness.
