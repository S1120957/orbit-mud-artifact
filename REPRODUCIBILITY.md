# Reproducing the ORBIT-MUD results

Every number in the manuscript is produced by the scripts in this repository.
There are no hand-entered measurements.

## 1. Environment used for the reported numbers

```
OS        Ubuntu 24.04 LTS (x86-64)
Python    3.12.3
CPU       1 vCPU, Intel Xeon @ 2.10 GHz   <-- single core: throughput is serial
Crypto    ecdsa 0.19.2, curve secp256r1, SHA-256
Model     single process, single thread, in-memory state
LaTeX     pdflatex + bibtex, Springer llncs.cls, splncs04.bst
```

A machine-readable copy is written to `results/environment.txt` by the
benchmark run.

Timing numbers are hardware-dependent. The **security-scenario outcomes
(22/22)**, all **byte sizes**, and all **proof node counts** are deterministic
and reproduce exactly anywhere.

## 2. Install

```bash
pip install -r requirements.txt      # ecdsa, matplotlib, numpy, pytest, scapy
```

The manuscript additionally needs `pdflatex`, `bibtex`, and the `llncs`,
`booktabs`, `algorithm`, `algorithmic`, and `tikz` LaTeX packages.

## 3. Run everything

```bash
make all
```

equivalently:

```bash
python3 -m pytest tests/ -q                  # 1. unit tests           -> 11 passed
python3 attacks/security_experiments.py      # 2. scenarios E1-E21     -> 22/22
python3 experiments/benchmark.py             # 3. latency, sizes, scalability
python3 experiments/benchmark_ledger.py      # 4. ledger anchoring cost
python3 experiments/make_figures_lncs.py     # 5. Figs. 5, 7, 9
python3 experiments/make_figures_ledger.py   # 6. Fig. 8
cd paper-lncs && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

## 4. Expected output

| Step | Expected |
|---|---|
| `pytest tests/` | `11 passed` |
| `attacks/security_experiments.py` | `22/22 experiments matched expected outcome` |
| `experiments/benchmark.py` | writes 6 files to `results/` |
| `experiments/benchmark_ledger.py` | writes `ledger_{aggregation,verify,storage,onboarding}.csv` |
| figure scripts | write `paper-lncs/fig_{scenarios,latency,scale,ledger}.pdf` |
| LaTeX build | 0 undefined references, 0 undefined citations, 0 overfull boxes |

Reference logs from the reported run are under `logs/`.

## 5. Where each manuscript number comes from

| Manuscript item | Source file |
|---|---|
| Scenario outcomes, Table 3, Fig. 5 | `results/security_experiments.json` |
| Latency, Table 4, Fig. 7 | `results/summary_results.csv`, `raw_results.csv` |
| DHCP encoding sizes | `results/sizes.csv` |
| Status-tree scaling, Table 5, Fig. 9 | `results/scalability.csv` |
| Ledger anchoring, Table 6, Fig. 8 | `results/ledger_*.csv` |
| Throughput range | `results/throughput.csv` |

`CLAIMS_EVIDENCE_MATRIX.md` maps individual claims to evidence and status.

## 6. Determinism and seeds

`experiments/world.py` builds populations from an explicit seed (`seed=7` for
the scalability sweep). Key generation uses fresh randomness per run, so
individual timing samples vary while medians and confidence intervals are
stable. Byte sizes, Merkle path lengths, and every scenario outcome are
independent of randomness.

## 7. Formal analysis

`formal/orbit_mud.pv` (ProVerif) and `formal/orbit_mud.spthy` (Tamarin) are
preserved but **were not executed**; neither prover could be installed in the
evaluation environment (`formal/RUN_LOG.txt` records the attempts). The
manuscript makes **no** machine-checked security claim and treats symbolic
verification as future work. `formal/README_PROVERIF.md` explains how to run
the ProVerif model yourself.

## 8. Known deviations from an ideal evaluation

Also stated in the manuscript's limitations paragraph.

1. Software-only, single-vCPU host; no embedded-hardware measurements.
2. Witnesses are three logical processes on one host: logical, not
   organisational, independence.
3. The FIDEM baseline is a protocol-level reproduction cross-checked against
   the authors' released implementation (see `FIDEM_BASELINE_CHECK.md`), not an
   execution of it; all configurations B1-B5 share one substrate so that
   measured differences reflect protocol structure.
4. The consortium ledger implements the cryptographic and data-structure layer
   only: no consensus, ordering-service latency, propagation, or energy.
5. DHCP figures are option encodings, not PCAP-derived full messages.
