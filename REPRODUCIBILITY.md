# Reproducing the ORBIT-MUD results

Everything in the paper is produced by the scripts in this repository. There
are no hand-entered measurements.

## 1. Environment used for the reported numbers

```
OS              Ubuntu 24.04.4 LTS (Linux 6.18.5, x86_64)
Python          3.12.3
CPU             1 vCPU, Intel Xeon @ 2.10 GHz   <-- single core: throughput is serial
Crypto          ecdsa 0.19.2, curve secp256r1, SHA-256
Process model   single process, single thread, in-memory state
LaTeX           TeX Live (pdflatex + bibtex), IEEEtran.cls 1.8b, IEEEtran.bst 1.14
```

The machine-readable copy of this block is written by the benchmark run to
`results/environment.txt`.

Timing numbers are hardware-dependent and will differ on other machines. The
*security* experiment outcomes (16/16) and all *byte sizes* and *proof node
counts* are deterministic and should reproduce exactly anywhere.

## 2. Install

```bash
pip install -r requirements.txt          # ecdsa, matplotlib, numpy, pytest, scapy
```

For the manuscript you additionally need `pdflatex`, `bibtex`, and the
`IEEEtran`, `booktabs`, `algorithm`, and `algorithmic` LaTeX packages.

## 3. Run everything

```bash
make all
```

which is equivalent to:

```bash
python3 -m pytest tests/ -q                  # 1. unit tests
python3 attacks/security_experiments.py      # 2. security experiments E1-E15 + E3b
python3 experiments/benchmark.py             # 3. latency, sizes, scalability, throughput
python3 experiments/make_figures.py          # 4. figures
cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

## 4. Regenerating the LaTeX result macros and the security table

The paper never contains a typed-in measurement. Both generated LaTeX
fragments are rebuilt from the result files:

- `paper/results_macros.tex` — one `\newcommand` per reported metric, built
  from `results/summary_results.csv`, `results/sizes.csv`,
  `results/scalability.csv`, `results/throughput.csv`, and
  `results/security_experiments.json`.
- `paper/_sec_rows.tex` — the rows of Table II, built from
  `results/security_experiments.json`.

The generator snippets are recorded in the session and reproduce these two
files deterministically from the result files. Note that the rows of Table II
are **embedded directly** into `main.tex` rather than `\input`, because
`\input`-ing a file whose final token is `\\` inside a `tabular` triggers a
`Misplaced \noalign` error under this TeX Live build; `_sec_rows.tex` is
retained as the generated source of truth for those rows.

## 5. Expected output

| Step | Expected result |
|---|---|
| `pytest tests/` | `11 passed` |
| `attacks/security_experiments.py` | `16/16 experiments matched expected outcome` |
| `experiments/benchmark.py` | writes 6 files into `results/`; medians close to Table III on comparable hardware |
| `experiments/make_figures.py` | writes `paper/fig_latency.pdf`, `paper/fig_scalability.pdf` |
| LaTeX build | 7-page `paper/main.pdf`, 0 undefined references, 0 undefined citations, 0 overfull boxes |

Reference logs from the reported run are in `logs/`:
`test_run2.log`, `security_run3.log`, `benchmark_run1.log`.

## 6. Determinism and seeds

`experiments/world.py` builds device populations from an explicit seed
(default `seed=7` for the scalability sweep). Key generation uses fresh
randomness per run, so individual timing samples vary; medians and CIs are
stable across runs. Byte sizes, Merkle path lengths, and every security-
experiment outcome are independent of randomness.

## 7. Formal analysis

`formal/orbit_mud.spthy` is a Tamarin model of the stateful core. It was
**not executed**: Tamarin and its Maude backend are unavailable in the
evaluation environment and could not be installed under the network policy.
The exact commands attempted and their output are in `formal/RUN_LOG.txt`.
The paper therefore makes no formal-verification claim. To run the model
yourself:

```bash
tamarin-prover --prove formal/orbit_mud.spthy
```

## 8. Known deviations from an ideal evaluation

These are also stated in Section XV of the paper.

1. Software-only, single-vCPU host; no embedded-hardware measurements.
2. The three witnesses run in one process — logical, not organizational,
   independence.
3. The FIDEM baseline is a reproduction from the paper specification; the
   original source repository was not reachable.
4. The DHCP integration is a byte-accurate reference encoding, not a Kea or
   Cisco MUD-manager deployment; option codes would require IANA allocation.
