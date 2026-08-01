# ORBIT-MUD — Claims / Evidence Matrix

Every substantive claim in `paper/main.tex` is listed with the evidence that
supports it. Status values:

- **demonstrated** — an executed program produced the result; the number or
  outcome in the paper is read from a result file, not written by hand.
- **analytically-derived** — follows from the construction or from standard
  cryptographic assumptions; argued in prose, not machine-checked.
- **assumed** — a trust or deployment assumption, stated as such.
- **limitation** — explicitly disclaimed in the paper.

Manuscript line numbers refer to `paper/main.tex` as shipped.

## 1. Security property claims

| # | Claim | Section / line | Evidence type | Source file | Generating command | Status |
|---|---|---|---|---|---|---|
| C1 | Only a device holding the key registered `active` for the claimed manufacturer/class/epoch is accepted (G1) | Sec. VI G1 (l.233); Sec. IX (l.377) | executed experiment | `results/security_experiments.json` (E10) | `python3 attacks/security_experiments.py` | demonstrated |
| C2 | A captured onboarding transcript cannot be replayed (G2) | Sec. VI G2 (l.236); Sec. IX (l.377) | executed experiment | `results/security_experiments.json` (E6) | same as above | demonstrated |
| C3 | A transcript is not reusable under a different checkpoint | Sec. VIII (l.329); Sec. IX | executed experiment | `results/security_experiments.json` (E7) | same as above | demonstrated |
| C4 | A returning Controller never accepts a lower version/epoch/sequence (G3) | Sec. VI G3 (l.239); Sec. IX (l.386) | executed experiment | `results/security_experiments.json` (E1, E2) | same as above | demonstrated |
| C5 | Strong first contact requires a *q*-of-*n* witness quorum (G4) | Sec. VI G4 (l.242); Sec. IX (l.390) | executed experiment | `results/security_experiments.json` (E12) | same as above | demonstrated |
| C6 | Witness quorum bounds freshness but does **not** prove global latestness; an old-but-time-valid endorsed checkpoint **is** accepted | Sec. VI (l.255); Sec. IX (l.396); Limitation 4 (l.617) | executed experiment | `results/security_experiments.json` (E3) | same as above | demonstrated (honest negative result) |
| C7 | A checkpoint beyond the acceptance window is rejected | Sec. IX (l.396) | executed experiment | `results/security_experiments.json` (E3b) | same as above | demonstrated |
| C8 | Bounded staleness: grace interval governs behaviour when the log is unreachable (G5) | Sec. VI G5 (l.245); Sec. IX (l.396) | executed experiment | `results/security_experiments.json` (E13, E14) | same as above | demonstrated |
| C9 | An individual device can be revoked or suspended without disabling the class (G6) | Sec. VI G6 (l.248); Sec. IX (l.400) | executed experiment | `results/security_experiments.json` (E4, E5, E9) | same as above | demonstrated |
| C10 | Emergency suspension withdraws installed policy and denies new joins | Sec. IX (l.400); Sec. XIII (l.586) | executed experiment | `results/security_experiments.json` (E15) | same as above | demonstrated |
| C11 | Equivocation is **detectable**, not prevented (G7) | Sec. VI G7 (l.252); Sec. IX (l.405) | executed experiment | `results/security_experiments.json` (E11) | same as above | demonstrated |
| C12 | A leaked FIDEM class secret enables class-wide impersonation | Sec. IX (l.409); Tab. II | executed experiment | `results/security_experiments.json` (E8) | same as above | demonstrated |
| C13 | A leaked ORBIT-MUD device key compromises only that identity, until revoked | Sec. IX (l.409) | executed experiment | `results/security_experiments.json` (E9, E10) | same as above | demonstrated |
| C14 | Schnorr proof soundness (an adversary without *k_i* cannot produce an accepting response except with negligible probability) | Sec. IX (l.377) | cryptographic assumption + construction | — | — | analytically-derived |
| C15 | Merkle inclusion/consistency proofs bind a unique log state (collision resistance of SHA-256) | Sec. VII (l.264); Sec. XIV (l.599) | standard argument, kept outside the symbolic model | `src/common/merkle.py` | `python3 -m pytest tests/ -q` (structural self-tests) | analytically-derived |
| C16 | Canonical length-prefixed encoding makes field boundaries unambiguous and prevents cross-type collisions | Sec. V (l.199); Sec. VIII (l.303) | construction + unit test | `src/common/encoding.py`, `tests/test_all.py` | `python3 -m pytest tests/ -q` | demonstrated (structural) |
| C17 | RFC 6962 consistency-proof verification is correct | Sec. VII (l.264) | exhaustive self-test over all size pairs ≤ 65 | `src/common/merkle.py` | `python3 -m pytest tests/ -q` | demonstrated |
| C18 | The Controller trusts a manufacturer public-key registry | Sec. V (l.199) | stated trust assumption | `configs/deployment.json` | — | assumed |
| C19 | Witnesses are honest-majority w.r.t. the quorum *q* | Sec. V (l.199); Limitation 2 | stated trust assumption | — | — | assumed |
| C20 | Manufacturer signing-key compromise is not prevented, only auditable | Sec. V (l.199); Limitation 3 | scope statement | — | — | limitation |
| C21 | A transparent real-time relay is not addressed | Limitation 6 | scope statement | — | — | limitation |
| C22 | No privacy/anonymity of device identity is provided | Limitation 7 | design consequence (explicit registry) | `src/lifecycle_log/log.py` | — | limitation |

## 2. Performance and size claims

All numbers enter the manuscript through `\newcommand` macros in
`paper/results_macros.tex`, which is generated from the result files. No
performance number is typed into `main.tex` by hand.

| # | Claim | Section / line | Macro | Source file | Generating command | Status |
|---|---|---|---|---|---|---|
| P1 | Device proof generation median 0.62 ms (95% CI 0.63–0.64) | Sec. XII (l.470); Tab. III | `\devProofGen`, `\devProofGenCI` | `results/summary_results.csv` | `python3 experiments/benchmark.py` | demonstrated |
| P2 | Controller Schnorr verification median 2.65 ms | Sec. XII; Tab. III | `\ctrlVerify` | `results/summary_results.csv` | same | demonstrated |
| P3 | Membership-proof generation median 0.89 ms | Tab. III | `\memGen` | `results/summary_results.csv` | same | demonstrated |
| P4 | Membership-proof verification median 0.0074 ms | Sec. XII; Tab. III | `\memVerify` | `results/summary_results.csv` | same | demonstrated |
| P5 | Returning-Controller onboarding median 9.66 ms | Sec. XII; Tab. III | `\returning` | `results/summary_results.csv` | same | demonstrated |
| P6 | First-contact onboarding median 17.45 ms | Sec. XII; Tab. III | `\firstContact` | `results/summary_results.csv` | same | demonstrated |
| P7 | 200 repetitions per latency metric; 95% bootstrap CI (2000 resamples) | Sec. XI (l.443) | `\nRuns` | `results/raw_results.csv` | same | demonstrated |
| P8 | Device Discover payload 132 B, Request 84 B, total 282 B | Sec. XII; Tab. IV | `\orbitDiscover`, `\orbitRequest`, `\orbitTotal` | `results/sizes.csv` | same | demonstrated |
| P9 | FIDEM-spec Discover 85 B; RFC 8520 MUD string 47 B; URL 42 B | Tab. IV | `\fidemDiscover`, `\rfcMud`, `\mudUrlLen` | `results/sizes.csv` | same | demonstrated |
| P10 | Device-side payload is fixed-size and independent of *N*; each option ≤ 255 B; each message < 576 B | Sec. XII (l.510) | — (byte-level check) | `results/sizes.csv` | same | demonstrated |
| P11 | Merkle proofs are Controller↔log traffic, **not** carried in DHCP | Sec. XII (l.510) | — | `src/device/device.py`, `src/controller/controller.py` | code inspection | analytically-derived |
| P12 | Membership proof grows 224 B (7 nodes) → 544 B (17 nodes) for *N* = 10²→10⁵ | Sec. XII (l.540); Fig. 2 | `\memBytesSmall`…`\popLarge` | `results/scalability.csv` | same | demonstrated |
| P13 | Membership verification < 12.85 µs even at *N* = 10⁵ | Sec. XII (l.540) | `\memVerifyLargeUs` | `results/scalability.csv` | same | demonstrated |
| P14 | 92–99 sequential joins/s on one vCPU (serial, reported as a single-core lower bound) | Sec. XII (l.553) | `\throughputLo`, `\throughputHi` | `results/throughput.csv` | same | demonstrated |
| P15 | 16/16 security experiments matched expectation | Abstract; Sec. XII (l.458); Tab. II | `\secPass`, `\secTotal` | `results/security_experiments.json` | `python3 attacks/security_experiments.py` | demonstrated |

## 3. Figures and tables

| Artifact | Generated from | Command |
|---|---|---|
| Fig. 1 `fig_latency.pdf` | `results/summary_results.csv` | `python3 experiments/make_figures.py` |
| Fig. 2 `fig_scalability.pdf` | `results/scalability.csv` | `python3 experiments/make_figures.py` |
| Tab. II (security) | `results/security_experiments.json` → `paper/_sec_rows.tex` | see `REPRODUCIBILITY.md` §4 |
| Tab. III (latency) | `paper/results_macros.tex` | `python3 experiments/benchmark.py` |
| Tab. IV (sizes) | `paper/results_macros.tex` | `python3 experiments/benchmark.py` |
| Tab. I (properties) | qualitative comparison; each ORBIT-MUD "yes" is backed by a row in §1 above | — | 

## 4. Claims deliberately **not** made

| Non-claim | Where stated |
|---|---|
| Global latestness of Controller state in an asynchronous network | Abstract; Sec. IV (l.150); Sec. VI (l.255); Limitation 4 |
| Machine-checked formal verification | Abstract; Sec. XIV (l.599); Limitation 11; `formal/RUN_LOG.txt` |
| Embedded-hardware latency, energy, RAM, flash, or TEE results | Sec. XI (l.443); Limitation 1 |
| Organizational independence of the three witnesses | Sec. XI; Limitation 2 |
| Production MUD-manager (Kea / Cisco) deployment integration | Sec. X (l.415); Limitation 10 |
| Reuse of original FIDEM source code (unavailable; spec reproduction used) | Sec. III (l.114); Sec. X; Limitation 9 |
| Full RFC 8520 DHCP option-allocation compliance (IANA allocation required) | Limitation 8 |
| Prevention of equivocation (detection only) | Sec. VI G7; Tab. I |
| Prevention of impersonation after a device key leaks (blast-radius limitation only) | Sec. IX (l.409) |
