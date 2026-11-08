# ORBIT-MUD reference artifact v2 after reviews

This is the self-contained reference implementation measured in the accompanying revised manuscript. It implements the paper's C1–C11 admission path, authenticated software-policy revalidation, session-scoped retransmission rules, durable controller state, incremental status trees, append-only history proofs, and an optional static-view three-of-four finalizer.

It is a **new protocol-reference revision**, not a byte-compatible patch of the earlier public repository, not a production MUD controller, and not an audited cryptographic SDK. The newly measured native-curve results must not be described as reproductions or speedups over the earlier Python/ecdsa results.

## Environment

The recorded run used Python 3.13.5, cryptography 46.0.4, an AMD EPYC 9V74 host, Linux x86-64, and system OpenSSL 3.5.5. See `results/environment.json` for the actual execution environment. Native point arithmetic loads system `libcrypto.so.3` through ctypes; a Linux OpenSSL 3 installation is required. No GPU or constrained board is required or used.

Create an isolated Python environment, install `requirements.txt`, and run commands from this directory. Keep this directory and the sibling `paper/` directory together to rebuild the complete package.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

## Reproduce measurements from a fresh output directory

```sh
python run_all.py --runs 200 --out reproduced_results
python build_paper_assets.py --results reproduced_results --paper ../paper
cd ../paper
latexmk -pdf main.tex
```

A fresh output directory avoids mixing a new run with recorded metadata. The manuscript distributed here uses `results/`, not `reproduced_results/`. Run `python build_paper_assets.py --results results --paper ../paper` to restore the distributed tables and plots. A new experiment may change rounding, signature-encoding lengths, and page layout; recheck the page limit after rebuilding with new measurements.

`run_all.py` stops if a command fails. It launches tests and each benchmark family in a fresh process, writes command logs, and records source hashes in `execution_manifest.json`. `--quick` reduces tree/network workloads for a smoke check; **quick results are not the published results**. Running `experiments.py --section ...` is also supported for a single family.

For a source-only Overleaf upload, the generated figures/tables are already present; Python execution is unnecessary for compilation. The tested build used the unmodified LNCS class and `splncs04` bibliography style. On systems where the executable is named `bibtex.original`, run it in place of `bibtex` or set the local latexmk command accordingly; that naming issue is specific to the execution environment, not an Overleaf requirement.

## What was actually executed

- 60 passing pytest cases, including exhaustive small-tree inclusion/prefix checks inside a case.
- 30 observed security decisions across B1–B6 and five scenarios.
- 200 observations per admission/local-operation timing condition, with median confidence intervals computed from 4,000 bootstrap resamples.
- Five status populations through 1,000,000 synthetic leaves and five history lengths through 100,000 entries; 100 operation repetitions per size, one descriptive build per size.
- Four spawned validator processes with separate SQLite stores, real loopback TCP, and 30 finalization rounds for each injected server-delay setting (0, 2, 10 ms per RPC).
- Actual process termination: one unavailable validator permits the honest-proposer path; two unavailable validators fail closed.
- Seven batching factors, with 200 local anchor-verification observations per factor.
- Generated DHCP/IPv4/UDP packet fixtures for URL lengths 42, 128, 240, and 255 bytes, exported as `synthetic_dhcp.pcap`.

The packet file is **synthetic serialized traffic**. Protocol fixtures use a fixed logical time; elapsed execution measurements use `perf_counter_ns`. Byte counts distinguish option payloads, TLV fields, DHCP bodies, IP/UDP datagrams, binary header/certificate accounting, and JSON transport.

## Safety and trust boundaries

The PEP is a software policy map with an access predicate and lease expiry, not a switch driver. `open_session(handle)` is a trusted local API. A production deployment must bind this API to an actual protected port or authenticated link session; hashing an arbitrary MAC address is not sufficient.

The finalizer uses durable prepare locks, three distinct prepare/commit signatures among four configured validators, a pinned chain/membership, finalized-parent validation, and lifecycle-prefix checking. Under at most one faulty signer and intact honest locks it provides the safety argument described in the paper. **There is no view change, dynamic membership, automated catch-up, or Byzantine liveness guarantee.** A malicious proposer can halt progress. The RPC interface is a local experiment, without TLS or production hardening.

SQLite/HMAC snapshots detect unauthorized editing, not replay of an authentic old database. `MemoryFloor` is a test model of a separately protected monotone reference; it is not hardware protection. Missing/corrupt state fails closed unless explicit bootstrap is requested.

ECDSA/profile fixtures use a canonical signed envelope, not a CMS parser or a complete MUD policy compiler. Schnorr scalar computations include Python operations and are not claimed constant-time. Fixture keys, integrity-key constants, URLs and identities are synthetic and must never be reused as production credentials. Controller session caches are reference structures, not a memory-bounded production anti-DoS implementation.

No constrained-device RAM/flash/energy experiment, formal protocol verification, real switch enforcement, hospital deployment, wide-area consensus test, or organizational independence experiment was performed. These are not hidden in the reported software metrics.

## Main files

`orbit/controller.py` implements admission/revalidation; `orbit/ledger.py` implements validators and anchor verification; `orbit/storage.py` implements snapshots; `orbit/merkle.py` implements both trees; `orbit/model.py` defines canonical objects and fixtures; `orbit/wire.py` defines the private-use option encoding; `orbit/network.py` runs the validator processes. Tests are in `tests/test_revision.py`; `experiments.py` records raw results and summaries.

The distributed results contain the actual final run logs and JUnit report. `execution_manifest.json` authenticates the recorded source selection by hashes, not by an external attestation service. `MANIFEST.sha256` in the release identifies all distributed files; it is a file-integrity aid, not a security certificate.
