# Running the ORBIT-MUD ProVerif model

`orbit_mud.pv` is a symbolic model of the ORBIT-MUD admission core.
**It has not been executed in the artifact environment** (see `RUN_LOG.txt`);
ProVerif's only distribution host is outside the sandbox network allowlist.
It runs unmodified on any machine with ProVerif installed.

## Install (about five minutes)

Option A - opam (recommended):
    opam init -y && eval $(opam env)
    opam install proverif

Option B - source:
    curl -O https://proverif.inria.fr/proverif2.05.tar.gz
    tar -xzf proverif2.05.tar.gz && cd proverif2.05 && ./build

Debian/Ubuntu users may also find it via `apt install proverif` on some
releases; it is not in the Ubuntu 24.04 archive.

## Run

    proverif -in pitype orbit_mud.pv | tee proverif_out.txt

## How to read the result

Four queries are declared. Read them together:

| Query | Meaning | Expected |
|---|---|---|
| `attacker(kA)` | device private key secrecy | `cannot be proved false` -> **true** |
| `inj-event(accepted(P)) ==> inj-event(deviceRuns(P))` | per-device entitlement and replay resistance | **true** |
| `event(acceptedWithStatus(P,revoked)) ==> false` | no acceptance with revoked status | **true** |
| `event(accepted(P)) ==> false` | **vacuity check** | must be **false** (ProVerif finds a trace) |

The fourth query is the important one and is deliberately inverted. If
ProVerif reports it `true`, then acceptance is unreachable, the model is
degenerate, and the other correspondence results are vacuously true and mean
nothing. Only report the first three if the fourth is falsified.

## Why verification is a destructor here

`zkp_verify` is declared with `reduc`, so it reduces only on a well-formed
response. A model that instead declares verification as a plain constructor
and tests `result = success` against a constant makes the success branch
unreachable, which silently makes every "binding succeeded ==> ..." query
vacuous. This is worth checking in any ProVerif model of a proof-of-possession
protocol, including the baseline's.

## If a query fails

Report it. A falsified authentication query is a finding about the design and
should change the paper, not the model.
