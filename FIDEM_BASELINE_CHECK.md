# FIDEM baseline: cross-check against the released implementation

Checked 23 August 2026. Repository: https://github.com/aleLtt/FIDEM
(HTTP 200; default branch `main`). It was unreachable (404) on 1 August 2026,
which is why earlier drafts described it as unavailable; that statement has
been corrected throughout the manuscript.

## Contents of the release
- `IoT Device - ESP32/`, `IoT Device - ESP32_TEE/` : device firmware (C, ESP-IDF)
- `MUD_Controller/` : C++ MUD Controller, Kea DHCP hooks, OpenSSL crypto
- `ProVerif/` : formal model
- `kea_wrapper.py`

## Cross-check against our B2 reproduction
| Property | Released code | Published Fig. 3 | Our B2 |
|---|---|---|---|
| Curve | secp256r1 (`crypto_utility.cc:116`, `NID_X9_62_prime256v1`) | EC, G, n | secp256r1 |
| Hash | SHA-256 | `Hash(h) mod n` | SHA-256 |
| Verification | `z*G ?= A + e*Xc` (`cu_ec_sigma_verify`) | `Z*G = R + H*Xc` | `zG = R + hXc` |
| Credential | class public key `Xc` | class key `Xc`, secret `Kc` | class-wide `Kc` |
| Challenge inputs | `A, Xc, C, URL, device_id` (`cu_ec_compute_challenge_e_with_url`) | `[R || Xc || C || URL]` | both variants (B2, B2') |

## Discrepancy found and tested
The released controller binds a **device identifier** into the challenge; this
input does not appear in the published message sequence (Fig. 3). We
implemented the released variant as B2' (`FidemDeviceRel`, `b2rel_verify`) and
tested it in experiment **E21**.

Result (`results/security_experiments.json`):
```
spoofed_victim_id_accepted=True; own_id_accepted=True; fig3_variant_accepted=True
```
An adversary holding only the class secret `Kc`, with no device key at all, is
accepted while claiming a victim's device identifier. Identifier binding is not
authenticated by any per-device secret, so entitlement remains class-level
however the challenge is composed. Experiment E8 is therefore unaffected, and
E21 extends it to the stronger released variant.

## Structural observations on Fig. 1 and Fig. 3
1. The verification key `Xc` is read from the MUD file located at the URL the
   device itself emits (Fig. 1 steps 1-4; Fig. 3 step 2). The proof establishes
   membership of whichever class the presented file declares; the manufacturer
   signature attests authenticity, not currency.
2. The challenge binds no profile version, credential epoch, or device status,
   so a validly signed but superseded profile yields an equally valid binding.

## Why we did not execute the release
Methodological: configurations B1-B5 are implemented on one common substrate
(one language, one EC library, one host) so that measured differences are
attributable to protocol structure rather than to language, compiler, or
runtime. Running a separately engineered codebase alongside them would not
sharpen the security comparison.
