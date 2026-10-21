# GPU day: real proof of the reviewed guest and dry-run proofs at the cap

PRODUCTION RELEASE HOLD. Every witness is public synthetic test data. No chain was
written to, and no proving network or production key was used. The only network
read was the public Base Sepolia RPC that the fork rehearsal forks from. Every
number below comes from `gpu-day.json` and `raw/`.

Date: 2026-10-21. Tools from commit `6fb38a5` (`sp1-host` and `prover-service` built
with `--features cuda`; binary hashes in `gpu-day.json`).

## Host

| | |
|---|---|
| GPU | 1× NVIDIA H100 80GB HBM3, compute capability 9.0, driver 595.91.07, host CUDA 13.2 |
| CPU / RAM | 26 vCPU and 251 GB allotted to the container (Runpod Secure Cloud pod) |
| Prover | SP1 6.1.0 `sp1-gpu-server` 6.1.0, from the `v6.1.0` release archive checked against its SHA-256 before use |
| Groth16 | the pinned circuit from `scripts/local-verification/download_clock_circuit.py`; the GPU server runs gnark on the CPU (`acceleration=none`) |
| Not | confidential computing: the GPU was not in CC mode and the host is not attested |

## The proof of the reviewed fixture

`clock-proof --elf contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf OUT --prove`
proved the normal fixture under the reviewed guest. Its outputs are committed in
`contracts/integration/fixtures/clock-pkg3-verified/`.

- Before proving, it checked native == guest on the fixture, the nine case witnesses
  and the 22 negatives.
- The Groth16 proof took 78.2 s of wall time. Of that, about 25 s was the one-time
  circuit load: R1CS 21.2 s and proving key 4.0 s. The gnark proof itself took 37.8 s.
- The SP1 SDK verifier accepted the proof.
- `real-clock-proof/` holds the `verify_clock_proof.py` run on it: all 24
  real-verifier Solidity checks pass, `real_proof_status` is `PROVEN` and
  `proof_matches_reviewed_guest` is true.

## Dry-run proofs

`prove-witness` proved each witness end to end (Groth16 unless noted). It checked
native == guest before proving and SDK verification after, then kept no proof file.

- **Wall time** is the whole proof: core, recursion and wrap on the GPU, plus Groth16.
- **Cold load.** The first proof of each process also loads the Groth16 circuit, about
  20–25 s. Those proofs are marked *cold*.
- **Case witnesses.** The nine case witnesses are the files in
  `contracts/integration/fixtures/clock-pkg3-reviewed/cases/`.
- **Cap witnesses.** These come from `measure-history --witness-dir`, with the measurement
  gate's shapes. History is `H`; there are `H/5` notes and `H/10` positions over 4
  markets. The local execution records are in `raw/cap-measure-*.json`.

| Witness | Cycles | SP1 gas | Wall time |
|---|---:|---:|---:|
| 9 case witnesses, 0.25–5.8 M cycles | | | 44.4–57.7 s (cold first: 68.7 s) |
| 5 lifecycle witnesses, 0.27–16.8 M cycles | | | 46.5–55.4 s (cold first: 69.4 s) |
| phase0, H = 13,280 | 101,771,486 | 153,645,768 | 66.7 s |
| phase1, H = 13,280 | 92,280,122 | 144,421,353 | 69.8 s |
| phase1-haircut, H = 13,280 | 129,942,028 | 188,853,499 | 97.1 s (cold) |
| phase1-haircut, H = 26,560 | 263,319,293 | 380,055,050 | 153.7 s (cold) |
| phase1-haircut, H = 53,120 | 533,028,720 | 777,691,858 | 186.2 s |
| phase1-haircut, H = 79,680 | 807,423,472 | 1,175,976,130 | 281.6 s (cold) |
| phase1-haircut, H = 106,240 | 1,081,722,393 | 1,584,210,596 | 320.2 s |

The compressed proof stops before the wrap; it shows the GPU stages alone. For
phase1-haircut it took:
- 37.7 s (cold) at H = 13,280;
- 69.5 s at H = 26,560;
- 133.6 s at H = 53,120.

The gap between the compressed and Groth16 times (about 50 s with the circuit loaded)
is the shrink, the wrap and gnark.

## The admission cap, re-derived (recommendation; not adopted here)

The measurement gate (`docs/audits/2026-10-19-pkg3-measurement-gate/`) admits a size
only when its costliest batch fits half of the 900 s prover budget: `T(H) <= 450 s`.
It had no GPU rate, so it assumed 1,000,000 cost-equivalent cycles/s plus a 250 s
wrap. That gave `MAX_PROVABLE_HISTORY` = 13,280, which the gateway uses today.

Measured on this host:
- At H = 13,280 the costliest batch (phase1-haircut) took **97.1 s** cold, against the
  gate's assumed 449 s.
- At **H = 106,240** (8× today's cap; 1.08 billion cycles) it took 320.2 s with the
  circuit already loaded. Adding the measured 25 s load gives about **345 s** cold.
  That is inside 450 s, with about 23% headroom.
- Between 13,280 and 106,240 the cold-equivalent time grows about 0.26 s per million
  cycles, so the measured rate is about 3.8 M cycles/s.

The largest measured size that fits is therefore H = 106,240. With the gate's ratios
that gives:

| Bound | Hard | Soft (80%) |
|---|---:|---:|
| `MAX_PROVABLE_HISTORY` | 106,240 | 84,992 |
| `MAX_POSITIONS` | 10,624 | 8,500 |
| `MAX_NOTES` | 21,248 | 16,999 |

The gate measured phase0 and solvent phase1 as cheaper than phase1-haircut at every
size; that holds at H = 13,280 here. Larger sizes were not proven, so this
recommendation does not extrapolate past 106,240.

This PR leaves `crates/gateway/src/admission.rs` unchanged. Adopting the new bounds is
a policy change with its own PR. Before that, two measurements are worth having:
- one on the CC-mode prover host the alpha will use, because CC adds overhead and the
  CPU that runs gnark differs;
- several runs of each size, to get a p95.

## Prover service on the GPU (design step 20)

`prover-service` was built with `--features cuda` and the reviewed guest ELF, then
started with `PROD=0 DEV_INSECURE=1`.
- `GET /identity` reported ELF `a6d51648…`, program key `0x009cfc02…` and
  `supported_witness_domains` `["DPCLK4"]`.
- `POST /prove` with the `seal-client` witness, sealed to the service's root, returned
  200 with a Groth16 proof (selector `4388a21c`) in 78.9 s.
- The 422 refusal of non-`DPCLK4` bodies is covered by the service's unit tests
  (`cargo test --manifest-path crates/prover-service/Cargo.toml`, run locally: 30
  passed, 2 ignored).

## Deploy rehearsal on a Base Sepolia fork

`base-sepolia-fork-rehearsal/` repeats the deploy on a local Anvil fork of Base
Sepolia, now that the status is `PROVEN`:
- the launch policy values;
- our own SP1 verifier and gateway;
- a genesis root printed by the built gateway (`--print-genesis-root`) for a synthetic
  recipient and oracle address.

Its steps:
1. `deploy_clock_stack.py` deployed the seven contracts.
2. `release_manifest.py create`, which refused while the status was pending, passed.
3. `observe-target` with `--require-operator-policy` reported
   `VERIFIED_AT_FINALIZED_BLOCK`.

Anvil's public development accounts signed. Nothing was sent to Base Sepolia.

## Files

| File | Content |
|---|---|
| `gpu-day.json` | Host, tools and binary hashes, the fixture proof and every dry run |
| `raw/*.json` | The `prove-witness` records, `measure-history` records of the cap witnesses, and prover-service responses |
| `raw/*.log`, `raw/timeline.txt` | The runs' logs (ANSI colour removed) and their start and end times |
| `real-clock-proof/` | `verify_clock_proof.py` evidence for the committed proof |
| `base-sepolia-fork-rehearsal/` | The fork rehearsal's config, public config, deployment record, manifest and observation, and its script |

## Not verified

- Each size was proven once, on one host. There is no p95, and peak memory was not
  recorded.
- The prover was not in CC mode, and no attestation was involved.
- No proof was submitted to a public chain.
- The phase-1 sink leaf was not claimed on a fork with a real proof.
