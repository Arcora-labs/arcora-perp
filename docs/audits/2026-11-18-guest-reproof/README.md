# Guest rebuild and real proof after the 2026-11-16 audit fixes

PRODUCTION RELEASE HOLD. Every witness is public synthetic test data. No chain was
written to, and no proving network or production key was used. Every number below
comes from `reproof.json`, `raw/` and `real-clock-proof/`.

Date: 2026-11-18. The audit 2026-11-16 PC-1 and PC-2 fixes changed seven pinned guest
sources in `crates/perp-core` (`engine.rs`, `error.rs`, `funding.rs`, `hash.rs`,
`merkle.rs`, `position.rs`, `state.rs`), so the reviewed guest had to be rebuilt,
re-pinned and proven again (`docs/audits/2026-11-17-security-audit-remediation/`).

## Rebuild (macOS on aarch64, Apple M4)

- `cold_rebuild_reviewed_guest.py` with the SHA-256-pinned official
  `succinct-1.93.0-64bit` compiler archive and Cargo 1.99.0, twice, each time with an
  empty Cargo home, registry and target. The first run compiled the guest and refused
  at its identity check, as it must while `REVIEWED_GUEST["elf"]` still named the
  earlier guest. With the new ELF pinned, the second run reported
  `PASS_COLD_BYTE_EXACT_REVIEWED_ELF_REBUILD`. The two ELFs were byte-identical:
  566,368 bytes, SHA-256 `3c0bbb2a…`.
- `vkey --elf` printed the setup key `0x001dba0f…` for both ELFs.
- `clock-proof --no-prove`, once per ELF, gave byte-identical outputs. Against the
  earlier guest, the normal fixture's witness and bound commitment are unchanged; the
  cases `bad-debt-treasury-adl`, `debt-top-up-prune` and `debt-top-up-next-batch`
  and the negative `deposit-in-close-only` changed with the liquidation rule, and
  every cycle count moved (the fixture: 5,751,985 cycles).
- `check_reviewed_guest_execution.py` (the CI "reviewed guest execution (CPU)" job)
  passed, and so did the funds-lifecycle replay of the four exact wallet witnesses
  on the new ELF (`verify_funds_replay.py`, `replay-funds`).

## Proof (Google Colab, 1× NVIDIA L4)

`clock-proof --elf contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf OUT --prove`,
built with `--features cuda`, on SP1 6.1.0's `sp1-gpu-server` from the `v6.1.0`
release (archive and binary checked against the pins in `reproof.json`) and the
Groth16 circuit verified by `download_clock_circuit.py`.

- It checked native == guest on the fixture, the nine cases and the 22 negatives,
  then generated the proof and verified it with the SP1 SDK verifier.
- The Groth16 proof took 110.6 s of wall time: about 32 s of circuit loading
  (R1CS 27.4 s, proving key 4.2 s) and 48.2 s in the gnark prover, for 15,972,262
  constraints. Setup took 5.5 s.
- The L4 has 23,034 MiB, just under the 24 GB the runbook names; it was enough for
  this fixture. Nothing here measures larger witnesses on it.
- The image ships CUDA 13 only. The server links `libcudart.so.12`, which came from
  NVIDIA's `nvidia-cuda-runtime-cu12` 12.9.79 wheel preinstalled on the image,
  prepended to `LD_LIBRARY_PATH` ahead of the driver directory (replacing the
  variable instead fails with "CUDA driver version is insufficient").

The outputs are committed in `contracts/integration/fixtures/clock-pkg3-verified/`
(proof SHA-256 `0ff6c29f…`). `raw/` keeps the run's log and evidence record.

## Real-verifier check

`real-clock-proof/` holds the `verify_clock_proof.py` run on the committed proof:
all 27 real-verifier Solidity checks pass (`SP1RealVerifierGuardTest` 10,
`SP1RealProofTest` 11, `ClockBoundRealProofTest` 6), `real_proof_status` is
`PROVEN` and `proof_matches_reviewed_guest` is true.

## Not done

- No case, cap or lifecycle witness was proven; CI executes them on CPU.
- The GPU was not in confidential-computing mode and the host is not attested.
- No target settlement accepted the proof on a chain, and no deployed stack uses the
  new setup key yet: the redeploy the audit's SV-1 item requires is still open.
