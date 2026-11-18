# Guest rebuild and real proof after the 2026-11-16 audit fixes

PRODUCTION RELEASE HOLD. Every witness is public synthetic test data. No chain was
written to, and no proving network or production key was used. Every number below
comes from `reproof.json`, `raw/` and `real-clock-proof/`.

Date: 2026-11-18. Two changes on the audit-remediation branch changed pinned guest
sources, so the reviewed guest was rebuilt, re-pinned and proven again
(`docs/audits/2026-11-17-security-audit-remediation/`):

- the audit 2026-11-16 PC-1 and PC-2 fixes in `crates/perp-core` (`engine.rs`,
  `error.rs`, `funding.rs`, `hash.rs`, `merkle.rs`, `position.rs`, `state.rs`);
- the move from k256 0.13 to k256 0.14 (RUSTSEC-2026-0387: k256 0.13 rests on
  crypto-bigint 0.5, whose constant-time operations could branch on secret data),
  which changed `crates/perp-core/Cargo.toml`, `crates/perp-core/src/oracle.rs` and
  `crates/sp1-guest/Cargo.lock`. ecdsa 0.17's `recover_from_prehash` no longer
  re-verifies the signature; `OracleSig::recover` now verifies against the recovered
  key itself, which keeps the high-`s` refusal ecdsa 0.16 performed
  (`crates/perp-core/tests/oracle_sig_malleability.rs`).

An intermediate rebuild and proof of the same day, made before the k256 upgrade
(ELF `3c0bbb2a…`, proof `0ff6c29f…`), was replaced on the branch and never merged.

## Rebuild (macOS on aarch64, Apple M4)

- `cold_rebuild_reviewed_guest.py` with the SHA-256-pinned official
  `succinct-1.93.0-64bit` compiler archive and Cargo 1.99.0, twice, each time with an
  empty Cargo home, registry and target. The first run compiled the guest and refused
  at its identity check, as it must while `REVIEWED_GUEST["elf"]` still named the
  earlier guest. With the new ELF pinned, the second run reported
  `PASS_COLD_BYTE_EXACT_REVIEWED_ELF_REBUILD`. The two ELFs were byte-identical:
  544,920 bytes, SHA-256 `151afdba…`.
- `vkey --elf` printed the setup key `0x00a64436…` for both ELFs.
- `clock-proof --no-prove`, once per ELF, gave byte-identical outputs. Against the
  guest before the audit, the normal fixture's witness and bound commitment are
  unchanged; the cases `bad-debt-treasury-adl`, `debt-top-up-prune` and
  `debt-top-up-next-batch` and the negative `deposit-in-close-only` changed with the
  liquidation rule. The k256 0.14 guest is cheaper: the fixture takes 3,812,229
  cycles (5,751,985 on k256 0.13), so the admission caps measured on the earlier
  guest stay conservative.
- `check_reviewed_guest_execution.py` (the CI "reviewed guest execution (CPU)" job)
  passed, and so did the funds-lifecycle replay of the four exact wallet witnesses
  on the new ELF (`verify_funds_replay.py`, `replay-funds`).

## Proof (Google Colab, 1× NVIDIA A100 40 GB)

`clock-proof --elf contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf OUT --prove`,
built with `--features cuda`, on SP1 6.1.0's `sp1-gpu-server` from the `v6.1.0`
release (archive and binary checked against the pins in `reproof.json`) and the
Groth16 circuit verified by `download_clock_circuit.py`.

- It checked native == guest on the fixture, the nine cases and the 22 negatives,
  then generated the proof and verified it with the SP1 SDK verifier.
- The Groth16 proof took 102.4 s of wall time: about 32 s of circuit loading
  (R1CS 27.8 s, proving key 4.2 s) and 48.1 s in the gnark prover, for 15,972,262
  constraints. Setup took 7.7 s.
- The circuit archive was fetched over 16 parallel connections (one connection from
  this VM ran at about 2 MB/s) and then checked by `download_clock_circuit.py`'s own
  verification: the archive's SHA-256 and size and each extracted file's size and
  SHA-256.
- The image ships CUDA 13 only. The server links `libcudart.so.12`, which came from
  NVIDIA's `nvidia-cuda-runtime-cu12` 12.9.79 wheel preinstalled on it, prepended to
  `LD_LIBRARY_PATH` ahead of the driver directory (replacing the variable instead
  fails with "CUDA driver version is insufficient").

The outputs are committed in `contracts/integration/fixtures/clock-pkg3-verified/`
(proof SHA-256 `81239e2e…`). `raw/` keeps the run's log and evidence record.

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
