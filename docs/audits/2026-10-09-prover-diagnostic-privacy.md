# R08 follow-up: private prover diagnostic output guard

Status: **local regression verified; R08 remains partial and release remains HOLD.**
This follows the opened-buffer unwind wipe in the first alpha-hardening change.
It preserves the custodial alpha model, guest sources, proof statement, dependencies,
and pinned proof identity.

## Source-confirmed risk

The pinned SP1 6.1.0 CPU prove path invokes `sp1_dump` before proving. With
`SP1_DUMP=1` or case-insensitive `true`, that helper serializes `SP1Stdin` to
`stdin.bin`, writes `program.bin`, then calls `process::exit(0)`. The stdin carries
the opened private witness; an exit also bypasses the opened-buffer Drop guard.

Two other inspected switches create outputs outside the proof response:

| Configuration | Inspected pinned source | Effect |
| --- | --- | --- |
| `SP1_DUMP` | `sp1-sdk-6.1.0/src/utils.rs:11`, `src/cpu/prove.rs:99` | Serialize private stdin to disk and exit |
| `SP1_DUMP_SHARD_DIR` | `vendor/sp1-prover/src/worker/config.rs:98`, `worker/prover/core.rs:475` | Serialize execution shard records and verification keys |
| `TRACE_FILE` | `sp1-core-executor-6.1.0/src/minimal/arch/portable/mod.rs:312` | Write guest control-flow profiling traces when the optional profiling feature is enabled |

`TRACE_FILE` is a control-flow trace, not asserted to contain the complete raw
witness. The private service disallows it because guest behavior is sensitive.
The inspected SDK/source hashes are in [verification.json](2026-10-09-prover-diagnostic-privacy/verification.json).

## Change

`prover::validate_sp1_environment` refuses the output switches before private
data is released. `SP1_DUMP` may be absent, `0`, or case-insensitive `false`.
The path variables must be absent: empty, `false`, and `0` are paths, not disable
flags. Unknown and non-UTF8 values are refused. Errors name only the variable,
never its supplied value.

The service checks before SDK construction and before reading/decoding an
admitted HTTP request body. Both sealed proving entrypoints check before key
release or opening the witness. Direct `Sp1GnarkProver` construction and proving
also check before capturing worker configuration or allocating `SP1Stdin`.
The HTTP guard reports a server configuration error as 503.

## Verification

Before the guard, the new regression ran against the original `AttestedProver`
entrypoints. The enabled-output and non-UTF8 tests failed: each child observed
two key releases, including the malformed batch path, while the supplied-public
path also reached the plaintext backend. The normal configuration test passed.
This was a canary backend/key provider; no real witness or SDK dump was written.

After the guard:

- `cargo +1.99.0 test -p prover --locked`: **40 passed**, one child-only worker
  marked ignored during ordinary test discovery.
- Three privacy parent tests run **23 separate child processes**: 18 denied
  environments and five allowed environments. No process-global environment
  mutation races with other tests. Both sealed entrypoints deny before key release.
- `cargo +1.99.0 test -p prover --test privacy_environment --release --locked`:
  all three parent tests passed with optimized code, including their child cases.
- `cargo +1.99.0 clippy -p prover --all-targets --locked -- -D warnings`: passed.
- `cargo +1.99.0 fmt -p prover --check` and `git diff --check`: passed.

The exact fail-before, debug, optimized, and Clippy logs are linked by the
[machine-readable record](2026-10-09-prover-diagnostic-privacy/verification.json).
The excluded service was not locally built with the full SDK for this change;
its service hooks still require the separate CI typecheck.

## Remaining boundary

This prevents the inspected diagnostic output modes; it does not prove that all
backend scratch files or process memory are free of sensitive material. Decoded
state, `SP1Stdin` and SDK copies, seal-provider secrets, cryptographic backend
scratch, core dumps, swap, register copies, and abrupt-termination behavior still
need separate treatment. An environment guard is not protection against trusted
code changing environment variables concurrently. No real SP1 proof generation,
hardware attestation/key release, target service deployment, or forensic disk
verification was performed for this regression.
