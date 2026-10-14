# Finite native preparation diagnostics, 2026-10-14

PRODUCTION RELEASE HOLD. Candidate submission remains disabled.
This is the bounded follow-up proposed in the PR68 handoff, not an admission,
throughput, real-proof, candidate-backend, CC, or production release acceptance.

## Scope and inputs

Test-only code starts with the unchanged PR65 funded native Sequencer golden
`docs/audits/2026-10-14-seal-window-ownership/baseline-export/normal-00-before_first_seal_seq.bin`.
A setup window creates 64 or 160 live notes using value-preserving native Unbind
operations. A separately sealed measured window contains one signed historical
funding tick and 16 or 48 native withdrawals. Counts describe the PRE-state; the
post-state contains 48, 144 or 112 live notes. There is no account/API ingress,
new fabricated deposit, gateway boot, live oracle, network or chain transaction.
All signing and software-seal keys are fixed test material.

The test verifies actual post-state bytes against the live native Sequencer,
whole PreparedSettle bytes, all native claim paths, exact legacy/clocked cached
proof envelopes, deterministic reconstruction, and immutable witness inputs.
Committed recipient, amount, nonce and dropped-withdrawal mutations are refused
before clock or prover callbacks. Sorted-pair odd-node promotion is preserved:
16 claims each have four siblings; for 48 claims, 32 have six and 16 have five.

## Observed local results

Apple M4, macOS 26.5.1, Rust 1.99.0. Thread CPU medians below are microseconds per
operation, computed from five ten-call batch averages. There are eight phases,
three fixed fixtures and exactly 120 CPU samples. Wall time is recorded separately.

| Pre-live notes / withdrawals | Unproved prepare CPU (us) | Clocked cached-stub prepare CPU (us) | Claim-path CPU (us) | Clocked JSON request bytes | Whole-child peak RSS (MiB) |
|---|---:|---:|---:|---:|---:|
| 64 / 16 | 224.121 | 228.200 | 52.233 | 22,027 | 5.375000 |
| 160 / 16 | 330.396 | 334.321 | 52.396 | 47,377 | 5.812500 |
| 160 / 48 | 739.146 | 743.758 | 425.983 | 53,009 | 6.046875 |

`summary.json` contains every phase's median/min/max, all actual frame lengths,
claim-path lengths and exact witness/prepared SHA-256 identities. These are NOT
p95/p99 latency observations. The proof callback supplies 32 synthetic cached
bytes, not a proof accepted by any verifier.

CPU setup, warmup, output assertions and output destruction are outside timing;
input destruction and result-vector pushes are inside. The clocked callback's
context equality check and atomic counters are inside. Phases overlap and MUST
NOT be added to estimate end-to-end latency. The in-memory software-seal/hex phase
is separate from prepare and does not exercise TLS or any remote service.

RSS uses `os.wait4` for each exact freshly exec'd child PID, not cumulative
RUSAGE_CHILDREN. The current macOS getrusage manual defines ru_maxrss in bytes;
MiB is bytes / 1048576. One RSS child/sample is recorded for each fixture, with
three distinct PIDs. Each peak includes the test harness, fixture construction,
correctness checks, cached callbacks and frame roundtrips. It is NOT the allocation
of a preparation phase, a service steady state, or an upper bound on real inputs.
No memory-growth trend or OOM safety claim is made from these single-child peaks.

The recorded performance build uses Cargo's default release profile: opt-level 3,
no debug information, debug_assertions=false and overflow_checks=false, as reported
by the actual compiler artifact in `build.stdout.log`. This is a measurement build,
NOT the separately configured safety-enabled release CI or a deployment command.

## Actual frame coverage

Lengths are measured from serialized bytes, not estimated from struct sizes:
pre-state, WindowWitness, withdrawal list, unproved PreparedSettle, legacy and
DPCLK2 plaintext, actual production software-sealed envelopes, actual JSON request
bodies, and an in-memory sealed DPRBJL5 intent journal. The production seal helper
is exercised and its envelope is byte-compared with the fixed-wire construction;
the journal is decoded by the production versioned decoder. This does not exercise
DPCLK3 candidate transport/backend, candidate archive authenticity, a file write,
fsync, durable WAL recovery, actual proving or chain verification.

## Reproduction

From the canonical repository root, put the selected Rust 1.99.0 toolchain and
Python 3.11+ on PATH. The build-identity helper requires Python 3.11+.
The output directory must not already exist; previous evidence is never overwritten.

```sh
python3 -m unittest discover -s scripts/local-verification -p test_finite_preparation_profile.py -v
python3 scripts/local-verification/finite_preparation_profile.py --output target/finite-profile-new-run
cargo test -p gateway --bin gateway --locked --offline -- --test-threads=1
cargo clippy -p gateway --all-targets --locked --offline -- -D warnings
cargo fmt --all --check
```

The macOS runner builds the release test binary itself, pins its SHA-256, executes
four correctness tests, explicitly executes the one normally ignored CPU test and
three normally ignored fresh-child RSS tests, and refuses zero-test success,
missing/duplicate/unknown CPU samples, wrong counts/path distributions, changed
input identities, changed source or changed executable. Its five Python validator
tests include malformed-grid, zero-test, boolean/numeric and metadata refusals.

The ordinary gateway suite intentionally ignores the four opt-in diagnostics;
they are separately executed by the runner. No ignored test is counted as a PASS.

## Source identity and provenance

Measured from base main `a4b35e20f377bd3ffb0f09c854fd4e1f69bb08d7`, before publication.
Measurement source map: `96f6e8927c7a5fbed7598111d3d6f08e561d37d65b30d4c7291b2dfd7d80b7cf`.
Test executable: `0c3f869427bd8b7853006822bf2ea6c10975208b129976ad61d0b256acabceda`.
`source.json` includes the existing bounded public service source inventory,
the two new diagnostic Python files and the exact reused golden. The runner checks
source/executable stability across all observations. This local diagnostic source
map is not process attestation or a cryptographic production release approval.

Only a cfg(test) registration is added to the existing prover_client module.
Production logic, core/guest source, dependency locks, workflows and protocol/wire
schemas remain unchanged. Earlier committed audit records and PR67 pointers are
not rewritten. Other local checkouts were not edited; their entire dirty bodies
were not re-hashed in this task.

## Historical failures retained

`history/initial-build.log`: the first shell selected system Python 3.9 and the
existing build-identity guard refused the build. Selecting the already installed
Python 3.14 and Rust 1.99 resolved this without weakening the guard.

`history/focused-debug.log` and `history/initial-finite-profile-tests.rs`: the first
new test incorrectly assumed six siblings for all 48 claims (3 PASS / 1 FAIL /
4 IGNORE). The test and parser were corrected for existing odd-node promotion;
production Merkle behavior was not changed. `focused-debug-v2.log` is the corrected
4 PASS / 0 FAIL / 4 deliberately ignored diagnostic run.

## Next bounded investigation, not implemented

The standalone claim-path observation rises from about 52 us with 16 withdrawals
to 426 us with 48, while the same 160-note native replay changes from about 276 to
311 us. The current gateway invokes merkle_proof separately for every withdrawal;
each invocation rebuilds the tree. This is a candidate for reusing tree levels
within one preparation invocation, not evidence that a proposed optimization works.
Any follow-up must preserve exact PreparedSettle/wire bytes, sorted-pair ordering,
odd-node promotion, rejection precedence and callback counts, with direct before/
after measurements on these exact fixtures. No production cap is introduced here.

## Acceptance boundary

Local focused Rust: 4 PASS / 0 FAIL / 4 opt-in diagnostics ignored.
Explicit release runner: 4 correctness + 1 CPU + 3 fresh-child RSS tests PASS,
0 FAIL / 0 IGNORE, with all 120 expected CPU samples. Python validator: 5 PASS.
The full local gateway regression and Clippy are still in progress at this
pre-publication cut; their later results must not be inferred from these counts.

Local results are recorded in the accompanying command logs and status JSON.
PR/main CI and normal merge are separate later readbacks, not claimed by this
pre-publication snapshot. The six existing target/backend/proof/CC/custody/
independent-release gates remain open. PRODUCTION RELEASE HOLD.
