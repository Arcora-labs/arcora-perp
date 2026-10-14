# Invocation-local withdrawal Merkle levels

PRODUCTION RELEASE HOLD. Candidate submission remains disabled.

## Scope

Base main: `93ac853e100ca042cc12c67d7f430e43f19367ca` (PR69).
Before this work, its three push workflows / 14 actual jobs were independently
confirmed SUCCESS, including strict contexts and workspace test/serde/no_std steps.
Repository rules and all previous public audit files remain unchanged.

The gateway now borrows its hashed withdrawal leaves and retains parent levels
once per preparation invocation. Every parent uses the EXISTING native
`perp_core::merkle::merkle_root` on exactly two leaves: there is no duplicate
cryptographic rule, core/guest change, protocol pin update or wire/serde change.
Unpaired nodes are promoted unchanged. Each proof walks the retained levels.
There is no shared/persistent/cross-window cache.

Root mismatch still returns BEFORE claim-map production and clock/prover callbacks.
Empty/single trees, sorted-pair ordering, duplicate-key last-insert behavior and
owner-only leaf semantics are preserved. Durable intent and recovery replays
remain separate. Retaining levels changes temporary allocation lifetimes; this
is not an RSS ceiling, allocation limit or OOM guarantee.

For n positive withdrawals, the previous gateway root-plus-path stage performed
(n+1)(n-1) native parent hashes; the new retained tree performs n-1 plus O(n log n)
path materialization. This counts only gateway claim-tree construction, not the
authoritative native replay, signatures, sealing, or actual proving.

## Functional acceptance

61 focused prover-client tests PASS / 0 FAIL / 4 opt-in diagnostics IGNORE.
The three new tests cover 234 deterministic trees and 12,195 exact path
comparisons, including empty, odd and power-of-two boundaries, distinct/repeated/
equal leaves. Every path verifies natively and duplicate-key map bytes match.

Exact immediate-PR69 copies of three prepare/prove functions are compared with
only function identifiers renamed. Their fidelity and hashes are checked.
All three existing native fixtures match in whole PreparedSettle, proof envelopes,
software-sealed witness bytes, and three legacy journal stages. Existing literal
PR68 wire/v6-journal tests also pass. Manifest and withdrawal mutations preserve
exact error precedence and callback counts. Context, transport, empty-proof and
wrong-commitment refusals remain unchanged; diagnostic-only remote roots retain
the old acceptance behavior.

Gateway all-target Clippy (-D warnings), format, SP1 pin guard and the existing
five Python result-validator tests passed on this exact source. Full local
gateway and workspace Clippy results are pending later closure at this publication cut.
The normally ignored observation tests are not counted as passes unless explicitly
executed, as recorded below.

## Build supervision failure and executable verification

The current default-release build supervisor hit its 900-second timeout and
killed Cargo. Its record is a FAILURE, not a successful Cargo build. The compiler
child subsequently completed an executable. Its compiler exit status was not
recovered. This limitation and the raw timeout records are preserved.

Before executing that file, its SHA-256, embedded public source-map checksum,
and ALL 389 mapped source file hashes were checked against the frozen source.
The observed compiler invocation used --test, opt-level 3, fat LTO, one codegen
unit and stripped debug information. Embedded build identity is self-reported
local provenance, NOT attestation or independent proof of compilation.
The verified file was copied, pinned, executed and re-hashed after observation.
No build-success claim is inferred from the timeout or from executable existence.
Clean-build CI remains an independent required acceptance gate.

An attempted debug-only fallback helper was abandoned after a Clippy constant-
assertion diagnostic. It was not merged or measured. The production/test source
was restored byte-exactly to the frozen source before release observations.
That attempt and its failure remain in the raw history; no lint was suppressed.

The verified release executable actually ran 4 correctness + 1 CPU + 3 fresh-child
RSS tests: 8 PASS / 0 FAIL / 0 IGNORE and 120 CPU samples. Entire native fixture
metadata, witness/prepared hashes, claim paths and frame lengths exactly equal
the initial baseline. The same existing parser rejects missing/duplicate samples,
zero-test results, changed source/executable and wrong fixture identities.

## Counterbalanced release observations

Initial total timings were noisy, so both pinned executables were then run in
AB/BA order across FOUR blocks. All eight explicitly invoked CPU tests passed;
960 raw CPU samples were collected. Each implementation has 20 ten-call batch
averages per fixture/phase. The table reports their thread-CPU medians in us per
WHOLE WINDOW PREPARATION CALL, not per withdrawal or user transaction.

| Pre-live notes / withdrawals | Before claim paths us | After claim paths us | Claim reduction | Before clocked prepare us | After clocked prepare us | Total reduction |
|---|---:|---:|---:|---:|---:|---:|
| 64 / 16 | 203.910 | 35.406 | 82.6% | 1337.654 | 1116.148 | 16.6% |
| 160 / 16 | 243.629 | 47.567 | 80.5% | 1836.883 | 1750.800 | 4.7% |
| 160 / 48 | 1742.944 | 127.344 | 92.7% | 3128.606 | 1733.546 | 44.6% |

These are observed medians, not guaranteed gains. CPU affinity/frequency were not
fixed. The unchanged native-replay control phase was 3.5-11.3% slower in current
runs, demonstrating residual environmental variation; small total differences
(such as 4.7%) are NOT a firm general speedup claim. The large claim-stage reduction
is the main measured result. Do not compare absolute values with a previous day's
or PR69's separate run, and do not convert them to service throughput/capacity.

CPU setup/warmup/assertions/output cleanup are excluded; input destruction and
result pushes are included. Overlapping phases MUST NOT be added. Proof callbacks
return synthetic cached bytes. No real proof, backend, verifier or chain call is
measured. This is the default performance-release executable, NOT the separate
safety-enabled release CI/deployment configuration.

The original and verified-executable runs also each contain three separate fresh-
child RSS observations. Each peak includes harness, native fixture construction,
validation and in-memory frame codecs. It is not phase allocation, service RSS,
a hard memory bound or OOM acceptance. No RSS reduction is claimed.

## Evidence and reproduction

Baseline measurement source: `189438f2e9f5f3ca6c0717d9a63500f11e6416edc5be608d7c3a447f59a5cffb`.
Current measurement source: `7f8874a7b75b8aa067e1ea36e7076c683366c3aed50ee243de434bedbaa816d7`.
Current executable: `7eb86207c8d9e27e79f810bb67910e60487c04ed54c1f41369bba6a835e14779`.
Current public source-map checksum:
`10cc8fc185e902c8c0d7dbc39a6dfcc3b85aeaf0c23836a6e2057be72b6872f3`.

source-maps.json records complete maps and literal-function hashes.
measurements.json keeps initial observations AND the counterbalanced aggregate;
no earlier unfavorable observations are hidden. raw-evidence.tar.gz contains all
raw CPU rows, commands, logs, source cut, supervision failure and execution
provenance. validation.json records every member hash/length and archive hash.
Every archived record was reopened and hash-verified before publication.
One-off orchestration scripts in the archive describe the actual execution paths.
They are historical runners, not a portable production deployment interface.

Standard clean-build reproduction with Rust 1.99.0 and Python 3.11+ on macOS:

```sh
python3 scripts/local-verification/finite_preparation_profile.py --output target/new-measurement
cargo test -p gateway --bin gateway prover_client:: --locked --offline -- --test-threads=4
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test -p gateway --bin gateway --locked --offline -- --test-threads=4
```

A build timeout must remain a failure. Do not invent a success status or silently
change codegen/safety settings to produce a comparable timing. Compare exact
fixture identities and source/binary hashes before interpreting any new run.

## Release boundary

No production cap, real DPCLK3 backend/recovery, proof/chain verification, CC/key
release, custody/restore drill or independent release approval is accepted here.
Dependency locks, core/guest source, contracts, protocol pins, wire/serde schemas,
workflows and repository rules are unchanged. Other checkouts were not edited.
All six prior production gates remain open. Full local/PR CI/normal merge/main CI
are separate later readbacks, not implied by this snapshot.
