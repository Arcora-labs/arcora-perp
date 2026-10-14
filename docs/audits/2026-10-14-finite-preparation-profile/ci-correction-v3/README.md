# Current local acceptance: CI correction v3

PRODUCTION RELEASE HOLD. Candidate submission remains disabled.
The parent README/packet is the immutable first-publication measurement cut.
This directory is the CURRENT source-bound local diagnostic acceptance.

## Correction

On first published head `584b0ca339b2c3d0b1c2ef09cf7ba77d7e0806f1`, Rust 1.99
Clippy refused the test helper's constant-size `chunks_exact(2)` under the existing
`-D warnings` policy. Both required lint/release-regression jobs failed at Clippy,
not at a protocol assertion. Their completed-job raw logs are retained in history.
The helper now uses `as_chunks::<2>()` and explicitly requires an empty remainder.
No warning suppression, dependency change, workflow/rule weakening, production
logic change, core/guest change, wire/schema change or deployment was introduced.

## Actual current-source results

Workspace/all-target Clippy, format, five Python validator tests and SP1 release
pin guard: PASS. The v3 release runner actually executes 4 correctness + 1 CPU +
3 fresh-child RSS tests: 8 PASS / 0 FAIL / 0 IGNORE, exactly 120 CPU samples.
All fixed witness/prepared hashes, counts, native claim paths and actual frame
lengths are byte-identical to the first-publication cut; this equality was checked
before packaging. Every entry in the prior 30-entry ledger was also rechecked.

Thread CPU medians are microseconds per operation (five ten-call batch averages).
RSS is one whole fresh-child peak per fixture, including construction/validation/
frame codecs, NOT a phase allocation or service memory requirement.

| Pre-live notes / withdrawals | Unproved prepare CPU (us) | Clocked cached-stub CPU (us) | Claim paths CPU (us) | Clocked JSON bytes | Whole-child RSS (MiB) |
|---|---:|---:|---:|---:|---:|
| 64 / 16 | 225.550 | 230.037 | 52.850 | 22,027 | 5.375000 |
| 160 / 16 | 364.100 | 345.692 | 54.325 | 47,377 | 5.875000 |
| 160 / 48 | 760.233 | 769.550 | 438.325 | 53,009 | 6.000000 |

Measured source: `189438f2e9f5f3ca6c0717d9a63500f11e6416edc5be608d7c3a447f59a5cffb`.
Executable SHA-256: `fa69da7790d0ce68245ed953c85e4d3195dbbb1792e2b964b99ad6dccfda2c80`.
Raw command status, logs, source map, timing grid and per-child PIDs/RSS are retained.
`source.json` names 387 covered files; source and binary were unchanged throughout
the observation. This is local provenance, not attestation or release approval.

## Full-suite chronology

The original-source serial gateway run finished with 777 PASS / 0 FAIL / 29 IGNORE;
its log/command are in history and remain bound to source
`96f6e8927c7a5fbed7598111d3d6f08e561d37d65b30d4c7291b2dfd7d80b7cf`.
The current-source full gateway run starts only AFTER the isolated v3 CPU/RSS
runner closes, using four test threads. It is still running at this publication
cut and is NOT claimed complete here. Its later result and final PR/main CI are
separate closure readbacks. The four opt-in diagnostics are normally ignored by
the full suite, but all four are explicitly executed in this runner.

## Interpretation and remaining boundaries

All measurement boundaries in the parent README still apply. These are three
finite native inputs, synthetic cached proof responses and software test seals;
no account ingress, external service, TLS, DPCLK3 backend, actual proof/verifier,
chain, CC handshake/key release, file-WAL durability or capacity/admission cap was
accepted. The actual legacy/DPCLK2 request and in-memory DPRBJL5 frame lengths are
codec observations only. CPU phases overlap and cannot be summed.

The actual compiler profile remains default performance release (opt-level 3,
debug_assertions=false, overflow_checks=false), NOT safety-enabled release CI or
a deployment configuration. Raw build artifact metadata is in build.stdout.log.
The 16-withdrawal claims have four siblings each; for 48 claims, 32 have six and
16 have five because unpaired nodes are promoted. This native behavior remains
unchanged. The next bounded investigation is reusing Merkle levels within one
preparation invocation; it has not been implemented or claimed faster here.

All six existing production release gates remain open.
