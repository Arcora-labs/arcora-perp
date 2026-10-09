# PR #29 pre-merge execution-clock regression

Date: 2026-10-09. Baseline: `7736626e86dee8433838dbf32b89e675e31c6968`.

## Reproduced defect

Two valid funding operations at 1000 and 3000 ms, with opposite premiums, produce
live cumulative funding **-13889**. Re-stamping both to the final tick at seal
produces replayed funding **41666**. The new regression failed on the baseline
with precisely that mismatch. This is a native execution/proof-input mismatch,
not evidence of a real Groth16 exploit or an on-chain loss.

## Correction

- Never change original operation times or their signed oracle transcripts.
- Validate `batch_time_ms` as the exact maximum original op time, zero without
  clock-bearing ops. The manifest field remains a summary, not a trusted clock.
- Build the sealed window's oracle-update hashes from its actual operation log,
  so advancing the live feed cannot change a retry manifest.
- Remove the snapshot-test feed refresh that accommodated the invalid rewrite.

## Regression coverage

The sequencer spine now covers opposite-sign nonzero funding across ticks,
long windows with historical signed prices, a feed advancing before sealing and
after rollback, and incorrect maximum timestamp summaries in both directions.
The focused suite passes **29 tests** (including these three new tests).
Rust 1.99 core unit tests pass **96**, serde-witness tests pass **7**, and workspace
Clippy with `-D warnings` passes. These are overlapping test selections, not an
aggregate count. Full-workspace and CI results are reported separately on the PR.

## Remaining release blockers

The sequencer may still backdate an entire execution log and its manifest.
Independent L1 time anchoring is not implemented here. Rejection membership does
not prove rejection legitimacy. A real guest/vkey/proof/deployment match, vault
migration, custody/privacy review, and emergency-exit policy remain separate.
This change does not authorize deployment or change loss-distribution rules.
