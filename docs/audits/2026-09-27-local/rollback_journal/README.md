# S4-03: configured journal failures stop settlement progression

The live settlement loop previously logged failed stage-1 and stage-2 rollback-journal writes and continued. With configured persistence, a settlement could therefore reach proving or settlement broadcast without an acknowledged recovery record.

The patch introduces the shared `after_settle_journal` barrier in `main.rs`. Its continuation runs only after `rollback_journal::write` succeeds. Stage 1 rolls the sealed witness and drained withdrawals back in memory, requests a new snapshot and skips that attempt when the write fails. Stage 2 wraps the actual `settle_proved` continuation; write failure maps to the existing `ProveFailed` branch, which rolls back before settlement broadcast, feeds the settlement circuit breaker/backoff and keeps the journal. The unconfigured `None` path is deliberately unchanged; it is not durable evidence. `rollback_journal.rs` only receives a documentation correction for this change; its pre-existing bounded-read edit is preserved.

## Negative control and closure

The two live writes were first extracted into the shared continuation helper while retaining their original **log-and-continue decision**. This was the failed-before subject, recorded by `../checks/journal-guard-failed-before.json`; it was not an untouched base checkout. The tests executed the helper with real temporary filesystem failures, not source-text/regex assertions:

| Case | Real setup / assertion | Before | After |
|---|---|---|---|
| Stage 1 | Parent component is a regular file (`ENOTDIR`); proving callback must not run | Callback ran; assertion failed | Error propagated; callback not reached; sentinel unchanged |
| Stage 2 | Valid stage-1 journal renamed to a legal 240-character filename; exclusive temporary suffix exceeds filesystem name limit (`ENAMETOOLONG`) | Broadcast callback ran; assertion failed | Callback not reached; original bytes unchanged; retained journal decrypts with `prepared=None`; no leaked temp file |
| Success | Actual signed withdrawal/deposit window; read persisted stage 1 and prepared stage 2 from inside callbacks | Passed | Both callbacks run once, only after their journal state is readable |
| Persistence absent | `None` path with bounded callback | Passed | Existing explicitly unjournaled path preserved |

The long-name failure case is Unix-only and was exercised on the local macOS filesystem. It avoids permission tests that silently succeed when CI runs as root. It relies on this filesystem's filename limit, not a mocked write function.

Commands used `CARGO_TARGET_DIR=/tmp/arcora-gateway-target`:

- `cargo test --locked -p gateway settle_journal_guard -- --test-threads=1`: before **2 passed / 2 failed**, exit 101; after **4 passed**, exit 0.
- `cargo test --locked -p gateway journal -- --test-threads=1`: **12 passed**, exit 0. This selection includes the four tests above; counts must not be summed. It also covers original journal encryption/framing/read failures, recovery decision table, snapshot-before-delete ordering, live-window journal lifecycle and native replay/root consistency.
- `cargo clippy --locked -p gateway --all-targets -- -D warnings`: exit 0.

Each `../checks/journal-*.json` records full pre/post source fingerprints, the exact command, exit/counts and log SHA-256. `evidence.json` summarizes this focused patch; root's full-workspace evidence from before this patch is not relabelled as a run of the new source.

## Explicit limits

This closes the observed **continue after configured journal write failure** defect. It does not close S4-03 or certify production settlement:

- `begin_window_settle` and the independently running periodic snapshot writer are not made atomic by this patch. A process crash around the initial seal/write/rollback boundary still needs a broader snapshot-journal crash matrix.
- A failed directory fsync can occur after rename. The guard treats that as unacknowledged durability and prevents the continuation; it does not promise the old file bytes survive every possible I/O failure. Byte-preservation is demonstrated for the injected pre-rename failure.
- The callback checks use a real sealed native window and `MockProverClient` for prepared-state construction. No SP1 hardware proof, actual L1 settlement loop, RPC call, bond top-up, `cast send` or external transaction is performed. The stage-2 helper is wired around the production settlement continuation, but the full real-proof loop remains blocked by the separately recorded local prover/hardware gate.
- The existing initial bond top-up is outside this settlement-journal barrier and is unchanged. “No broadcast” here means the guarded settlement transaction, not every possible loop action.
- Persistence-off behavior remains available as before. Deployment policy must independently require the intended durable state path.

RecoveryPanel IR01 is implemented by this same agent, so its previously reported review is not renamed independent here. Its final 38 browser tests and persistent `client.credentialStorage` warning remain unchanged by this Rust-only patch.
