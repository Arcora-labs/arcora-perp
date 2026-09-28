# Journal and settlement continuation — 2026-09-28

Status: focused local fixes PASS; S4-03 / S4-07 / S6-03 remain PARTIAL. No deployed contract, live chain transaction, real SP1 guest/proof, or physical crash certification is claimed.

## Changes

- `begin_journaled_window_settle` seals and durably writes stage 1 under the same `Gw` lock used to capture every snapshot. A failed write rolls the seal and drained withdrawals back before unlocking. Periodic/shutdown capture cannot persist a sealed counter without its corresponding recovery journal.
- Before replacing a previous journal, the settlement loop requires an acknowledged snapshot of the previous resolution. After every configured seal it requires another acknowledged snapshot before proving/broadcasting. This applies to all windows, including windows without deposits. Production also refuses to seal if persistence is unconfigured. The strict deposit-constructor inventory changed 9 to 8 solely because the old deposit-only persistence classifier was removed; no credit constructor was added or exempted.
- Prepared journal data means a transaction may have been broadcast. An unchanged counter, even on repeated reads or after a delay, does not authorize rollback, journal deletion, or resealing. Stage-1 recovery can still roll back because stage 2 always precedes broadcast. A later matching landed root recovers the original prepared window and its claim proofs.
- Ambiguous send failure, root disagreement, failed observation, or worker panic stops the settlement loop and retains recovery material. Health immediately becomes `HELD` with a reason and timestamp. The admin retry decision refuses this state; the HTTP handler maps it to 409 with reconciliation/restart guidance. Ordinary prover-failure backoff can still be retried. A configured unresolved, unreadable, orphaned, or undeletable journal prevents startup, even if the old settled-root continuity check would otherwise pass.
- Boot and ambiguous-send reconciliation now read counter, root, and bond at one finalized block hash, using EIP-1898 `requireCanonical`, followed by a canonical header recheck. Missing finalized support, failed reads, malformed ABI words, counter/bond overflow, changed hash, or a mismatched header height fail closed. Independent latest reads and the 15-second “absent transaction” assumption were removed from those recovery paths.
- Final shutdown capture waits for the snapshot writer's serialization lock, then retains the `Gw` guard through capture, fsync and process exit. The serialization guard belongs to the blocking filesystem worker so cancellation cannot release it while that worker still writes the shared atomic temporary file. State mutations cannot slip into the final-capture-to-exit gap.
- Gateway window sealing rejects `u64::MAX` before mutation; ambiguous-send successor comparison uses checked addition. The initial bridge counter parser no longer truncates u128 to u64.

## Focused evidence

Command:

```text
env CARGO_TARGET_DIR=/tmp/arcora-gateway-target cargo test --locked -p gateway --bin gateway journal -- --test-threads=1
```

Result: 22 passed, 0 failed, 0 ignored, 372 filtered out. Discovery/result, exact command, content hashes and captured output are in `journal-tests.json` and `journal-tests.log`. The six recorded subject files were unchanged during this check. The earlier integration compile failure is retained in `journal-before-policy-integration.*`; it observed an in-progress service-policy signature integration and is not presented as passing evidence. The root continuation lane records the full integrated gateway suite and clippy.

New fixtures exercise real encrypted journal/snapshot files and real gateway replay state:

| Test | Observed property |
| --- | --- |
| `journal_stage1_failure_rolls_back_before_snapshot_can_capture` | Failed filesystem stage 1 leaves the original counter, state root and withdrawal set; restored state remains pre-seal. |
| `journal_seal_and_snapshot_capture_share_the_state_lock` | A concurrent snapshot task cannot acquire state during seal/journal; its eventual sealed capture has a readable matching journal and can recover. |
| `journal_late_transaction_keeps_original_until_matching_landed_root` | Repeated old-counter observations preserve both pre-/post-seal state and byte-identical prepared journal; the original late transaction then rolls forward with its original claim proofs. |
| `journal_shutdown_snapshot_holds_mutations_until_exit_guard_drops` | Success and failed final persistence both retain the mutation guard; saved bytes match the frozen state. |
| `journal_window_counter_exhaustion_refuses_before_any_mutation` | Max counter does not wrap, panic or change serialized state. |
| `journal_ambiguous_hold_surfaces_health_and_refuses_admin_retry` | Terminal ambiguity reports HELD/reason/timestamp and cannot set the admin force-retry flag. This tests the shared decision helper, not an authenticated HTTP exchange. |
| `journal_recovery_hold_is_immediate_and_cleared_only_by_success` | Recovery-required hold is immediate even below the normal prove-failure threshold. |
| `journal_recovery_observation_pins_every_term_to_one_finalized_hash` | Scripted transport observes exactly the three intended selectors and one canonical hash pin, followed by the same-height header recheck. |
| `journal_recovery_observation_refuses_failure_at_every_read` | Any of the five RPC operations can fail without a successful observation or fallback. |
| `journal_recovery_observation_refuses_malformed_overflow_and_forked_data` | Missing finalized header, oversized count/bond, malformed root, changed hash and wrong height all fail. |

## Remaining limits

- Recovery favors safety over availability. A normal mined receipt may not yet be finalized; a restart or ambiguous send can remain held until a later restart observes its finalized root. A prepared-but-never-broadcast record also holds conservatively. There is no durable sender nonce/transaction-hash/replacement/receipt reconciliation that can prove non-landing and safely authorize an automatic retry. Operators must preserve journal/snapshot files; deleting the journal is not a supported recovery shortcut.
- The RPC fixtures run the real parser/observation routine through a scripted transport. They do not prove a deployed provider is honest, supports EIP-1898/finalized, or agrees with a second independent provider. No two-provider quorum is implemented.
- The tests do not kill a process at every write/rename/fsync boundary, inject device-level durability failure, or test the full cancel/fill/settle/API crash matrix. The prior-resolution and all-window ACK placement is source-inspected runtime wiring; bounded fixtures exercise the underlying journal, snapshot and state-lock behavior.
- Shutdown freezes `Gw` mutations and keeps snapshot/journal recovery consistent. It does not drain listener requests/WebSockets, wait for every accepted response, join every background task, or establish cancellation semantics for already-broadcast L1 transactions. S4-07 is not closed by this helper change.
- Native MockProverClient replay validates local roots/proofs data flow only. The blocked A06 guest verification and actual settlement-proof path were not retried, modified, or bypassed.
