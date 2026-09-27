# S4-03 / S6-03 source and existing-test coverage map

This is a bounded source review of the isolated current worktree. Names below are verified in source, not fresh execution claims by this reviewer. The parent workspace/gateway logs are the authority for discovery counts, result and final content fingerprint. No chain call, transaction, deployment or live balance was used here.

## Journal and settlement

The running path calls `begin_window_settle`, writes sealed stage-1 journal (witness plus drained withdrawals), optionally waits for a post-seal snapshot ACK on deposit-bearing windows, proves/prepares off the Gw lock, writes stage-2 journal (including prepared roots and withdrawal proofs), then broadcasts. Success commits finality/claim proofs and requests a snapshot. The settle loop retains its journal; boot recovery alone deletes it after resolving against chain counters and roots. The journal uses the same authenticated snapshot sealing and atomic write primitive.

| Observation | Decision | Existing executable coverage |
|---|---|---|
| Snapshot B=J+1, chain=J+1, persisted settled root matches | Stale journal; no state mutation | `rollback_journal::tests::recovery_action_full_matrix`, `tests::boot_recovery_roll_forward_commits` |
| Snapshot B=J, chain=J | Seal never persisted; delete journal without new mutation | Same matrix; `tests::settle_loop_journal_lifecycle` |
| Snapshot B=J+1, chain=J | Roll back sealed window and prepend drained withdrawals | Same matrix; `tests::boot_recovery_rollback_restores_reseal`, `tests::rollback_window_withdrawals_prepends` |
| Snapshot B=J+1, chain=J+1, prepared new root matches and old settled root differs | Roll forward bookkeeping and proofs | Same matrix; `tests::boot_recovery_roll_forward_commits`, `tests::the_boot_roll_forward_arm_carries_the_gate_observation_both_ways` |
| Unknown counter/root combination or missing prepared evidence | Hold, retain journal | Same matrix; hold assertion in rollback restore test |
| Missing journal | None | `rollback_journal::tests::journal_missing_is_none` |
| Wrong seed/version, batch identity mismatch | Read error, hold rather than absence | `journal_wrong_seed_fails_closed`, `journal_with_a_stale_magic_is_refused`, `journal_batch_id_mismatch_fails_closed` in `rollback_journal::tests` |
| Mutating boot recovery and failed durable snapshot write | Keep journal; persist before delete on success | `tests::boot_recovery_persists_before_journal_delete` |
| Witness serialization across journal and native replay | Same commitment/new root/withdrawal proofs/deposit count | `rollback_journal::tests::journal_seal_round_trip` (MockProverClient native replay) |
| Matched events before on-chain commit | MATCHED remains soft; later commit hardens mapped tick/window | `tests::window_mode_defers_settled_until_commit`, `tests::l1_without_a_prover_must_not_simulate_settled`, sequencer `mark_window_settled_hardens_through_window` |
| Multi-tick rollback and reseal | Same replayed live root and window map | sequencer integration `seal_window_replays_multi_tick_window_to_live_root`, `rollback_window_restores_and_reseals_to_live_root`; unit `rollback_keeps_the_window_map_correct` |
| Repeated proving failure | Backoff, held threshold and once-per-episode alert; success resets | `settle_health::tests::{first_failure_degraded_base_backoff,second_failure_exponential,third_failure_enters_held_alerts_once,backoff_never_exceeds_cap,success_resets_and_rearms_alert}` |
| Remote roots disagree / empty proof | Refuse before broadcast | `prover_client` tests `a_disagreeing_prover_is_refused`, `a_disagreeing_prover_names_the_differing_root`, `an_empty_proof_is_refused_before_broadcast` |

Open source-inspected durability/reconciliation questions:

1. CLOSED in the final local patch: stage-1/stage-2 write errors now stop the settlement continuation. Real filesystem assertions and exact limits are in ../rollback_journal/evidence.json. This does not close the remaining seal/snapshot crash boundaries below.
2. Only deposit-bearing windows wait for post-seal snapshot ACK; other windows request it asynchronously. The guide's every-crash-boundary requirement is therefore not established.
3. The ambiguous `SettleFailed` recheck performs separate unpinned batch_count/current_root reads. It holds on read failure or root mismatch, but a same-height/two-provider disagreement matrix for this specific call path is not present.
4. Counter equality at one instant does not establish that a previously broadcast transaction can never land later. A late-old-transaction after reseal scenario needs explicit pending-transaction reconciliation/fault injection before S4-03 is closed.
5. Gateway signal handling snapshots then process::exit; listener request draining and journal/write race fault injection are not covered by the test harness's own orderly shutdown.
6. Combined cancel/fill/settle/API-recovery crash races and physical process kill at each persistence boundary remain open. Native replay/mock proof is not SP1 proof or contract settlement.

## Finalized deposit intake

`VaultSource::fetch` verifies chain domain, requests `finalized` without a latest/safe fallback, uses hash-pinned contract/log reads, validates the old consumed prefix, checks whole-block boundaries/log ordering/tips, and rechecks canonical hashes. Previously credited anchor reorg or prefix mismatch becomes durable Halt; transient read failure becomes Retry without cursor advance. `apply_deposit_page` validates immutable route payer/amount/account/purpose and stages ops before committing an atomic block. No autonomous two-RPC voting/selection policy was found; provider disagreement is handled only insofar as these checks detect inconsistency.

| Vector | Existing exact test name | Evidence class |
|---|---|---|
| No finalized header | `deposit_rpc::tests::a01_missing_finalized_header_is_not_an_empty_page` | scripted RPC |
| Failure at each RPC read | `deposit_rpc::tests::a01_rpc_failure_at_each_read_never_becomes_an_empty_success` | scripted RPC |
| Wrong chain/persisted prefix/finalized anchor reorg | `deposit_rpc::tests::a01_rpc_domain_prefix_and_credited_anchor_reorg_are_durable_halts` | scripted RPC |
| Bad/missing/removed/forked/conflicting logs, UTF-8 hex | `deposit_rpc::tests::a01_rpc_malformed_removed_forked_or_conflicting_logs_fail_closed`, `a01_rpc_missing_log_and_reordered_ids_do_not_advance_prefix` | scripted RPC and validator |
| Wrong historical header number | `deposit_rpc::tests::a01_rpc_wrong_historical_header_number_is_rejected` | scripted RPC |
| Whole-block catch-up and duplicate rows | `deposit_rpc::tests::a01_rpc_pages_whole_blocks_in_canonical_order_deduplicates_and_catches_up` | scripted RPC |
| Legacy midblock restart | `deposit_rpc::tests::a01_rpc_legacy_midblock_prefix_resumes_without_skipping_or_recrediting` | scripted RPC |
| Native cast transport hash-pinned roundtrip | `deposit_rpc::tests::a01_native_cast_hash_pinned_jsonrpc_roundtrip` | ignored by default; must be explicitly run, loopback scripted JSON-RPC, not live chain |
| Duplicate commit / exhausted account counter no partial credit | `deposit_ingestion::tests::a01_counter_overflow_and_duplicate_commit_leave_no_partial_credit` | state snapshots |
| Multiple accounts credited once, strict L1 order | `deposit_ingestion::tests::a01_offline_customers_and_same_transaction_credit_once_in_l1_order` | engine fixture |
| Wrong account/market route replacement | `deposit_ingestion::tests::a01_explicit_legacy_adoption_is_owned_and_immutable` | route and engine fixture |
| Insurance never user collateral | `deposit_ingestion::tests::a01_insurance_is_never_user_collateral` | purpose fixture |
| Funding failure atomicity | `deposit_ingestion::tests::a01_atomic_second_funding_failure_preserves_every_account_and_replay_op` | full snapshot equality |
| Auto/manual confirm race | `deposit_ingestion::tests::a01_auto_and_manual_race_wait_for_durable_ack_then_credit_once` | controlled ACK fixture |
| Disk failure then restart without double credit | `deposit_ingestion::tests::a01_disk_failure_retries_persistence_before_rpc_and_restart_is_exactly_once` | controlled ACK plus serialize/restore |
| RPC timeout and durable finalized reorg halt | `deposit_ingestion::tests::a01_rpc_failure_preserves_cursor_and_finalized_reorg_halt_survives_restart` | injected source errors plus serialize/restore |
| Cancel at ACK | `deposit_ingestion::tests::a01_cancellation_at_ack_keeps_barrier_and_retry_never_recredits` | controlled ACK fixture |
| Payer/amount mismatch | `apply_deposit_page` explicitly rejects route.from/amount versus event; no separately named independent negative test located in this bounded review | source only |

S6-03 remains PARTIAL/BLOCKED for deployment evidence: no current chainId/block hash/runtime code hash/vault/verifier/vkey/roles observation was made. `contracts/deployments/base-sepolia.json` is repository configuration, not current chain evidence. No user authorization for live writes is inferred.

## Independent review of parent changes

Reviewed `listen_config.rs`, main bind integration, `perp-core::State::apply_batch` overflow guard/tests and CI changes. No blocking defect found in these narrow diffs: parsing rejects invalid explicit bind/port before service side effects, binds typed IPv4/IPv6, and logs actual selected port; existing public default is intentionally preserved. `apply_batch` computes the next id before applying any op; max and final-representable vectors check no mint on rejection. CI --locked changes and release-profile environment variables target the correct release profile; the miniature control exercises actual flags rather than inferring from YAML text alone.

Scope caveat sent to parent: sequencer `seal_window` and gateway `settle_failure_action` still contain unchecked `+1`; the core fix alone does not prove every window-counter exhaustion path. Final parent changes may address this separately. Local tests do not assert remote CI status or branch-protection policy.
