# S1 recovery authority and rebind matrix

Source base: `098e4952c189f92e4293ed7d49f81222b626e406`. This note describes the isolated local audit tree; final dirty-tree fingerprints are recorded in `source-manifest.json` after verification. Synthetic keys only; no L1 calls or live account state.

The current contract is `account.signer.or(account.deposit_address)`. A registered caller signer remains recovery authority after a deposit-address rebind. An account without a caller signer uses its currently bound deposit wallet. Recovery signs chain, vault, owner and current recovery nonce. Binding a new deposit address additionally requires its ownership proof; replacing a binding requires the current bound wallet's signature over chain/vault/owner/rebind generation/old/new addresses. API key alone cannot authorize replacement.

| Vector | Caller signed | Bound-wallet only | Runtime evidence |
|---|---|---|---|
| Registered signer valid recovery | Accept | Reject after signer removed | `local_recovery_authority_and_domain_matrix_preserves_rejected_state` |
| Bound deposit wallet valid recovery | Reject if distinct from signer | Accept | Same matrix |
| Unrelated signer; correct digest | Reject | Reject | Same matrix; full snapshot unchanged |
| Correct authority; wrong chain, vault, owner, nonce | Reject each | Reject each | Same matrix; one variable changed per vector |
| Malformed 65-byte signature | Reject | Reject | Same matrix; full snapshot unchanged |
| Replay consumed nonce | Reject | Reject | Same matrix; snapshot/nonce unchanged |
| Fully authorized HTTP rebind queued before recovery | Original signer remains valid | Original bound signer rejected; new bound wallet can recover | `local_real_rebind_before_recovery_rechecks_current_authorizer` |
| Same nonce two concurrent recoveries | One winner only | Identical per-account fence logic | `local_same_nonce_race_has_one_winner_and_no_secret_for_loser`; loser gets no secret and publishes no snapshot request |
| Recovery nonce maximum | Reject without mutation | Same shared check | Existing `recovery_rejections_and_nonce_overflow` |
| Rebind generation maximum | Must reject without partial mutation | Same shared check | `local_rebind_nonce_exhaustion_rejects_before_any_mutation`; failed-before assertion evidence and narrow checked-add fix |
| Snapshot queue full/closed/no writer | No mutation; unavailable | Same shared route | Existing `recovery_full_queue_is_preflight_503_and_state_unchanged`, `recovery_closed_queue_is_preflight_503_and_state_unchanged`, `recovery_without_writer_is_503_and_state_unchanged` |
| Negative/dropped/missing ACK | Unknown outcome; no secret; nonce not reset | Same shared route | Existing false/drop/timeout/cancel recovery tests |
| Post-ACK authorizer recheck | Revalidates signature to current authority | Revalidates signature to current authority | Existing `s1f_post_ack_authorizer_change_is_conflict_without_secret` uses controlled internal mutation, not an authorized route |
| A01 pending permits, credited receipt, unrelated account, prefix | Preserved except API-key reference | Same shared mutation | Existing account_recovery tests for pending routes and ingested receipts |

The real-rebind test uses the real JSON route and cryptographic proofs, with FIFO Gw lock waiters explicitly polled at a barrier. The same-nonce test parks disk ACK explicitly; it does not count a timeout as successful revocation. Snapshot roundtrips in new matrix tests use real serialization/restore in memory, not fsync. Existing file-backed write/restore and cancellation tests provide separate disk evidence.

Scope remaining: no claimed exhaustive schedule exploration; no user device wallet or external signer; no guarantee to retract bytes already accepted by TCP. Final S1 status depends on the test logs and the parent evidence report, not table presence.
