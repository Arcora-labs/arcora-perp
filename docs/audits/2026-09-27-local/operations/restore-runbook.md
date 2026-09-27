# Local restore and incident rehearsal

This runbook is for copied fixtures and newly created test processes. A process kill is not an electricity-loss test. Never run it against the user's original gateway, real snapshot or live vault.

1. Record source fingerprint, snapshot/journal SHA-256, fixture seed identifier (never seed value), and local block/hash/root. Copy both files; retain originals untouched.
2. Start on 127.0.0.1 with an empty environment allowlist, disposable identities and a fresh test directory. Confirm the PID belongs to this rehearsal and record the listener.
3. Inject one bounded failure: queue full/closed, writer I/O error, process termination at a controlled barrier, malformed copy, or pinned RPC disagreement. Record the exact mutation/ACK/response boundary. Do not fill the real disk.
4. Restart against the same copied state. Confirm old credentials remain revoked after a durable success; if ACK/response was lost, query current challenge and reconcile before retrying any mutation.
5. For settlement, compare batchCount/root to journal prepared outcome and snapshot. STALE, seal-never-persisted, rollback and roll-forward require the corresponding exact evidence; any absent/conflicting observation means HOLD with journal retained. Do not delete state to make boot succeed.
6. Compare note/nullifier/deposit cursor, external-in/out, withdrawal roots and claims to the pre-rehearsal ledger. A successful HTTP response alone is not evidence.
7. Stop only the recorded test PID, check that its listener and tasks closed, and hash the resulting copies. Keep the hashes/log and label limits.

Snapshot parser mutation/failure tests, recovery ACK tests and real socket closure tests are separately recorded. A complete process-kill matrix with genuine proof settlement, disk-full/fsync/directory failure injection and external-operator execution is not implied by these unit/integration results. S6-02/S7-01 remain open until those controls are actually run.

For CloseOnly, follow `docs/FINAL_SETTLE_RUNBOOK.md` using local fixture contracts and a source-bound genuine proof. Never infer that restarting or resuming settlement settles an unresolved root. Lost signer, compromised browser, missing journal or unknown transaction status should halt dependent mutations and preserve evidence. External communication requires an identified incident owner and an explicit instruction; this run created no notification.
