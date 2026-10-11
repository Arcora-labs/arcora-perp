# Next GPU-free A4 packet: offline broadcast-outcome recovery

Read-only design, 11 October 2026. No implementation or tests run for this note.
Production release remains HOLD. Preserve all existing witnesses, builders,
guest/core/ELF/vkey pins, production routes, custody and old DPCINT3/DPCINT4 records.

## Concrete gap

`candidate_recovery.rs:510-513` calls `broadcast(&prepared)` and returns without
advancing or saving an outcome. Both callback success and accepted-but-lost reply
leave the same Prepared cut. The existing positive resume test explicitly expects
another Broadcast (`candidate_recovery_tests.rs:350-359`). The older protocol has
the same boundary at `candidate_protocol.rs:473-476`.

The store mutex protects individual loads/writes, not the complete invocation or
callbacks (`candidate_recovery_store.rs:75-80,127-150`). Concurrent Prepared resumes
can therefore both broadcast, including through the same handle. Independent
handles/processes can also race publication. Adding only BroadcastPending does
not fix this: an identical already-published next cut is successful at lines
135-136, so two callers could both mistake idempotent success for ownership.

## Smallest independently reviewable scope

Add a NEW cfg(test) dispatcher and authenticated bounded outcome sidecar starting
from an explicitly validated terminal DPCINT4 Prepared cut. Do not call the old
execute function: it already broadcasts. Reuse pure canonical Prepared/request,
response, target, report and clock validators. Existing formats stay unchanged;
there is no import, downgrade, replacement, reset or automatic retransmission.

Use one immutable attempt plan: exact source-cut/request/Prepared digests, configured
target identity, exact settlement call tuple or independently checked ABI bytes,
seven roots, expected pre/post root and batch publication, consumed count/tip,
public32, proof bytes and explicit mock submission identity. Pin all bytes before
the first callback. A domain-separated mock attempt ID may bind those exact bytes;
it must be named as a mock identity, not a signed Ethereum transaction or real tx
hash. A later real transport would need a separately reviewed precomputable signed
transaction identity. Reuse fixed bridge normal/liquidation data without changing
witnesses or relabelling old archive IDs.

Acquire a nonblocking cooperative local exclusive lease before reading the cut and
hold it through validation, recheck, publication, callback, lookup and outcome
publication. It must serialize the whole invocation across same-handle threads,
independent handles and local processes, not just individual writes. Use a stable
private lock inode separate from renamed data, never unlink it on release, reject
symlink/alias/replacement cases and verify owned parent/file identity. Contention
returns Busy with zero transport callbacks. No NFS/distributed/hostile-filesystem
fencing is claimed. Verify available std locking support at implementation time;
do not add an unnecessary dependency or manifest change.

Only two sidecar cuts are required:

1. Fresh validates/rechecks the exact Prepared and creates **Pending** with the
   immutable attempt plan before broadcast. Fresh refuses every existing sidecar.
   Publication must be acknowledged before the one broadcast callback. Pre-save
   failure makes zero attempts; uncertain post-publication durability stops the run.
2. After broadcast, use a mock lookup keyed by the original attempt/plan. Only a
   validated finalized success or finalized revert becomes immutable **Outcome**.
   Callback Ok alone is not settlement acceptance. Resume Pending never broadcasts,
   registers or proves: it only looks up that original attempt. Absent, Pending,
   Unknown, Reorg, replacement or mismatched results HOLD, including the crash cut
   after Pending but before its callback. Outcome resume returns exact saved result
   with no side effects. No nonce refresh, new proof, new epoch or new attempt ID.

Outcome validation pins target, attempt/call identity, nonzero tx/block/hash mock
anchors, finality consistency, exact public32 and the exported settlement result.
Success checks post-root, batch/manifest/ordered/rejected data and withdrawal
publication. Count/tip belongs to the mock prefix gate: settlement has no stored
post-deposit-count field. Reverted outcome is distinct from success and never
triggers resend. Reconciliation concerns the original attempt; an uptime change
after an already finalized result must not cause a new attempt. Finality remains
caller-owned mock consistency, without real RPC authentication or ancestry.

## Required tests

- Both fixed normal/liquidation cases: Pending is visible inside broadcast;
  exact successful outcome is saved; terminal resume performs zero side effects.
- Accepted side effect followed by callback error/lost reply, and failure saving
  Outcome: reopened Pending looks up the same attempt and never sends it again.
- Before-Pending write/rename failure, uncertain directory acknowledgement, and
  crash after durable Pending before callback: preserve/reload the exact cut;
  no next action on save uncertainty; Absent HOLD cannot create a fresh attempt.
- Wrong Prepared/request/target/call bytes/public32/root/batch/count/tip, wrong
  outcome tx/block/hash/status, pending/unknown/reorg and finality regression:
  no accepted result or resend. Prior clock/report writes are counted honestly.
- Authenticated opaque semantic corruption, version/downgrade/trailing/bounds,
  stale compare state and established-payload mutation fail before callbacks.
- Barrier/IPC-driven two threads, two independently opened handles and two child
  processes: exactly one callback attempt; contender has zero callbacks. Process
  exit releases the lease; successor reloads Pending and performs lookup only.
  Add stable-lock inode/alias/symlink tests, without relying on sleeps or merely
  testing one in-memory mutex.

This closes a software-only durable attempt/outcome and cooperative local writer
boundary. It does not prove real transaction finality, exactly-once chain delivery,
proof/DON authenticity, fund custody, deployment/service identity, power-loss
durability, hostile rollback freshness or the broader registration-writer problem
in the unchanged historical runners. No GPU or fresh CPU fixture execution is
needed when the old witness/public inputs remain byte-identical.
