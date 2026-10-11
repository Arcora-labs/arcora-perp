# Next GPU-free A4 packet: Prepared → separate broadcast handoff

This is a proposed offline harness extension, **not an implemented handoff**.
The current `RegistrationCoordinator::run_prepared` stops at an acknowledged
DPCINT4 `Prepared` cut. Its `PreparationTransport` cannot broadcast. The existing
broadcast dispatcher separately leases DPCBTX1 Pending/Outcome storage and reads
its caller-supplied `RecoveryStore`; it does not acquire the new preparation
coordination lease. A returned `PreparedCut` alone does not supply that continuity.

## Proposed bounded flow

1. Acquire the source's existing `CoordinationStore` lease, then the selected
   broadcast-store lease, in that fixed order. Use nonblocking acquisition;
   contention stops before callbacks. Keep both leases through final durable
   readback. Select one fixed broadcast lane per owned source; a changed request,
   proof or nonce must fail plan comparison, never select an alternate lane.
2. Require both source and DPCREG1 binding. Check private parent/source/binding/
   stable-lock identities, exact absolute source-path hash, binding lock identity
   and exact serialized request hash. Reload the owned source under its lease;
   require `Prepared`, validate its canonical complete cut against the trusted
   request, and compare the exact record with any supplied `PreparedCut`.
3. Add a small borrowed-source seam to reuse existing dispatcher validators and
   plan construction. Do not expose the preparation store's raw `RecoveryStore`
   or accept an arbitrary source path/seed. Pin the original logical source-cut,
   prepared/request/witness hashes, full report input versus body evidence,
   clock/report anchors, policy/target/program pins, seven roots, public values,
   exact settlement calldata/proof and deposit count/tip. Retain original times.
4. Guard every Recheck/Broadcast/Lookup callback before **and after** with both
   leases, source/binding cut checks and unchanged canonical source/plan checks.
   Verify again before Pending/Outcome publication and final return. An external
   replacement, in-place write, permission change or mismatched cut stops later
   actions; it cannot refresh the preparation lease's accepted source cut.
5. Preserve the existing Fresh sequence: exact mock Recheck → acknowledged
   Pending → one mock Broadcast → mock Lookup → validated durable Outcome.
   Any write error stops the invocation, including uncertain post-publication
   acknowledgement. Drop leases, reload exact bytes and reconcile explicitly;
   never restore old bytes or retry a broadcast because an acknowledgement failed.

## Fresh and restart rules

- Handoff accepts only an already bound, validated `Prepared` source. Partial
  preparation is resumed explicitly through the preparation coordinator first;
  the handoff never registers, proves, advances preparation or auto-adopts.
- Fresh refuses every existing broadcast cut. Resume requires an existing exact
  Pending/Outcome and the same bound source/request/plan. Missing source/binding,
  orphan binding, changed material/target/proof/nonce or malformed payload holds
  before callbacks; none starts a replacement attempt.
- Pending Resume performs lookup only. Pending/Absent/Unknown/Reorg or inadequate
  finality leaves Pending intact and stops. Valid finalized mock success/revert
  is persisted distinctly. Terminal Outcome is revalidated and returned with
  zero transport callbacks. Preserve honest counts of earlier attempted actions.

## Acceptance and limits

Add fixed normal/liquidation handoff tests, both-lease callback fences,
independent-handle/process contention, SIGKILL after durable Pending, lookup-only
restart, source/binding substitution and ambiguous-write recovery. Keep existing
DPCINT4/DPCREG1/DPCBTX1 formats, old golden builders, guest/core pins and mock proof
bytes unchanged; no new witness corpus, GPU run or fresh proof is needed for this
packet. Record failed-before/passed-after evidence for any discovered defect.

Coordination covers cooperating writers of one private canonical source lane.
Source basenames remain lowercase ASCII letters/digits/`._-`; lock names derive
from physical parent dev/ino/uid plus basename, while the binding pins exact path
spelling. Copies, relocation and historical uncoordinated writers require explicit
review/adoption; there is no global cross-path uniqueness, hostile same-user
sandbox or rollback-freshness guarantee. Mock transaction IDs, observer pins,
finality hints and prefix-vault effects do not establish signed transactions,
real DON/RPC truth, proof verification or exactly-once chain delivery. Live
submission and production remain HOLD.
