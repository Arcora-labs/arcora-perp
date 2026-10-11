# Next offline A4 packet: coordinated registration through Prepared

Design only, based on the frozen broadcast/outcome composition. No implementation,
test run, cryptographic proof, live transport or custody acceptance is claimed.

## Smallest useful scope

Add one `cfg(test)` registration coordinator whose cooperative local lease spans
source validation, every registration/lookup/mock-prove callback, and every
DPCINT4 checkpoint through terminal `Prepared`. It returns a validated Prepared
cut to the separate broadcast dispatcher. It never calls either historical
runner's broadcast tail.

Keep DPCINT4 framing/stages and the four protected builders byte-identical.
Keep DPCBTX1 Pending/Outcome and its explicit Fresh/Resume behavior unchanged.
No guest/core/program/vkey/clock/protocol pin, production route, or runtime change.

## Runner seam requiring compatibility review

The current `candidate_recovery::execute` already has a clear boundary: it writes
`Stage::Prepared`, then reconciles again and calls the old `broadcast` method.
Factor only the driver through that durable boundary into a shared internal
helper; expose a narrow `prepare_only` entry for the new coordinator. Preserve
the old execute tail and its existing callback schedule with compatibility tests.

Prefer a new `PreparationTransport` trait with only register_clock, lookup_clock,
register_reports, lookup_reports, and mock prove. A legacy adapter delegates from
the unchanged `RecoveryTransport` interface. The new coordinator cannot invoke a
broadcast method through its transport type. Do not intercept the old broadcast
with a success/error sentinel, and do not duplicate the staged driver.

Suggested public test-only result:

```text
PreparedCut { record: DPCINT4 Record, prepared: PreparedCandidate }
prepare_only(mode, request, trusted, recovery_store, preparation_transport)
    -> Result<PreparedCut, RecoveryError>
validate_stored_cut(record, request, trusted) -> Result<(), RecoveryError>
```

The pure cut validator must cover staged anchor semantics, canonical payloads,
exact request equality, and terminal Prepared correspondence. Terminal Prepared
resume returns without registration or proof callbacks. The separate broadcast
dispatcher performs its own current preflight before creating a new Pending.

## Coordination and compatibility

Create a NEW small authenticated coordination manifest and stable lock, with a
distinct explicit format/domain. Derive both filenames deterministically from
the canonical DPCINT4 source path; callers cannot choose a second lock lane for
the same source. Manifest fields need only canonical source-path digest, exact
canonical request digest, and lock dev/ino/uid. Bound it to a small fixed payload.
Do not modify DPCINT4 to insert lock metadata or duplicate its changing stages.

Use the already-reviewed private Unix directory, stable lock-inode and advisory
lease rules, preferably through an reviewed mechanical filesystem-helper reuse.
Require canonical absolute paths, private owned directory/files, nlink=1 for
regular files, distinct source/manifest/lock inodes, and stable parent/lock identity.
The lease spans the whole invocation and checks identities before callbacks.
Source advances are intentional atomic replacements; validate the new exact
DPCINT4 cut after an owned save rather than treating its old inode as permanent.
The manifest and authenticated source must agree before any callback.

```text
RegistrationCoordinator::new(canonical_source_path, seed)
run_prepared(Fresh | Resume, request, trusted, preparation_transport)
    -> PreparedCut
attach_existing(request, trusted) -> binding             // no callbacks
```

Fresh requires absent source and absent binding. Resume requires both. A crash
after binding publication but before Intent publication leaves a missing-source
HOLD; it must not silently turn Resume into Fresh. Existing DPCINT4 data may be
adopted only with explicit `attach_existing`, after exact authenticated and
semantic validation and with historical writers quiescent. Adoption performs no
registration, proof, timestamp refresh, or historical metadata reconstruction.
Missing/replaced lock, wrong binding, corrupt/foreign source or ambiguous save
requires HOLD and explicit reload/reconciliation.

All new wrapped writers must use this deterministic lease. Direct historical
RecoveryStore/execute callers that bypass it remain outside the coordination
guarantee. Advisory locks do not fence hostile same-user deletion/replacement,
and a source path does not establish global uniqueness across copied requests.

## Acceptance gates

- Preserve old execute callback schedules and the old framing/golden hashes.
- Fresh normal and liquidation flows retain exact witness, report containers,
  selected IDs, original anchors, uptime epoch, response and Prepared payload.
- Assert the authenticated DPCINT4 stage and held lease before every callback;
  ClockPending/ReportsPending must be durable before their registration calls.
- Restart each staged cut: pending registration states only observe/reconcile;
  absent/unknown/reorg never automatically re-register. Prepared resume performs
  zero register/prove/broadcast callbacks.
- Fresh existing and Resume missing source/binding refuse before callbacks.
  Explicit staged/Prepared adoption is bounded, exact and callback-free.
- Real independent handles/processes contend while a registration callback is
  blocked on an IPC barrier. The loser has zero callbacks. SIGKILL releases only
  the kernel lease; successor resumes the exact staged cut without registration.
- Cover path aliases, symlinks/hardlinks, lock/parent/source replacement,
  permissions, wrong key/version, trailing/oversized data and binding mismatch.
- Before-publication failure preserves the old source bytes and stops later
  callbacks. After-publication fsync ambiguity stops the invocation and requires
  reload; no rollback or universal old-bytes guarantee.

Keep original durable anchors as the restart finality baseline. Later observed
tips are invocation-local unless explicitly persisted by a future format; do not
claim those tips survive restart. A failed Prepared save may repeat mock prove
from ReportsObserved under the existing protocol; no exactly-once proof claim.

## Still open

Live RPC/DON/discovery/credentials, actual finality or ancestry authentication,
fresh cryptographic SP1 proof, signed Ethereum transaction/nonce coordination,
production deployment/activation, global exactly-once delivery, and real vault
custody remain outside this packet. Production candidate submission and exact
v2 resume remain HOLD.
