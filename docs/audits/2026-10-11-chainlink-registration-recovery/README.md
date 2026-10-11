# A4: offline intermediate registration recovery

11 October 2026. **PRODUCTION RELEASE HOLD.** Base main is
`5dac90412b65c299cb62bcff1ab2e1ae0533b6a0`. #48 was normally merged at
13:34:36 UTC after all 19 checks succeeded on `f0f1d406`; the tested head and
merge have the same tree. [Exact merge observation](merge-observations.json).
Repository protections were not changed.

The previous DPCINT3 harness persisted intent and Prepared, but a restart before
Prepared did not durably pin intermediate registration outcomes. This separate
`cfg(test)` packet adds an authenticated DPCINT4 record and a recovery runner.
Production submission, the old v2 resume path, core/guest/ELF/vkey and runtime
configuration are unchanged. There is no live transport activation or migration.

## Durable stages and recovery

| Stage | Saved original data | Next allowed work |
|---|---|---|
| Intent | Exact request | Persist ClockPending before a fresh clock registration attempt |
| ClockPending | Exact request | Lookup finalized original clock; Resume never registers |
| ClockObserved | Request and exact anchored clock | Reconcile saved clock, then persist ReportsPending |
| ReportsPending | Request and exact anchored clock | Fresh may register reports; Resume only looks up their outcome |
| ReportsObserved | Request, exact clock and exact reports | Reconcile both anchors before mock proof |
| Prepared | All original data and exact Prepared response | Reconcile both before mock broadcast; skip registration and proof |

Stages advance only to the adjacent stage. Request and previously saved payload
bytes cannot change. Each callback follows its relevant durable marker; all saved
payloads are authenticated, bounded, canonically decoded and semantically checked
before any callback. Shared Prepared/response/recheck validators preserve the
original protocol guards. The request limit is 24 MiB, each observation 64 KiB,
and Prepared 16 MiB; sealed input is bounded before allocation of decoded fields.

Fresh refuses every existing target. Resume requires the expected record and
never invokes either registration, even from Intent or ClockObserved. Missing,
pending, absent, unknown and reorg outcomes cannot automatically register again.
A marker can represent an attempt whose callback never ran or whose outcome is
ambiguous. In either case, a finalized exact outcome must be reconciled or the
run holds. DPCINT3/v2 records cannot be resumed as DPCINT4.

Saved clock and report tx/block/hash anchors remain exact across restarts. A
lookup must agree with its canonical block hash, be at or below a nonzero
finalized tip, preserve the original target, receipt, input/evidence hashes and
uptime epoch, and obey report-after-clock block ordering. Priced flows additionally
require readiness/grace; price-free flows retain their pinned zero sentinel and
do not depend on uptime health. Same-block
matching hashes are allowed; no transaction-index ordering is claimed.
Saved checkpoints establish the finality baseline. A later lookup cannot lower
this invocation's tip or change the hash at the same height. Advancing tips and
health-read times never rewrite original payloads or Prepared.

## Persistence and failure boundary

The owned store serializes read/compare/advance on one handle. Fresh publication
uses an exclusive 0600 temp file, fsync and atomic no-clobber publication. Advance
checks exact expected state, fsyncs a temp file, then renames and acknowledges the
parent directory. An identical already-published next state is byte-idempotent.
File bounds, authentication, stage shape, symlink/nonregular input, stale compare
state and payload mutation fail closed.

Pre-publication failure preserves prior bytes. A directory acknowledgement error
after publication is ambiguous: later callbacks stop and recovery reloads the
exact published state. It does not claim rollback to old bytes. Tests inject write,
rename and post-publication directory acknowledgement errors and exercise an
actual NAME_MAX write failure; they reopen records at durable cuts. They are not
a power-loss, SIGKILL, disk-controller or cross-machine durability exercise.

Finality metadata is supplied by caller-owned mocks. These checks are consistency
rules, not authenticated RPC, consensus, canonical ancestry or real transaction
proof. The latest observed tip is invocation-local; only the original checkpoint
baseline persists, so no latest-tip history across restarts is asserted.
Independent handles/processes must not share writers: no cross-process lock or
hostile rollback freshness guarantee is supplied. Proof can repeat until Prepared
is published, and Prepared broadcast can repeat; broadcast transaction outcome
WAL and exactly-once delivery remain open.

## Verification

Tested code commit: `df3f296bfa22d2e632f8985d462db27b320b40ad`.

| Current-packet check | Result |
|---|---|
| Focused recovery | 25 PASS / 0 FAIL: 17 integration + 8 store |
| Original protocol regression | 10 PASS / 0 FAIL / 1 intentional ignored exporter |
| Full gateway | 597 PASS / 0 FAIL / 18 IGNORE; 4,100 admission/restart included |
| Workspace Clippy, format and diff | PASS |
| Python guards | 47 PASS |
| Reviewed/candidate source pins | 21 / 9 unchanged; release/candidate locks PASS |

The first focused run passed 24 tests; final coverage added pre-attempt Absent
recovery and in-invocation finality watermark cases. No failed run occurred.
The final root run finished at 14:12:38 UTC. All five source files remained byte
identical throughout the combined checks. Later publication commits add only
documentation, evidence and a narrowly scoped audit-log whitespace attribute.
Cargo's terminal empty lines are preserved byte for byte; only those log files
omit Git's blank-at-EOF check, retaining trailing-space and space-before-tab checks.
Final command results and source/log hashes are in
[verification.json](verification.json).
The previous #48 contract and CPU results remain historical evidence. Its four
golden builder sources, contract files, corpus and pinned runtime inputs are
checked unchanged here; no fixture regeneration, fresh Foundry run, CPU execution
or proof generation is claimed for this host-only packet.

Original dirty checkouts are preserved. The current recheck confirms all 13
primary file hashes and the seven staged job--17 documents' diff hash. The old
Desktop checkout retains its HEAD and 62 dirty files. [Recheck](original-checkouts.json).

The next software packet is specified in
[native-to-contract bridge design](next-a4-native-contract-bridge.md). Live DON,
approved feeds/quote/scale/entitlement, uptime/grace identity, candidate service
and deployment identity, real proof/settlement/claim acceptance, prover capacity,
CC/key release, custody/exit and independent audit remain open. Live feed
discovery remains user-deferred; this packet makes no discovery or credential call.
