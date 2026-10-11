# Offline registration coordination through durable Prepared

**PRODUCTION RELEASE HOLD.** This packet adds a test-only coordinator that
owns the existing DPCINT4 source store and keeps a deterministic local lease
through registration, observation, proof preparation and acknowledged Prepared.
It implements the previous packet's preparation design. There is no live
transport, gateway activation, public transaction, fresh proof or deployment.

Base main is PR #51's normal merge,
`56f91ab740d5cce42edcc287ded4b0c39eb4f9f8`. Its publication head
`176549478079536b274862d487133ba053b0edb1` passed 19/19 checks before merge;
both trees are `9bcb4f9b257494c9b1e055e4368da297c64c15e4`. This packet's code
commit is `606894c7dbe7faf688fd1e8d169e7e89430c07f0`. Local command receipts
identify the exact source bytes before and after each check. Publication-head
CI is a separate result, recorded outside this immutable local packet.

## Behavior

The coordinator owns the exact source path and original recovery seed; callers
cannot substitute another store. Fresh durably publishes a new authenticated
DPCREG1 binding before Intent. It refuses existing source or binding rather than
resetting either. Resume requires both and validates the complete authenticated
and canonical staged cut. A pre-existing unbound legacy cut can only be attached
with an explicit callback-free adoption operation; it validates the request,
anchors and Prepared payload before publishing the immutable binding.

Binding pins exact source-path SHA256, canonical request SHA256 and stable lock
dev/ino/uid. Source, binding, parent and lock identity are checked before and
after every callback and owned checkpoint write. A definite failed publication
preserves the previous cut. Any ambiguous acknowledgement ends the invocation;
the next Resume reloads and reconciles the visible cut. No registration is
repeated from a pending checkpoint. Orphan bindings, missing sources, tampering,
foreign requests, replacement and observation/finality failures hold the run.

Preparation has a separate transport with no broadcast method. It returns only
after exact Prepared bytes have been acknowledged and read back. The historical
runner uses the same stage driver, then retains its original reconciliation and
mock broadcast tail with the same invocation-local watermark. Its old callback
schedule remains 11 calls for Fresh and 3 for Prepared Resume. A higher tip seen
before proof followed by a lower tail tip still holds before broadcast.

## Physical lane and the Mac regression

The parent must be a private owned canonical directory. Source basenames are
limited to lowercase ASCII letters, digits and `._-`, at most 128 bytes; reserved
sidecar names are refused. Binding and lock filenames are derived from a
length-framed physical parent dev/ino/uid plus that basename. Raw parent spelling
does not select a second lock lane. The authenticated exact source path remains
an additional check, so an established binding cannot silently move to an alias.

An owned APFS probe observed that an uppercase basename could address the same
physical source inode. Before the repair, the new regression failed because the
constructor accepted that spelling: **9 PASS / 1 FAIL**. The final lowercase
policy rejects it on every platform. The parent-case regression already refused
the alias through Rust's canonical parent check on this Mac; no parent-case
bypass was observed. That test prints an explicit unavailable marker on a
case-sensitive filesystem. [Probe](filesystem-case-probe.json),
[failed log](logs/alias-regression-before.log), and
[repair history](repair-history.json) retain this distinction.

## Verification

Final focused tests passed **28 / 0 FAIL / 1 intentional helper IGNORE**:
16 semantic coordinator tests, 10 store tests and 2 actual process tests.
The ignored child helper is run explicitly by its parent with owned fixtures
and IPC pipes. The unchanged legacy recovery filter passed **17 / 0 / 0**.
Workspace Clippy passed with `-D warnings`, format passed, all **47 Python
guards** passed, and **21 reviewed / 9 candidate pins** plus release/candidate
locks remained valid. Full gateway passed **656 / 0 FAIL / 22 intentional
IGNORE**, 219.95 test seconds, with actual Rust 1.99. The
[verification ledger](verification.json) and retained final command log identify
the exact source and command.

Both canonical #50 normal and liquidation fixtures reach byte-exact Prepared.
Tests inspect each stage and held lease before callbacks, exercise callback
failures, pending/absent/unknown/reorg outcomes, explicit adoption, missing and
orphan records, tampering, source replacement and ambiguous saves. All six source
checkpoint stages have all three save failure modes across the coordinator and
lower-level store tests: Intent Rename is covered at the lease/store layer,
not by a complete 18-case coordinator matrix. Prepared-save failure may rerun
the mock proof on Resume; this is not exactly-once proof execution.

Two real child-process cases block inside RegisterClock or RegisterReports
after the corresponding durable Pending cut. A separate process contends on
that exact source and returns Busy with zero callbacks. The parent sends SIGKILL
only to its owned holder. A successor reaches Prepared with lookup/proof calls
and no repeated registration, preserving original request, clock, anchors and
stable binding/lock inode. IPC barriers are used instead of sleeps. Scratch
belongs to the surviving parent cleanup scope. This is a process-kill test, not
a physical power-loss or network acceptance experiment.

Actual child tools use the installed Rust 1.99 toolchain directory first in PATH
and `RUSTUP_TOOLCHAIN=1.99.0`; global settings remain unchanged. The tool identity
receipt and current object DWARF producer independently record Rust 1.99. Every
command pins 36 source/corpus files and confirms unchanged bytes during execution.
The preserved base has 2,468 file fingerprints; intentional existing-file changes
are the shared driver, eight test-only module lines, ACTIVE_WORK and the new raw
log attributes. Original DPCINT3/4/DPCBTX1 formats, old tests, golden builders,
runtime inputs, CI workflow and earlier evidence packets are unchanged. Original
dirty checkouts remain 13 / 7 / 62 with matching bytes, staged diff and heads.

The initial compile failure was a new IPC assertion requiring unavailable
ProtocolRequest equality/debug traits; it now compares canonical request bytes.
No pinned type or old assertion changed. The second repair is the observed APFS
basename issue. Both raw failures and final successful receipts are retained.
A first preservation helper mistakenly interpreted an annotated allowed-path
description as a literal path; the corrected helper extracts the same planned
path. Its raw false receipt is retained and is not a source-code regression.
Combined command logs concatenate stdout then stderr; they do not claim
chronological interleaving. Read-only source comparison and an independent
coordinator review are separate from executed tests.

## Scope and next work

Coordination applies to cooperative writers using this coordinator and the same
physical private parent and allowed basename. Copies, other paths and direct
legacy runners do not gain a global deduplication guarantee. Adoption requires
quiescent legacy writers. Changing physical directory identity changes the lane;
renames/aliases retaining that identity still fail an existing raw-path binding
when the exact spelling differs. Hostile filesystem fencing, NFS behavior,
consensus ancestry and chain exactly-once effects are not established.

Finality and chain observations are caller-owned mocks. The original saved
anchor remains the restart baseline; later observed tip history is invocation
local. No new local Foundry or SP1 CPU run is part of this host-only packet;
#50's source/corpus evidence is reused only after unchanged fingerprints are
verified. Existing remote CI CPU/Foundry gates execute separately. DON/uptime,
custody/economics, real proof and production gates remain open.

[Next GPU-free design](next-gpu-free-a4.md) covers an explicit offline handoff
from this durable Prepared coordinator to the separate broadcast dispatcher.
It is a design, not an implemented combined lifecycle.

To repeat software checks, prepend the actual installed Rust 1.99 bin directory
to PATH, set `RUSTUP_TOOLCHAIN=1.99.0`, then run:

```sh
rustc -Vv
cargo-clippy --version
cargo test -p gateway --locked --offline --bin gateway candidate_preparation -- --test-threads=2
cargo test -p gateway --locked --offline --bin gateway candidate_recovery_tests -- --test-threads=2
cargo test -p gateway --locked --offline -- --test-threads=2
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo fmt --all --check
```

Do not invoke the ignored process helper without its explicit owned fixture and
IPC inputs. Exact guard/pin commands and their environment are in `commands/`.
