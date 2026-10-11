# Offline broadcast attempt and outcome recovery

Started 11 October 2026; final local checks completed 12 October, 00:01:03
Europe/Istanbul (11 October 21:01:03 UTC). **PRODUCTION RELEASE HOLD.** Test-only software packet based on
normally merged PR #50, main `0ea5048627840cbe7e125d7b914b1303b109b224`.
The exact tested #50 head and merged tree both equal
`146b6da49f322bcabf68a7e5fca1e216aea52c45`; current 19/19 checks passed before merge.
[Merge observations](merge-observations.json).

The historical DPCINT3/DPCINT4 runners remain unchanged. Their Prepared resume
can broadcast again. A separate dispatcher starts from an explicitly validated,
terminal DPCINT4 Prepared, without invoking those historical runners. It derives
seven roots, count/tip and exact settlement ABI from the immutable request and
opaque mock proof. The unchanged #50 normal/liquidation corpus supplies both
inputs; no archive identity, witness, guest, key, contract or production route is
updated. Adapter/gateway/prefix-vault addresses and code hashes are configured
caller-owned pins, not live deployment discovery.

A distinct bounded authenticated DPCBTX1 sidecar holds Pending then Outcome.
Opaque Plan is capped at 2 MiB, Outcome at 64 KiB, proof at 1 MiB and revert data
at 4 KiB. Fixed lengths are checked before payload allocation; nested calldata
and revert length prefixes are also bounded. The authenticated frame pins the
stable lock device/inode/owner so existing records cannot resume under a
recreated or copied lock domain.
Pending must be durably acknowledged before one mock broadcast callback. A
callback success is not acceptance. After a lost response or restart, Pending
looks up only the original precomputed mock transaction/attempt identity. It
never refreshes nonce, proof, clock, epoch or attempt. Absent, unknown, pending,
reorg or inconsistent results HOLD. Terminal Outcome returns the exact saved
success or revert with no callbacks. A crash after Pending but before broadcast
also requires lookup; absence does not authorize retransmission.

The local cooperative exclusive lease spans the entire invocation. Stable empty
private sibling lock inode is never unlinked or renamed on release. The parent,
lock and target identities/permissions are checked before callbacks and writes.
The directory must already exist, be canonical and private. This is local
same-user coordination; distributed/NFS or hostile-filesystem fencing and
rollback freshness are not established. The configured sidecar path must remain
fixed across restarts: separate paths are separate coordination domains, with no
global deduplication across copied Prepared cuts. Direct historical runners do
not acquire this lease and remain outside its guarantee.

Fresh recheck may advance an invocation-local finality watermark. The sidecar
pins the original durable Prepared anchors; the latest observed tip is not
persisted across restarts. Resume validates against that original baseline,
without an ancestry or cross-restart monotonic-tip claim.

The transaction and attempt IDs are domain-separated **mock hashes**, not a
signed Ethereum transaction hash. Finality and code identities are caller-owned
mock assertions. Successful outcome checks exact post-root, batch increment,
manifest/ordered/rejected roots and mock withdrawal publication. Count/tip is a
prefix-gate input, not a stored settlement count. A revert is terminal for this
attempt; it does not assert unchanged global state or undo prior registration.

## Final checks

Tested code commit `44b81edd3ac4c2781e91ddbbb75f9bd9dd882d44`.
Source bytes remained unchanged throughout the final checks.

| Check | Observed result |
|---|---|
| Full gateway, two test threads | **628 PASS / 0 FAIL / 21 intentional IGNORE**, 811.97 test seconds; includes original HTTP route and 4,100-admission/restart test |
| Focused new packet | **26 PASS / 0 FAIL / 1 intentional ignored child helper**, 63.93 test seconds |
| New tests | 15 dispatcher/semantic cases, 8 store cases, 3 actual IPC/process cases |
| Workspace Clippy | PASS with `-D warnings` |
| Python guards | **47 PASS** |
| Reviewed/candidate pins | **21 / 9 unchanged**, release/candidate locks PASS |
| Format/source diff | PASS |
| Preservation | **1,927 existing tracked source/artifact fingerprints unchanged**, original checkout status/content/staged diff unchanged: **13 / 7 / 62** dirty files |

The 21 ignored tests are existing explicit exporters/helpers plus this packet's
owned subprocess helper. Parent tests invoke that helper with its exact owned
inputs; it is not skipped process coverage. Final process evidence includes real
kernel contention and actual dispatcher SIGKILL at Broadcast, followed by
lookup-only Resume and exactly one persisted mock broadcast marker.

The first focused compile failed on three new test references to an unavailable
hex crate. Local bounded hex conversion fixed them without adding a dependency.
The first Clippy failed on a large enum variant and manual range pattern; boxing
the fixed success effect and using a range fixed both. A read-only review also
moved hard-killed child scratch under the parent cleanup scope. Final checks use
those exact final sources. No lint policy, original test, age threshold or
assertion was weakened. [Repair history](repair-history.json) and raw failed and
successful logs are retained. Combined logs concatenate stdout then stderr;
they are not a chronological interleaving claim.

[Verification ledger](verification.json) binds exact source and artifact hashes.
 No fresh SP1 CPU execution, proof generation, GPU, real DON,
live RPC, funds, public deployment, claim/custody acceptance or power-loss
experiment is part of this packet. #50 Foundry/CPU evidence is historical and
reused only after its source/corpus fingerprints are rechecked unchanged.


## Repeat the software checks

From repository root with Rust toolchain 1.99.0:

```sh
rustup run 1.99.0 cargo test -p gateway --locked --offline --bin gateway candidate_broadcast -- --test-threads=2
rustup run 1.99.0 cargo test -p gateway --locked --offline -- --test-threads=2
rustup run 1.99.0 cargo clippy --workspace --all-targets --locked --offline -- -D warnings
rustup run 1.99.0 cargo fmt --all --check
```

The ignored child helper is automatically invoked by its parent tests with an
owned fixture directory and IPC pipes. Do not run it without those explicit
inputs. Processes and thread contenders use IPC/channel barriers, not sleeps.
SIGKILL targets only the direct owned test child. Their private scratch is inside
the parent test's cleanup scope in final source. This is an actual process kill,
not a physical power-loss or real broadcast acceptance experiment.

[Next GPU-free design](next-gpu-free-a4.md): registration coordination through
Prepared, with the historical schedule preserved and no broadcast method on the
preparation transport. It is a design note only; implementation and tests remain
open. The broader registration-writer issue and production gates remain open.
