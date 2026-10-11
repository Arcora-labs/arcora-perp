# Offline broadcast attempt and outcome recovery

Started 11 October 2026; initial local check set completed 12 October, 00:01:03
Europe/Istanbul (11 October 21:01:03 UTC). **PRODUCTION RELEASE HOLD.** Test-only software packet based on
normally merged PR #50, main `0ea5048627840cbe7e125d7b914b1303b109b224`.
The exact tested #50 head tree and merged tree both equal
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

## Initial local checks

Tested code commit `44b81edd3ac4c2781e91ddbbb75f9bd9dd882d44`, published as
`c98ff6e3c541085df29b4a679af7f84ecc9ee471` with documentation only.
Source bytes remained unchanged throughout those checks. Subsequent CI exposed
that local Cargo 1.99 selected Homebrew Rust/Clippy 1.95 and rustfmt 1.9.0 through
PATH. The initial local results below are historical Rust 1.95 evidence, not
Rust 1.99 evidence. Direct `rustup run 1.99.0 rustc --version` did not identify
the compiler subsequently selected by Cargo. The retained compiler-resolution
receipt binds the original object's Rust 1.95 DWARF producer.

| Check | Observed result |
|---|---|
| Full gateway, two test threads | **628 PASS / 0 FAIL / 21 intentional IGNORE**, 811.97 test seconds; includes original HTTP route and 4,100-admission/restart test |
| Focused new packet | **26 PASS / 0 FAIL / 1 intentional ignored child helper**, 63.93 test seconds |
| New tests | 15 dispatcher/semantic cases, 8 store cases, 3 actual IPC/process cases |
| Workspace Clippy | PASS with `-D warnings`, actual Clippy 1.95 |
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

## CI repair and current checks

Initial Linux publication CI ran the full gateway suite successfully with Rust
1.99: **628 PASS / 0 FAIL / 21 intentional IGNORE**, 194.18 test seconds. Three
jobs then failed on the same new `chunks_exact_to_as_chunks` lint in the hex
test helper. No lock, dispatcher, SIGKILL or gateway assertion failed in that
run. The raw failed CI logs are retained separately from local command logs.

Code commit `92d469335c67967d45fa7d0360d7345329e57bb1` changes only that helper
to `as_chunks::<2>().0.iter()`, preserving the preceding even-length assertion.
One additional repair round is justified by this fresh CI finding. No lint,
source guard, original test, dependency, core, guest, contract or runtime pin is
weakened. Corrected commands prepend the exact installed toolchain bin directory
to their own PATH; global toolchain settings remain unchanged. Rust/Cargo/Clippy
1.99 and rustfmt 1.10 identities are now recorded before the fresh checks.

Current local receipts are named `*-ci-repair`. The full original local and
Linux runs above remain historical results. The publication commit's complete
CI result must be freshly verified before normal merge; a local pass or the
earlier Linux gateway pass does not establish a green publication head.

The same initial workspace job later hit its 20-minute total job deadline.
The workspace test step passed in 15m20; the serde step produced successful
results for 4m13 before cancellation. The following no_std build step was
skipped, not passed. PR #50's equivalent job had completed in 17m08. Only the
workspace job's finite ceiling changes from **20 to 30 minutes**, in CI commit
`eb07a79297dcf2e4ac3e8b6506c8a7b5007a96bc`; all commands, assertions and
`RUST_TEST_THREADS=2` remain unchanged. The initial cancellation and job timings
are retained in [budget evidence](workflow-budget-ci-repair.json). This is part
of the bounded repair of the initial CI findings. The updated CI configuration
has its own fingerprint and must execute every step on the publication head.

| Corrected local check, code `92d4693` | Observed result |
|---|---|
| Focused packet, Rust 1.99 | **26 PASS / 0 FAIL / 1 intentional helper IGNORE**, 61.08 test seconds |
| Workspace Clippy 1.99 | PASS with `-D warnings` |
| Format, rustfmt 1.10 | PASS |
| Python guards | **47 PASS** |
| Reviewed/candidate pins | **21 / 9 unchanged**, release/candidate locks PASS |
| Source diff and preservation | PASS; **1,926** existing frozen fingerprints and **13 / 7 / 62** original dirty checkout files unchanged; sole existing-file delta is the exact workspace timeout change |

These fresh checks identify all 28 exact source fingerprints before and after
each command. The original full local suite was not repeated after the helper
repair; complete publication-head Linux CI is required for merge.
The [compiled-binary receipt](compiler-current-ci-repair.json) independently
identifies the corrected test binary's actual Rust 1.99 DWARF producer.

[Verification ledger](verification.json) binds exact source and artifact hashes.
 No new local SP1 CPU execution, proof generation, GPU, real DON,
live RPC, funds, public deployment, claim/custody acceptance or power-loss
experiment is part of this packet. #50 Foundry/CPU evidence is historical and
reused only after its source/corpus fingerprints are rechecked unchanged. Existing
Linux CI gates run separately; the local CPU/Foundry flags do not describe those
remote executions.


## Repeat the software checks

From repository root, put the actual installed Rust 1.99 toolchain bin first in
PATH so Cargo's rustc, Clippy and rustfmt children resolve to the same toolchain:

```sh
arcora_tool_bin="$(dirname "$(rustup which --toolchain 1.99.0 rustc)")"
export PATH="$arcora_tool_bin:$PATH"
export RUSTUP_TOOLCHAIN=1.99.0
rustc --version
cargo-clippy --version
rustfmt --version
cargo test -p gateway --locked --offline --bin gateway candidate_broadcast -- --test-threads=2
cargo test -p gateway --locked --offline -- --test-threads=2
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo fmt --all --check
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
