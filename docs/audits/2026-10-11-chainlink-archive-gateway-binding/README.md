# Chainlink report archive → gateway → sealed journal → recovery binding

Date: 2026-10-11 (local run, Europe/Istanbul host)
Branch: kimi/job--17-implement-and-publish-the-actual-chainli
Base: origin/main (merge PR #43) = c34fb56b05db13ce09efc0104c2d44abba6d6895; stale local main ref 73e87c1 noted for the record
HEAD at capture: c34fb56b05db13ce09efc0104c2d44abba6d6895

## Scope
Opt-in candidate gateway binding: archive-before-admission, actual-op-stream
binding at seal, authenticated DPRBJL6 journal envelope, recovery verification.
Candidate only; PRODUCTION RELEASE HOLD; no v3 witness is sent to the v2 prover;
no merge, no live Chainlink requests, no credentials used.

## Source hashes (sha256)
d6d9b0e834614daae834d30bc27e1e47b8c72d3140850ec4e2a37396b8f15acf  crates/gateway/src/report_archive_binding.rs
0865e3f4e97f2436150022927ef14334d8152a6df270e21ce5b78c3c3c48fcf4  crates/gateway/src/report_archive_binding_tests.rs
087161cb8d63ec1b9f74e3c6751423718d4b1dc613bd26c8f1e2c161c461e6fc  crates/gateway/src/rollback_journal.rs
5e4afad09455d56e884a8ecaaf4a52ce4356c9d90da44d2916da08c78e0a9653  crates/gateway/src/clock_client.rs
803a1c8676f13cf2423a0d7ee7c209b38c857c7106e064195ed7737f0a98d604  crates/chainlink-streams-client/src/report_pair.rs
7db6e4f67577a6a78c0747ed22322e2c62dab3b2a10271aa4193f21f9ef9f62a  crates/chainlink-streams-client/src/report_archive.rs
0c8b862f82779dbab6a1c0dabeaa768e069396a3adb08799c38ec785e7ec47e7  Cargo.toml
59bbd6269c868acbca776536065fb461e3c53221338d3debb11e1798579cdae0  Cargo.lock
dda9d2f0890d41b94152cccb7fe72c1d22caa8bb59902b8492cb4c92ff0311ea  crates/gateway/Cargo.toml

## Cargo.lock delta vs base
 Cargo.lock | 24 ++++++++++++++++++++++++
 1 file changed, 24 insertions(+)
diff --git a/Cargo.lock b/Cargo.lock
index bffba52..b8474ab 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -283,6 +283,28 @@ dependencies = [
  "zeroize",
 ]
 
+[[package]]
+name = "chainlink-oracle"
+version = "0.0.1"
+dependencies = [
+ "perp-core",
+ "postcard",
+ "serde",
+]
+
+[[package]]
+name = "chainlink-streams-client"
+version = "0.0.1"
+dependencies = [
+ "chainlink-oracle",
+ "hmac",
+ "serde",
+ "serde_json",
+ "sha2",
+ "ureq",
+ "zeroize",
+]
+
 [[package]]
 name = "chrono"
 version = "0.4.45"
@@ -800,6 +822,8 @@ name = "gateway"
 version = "0.0.1"
 dependencies = [
  "axum",
+ "chainlink-oracle",
+ "chainlink-streams-client",
  "dark-perp-attestation",

## Validation actually run on this branch (exit codes)

### cargo test -p gateway report_archive_binding (new binding tests)
test report_archive_binding::tests::admit_persists_the_exact_record_before_returning ... ok
test report_archive_binding::tests::bind_fails_closed_for_unarchived_or_substituted_transcripts ... ok
test report_archive_binding::tests::bind_binds_the_actual_op_stream_in_order_with_repeated_use ... ok
test report_archive_binding::tests::candidate_journal_round_trips_through_the_real_sealed_journal_path ... ok
test report_archive_binding::tests::verify_fails_closed_on_missing_corrupt_or_mismatched_records ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 516 filtered out; finished in 0.25s
exit=0

### cargo test -p gateway (full suite)
test result: ok. 505 passed; 0 failed; 16 ignored; 0 measured; 0 filtered out; finished in 18.81s
exit=0

### chainlink-streams-client: cargo test (debug) — 62 passed, 0 failed, 1 ignored (child driver); exit=0
### chainlink-streams-client: cargo test --release — 62 passed, 0 failed, 1 ignored; exit=0
### chainlink-streams-client: cargo clippy --all-targets — Finished, no warnings; cargo fmt --check OK

### chainlink-oracle: cargo test
test result: ok. 16 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.14s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0
### gateway clippy/fmt/release-check
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s
fmt exit=0
    Finished `release` profile [optimized] target(s) in 15.45s
### repository guards (scripts/local-verification)
test_repository_policy: OK
test_operator_policy: OK
test_check_sp1_release: OK
test_chainlink_replay: OK
test_release_manifest: OK (skipped=1)
### journal/recovery regression scope actually exercised
cargo test -p gateway: rollback_journal mod tests, recovery_checkpoint mod tests,
settle_journal_guard tests, boot recovery fixtures, oracle_intake/crosscheck suites,
snapshot_crash_tests, continuation_settlement_tests, funds_lifecycle_tests — all in the 505.
## Known limitations
- Candidate mode is opt-in and never routed to the reviewed v2 prover differently;
  no v3 chainlink witness is constructed or submitted anywhere in the gateway.
- Live Data Streams pull runs only with explicit credentials; otherwise deferred.
- Internal gateway re-mark paths (oracle_of) re-sign current marks; in candidate mode
  windows carrying such transcripts fail to bind and are not sealed (fail-closed).
- used_oracle classifier mirrors chainlink-oracle binding::used_oracle; a new BatchOp
  variant must update both or seal-time binding fails closed.
- Root Cargo.toml delta: exclude list gains the two chainlink crates (host-only
  workspace membership); no versions/pins/members changed. Cargo.lock delta is
  additive only (two package entries + two gateway deps).

## Review round 2 (2026-10-11): guard placement before prover/chain side effects
- `ensure_archive_binding_current` (main.rs) re-verifies the sealed window's
  archive binding immediately before the settle loop's `prove_and_prepare`
  (whose clock-client `clock_context` performs the `register_clock` CHAIN
  MUTATION); failure holds settlement with the journal kept. Bind-at-seal alone
  was insufficient: records can be corrupted/deleted between seal and prove.
- `clock_client::ensure_resume_supported` rejects candidate-bound journals in
  the v2 exact-resume path; `resume_exact` re-checks it as its first statement
  (before any L1 read/registration/prove), and the boot block refuses before
  even constructing the resume call. Legacy (envelope-less) resume unchanged.
- No fallback: a candidate journal with missing archive references still opens
  as Candidate (never Legacy), and `verify` fails → recovery HOLD. An unproved
  (prepared=None) candidate journal resolves only via the existing stage-1 rows
  (SealNeverPersisted/RollBack); the v2 resume is never attempted for it.
- New tests (2): a counting prover shows ZERO invocations on missing/corrupt
  record and on op/envelope mismatch (and exactly one on the intact control);
  candidate-bound journals are rejected by the v2 resume gate and never demote
  to legacy.
- Re-run: cargo test -p gateway → 507 passed / 0 failed; clippy 0 warnings;
  fmt clean.

## Archive-copy inventory: primary checkout → task worktree (sha256, verified identical)
Source: /Users/huseyinarslan/Desktop/arcora-perp/repo (branch feat/chainlink-streams-client-20261010, HEAD 2a03bb0, uncommitted task work)

MATCH  4a63eec6941704583a83b395a5c8f34c5e685c33950c7e7bf96eb9999479de54  crates/chainlink-streams-client/src/lib.rs
MATCH  17259c937c1d90e3b0950fadf78d71caaab2e6d1bf0b457cae93b83a486c4079  crates/chainlink-streams-client/src/transport_tests.rs
DIFFERS  7f9154fe5cafe182ed5bdc80976b44f19667bc4747ac801f3cec583de362ad7a  crates/chainlink-streams-client/src/report_pair.rs
DIFFERS  7ce55278f094ff7ad67e1dc9fbbe8f4744b1e29ef1f6304f6a5e70594bd2805e  crates/chainlink-streams-client/src/report_archive.rs
MATCH  e26ad11aac0d1510354003e3cc6ec494b06b6938c1d4778bfa46135fe80c04ab  crates/chainlink-streams-client/src/report_archive_tests.rs
DIFFERS  57d2fd9fe21055c7e2c269d272a4f12436b4f75c8f479a74913c5307849924c1  docs/ACTIVE_WORK.md
DIFFERS  923ce0fbca1aab31f61fd0d23c542c0f6575b0089032085e13ce61d5d766d9f2  docs/CHAINLINK_STREAMS_CLIENT.md
DIFFERS  b150b8a38bef610f5fe25bfef30aee87b5d07ca0435b350fdb45bac68f8672f8  docs/CHAINLINK_REPORT_ARCHIVE.md
MATCH  2c1ce26530e60512a630e039b7b3ed4f644de43ede8dad86f905bf3c94e25c07  docs/audits/2026-10-10-chainlink-report-archive/README.md
MATCH  8fe1cceb492aa4a00019f1138dcc7086d618b771c15415d7c89709480672bd9c  docs/audits/2026-10-10-chainlink-report-archive/client-debug.txt
MATCH  200dcb6a224946470eee5349dc4f04077fa4e02bd6104e9a8a9d10a1b031ed98  docs/audits/2026-10-10-chainlink-report-archive/client-release.txt
MATCH  48e36c7a0e9d641c64badc95fa235bb3a5e024163ecc361372ea57307946490b  docs/audits/2026-10-10-chainlink-report-archive/publication-state.json
MATCH  95b9e0448233ba84bc24c05bc581b4c9ea56b23a1ca838f1950c846457c390b7  docs/audits/2026-10-10-chainlink-report-archive/verification.json

DIFFERS entries are the task's own subsequent edits, not copy drift:
- report_pair.rs / report_archive.rs: additive API only (pub policy_binding,
  serde on ArchiveId) made in this branch for the gateway envelope.
- docs/ACTIVE_WORK.md, CHAINLINK_STREAMS_CLIENT.md, CHAINLINK_REPORT_ARCHIVE.md:
  updated on this branch to record PR #43 merged, the gateway binding, and the
  deferred live work. The primary checkout's copies are untouched.

Nothing was written back to the primary checkout; its working tree retains
the same uncommitted set (git status below, captured 2026-10-11 after the copy):
 M crates/chainlink-streams-client/src/lib.rs
 M crates/chainlink-streams-client/src/transport_tests.rs
 M docs/ACTIVE_WORK.md
 M docs/CHAINLINK_STREAMS_CLIENT.md
?? crates/chainlink-streams-client/src/report_archive.rs
?? crates/chainlink-streams-client/src/report_archive_tests.rs
?? crates/chainlink-streams-client/src/report_pair.rs
?? docs/CHAINLINK_REPORT_ARCHIVE.md
?? docs/audits/2026-10-10-chainlink-report-archive/
HEAD: 2a03bb03a7db9736e72573fa22d8fe8f4fe37f94

## Source and prover barriers
Source barriers (verified by this branch's changes and the repo guards):
- Reviewed v2 guest/perp-core sources, ELF/vkey pins, public input and risk
  thresholds: unchanged; `scripts/local-verification` guards (repository
  policy, operator policy, SP1 release, chainlink replay, release manifest)
  all pass on this branch.
- `chainlink-oracle` and `chainlink-streams-client` remain host-only: neither
  is a dependency of any guest root; the root workspace `exclude` list change
  is membership-only. Root pin tests were updated for one legitimate new
  PATTERN use (the binding's `used_oracle` classifier), per that test's own
  contract; expected hashes were not altered.
- Gateway-side transcript format is unchanged (ZK-001 gateway-signed
  OracleTranscript); chainlink data is archived corroboration, never marked
  DON-verified, no source timestamp refreshing, no latest-file fallback.

Prover/chain barriers:
- Durability order is enforced at three points: archive durable before
  state-changing admission (ArchiveBinding::admit), bind+seal before the
  stage-1 journal (begin_journaled_window_settle), and
  `ensure_archive_binding_current` re-verification immediately before
  `prove_and_prepare` — the call that performs the `register_clock` CHAIN
  MUTATION via ClockProverClient::clock_context. A counting-prover test shows
  zero prover invocations on missing/corrupt records and op/envelope mismatch.
- The v2 exact-resume path rejects candidate-bound journals
  (`clock_client::ensure_resume_supported`, checked at boot and first in
  `resume_exact`) until real v3 submission is wired; no v3 witness is
  constructed or submitted anywhere.
- Decoder barriers: both journal versions decode with
  `postcard::take_from_bytes` + empty-remainder (postcard `from_bytes`
  discards suffixes); v6 additionally requires canonical re-encoding; a v6
  payload under the v5 magic is refused as version confusion; valid v5 output
  still opens through both decoders (deliberate compatibility).
