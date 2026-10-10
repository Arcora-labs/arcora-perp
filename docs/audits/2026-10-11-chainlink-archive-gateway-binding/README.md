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
