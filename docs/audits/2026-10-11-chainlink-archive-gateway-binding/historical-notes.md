# Tarihsel ara notlar: güncel kabul kanıtı değildir

Bu dosya önceki README'nin ara aşama kaydını korur. Aşağıdaki metin bazı
**yanlış iddiaları ve yanlış tarihleri** de tarihsel kayıt olarak içerir; bunlar
onaylanmış sonuç değildir. Güncel düzeltmeler ve exact-code kanıtı için
[README.md](README.md), [final-verification.json](final-verification.json) ve
[evidence-recheck.json](evidence-recheck.json) esas alınmalıdır. Kişisel yerel
checkout yolu yayın için rol adıyla değiştirilmiş, satır sonu boşlukları
temizlenmiştir; tarihsel iddialar güncel sonuçlara dönüştürülmemiştir.

Özellikle: `298e30f` öncesi root pinleri geçmiyordu; `chainlink-oracle` aday
guest'in de bağımlılığıdır; `a4e1c3e` içindeki snapshot/marker-loss testi iddiası
o commit için yanlıştı. Test `e283958` ile gerçekten eklendi. Aşağıdaki 12 Ekim
başlıkları hatalıdır; doğrulama 10 Ekim UTC / 11 Ekim Türkiye saatindedir.
524/505 gibi ara sayılar güncel 528 sonucunun yerine geçmez. “real replay prove”
yalnız native MockProverClient replay'dir, SP1 proof değildir. Snapshot aday
etiketi vardır, açık-pencere admission indeksinin kalıcı kurtarması ise yoktur.

---

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
Source: preserved primary checkout (branch feat/chainlink-streams-client-20261010, HEAD 2a03bb0, uncommitted task work)

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

## Review round 4 (2026-10-11): identity-keyed binding, not recency
- `bind_ops` now derives references in OP ORDER from retained admissions keyed
  by exact (market, transcript) IDENTITY (price, publish time, confidence,
  backup TWAP — all derived from immutable report bytes, clock-independent).
  The previous newest-first/recency candidate scan is gone: a window can hold
  both an earlier and a later transcript for the same market, and repeated use
  of the same valid archive ID is legitimate (identical report bytes hash to
  the same record anyway). `PreparedPair::for_operation`'s
  original-operation >= preparation-time rule is unchanged and still enforced
  at admission/verification; the policy binding continues to include the
  wrapper/proxy addresses that `Policy::hash` omits.
- New test: `bind_handles_multiple_observations_per_market_in_op_order_with_
  repeated_use` — non-monotonic op timestamps, Fill/Liquidate/AccrueFunding
  mix, same ID referenced 3x, refs asserted in exact op order, verify accepts,
  and a mid-stream unarchived transcript fails the whole seal.
- Re-run: cargo test -p gateway → 511 passed / 0 failed; clippy 0 warnings;
  fmt clean.

## Review round 5 (2026-10-11): durable candidate-mode boundary
- New sealed, versioned mode marker `<state>.chainlink` (magic DPCAM1): written
  only in candidate mode, sealed with the enclave seed exactly like the
  rollback journal, holding the policy binding. Snapshot wire bytes are
  unchanged; the marker is a separate sidecar and is never deleted by the
  gateway (leaving candidate mode is a conscious operator act).
- Boot order: the mode gate (pure, unit-tested `mode_gate`) runs BEFORE the
  crash-recovery block, so apply_boot_recovery — including its
  Stale/SealNeverPersisted journal deletions — can only ever run after the
  mode is settled. Cases: no marker + no config = legacy (unchanged); no
  marker + config = persist the marker first (refuse startup if the marker
  cannot be made durable); marker + matching config = continue; marker with
  config omitted/disabled or policy-mismatched = REFUSE; marker present but
  unreadable (wrong seed/tamper/future magic/trailing bytes) = REFUSE, never
  treated as absent.
- This closes the open-unsealed-window hole: a candidate gateway that
  persisted state mid-window (restored snapshot, archive-admitted ops, no
  `.rollback` journal yet) previously could reboot with the env flag omitted
  and settle unbound windows as legacy — the journal-level guards never saw
  it. Tested explicitly.
- New tests: mode_gate matrix (disabled/missing/mismatch/unreadable),
  open-unsealed-window restart refusal + legacy-state controls, marker IO
  round trip + fail-closed postures.
- Re-run: cargo test -p gateway → 514 passed / 0 failed; clippy 0 warnings;
  fmt clean.

## Review round 6 (2026-10-11): no substitution/fallback path in binding
- The old newest-first candidate scan is gone entirely (it was already
  replaced by identity matching in round 4; this round closes the remaining
  holes). `admit()` now stores the record durably and returns a
  PendingAdmission WITHOUT touching the ledger; `install()` is called by the
  intake ONLY after `apply_validated_real_oracle_at` accepts the transcript.
  A rejected admission can never become selectable or shadow an identity.
- The binding index maps each (market, transcript) identity to exactly ONE
  canonical ArchiveId: the FIRST accepted admission (insert-if-absent). Two
  different original full-report records CAN normalize identically; a later
  equal-normalized record is stored but never replaces the selection.
- `bind_ops` resolves ops in op order against that index and then loads every
  SELECTED record from the durable archive before the envelope is returned: a
  missing exact ID fails the seal (Err/Archive) even when an equal-normalized
  sibling exists. Repeated use of one valid ID is legitimate (loaded once).
- Capacity refuses (new BindError::Capacity) instead of silently evicting; the
  intake pre-checks `is_full()` so a full index rejects the fetch before any
  downstream admission. No eviction path remains.
- New tests: rejected admission never installed / cannot replace or shadow;
  same-normalized-but-different-full-report siblings keep the original ID and
  missing-the-exact-ID fails the seal and recovery even with the sibling
  present; capacity refusal with retained identities still binding.
- Historical/repeated ops remain covered by the round-4 multi-observation test.
- Re-run: cargo test -p gateway → 517 passed / 0 failed; clippy 0 warnings;
  fmt clean.

## Review round 7 (2026-10-12): no silent downgrade; reachable candidate path
- Poisoned archive mutex: the settle loop's `.map(lock).and_then(ok)` collapse
  is replaced by `archive_slot` (NotConfigured vs Guard vs Poisoned); Poisoned
  HOLDs the settle and never seals a candidate window unbound. Regression test
  poisons a real mutex and asserts the distinction.
- Missing journal path in archive-required mode: `begin_journaled_window_settle`
  refuses BEFORE the seal (Counter B unchanged) and `after_settle_journal`
  independently refuses an archive-bound stage with `path=None` before invoking
  the continuation. Both regression-tested.
- Reachability: candidate startup no longer refuses on default feed-backed
  markets; the legacy oracle loop is suppressed in candidate mode and the only
  startup requirement is policy coverage of every configured market
  (`uncovered_market`, tested) plus the crosscheck incompatibility. Demo-seeded
  marks remain unbindable in candidate mode (documented deliberate boundary).
- Re-run: cargo test -p gateway → 521 passed / 0 failed; clippy 0 warnings;
  fmt clean.

## Consolidated final review (2026-10-12): all 7 items, final state
1. Binding: exact (market, accepted-transcript) identity -> ORIGINAL ArchiveId,
   installed only on successful gateway admission; insert-if-absent (equal-
   normalized siblings never replace); existence barrier at seal; capacity
   refuses. Tests: rejected duplicate, same-normalization/different-bytes
   siblings, deletion of the selected record, historical/repeated ops.
2. Poisoned archive mutex: archive_slot (NotConfigured/Guard/Poisoned) HOLDs
   the settle; candidate + path=None refused BEFORE any mutation, and
   after_settle_journal independently refuses an archive-bound stage without a
   path before the continuation.
3. Submission gate: ensure_submission_supported refuses ALL v2 submission in
   candidate mode BEFORE the clock intent, register_clock, prove, or broadcast —
   including zero-oracle batches; counting-prover test shows 0 invocations on
   the refused path, 1 on the legacy control. V2 exact-resume rejects candidate
   journals first (round 2).
4. Decoder: take_from_bytes + empty remainder for both versions; v6 also
   canonical re-encode; authenticated-plaintext trailing and v6-under-v5-magic
   version-confusion tests; deliberate byte-compatible v5. Envelope retention
   verified at every later stage write (clock intent, stage 2; resume refuses
   candidate so its write is v5-only by construction).
5. Restart survival: sealed versioned mode marker <state>.chainlink (DPCAM1)
   + boot gate before ALL recovery branches (incl. Stale/SealNeverPersisted);
   marker+omitted-config refuses, unreadable marker refuses, open-unsealed-
   window restart tested; snapshot wire bytes untouched.
6. Reachable candidate path: legacy/simulated intake suppressed, policy must
   cover every market, crosscheck refused; submission routes refused until v3.
   THE end-to-end success test uses real signatures and a real engine fill:
   production-style fresh oracles -> archived pair through the real
   apply_validated_real_oracle_at -> real market-order fill at the archived
   mark -> real window seal -> encrypted v6 journal -> exact read/recovery ->
   real replay prove (identical commitments).
7. Config: partial settings (DIR/POLICY without MODE, or with disabled/unknown
   mode) FAIL; policy read is bounded (64 KiB), regular, non-symlink public
   data; policy_binding commits proxy/wrapper addresses (Policy::hash alone
   does not).

Final validation on head: cargo test -p gateway 524 passed / 0 failed;
streams-client 62/62 debug + release; chainlink-oracle 16; clippy 0 warnings;
fmt clean; repository/operator/SP1-release/chainlink-replay/release-manifest
guards OK (21+9 pins intact).

## Remaining candidate/live limitations (exact)
- No supported submission route in candidate mode until real v3 chainlink
  proving is wired: windows seal, journal, and HOLD; boot recovery rolls the
  stage-1 window back. No v3 witness is constructed or sent to the v2 prover.
- Live Data Streams pull requires explicit credentials; without them the
  stream stays DEFERRED (user-deferred discovery/entitlement after HTTP 403).
  Synthetic fixtures and an explicit public operator policy only.
- Demo-posture seeded marks are unbindable in candidate mode (documented); the
  reachable path is production-style fresh oracles fed by the archive intake.
- Wind-down windows flow through the same settle loop and are refused
  submission in candidate mode like any other window.
- Imported archive provenance: PreparedPair/ReportArchive and their tests/docs
  were copied uncommitted from the primary checkout (Desktop repo, HEAD
  2a03bb0) and reconciled onto post-#43 main; per-file sha256 inventory above
  (5 files carry only this branch's additive edits; the rest match exactly).
  The primary checkout was not modified.
- Publication: PR #44 OPEN (not merged, candidate, PRODUCTION RELEASE HOLD).
  The bridge publication monitor's /history route 404 is a monitor issue; the
  normal gh publication path succeeded and the PR state was verified directly.

## Build review fix (2026-10-12): host facades instead of a root-manifest edit
- Root Cargo.toml restored to the EXACT reviewed bytes (sha256 e3144a0a…,
  matches base c34fb56; the earlier exclude-list edit is reverted). No guest
  manifests, locks, verify_clock_proof pins, or expected hashes touched.
- New thin manifests only, NO duplicated source:
  - crates/chainlink-oracle-host/Cargo.toml — [lib] path =
    "../chainlink-oracle/src/lib.rs", test = false, doctest = false; same
    runtime features (std = perp-core/std) and dependency pins.
  - crates/chainlink-streams-client-host/Cargo.toml — [lib] path =
    "../chainlink-streams-client/src/lib.rs", test = false, doctest = false;
    chainlink-oracle aliased to the host package; identical version pins.
  Cargo auto-includes both facades as workspace members (no [workspace] table),
  so the root manifest stays byte-identical. Gateway dependency keys keep the
  original Rust crate names (chainlink_oracle / chainlink_streams_client).
- Source identity: facades compile the untouched originals
  (lib.rs sha256 a107bf74… / 4a63eec6… — same files as the standalone crates).
  Standalone suites still run under their ORIGINAL manifests (62/62 debug and
  release; oracle 16/16); no CARGO_MANIFEST_DIR-relative fixtures are used
  through the facades.
- Cargo.lock delta: exactly the two local package identities renamed to
  *-host (plus k256 now listed as the facade declares the same dev-dependency).
  NO registry version or checksum changed; shared locked dependencies: 41.
- Validation: cargo metadata resolves; cargo test -p gateway 524 passed /
  0 failed; clippy 0 warnings; fmt clean; repository/operator/SP1-release/
  chainlink-replay/release-manifest guards OK (21+9 pins intact).

## Final review round (2026-10-12): self-authenticating candidate snapshots
- Gap closed: marker absence cannot prove "never candidate" — a candidate
  snapshot with an OPEN/unsealed window (archive-admitted ops, no journal yet)
  could be restored with the `.chainlink` marker lost and MODE omitted, and
  boot as legacy. Candidate mode now prefixes every snapshot it writes with a
  versioned tag INSIDE the sealed plaintext (DPCAS1): persist_recovery (boot
  recovery persistence), write_snapshot and final_snapshot (the runtime
  writers). Restore detects and strips the tag and refuses the legacy boot
  (`snapshot_mode_refusal`) BEFORE any recovery branch when candidate config is
  absent. Valid legacy snapshot bytes are NEVER tagged and restore exactly as
  before — no snapshot wire migration, no live-state change.
- Marker semantics corrected: `mode_gate(Ok(None), None)` is documented as the
  reviewed legacy path for UNTAGGED state, explicitly NOT as proof of never-
  candidate; the tag is the authenticated identity.
- Test: `candidate_snapshot_refuses_legacy_boot_after_marker_loss_open_window`
  — a REAL Gw snapshot persisted via the real persist_recovery(candidate=true),
  marker deleted/omitted, MODE unset → refusal; config restored → proceed;
  legacy untagged positive control proceeds; untagged-with-marker still refuses.
- Validation: cargo test -p gateway 524 passed / 0 failed; clippy 0 warnings;
  fmt clean; all guards OK. chainlink-oracle pins untouched (0 commits/0 diff).
- PR #44 remains DRAFT per reviewer until scoped acceptance passes.
