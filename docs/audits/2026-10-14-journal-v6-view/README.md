# Candidate v6 journal serialization — pre-publication evidence

BASE: `16fde84b094d5964d58097441ced33b1cb7d21da` (normal PR65 merge).
Source: 380 files / `7fe776cc4f1f4c612b7584c11ae8715b0c6afc2c0273ebc411ba633911048fc8`.
Only changed source: `crates/gateway/src/rollback_journal.rs`, SHA
`5c8f2522a1177bd88406ee913c054d532d21d85c2d7065c0438883485fb1a5d9`.

A private Serialize-only borrowed v6 view replaces two serialization-only full
RollbackJournal/envelope clone sites: write and canonical re-encode. Owned
CandidateJournalV6 decoding and owned OpenedJournal returns remain. Reversing only
the added view and two replacements restores all pre-test production bytes to
BASE. No magic, layout, legacy path, error/check order, durability call, recovery
decision, caller, pin, lock, guest, workflow or repository protection change.

Three new normal tests compare whole bodies to the unchanged OLD owned-clone
reference across stage1, empty-proof registration intent and native mock stage2,
with empty and heterogeneous ordered/duplicate refs (six bodies). Actual write
plaintexts match old magic/body (three v5 and six v6 writes); all full owned decoded
values match. The old canonical decoder is copied from the BASE Git blob with only
name/indent/format changes. Exact negative errors match for suffix, noncanonical
integer, batch mismatch, zero policy, paired-fault precedence, wrong seed, tamper,
truncated envelope, stale magic and version confusion. A decodable noncanonical
v5 integer remains accepted; no new v5 canonical rule is imposed.

The new fixed fixture uses pure Sequencer deposit/FundInsurance/full-note Withdraw
operations with two nonempty claim paths. It uses no Gw::boot, environment identity,
wall clock, network or live prover. Stage2 uses native MockProverClient; intent has
an empty proof. Synthetic refs exercise codec fidelity, not archive authenticity;
existing archive-binding tests validate that separate boundary. Ciphertexts have
fresh random nonces, so comparisons open them and compare entire plaintexts.

Actual local accepted checks (overlapping filters, not summed):
- new candidate_v6: 3 PASS / 0 FAIL / 0 IGNORE;
- journal: 12 PASS / 0 FAIL / 0 IGNORE;
- archive_binding_v2 (includes five retention tests): 35 PASS / 0 FAIL / 0 IGNORE;
- price_lifecycle: 10 PASS / 0 FAIL / 1 existing IGNORE;
- format and gateway all-target Clippy with -D warnings: PASS.

Three zero-discovery records (archive_binding, retention, retention_v2) are retained
as HISTORICAL UNACCEPTED checks. They exit0 but run zero tests. Incorrect file/module
filters were corrected by archive_binding_v2, which actually executes binding and
included retention tests. These records are neither hidden nor promoted to PASS.

Scoped independent review and actual 5565-input preservation passed. Full baseline
5566 entries is outside Git only, SHA
`2a3957b46f33ee84fb8b99d8160be517b8738b1a0d8861ec1079b7e23ad35179`.
Previous reports, CI/evidence, 32 pins, 8 locks/manifests, 9 program artifacts and
82 public dirty bodies in three other checkouts remain protected. ACTIVE_WORK is
append-only and retains its complete BASE prefix; final protection is checked again.

PR CI / normal merge / main checks: PENDING at this historical packet cut. Full
gateway result requires separate actual CI (expected 766/0/24 in three logs), not a
sum of local filters. Later final records and the outside report prove publication.

No measured CPU/RSS/throughput benefit, global input cap, OOM/panic equivalence,
fresh proof, real CC/key release, live backend or production acceptance is claimed.
The existing 64MiB file cap is after serialization/sealing; this change does not
make it an early input/allocation limit. Custodial alpha, candidate submission
closure and six open production gates remain. PRODUCTION RELEASE HOLD.
