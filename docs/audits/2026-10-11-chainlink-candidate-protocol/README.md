# A4: offline candidate protocol, intent and registration evidence

11 October 2026. **PRODUCTION RELEASE HOLD.** First offline A4 software packet.
Tested code: `b5710f1206345a3f3d8c3d070d7d7cdc70d430f3`; base is merged main `969ecec2fecd29621c5508ab58fb778617b9bce2`.
This publication adds documentation/evidence to the tested source bytes.
[Verification ledger](verification.json) records commands, raw log hashes and source hashes.
[Current work and remaining gates](../../ACTIVE_WORK.md) supersedes the historical
[A4 design inspection](../2026-10-11-chainlink-price-lifecycle/next-a4-design.md).

## Behavior and scope

New candidate intent/protocol/registration modules, material extraction and fixture
builders compile only under `cfg(test)`. The harness has caller-owned mocks and
no HTTP/L1 transport, environment activation, live `PreparedSettle` conversion or
production candidate submission path. Existing submission and exact v2 resume
blockers, including price-free candidate batches, remain intact.

Material extraction checks the canonical authenticated envelope against exact
selected archive references, policy and original operation times. It loads each
immutable original full report, never a same-price or equal-body sibling. Archive
IDs establish host provenance; they are not added to guest public input. A material
checksum pins extracted data and does not independently authenticate the archive
or DON.

The candidate witness remains DPCLK3 with the existing **v2 inner clock**.
Program identity includes protocol magic, SDK 6.1.0, candidate ELF SHA and vkey.
Explicit target identity binds chain/network, clock/settlement/wrapper/proxy,
policy, immutable uptime feed/grace, and five nonzero runtime code-hash pins.
All target/runtime values supplied by these tests are synthetic configurations;
none is an approved deployment identity.

`inputHash = keccak256(abi.encode(Entry[]))` covers original full signature
containers and their order. Ordered body `evidenceHash` separately binds policy,
entry count, market, original time and both body hashes. Rust encoding is checked
against manual ABI offsets and Solidity reconstruction. Equal bodies with a
changed signature container preserve body evidence and change full input identity.

For priced requests, a healthy uptime round/startedAt is pinned before the first
callback. Original first-operation time and current observation time must be
strictly beyond grace. Any changed epoch rejects reuse. Price-free actual
wind-down uses only the canonical zero-epoch exception inside the offline harness.

The tested sequence is preflight → authenticated immutable intent → exact clock
registration/observation → full-report registration/observation → candidate-only
mock prove → authenticated Prepared → exact clock/target/report/epoch recheck →
mock broadcast. Known invalid inputs call nothing; later errors preserve counts
of earlier attempted actions and prevent subsequent actions. Invalid prover
identity/public commitment cannot reach broadcast.

The separate DPCINT3 authenticated file uses explicit stage/version, bounded
fixed-width length framing, at most 24 MiB request and 16 MiB Prepared payload,
owned-file size/growth bounds, authentication before parsing, canonical encoding
and rejection of trailing/version-confused bytes. An owned handle serializes its
writes; no cross-process coordination is claimed. Prepared restart reuses exact
material, response, receipt and anchor block hash, skips registration/proving and
rechecks before broadcast. Pending restart pins the exact initial request and
epoch but does **not** durably pin intermediate registration block outcomes before
Prepared. Real transaction/finality/reorg reconciliation remains open.

A pre-rename failure preserves previous target bytes, including an actual filesystem
NAME_MAX failure test. Directory fsync failure after rename is ambiguous: stop all
subsequent actions and reload exact persisted bytes; no rollback or old-byte
survival guarantee is claimed for that stage.

## Local results

| Check | Observed result |
|---|---|
| Full gateway on final rebased sources | 572 passed, 0 failed, 18 ignored |
| Focused protocol / intent / registration / exact extraction | 10 / 5 / 6 / 1 passed |
| Explicit public synthetic fixture exporter | 1 passed |
| Full Foundry suite | 168 passed, 0 failed, 0 skipped; 7 new paired contract tests |
| Python process/repository/operator guards | 47 passed |
| Workspace Clippy, format, diff | passed |
| Reviewed / candidate runtime source pins | 21 / 9 unchanged; release and candidate locks passed |
| Actual gateway normal / liquidation native vs SP1 CPU | both passed, public commitment byte-identical |

Ignored tests are not reported as executed; the fixture helper was run explicitly.
All 22 new non-ignored Rust tests also ran in the final full gateway suite. Real
normal open/funding/close/signed withdrawal, valid liquidation and price-free
wind-down/restart come from gateway flows with synthetic reports. Tests exercise
missing/corrupt selected reports, equal-body sibling refusal, wrong identities,
version/capacity/timing, callback faults, receipt/report/epoch mutation, invalid
response, actual persistence failure, exact pending/Prepared recovery and
malformed/trailing authenticated payloads.

The definitive fixed corpus is in [fixtures](fixtures/manifest.json), manifest SHA
`3147718b8db6036f0ecb540157dfaea260f010726abdc2895d53baf4d08c6480`.
Its four raw builder source fingerprints exactly match final sources. Export ran
before a later main `cfg(test)` module declaration-order formatting repair; the
[exact receipt](repair-history/main-format-receipt.json) and
[diff](repair-history/main-format.diff) document that sole main change. Final
full suite, protocol/golden focused checks, Clippy and format ran on formatted
main. Earlier intent/extraction focused logs cover unchanged builder modules;
those tests also ran in the final full suite. No post-format export is claimed and the incidental unused final3 corpus is not evidence.

| CPU case | Witness SHA-256 | Cycles |
|---|---|---:|
| Normal lifecycle | `8f23160f0a0ff9d004c4c78a25877fc84f4e50e8263b46115695f1d212f9e937` | 27,237,960 |
| Liquidation | `ba6b4cd72a38db1c4b0188b9eff98e41022dffceca7dd5de5ff47b0f5adb0337` | 24,293,454 |

The CPU runner executed the pinned candidate ELF:
`48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f`,
setup vkey `0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590`.
It reused the unchanged A3 driver binary after verifying source/binary/ELF hashes;
[audit receipt](cpu-driver-reuse.json). No fresh driver build is claimed. Total
51,531,414 cycles describes these two CPU cases, not proof p95/capacity. Outputs
are retained in [cpu-execution](cpu-execution/manifest.json).

## Contract parity is a bounded mock integration

The original full-report vectors in
[`contracts/test/fixtures/chainlink-candidate-protocol.json`](../../../contracts/test/fixtures/chainlink-candidate-protocol.json)
match the exporter as parsed and carry current source hashes. Real clock, oracle
wrapper and settlement contracts consume their ABI/body hash vectors, with
**mock DON, SP1 and uptime**. Replacement, reorder, count mismatch, clock endpoint
and changed epoch failures retain unchanged settlement state.

The contract fixture uses its own R/N roots (1/2) and a mock bound-hash proof.
These are **not** the complete native witness public commitment and are not an
SP1 proof. This is full-report registration/hash parity plus mock contract
registration/settlement behavior, not a complete host → real proof → contract
bridge. CPU execution above separately establishes native/guest parity.

## Repairs, merge observations and retained work

The first focused Foundry run failed two tests because a getter evaluated after
`expectRevert` consumed its next-call expectation. Computing the proof before
that expectation repaired the tests; 7/7 focused and 168/168 final full tests
passed. Clippy caught a redundant cloned slice; using `from_ref` repaired it.
Format then caught main test module order. Failed-before and passed-after logs
are retained in [repair-history](repair-history).

Fixture refresh after the lint edit changed randomized account roots/witness
identities. Original reports, ordered entries, full ABI, policy/input/evidence
hashes and timing remained exactly the same. The final refreshed witnesses were
executed independently on CPU; the refreshed contract fixture passed full
Foundry. The [delta receipt](repair-history/final2-fixture-refresh.json) records
this distinction; older randomized witness identities are not the final corpus.

#46 and #47 each merged normally after 19/19 successful checks at their exact
heads. #46 merge: `c32432f69bf60610e41ff6ef87fb0c5f5981e79d`; #47 merge/main:
`969ecec2fecd29621c5508ab58fb778617b9bce2`. #47 updated head, tested prior head and
merged main have the same source tree. Repository protections were not changed.
[Fresh merge observations](merge-observations.json) retain exact head check URLs.

The original primary 13 dirty files and job--17 seven staged documents retain
original hashes; [recheck](original-checkouts.json). Only this isolated A4
worktree was rebased; no reset/clean/migration touched original checkouts. This
new packet's published-head CI is a separate GitHub observation from local results
and from the already merged #46/#47 checks.

## Remaining acceptance

Real candidate proof generation/verification and approved guest/key provenance;
DON-authenticated matching reports; attested candidate service/transport; approved
chain/runtime/immutable deployment and live uptime; finalized/reorg observations
and interrupted-batch reconciliation; four exact wallet witness proof/claim
scenarios; production capacity and custody/exit/independent audit gates remain
open. Feed/entitlement discovery remains user-deferred. Core/guest sources,
reviewed ELF/vkey, manifests, locks and workflows are unchanged by this packet.
The existing CI exercises Rust and contract tests; these two new fixed CPU cases
are local evidence, not a newly added CI CPU step. No live oracle/chain credential or RPC use,
registration, proof, chain transaction, funds or production protocol rollout/release occurred.
