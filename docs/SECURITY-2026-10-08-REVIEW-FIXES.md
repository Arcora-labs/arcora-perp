# 2026-10-08 security review — fixes, migration assessment, and residual risks

This document records the fixes landed for the 2026-10-08 review, the
migration/redeploy assessment for each, and the items that were investigated but
deliberately **not** changed.

## 1. Market.id vs map-key binding (canonical state + SP1 witness)

**Finding.** `State::markets_digest` (`crates/perp-core/src/state.rs`) hashes the
`BTreeMap` **key**, never `Market.id`. Nothing anywhere compared the two, so a
witness could carry `Market { id: X }` stored under key `Y ≠ X` with an
*identical* state root, manifest digest, and proof commitment — the circuit was
blind to the mismatch.

**Fix (fail-closed, no honest-state change).**
- `State::validate_market_keys` (`state.rs`) rejects any map entry whose key ≠
  `Market.id`.
- `commitment::derive_roots` (the ONE derivation shared by the zkVM guest,
  `prover::run_transition`, and the SP1 host's native reference) calls it before
  deriving any root. New `EngineError::MarketIdMismatch`.
- Regression tests: `commitment::rejects_market_id_not_matching_map_key`,
  plus a guest-twin negative case `market-id-not-map-key` in
  `crates/sp1-host/src/lib.rs` (`normal_negative_cases`).

**Why not add `m.id` into `markets_digest`?** It would also close the hole, but
it changes the digest value for *honest* states, moving every existing state
root including genesis — a far heavier migration (see §5). The runtime check
detects the mismatch at zero honest-state cost.

## 2. Execution-clock consistency; external-time anchoring remains OPEN

`BatchManifest.batch_time_ms` is included in `manifest_hash`, after `batch_id`.
It is the maximum timestamp carried by the batch's original clock-bearing
operations, or zero when there are none. `derive_roots` checks that exact summary
before state mutation. This commits a summary; it does **not** authenticate time.
A malicious sequencer can still backdate the entire log and its manifest.

### Pre-merge correction, 2026-10-09

The first PR revision re-stamped historical operations to the final tick and
sometimes replaced their signed oracle transcripts with newer feed observations.
A new regression reproduced a live funding index of **-13889** and a replayed
index of **41666** from the same two honestly executed operations. This can stop
settlement through a replay/root mismatch. A fresh oracle cannot retrospectively
change an executed fill, liquidation, or funding interval.

The corrected sealer never changes operation times or signed oracle inputs.
It derives its oracle-update list from the actual operation log, not the mutable
latest feed. Funding intervals, historical prices, and rollback/re-seal identity
are preserved, even when proof generation is delayed or the feed advances.
`ClockMismatch` rejects an incorrect maximum summary, not legitimate distinct
per-operation times. Each oracle is validated against its original op time.

Regression coverage includes nonzero funding with opposite premium signs,
a window longer than oracle freshness bounds, feed changes during delayed
sealing and rollback, and both earlier/later incorrect timestamp summaries.

**Still open:** an independently checked L1 batch-time interval, cryptographic
binding of that interval to the guest's public inputs, and refusal of stale or
backdated logs. A pre-proof anchoring step can separate execution-time validation
from proof latency; that design requires explicit contract/gateway integration.
The current code must not be presented as having closed the freshness attack.

## 3. rejectedRoot challenge dismissal

**Finding.** `answerByRejection` trusts the settled batch's `rejectedRoot`.
That root IS bound into the verified proof commitment and derived in-circuit
from the manifest's committed rejected list, so under a **real** verifier a
sequencer cannot fabricate a `rejectedRoot`. The residual gaps:
1. **Rejection *reasons* are not proven** (the ordered-vs-rejected split and
   per-reason legitimacy are Proof-v2). A malicious sequencer can reject an
   order it could have included and dismiss the censorship challenge with a
   perfectly valid membership proof.
2. Under **MockZkVerifier** none of the above holds — any commitment verifies.
3. The challenger's bond always forfeited to the sequencer even when the
   rejecting batch settled only *after* the challenge opened — i.e. the
   challenger is what forced the order's on-chain disposition to be published.

**Fixes applied.**
- (3) `DarkPerpSettlement.answerByRejection` now mirrors `answerChallenge`'s
  SEQ-001 refund gate: rejecting batch settled after the challenge opened ⇒
  bond refunds to the challenger; settled before ⇒ forfeits to the sequencer.
  This removes the profit from "censor, then reject under pressure and collect
  the challenger's bond". Regression tests
  `test_rejection_answer_postdating_challenge_refunds` and
  `test_rejection_answer_presettled_forfeits_to_sequencer`.
- (1)/(2) **Documented limitation, not an enforced fail-closed fix:** rejection-reason
  semantics cannot be proven by the Proof-v1 circuit (that is Proof-v2's
  matcher-rerun scope), and MockZkVerifier deployments cannot enforce even the
  structural binding. Therefore: **a deployment running MockZkVerifier, or any
  pre-Proof-v2 deployment, must not treat a rejection answer as proof that the
  rejection was legitimate** — the challenge game's correctness in that regime
  still depends on honest sequencing. A refund is not a validity proof, and a
  dishonest rejection can still dismiss an inclusion challenge.

**Deliberately not done:** a manifest ordered∩rejected disjointness check was
implemented and removed — double-listing is a *legitimate* pattern (a resting
order listed in `ordered`, later cancelled into `rejected`; a partial fill with
its remainder rejected). Enforcing disjointness breaks valid flows and is not
required for the dismissal soundness argument.

## 4. Wind-down economic semantics — investigated, NOT changed

Per the review instructions, the wind-down loss distribution was investigated
and **left exactly as-is** (no unilateral change).

Current semantics (`op_settle_all`, `classify_wind_down_ops`, contract
`finalSettle`/`finalExit`): positions flatten at entry price (zero unrealized
PnL), funding is settled, and any pre-existing insolvency is reconciled
globally before the transition commits (`WindDownInsolvent` fails closed when
the socialization set cannot absorb the deficit). Bad debt beyond the insurance
fund is socialized through the ADL haircut list surfaced as attributable
receipts.

Observations recorded for a future, explicitly-governed decision (each changes
who loses what, so none was taken unilaterally):
- Flattening at entry price zeroes unrealized PnL: profitable positions give up
  unrealized gains (they keep realized/funded amounts), losing positions are
  made whole up to their collateral. This is simple and manipulation-resistant
  but is a *policy* choice (alternatives: oracle-mark flattening), with
  different distributional outcomes.
- The phase-2 `finalExit` withdrawals are gated on the one-shot phase-1
  `SettleAll` proof, and only price-free ops are permitted post-wind-down —
  verified in `a06_wind_down` tests.
- The `answerByRejection` bond asymmetry fixed in §3 interacts with wind-down
  only through the challenge game; wind-down loss distribution itself was not
  touched.

## 5. Migration / redeploy assessment (vkey compatibility)

The pinned `programVKey`
(`contracts/src/SP1ZkVerifier.sol`, deployed value in
`contracts/deployments/base-sepolia.json`) is **immutable on-chain**, and any
change to the guest circuit — or to anything linked into the ELF, which
includes all of `perp-core` — changes the vkey. Both fixes in §1 and §2 modify
`derive_roots`/manifest hashing, therefore:

- **The current deployments' vkey CANNOT verify proofs from the fixed circuit.
  A verifier redeploy is required before these fixes take effect on-chain.**
  Because `DarkPerpSettlement.verifier` is immutable, that means a full
  settlement-contract redeploy (or a pre-planned upgrade path) and repointing.
- **What does NOT migrate / what is preserved:**
  - `State`'s postcard encoding and every honest `state_root` (including
    genesis) are unchanged — `sec026_postcard_encoding_is_pinned` and the
    commitment KATs still pass unmodified. This establishes serialization/root
    compatibility only, not a safe live migration or transfer of vault funds.
  - The 7-word public commitment format is unchanged
    (`commitment_is_seven_field_state_root_domain` / KAT-COMMIT7).
- **What changes at the cutover:**
  - `manifest_hash` for every new batch (new field) — anything externally
    recomputing manifest hashes must include `batch_time_ms`.
  - The witness postcard encoding (`BatchManifest` field added) — proof
    pipeline (gateway → prover-service → sp1-host) versions must move together.
  - Historical operation times and signed transcripts must remain unchanged.
    Freshness is checked at each original operation time, not at seal/proof time.

**Rollout recommendation:** regenerate the vkey (`crates/sp1-host/src/bin/vkey.rs`),
redeploy `SP1ZkVerifier` + `DarkPerpSettlement` with the new vkey, and cut over
at a controlled boundary. Unchanged honest state roots do not migrate collateral:
`CollateralVault.settlement` is immutable too. Vault, deposit-prefix history,
withdrawal claims, and custody migration need a separate reviewed plan.
Until cutover, the on-chain system retains the pre-fix semantics documented
above; MockZkVerifier deployments must not carry real collateral.

## 6. Rust 1.99 CI and verification fixtures

The follow-up commit uses fixed-size `as_chunks`, retains strict ABI/hex length
checks, and adds three parser regressions. Lint and workspace tests are separate
Rust 1.99.0 jobs. Jobs running the native localhost L1 fixture install cast.
The seal-client initializes the manifest timestamp for its clock-free witness;
the ACK/crash drill requires the current `DPSNAP9` writer envelope, not legacy v8.

Rust 1.99 Clippy and focused tests were rerun for the pre-merge clock correction.
See `docs/audits/2026-10-09-clock-replay.md` and exact-head GitHub Actions for the
verification scope. Neither typechecking nor unit tests establish real SP1 proof
or deployed-verifier compatibility.
