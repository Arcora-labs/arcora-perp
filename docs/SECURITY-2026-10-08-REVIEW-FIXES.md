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

## 2. Oracle freshness clock bound to a committed batch time

**Finding.** Oracle freshness (`publish_time ∈ [now - max_staleness, now]`,
`OracleTranscript::validate`) was checked against a `now_ms` embedded per-op in
the *private* witness. The manifest doc-comment claimed the clock was
"committed in the manifest", but `BatchManifest` had no time field — the
freshness clock was prover-chosen and unverifiable by anyone holding only the
committed data.

**Fix.**
- `BatchManifest` gains `batch_time_ms: u64`, hashed into `manifest_hash`
  (word order: after `batch_id`). The freshness clock is now part of the
  manifest preimage anyone can recompute from the anchored `manifest_hash`.
- `derive_roots` rejects (`EngineError::ClockMismatch`) any clock-carrying op
  (`Fill`/`AccrueFunding`/`Liquidate`/`Unbind`) whose `now_ms` ≠
  `manifest.batch_time_ms`, before any state change.
- `Sequencer::seal_batch` stamps the manifest with its `now_ms` (every op in a
  per-tick batch already shares it).
- `Sequencer::seal_window` commits the window's single reference clock =
  **max op `now_ms` in the window** (deterministic; see below), re-stamps every
  clock-carrying op to it, and — only where the embedded transcript would fail
  the freshness gate at that clock — refreshes it from the freshest available
  per-market transcript (the sequencer's latest, else the freshest embedded in
  the window; both publisher-signed). Ops that remain stale are left alone and
  rejected fail-closed by the engine's staleness gate.
- Regression tests: `commitment::rejects_op_clock_disagreeing_with_manifest_time`,
  `commitment::manifest_hash_binds_batch_time`, `serde_witness` round-trip with
  a matching clock.

**Design constraints honored.**
- *Delayed proof generation*: the clock binds to **seal time, never settlement
  time**. A proof built minutes after sealing validates the same transcripts;
  nothing re-stamps at prove/settle time.
- *Re-seal identity*: `rollback_window` re-seals the same op log after a failed
  settle and recovery flows compare witnesses byte-for-byte, so the committed
  clock must be a deterministic function of the window content — the max op
  time — not a wall-clock reading. A wall-clock seal time was implemented first
  and reverted because it made every re-seal diverge.
- *Mixed-era windows* (snapshot restore + new ops): the conditional refresh
  keeps earlier-era ops provable exactly when a fresh signed transcript exists,
  as production's feed task (≤ one fetch interval old) guarantees.

**Residual limitation.** `batch_time_ms` is sequencer-attested, not anchored to
L1 time: nothing on L1 carries a trustworthy wall-clock for the batch (only
`settledAtBlock`, recorded after settlement, and delayed proving must not be
broken by binding to it). The clock is now *public and committed* — a
back-dated manifest is visible in the manifest preimage and attributable to the
bonded, slashable sequencer — but the circuit cannot prove the wall clock was
honest. Closing that fully requires an L1-anchored time source (e.g. a
`block.timestamp` commitment at batch submission), tracked as future work.

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
- (1)/(2) **Fail-closed statement where not provable:** rejection-reason
  semantics cannot be proven by the Proof-v1 circuit (that is Proof-v2's
  matcher-rerun scope), and MockZkVerifier deployments cannot enforce even the
  structural binding. Therefore: **a deployment running MockZkVerifier, or any
  pre-Proof-v2 deployment, must not treat a rejection answer as proof that the
  rejection was legitimate** — the challenge game's correctness in that regime
  rests on the sequencer's bond and the refund gate, not on the proof.

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
    commitment KATs still pass unmodified. No state migration is needed; the
    chain of state roots survives the cutover.
  - The 7-word public commitment format is unchanged
    (`commitment_is_seven_field_state_root_domain` / KAT-COMMIT7).
- **What changes at the cutover:**
  - `manifest_hash` for every new batch (new field) — anything externally
    recomputing manifest hashes must include `batch_time_ms`.
  - The witness postcard encoding (`BatchManifest` field added) — proof
    pipeline (gateway → prover-service → sp1-host) versions must move together.
  - Operational note: the sequencer must keep every market's oracle transcript
    fresh at seal time (production feed cadence already does); a market with a
    dead feed at seal now fails closed instead of settling on an old price.

**Rollout recommendation:** regenerate the vkey (`crates/sp1-host/src/bin/vkey.rs`),
redeploy `SP1ZkVerifier` + `DarkPerpSettlement` with the new vkey, and cut over
at a batch boundary (prev-root continuity makes the cutover a no-op for state).
Until cutover, the on-chain system retains the pre-fix semantics documented
above; MockZkVerifier deployments must not carry real collateral.

## 6. Rust 1.99 clippy — `observation.rs`

The flagged regions (`crates/gateway/src/l1/observation.rs`, the ABI-word parse
closure ~line 158 and the hex/`ok_or(...)? * 16 + ok_or(...)?` arithmetic
~line 347, plus the same `try_into().unwrap()` pattern in `abi_u64`/`abi_u128`)
were rewritten to plain fallible forms with no `unwrap` and no `?` inside
arithmetic expressions. Tests never depended on clippy (CI runs clippy and
tests as separate jobs); the local toolchain here is 1.95, so the 1.99 lint set
itself could not be executed — the rewrite targets the patterns rather than a
reproduced diagnostic and keeps `-D warnings` clean on 1.95.
