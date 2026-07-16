# Forge-suite audit remediation — design spec

**Date:** 2026-07-16
**Status:** approved design, pre-implementation
**Scope owner:** dark-perp core

## Context

An external "forge suite" audit (`darkperpforgeFINDINGS.md`) raised 8 architecture-claim
findings. All were independently re-verified against current `main`. The verification
(7 parallel read-only passes) produced this triage:

- **Solidly confirmed, fixable now, independent of TEE maturity:** SEQ-001 (censorship
  economics), EXIT-001 (open-position exit gap).
- **Confirmed but overstated / misframed:** EXIT-001 headline (the `claim()` path is *not*
  close-only-gated, so settled balances stay withdrawable), LIQ-001 (public leak is
  demo+MM only, not real `/v1` tenants; 2 sub-claims outright refuted).
- **Confirmed, but the real fix is P3 (circuit) and out of this pass:** SEC-019 (deposit
  ZK-binding), ZK-001/ORA-001 (oracle signature binding), SEC-020 (attested prover).
- **Meta:** most findings are docs-vs-reality honesty gaps measured against an aspirational
  `ARCHITECTURE.md` on a testnet alpha whose own `ROADMAP.md` already marks the ZK/TEE
  trust roots as not-built.

This spec covers the three buckets the user chose to fix now. The P3 architecture backlog
(SEC-019 deposit root, ZK-001 oracle signatures, SEC-020 real attestation) is explicitly
**out of scope** and remains on the roadmap.

## In scope

1. **SEQ-001** — ripeness gate + refund rerouting in the inclusion challenge game.
2. **EXIT-001** — governance final-settle escape hatch (contract) + manual runbook.
3. **LIQ-001** — fail-closed liquidation tag-key + public-snapshot guard.
4. **Doc-honesty pass** — `ARCHITECTURE.md` + `ROADMAP.md` corrected to mark aspirational
   guarantees as not-yet-delivered.

## Out of scope

- SEC-019 / ZK-001 / ORA-001 / SEC-020 substantive fixes (P3, circuit-level).
- EXIT-001 **automatic** gateway routing through `finalSettle` (documented follow-up; this
  pass ships the contract path + a manual governance runbook).
- An off-chain keeper that auto-fires `challengeInclusion` (documented follow-up; the
  challenge game stays user-initiated).

---

## 1. SEQ-001 — ripeness gate + refund rerouting

### Problem (verified)

`answerChallenge:373` and `answerByRejection:403` credit the challenger's ETH bond to the
**sequencer** on any successful answer, and late inclusion is an explicitly accepted defense
(`answerChallenge` comment, L346-359, "audit P2 — supersedes F1's over-strict predates rule").
So a victim of withholding pays their bond to the censor to un-censor themselves, and the
off-chain `inclusion_violations()` detector (`sequencer/src/lib.rs:1169`) is wired to no L1
path. The docs (§2) promise "include within T or slash," which does not exist on-chain.

### Why the auditor's literal fix is rejected

The auditor proposed refunding when `settledAtBlock > openedBlock`. Used as a **slash** gate
that reintroduces exactly the free-slash griefing that audit-P2 deliberately closed: normal
async settlement (ACCEPTED→MATCHED→SETTLED spans blocks) makes almost every honest order
`settledAtBlock > openedBlock`, so anyone could challenge a fresh order and free-slash an
honest sequencer.

### Design — the reconciliation

Use `settledAtBlock > openedBlock` as a **refund gate, not a slash gate**, and add a
**ripeness gate** so a fresh order cannot be challenged at all. Together they implement the
promised SLA without the P2 problem.

**1a. Ripeness gate (`challengeInclusion`).** No receipt schema change — `recvTimeMs`
(uint64 ms) is already enclave-signed and already a `challengeInclusion` parameter.

```solidity
// after the signature check, before writing the Challenge:
if (block.timestamp < recvTimeMs / 1000 + inclusionDeadlineSecs) revert NotRipe();
```

- New immutable `uint256 public immutable inclusionDeadlineSecs;` (constructor param).
- New error `NotRipe()`.
- A fresh order is not challengeable until `inclusionDeadlineSecs` past its signed receipt
  time → griefing of not-yet-settled orders is impossible.

**Threat note (documented, not fixed here):** `recvTimeMs` is enclave-self-reported, so a
sequencer that *plans* to censor at accept time could future-date the receipt to delay
ripeness. The realistic model — accept honestly (honest timestamp), then withhold — is
defended, since the timestamp is fixed before the withhold decision. A user handed a
visibly future-dated receipt has out-of-band evidence of misbehavior. Defending ripeness
against a fully-compromised enclave is moot (SEC-019/ZK-001 already break under that model).
Comment this explicitly.

**1b. Refund rerouting — `answerChallenge` ONLY.** The refund applies exclusively to the
**inclusion** answer, because proving inclusion of a challenged (ripe) order means a
forced-inclusion cured a withhold. `answerByRejection` proves the order was **validly
rejected** — the sequencer did nothing wrong and the challenger was mistaken/griefing — so
its bond stays forfeit to the sequencer unconditionally (its existing `pendingEth[sequencer]
+= c.bond` is left unchanged).

```solidity
// in answerChallenge, replace `pendingEth[sequencer] += c.bond;` with:
if (batches[batchId].settledAtBlock > c.openedBlock) {
    // the order settled only AFTER the (ripe) challenge → forced inclusion cured a
    // withhold; make the victim whole. NOT a slash — audit-P2's free-slash concern
    // does not apply to a refund, and the ripeness gate already excludes fresh orders.
    pendingEth[c.challenger] += c.bond;
} else {
    // the order was already settled when challenged → griefing/noise; forfeit to
    // the sequencer, preserving the anti-spam deterrent.
    pendingEth[sequencer] += c.bond;
}
```

No slash on answer in either function — slashing stays exclusively in `slashUnanswered`
(total non-response). Net effect: censorship is no longer profitable (sequencer gains
nothing from a ripe inclusion-challenge it answers by forced inclusion); griefing stays
deterred (fresh orders unchallengeable; already-settled orders and valid rejections forfeit
the bond).

### Files

- `contracts/src/DarkPerpSettlement.sol` — new immutable + error + constructor param; the
  ripeness check in `challengeInclusion`; the branch in `answerChallenge`/`answerByRejection`;
  update the L346-359 comment to record the P2 reconciliation.
- `contracts/script/Deploy.s.sol` — pass `inclusionDeadlineSecs` (env-overridable, default
  e.g. 600s for testnet).
- `crates/gateway/src/l1.rs` (+ any deploy helper) — constructor arg wiring if the gateway
  deploys/reads it.

### Tests (`contracts/test/DarkPerpSettlement.t.sol`)

- `test_challenge_reverts_before_ripe` — challenge at `recvTimeMs` with `block.timestamp`
  below the deadline → `NotRipe`.
- `test_challenge_allowed_after_ripe` — warp past `inclusionDeadlineSecs` → opens.
- `test_answer_forced_inclusion_refunds_challenger` — ripe challenge, then settle a batch
  (`settledAtBlock > openedBlock`), `answerChallenge` → `pendingEth[challenger] == bond`,
  `pendingEth[sequencer] == 0`, sequencer NOT slashed.
- `test_answer_presettled_forfeits_to_sequencer` — order in a batch settled before the
  challenge opened → `answerChallenge` credits `pendingEth[sequencer] == bond`.
- `test_rejection_answer_always_forfeits` — `answerByRejection` credits the sequencer even
  when the rejection batch settled after the challenge opened (challenger was wrong, not a
  victim) → `pendingEth[sequencer] == bond`, `pendingEth[challenger] == 0`.
- `test_answer_never_slashes` — neither answer path sets `slashed`/`closeOnly`.
- Existing `slashUnanswered` tests remain green (unchanged path).

---

## 2. EXIT-001 — governance final-settle escape

### Problem (verified)

Headline REFUTED: `CollateralVault.claim()` (`CollateralVault.sol:125`) has **no** close-only
gate, so any balance already settled into a withdrawals leaf stays permissionlessly
claimable in close-only ("stalled, not stolen" holds). Real narrower gap: collateral still
in an **open position** at freeze cannot be converted to a withdrawal leaf, because that
needs `settleBatch`, which reverts in close-only (`DarkPerpSettlement.sol:235`), and the
documented conservative-TWAP forced-close does not exist. A full trustless forced-close is
P3 (circuit). This pass adds the missing **landing pad** so an operator/governance can push
user-initiated reduce-only closes (which the engine already processes in close-only) during
a wind-down.

### Design — `finalSettle`

New state:

```solidity
uint256 public closeOnlyBlock;                       // block close-only was entered
address public immutable governance;                 // constructor; alpha = deployer
uint256 public immutable finalSettleGraceBlocks;     // constructor
```

Set `closeOnlyBlock = block.number` at **both** sites that flip `closeOnly = true`
(`triggerCloseOnly`, `slashUnanswered`).

New function (mirrors `settleBatch`, minus the close-only/slashed/bond guards, plus the
escape gate):

```solidity
function finalSettle(
    bytes32 prevRoot, bytes32 manifestHash, bytes32 newRoot,
    bytes32 orderedRoot, bytes32 withdrawalsRoot, bytes32 rejectedRoot,
    bytes calldata proof
) external {
    if (msg.sender != governance) revert NotGovernance();
    if (!closeOnly) revert NotCloseOnly();
    if (block.number < closeOnlyBlock + finalSettleGraceBlocks) revert GraceNotExpired();
    // NO !slashed check (wind-down is exactly when slashed), NO requiredBond check.
    if (prevRoot != currentStateRoot) revert BadPrevRoot();
    bytes32 commitment =
        publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot);
    if (!verifier.verify(commitment, proof)) revert BadProof();   // escape stays ZK-gated

    uint256 batchId = batchCount;
    batches[batchId] = Batch({
        manifestHash: manifestHash, orderedRoot: orderedRoot,
        rejectedRoot: rejectedRoot, settledAtBlock: block.number
    });
    currentStateRoot = newRoot;
    lastProgressBlock = block.number;
    batchCount = batchId + 1;
    emit FinalSettle(batchId, prevRoot, newRoot, manifestHash);
    if (vault != address(0)) ICollateralVault(vault).publishWithdrawals(withdrawalsRoot, batchId);
}
```

Properties:

- **Proof-gated** — governance cannot fabricate balances; it can only land proof-valid
  transitions the sequencer could already have landed normally. New trust surface = "during
  close-only, governance may act as sequencer." No `closeOnly` reset (still winding down).
- **Repeatable** — a wind-down may need several settlements; each is independently
  proof-gated and advances `currentStateRoot`.
- **Works when `slashed`** — the whole point.
- New events/errors: `FinalSettle`, `NotGovernance`, `NotCloseOnly`, `GraceNotExpired`.

### Off-chain (this pass = manual)

The gateway already lets the engine process reduce-only closes in close-only. For this pass,
the operator computes the wind-down roots/proof exactly as for a normal settle and calls
`finalSettle` manually (runbook in `docs/`). **Automatic** gateway routing (detect on-chain
`closeOnly && grace`, submit via `finalSettle` instead of `settleBatch`) is a documented
follow-up — deliberately kept out to avoid touching the fragile window-settle machinery in
the same pass.

### Files

- `contracts/src/DarkPerpSettlement.sol` — state, constructor params, `closeOnlyBlock`
  writes, `finalSettle`, events/errors.
- `contracts/script/Deploy.s.sol` — `governance` (default deployer), `finalSettleGraceBlocks`
  (env-overridable).
- `docs/` — wind-down runbook.

### Tests

- `test_finalSettle_reverts_when_not_closeOnly`.
- `test_finalSettle_reverts_before_grace`.
- `test_finalSettle_reverts_non_governance`.
- `test_finalSettle_reverts_bad_proof` / `test_finalSettle_reverts_bad_prevRoot`.
- `test_finalSettle_works_when_slashed` — slash → warp past grace → governance finalSettle
  lands, `batchCount` advances, withdrawals published.
- `test_finalSettle_publish_then_claim` — e2e: finalSettle publishes a root → `claim()`
  pays out.

---

## 3. LIQ-001 — fail-closed tag-key + public-snapshot guard

### Problem (verified)

- **Fail-open tag-key:** `sequencer/src/lib.rs:953,964` — `self.liq_tag_keys.get(owner)
  .copied().unwrap_or(*owner)`. When the per-owner key is missing, the liquidation/ADL tag
  is salted with the **public owner id**, so any known-pubkey observer can recompute it →
  linkable. Documented as "only fires for a position funded outside `apply`," untested.
- **Public per-position exposure:** `/api/state` + `/ws` (`main.rs` snapshot, bind
  `0.0.0.0`, no auth) emit `WPosition` (incl. `liquidation_price`) for the demo `user` and
  MM inventory (`mm_hedge`). Only demo+MM data — real `/v1` tenants are never iterated — so
  this is future-proofing + honesty, not an active customer leak. (SealedBatch/AdlReceipt
  disclosure and "only happy-path test" sub-claims were **refuted** and need no change.)

### Design

**3a. Fail-closed tag-key.** Add a sequencer-held secret fallback salt so a missing
per-owner key never falls back to the public owner id:

- New field on the sequencer: `liq_fallback_key: [u8; 32]`, seeded deterministically from
  the enclave seed (HKDF/keccak domain-separated), established at construction.
- Replace both `unwrap_or(*owner)` sites with a secret-keyed derivation, e.g.
  `self.liq_tag_keys.get(owner).copied().unwrap_or_else(|| derive(self.liq_fallback_key, owner))`.
- Deterministic (replay/proof-stable) and unlinkable to third parties (they don't know
  `liq_fallback_key`). Liquidation never bricks. Off-chain only — the tag is a SealedBatch
  privacy artifact, not in the proof commitment, so no circuit/guest change.
- Trade-off: in the abnormal fallback case the owner can't recompute their own tag (they
  have no key anyway), but third-party unlinkability — the property the tests assert — holds.

**3b. Public-snapshot guard.** In the gateway `snapshot()`:

- Enforce that the public `WState` positions list is built **only** from the demo
  `self.user.owner` and can never iterate `self.accounts` — explicit invariant comment plus a
  runtime filter that skips any owner present in `self.accounts`.
- Gate the detailed `mm_hedge` (inventory/hedge_target/notional — front-runnable) behind
  `!prod`; prod omits it.
- Keep demo `positions` (user's choice). Document `/api/state` + `/ws` as demo-only.

### Files

- `crates/sequencer/src/lib.rs` — `liq_fallback_key` field + seed + the two fallback sites.
- Wherever the sequencer is constructed (gateway boot) — pass/derive the fallback seed.
- `crates/gateway/src/main.rs` — `snapshot()` guard + `mm_hedge` prod-gate + comments.

### Tests

- Extend the existing adversarial privacy test (`sequencer/tests/spine.rs:288-314`): drive
  the **missing-key** path and assert the emitted tag does NOT equal
  `liquidation_tag(&owner_id, market, batch)` (i.e., not recomputable from the public owner
  id), and is stable across a replay.
- Gateway snapshot test: a populated `self.accounts` never appears in the public `WState`;
  `mm_hedge` empty under `prod`.

---

## 4. Doc-honesty pass

Mark aspirational guarantees as not-yet-delivered; describe actual current behavior.

- **`ARCHITECTURE.md` §0** — deposit integrity is currently **enclave-rooted**, not
  ZK-rooted; ZK deposit-binding (deposit-event root in the commitment) is P3 (SEC-019).
- **§4 / §8** — the oracle is currently an **unauthenticated prover witness**; freshness/
  confidence "invariants" are not enforced against an authenticated source; signature
  binding is P3 (ZK-001/ORA-001). **Remove `liquidation_price_guard`** from the §8 transcript
  schema (it exists nowhere in code).
- **§6** — conservative-TWAP forced-close is **not implemented**. Document the real escape:
  `claim()` against the last settled withdrawals root (settled balances) + the new
  governance `finalSettle` wind-down (open positions via reduce-only closes). Full trustless
  forced-close is P3.
- **§2** — describe the new challenge economics (ripeness gate + forced-inclusion refund,
  no slash-on-answer); the "slash within T of receipt" wording now maps to the ripeness
  SLA + `slashUnanswered`.
- **§10b / `ROADMAP.md:57`** — soften "attested confidential prover ✅" to reflect the stub
  measurement (`0xAB`) and public seal-root (`0x5E`); real TDX/Nitro attestation stays
  `⬜` (consistent with `ROADMAP.md:46`, SEC-020).

---

## Cross-cutting: deploy / migration

The new constructor params (`inclusionDeadlineSecs`, `governance`, `finalSettleGraceBlocks`)
mean a **fresh Settlement deploy** — consistent with the project's routine clean redeploys
(verifier is state-independent and reused). No snapshot-format change on the off-chain side
except the sequencer's new `liq_fallback_key` (seed-derived at boot, not serialized if
recomputed deterministically — confirm during impl). Deploy script + gateway boot wiring
updated for the new args. Genesis root unchanged.

## Risks

- **SEQ-001 digest parity** — none; `recvTimeMs` reused, no receipt/digest change. Lowest-risk.
- **EXIT-001** — `finalSettle` is a new privileged path; mitigated by proof-gating +
  close-only + grace + governance. Manual-only off-chain this pass avoids window-settle risk.
- **LIQ-001 fail-closed** — must stay deterministic for replay; verify the derivation is
  seed-stable across restart (snapshot parity).
- **Constructor changes** — require a redeploy + deploy-script/gateway arg updates; standard
  for this project.

## Success criteria

- `forge test` green including all new SEQ-001 / EXIT-001 tests.
- `cargo test --workspace` green including the extended LIQ-001 privacy tests.
- `forge fmt` / `clippy --workspace` clean.
- Docs no longer claim delivered any guarantee the code does not enforce; `liquidation_price_guard`
  removed.
