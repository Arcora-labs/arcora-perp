# SEC-027a — The wind-down settlement price — Design

> Prerequisite for `2026-07-27-sec027-forced-settlement-design.md`. Threat model:
> `2026-07-26-sec02x-threat-model.md`. **This is a rewrite; the first version was reviewed and rejected.**

**The problem.** SEC-027 closes every position at a settlement price. The existing `OracleTranscript` cannot supply it: it is not current (SEC-023 unimplemented, so a historical signed transcript replays against a witness `now_ms`) and not independent (the gateway holds the publisher key). Worse, close-only may trigger *because the gateway died*, so governance may hold no fresh signature at all — and once SEC-023 lands, replay stops working and the escape becomes unusable exactly when needed.

## The reframe: termination beats precision

The first version proposed an L1 feed read as the primary source, with an oracle-free fallback unmentioned. Review inverted that, correctly:

- **Feed availability is unverified for all three live markets**, not just SOL. The repo contains no feed addresses, aggregator interfaces, heartbeats, decimals, or sequencer-uptime handling. The claim that "BTC/USD and ETH/USD are well covered" was unsupported.
- **Fail-closed feed handling just relocates the brick.** "Gateway outage bricks the exit" becomes "feed outage bricks the exit". For an escape hatch, that is not an improvement.
- **A wind-down must terminate.** That is the whole point of SEC-027.

So the primary design is the one that always works, and the feed is an optimization layered on top.

## Design

### 1. Primary — oracle-free terminal settlement

**Close every position at its own `entry_price`.** Unrealized PnL becomes exactly zero; each account keeps the collateral it actually posted.

```
for each open position: realize at entry_price  →  PnL = size · (entry − entry) = 0
                        zero size and entry_price
```

Properties:

- **No price input at all**, so nothing to manipulate, nothing to be unavailable, and no timing option for governance. It terminates unconditionally.
- **It cannot manufacture a new deficit.** Every deficit that remains was already there — pre-existing negative collateral and a negative `vault_pool` — rather than created by the settlement price. This matters because SEC-027's global haircut is computed from that deficit: an unavailable or manipulable price could otherwise *invent* the shortfall other users then pay for.
- **It is honestly unfair, and must be documented as a bankruptcy policy rather than a valuation.** It voids winners' unrealized gains and forgives losers' unrealized losses. That is a policy choice; it is not a liveness failure, and a liveness failure is what the alternative risks.

Funding: either settle accrued funding at the current index or explicitly waive it. **Decide and write it down** — "settle" keeps the funding ledger consistent, "waive" avoids one more price-adjacent input. Recommendation: settle, since `funding_index` is already state and needs no oracle.

This does **not** remove SEC-027's insurance draw, global reconciliation, or terminal solvency postcondition. Already-flat negative positions and a negative `vault_pool` still exist and still have to be reconciled.

### 2. Optional — an L1-verified price, if and when feeds are real

Better valuation, strictly optional, and only for markets with a verified feed. If adopted it must be a **two-stage deterministic snapshot**, not a read at execution time:

1. After close-only, **anyone** may permissionlessly record a deterministically selected feed round into contract storage.
2. The proof is built against that immutable snapshot.
3. Execution happens after the grace period.

Why not a read at `finalSettle` time: the contract only enforces a *lower* bound on execution (`DarkPerpSettlement.sol:376`), so governance can wait arbitrarily and pick its moment — a free timing option. And a band around a live read (the first version's proposal) does not remove discretion, it bounds it; at leveraged notional even 1% is economically large and changes the size of the global haircut. **Bind the exact recorded answer, or state plainly that governance has bounded price discretion.** The first version's "no discretion" claim was false.

If a TWAP or median is wanted, its window and rounding must be fixed *before* the emergency, not chosen during one.

### 3. Tier 2 is deleted

The first version proposed, for markets without a feed, a reference price recorded by `settleBatch` during normal operation plus a timelock. **That is not adversary-independent.** Every market trusts the gateway's key (`gateway/main.rs:1520`), and the gateway rewrites the feed timestamp and re-signs the tuple itself (`:3168`). A recorded price proves only *"the gateway chose and signed this before it stopped progressing"* — a compromised gateway records a malicious reference, settles that batch, and disappears. Moving the value to L1 changes **when** the attack is committed, not **who** controls it.

The timelock adds little: if the gateway is dead, users cannot trade or submit corrective closes, and `settleBatch` is disabled once close-only is set (`DarkPerpSettlement.sol:322`). Users may observe and object with no executable remedy.

For a market with no independent feed, the honest options are the oracle-free rule in §1, or not listing it.

### 4. Two phases, because withdrawals must not depend on the price forever

SEC-027 leaves value as collateral on flat positions, expecting later `Unbind → Withdraw`. But `finalSettle` is repeatable (`DarkPerpSettlement.sol:358`), so if *every* `finalSettle` requires wind-down machinery, withdrawals stay coupled to it indefinitely.

- **Phase 1:** one-shot `SettleAll`. Price-dependent only if §2 is adopted.
- **Phase 2:** price-free post-wind-down proofs permitting **only** flat-position `Unbind` and `Withdraw`.

**Open operational question this exposes:** if the gateway is genuinely dead, how do users submit those Phase-2 exits, and how does governance obtain the private state and witness needed to prove them? SEC-027 assumes the exits happen; nothing specifies who produces them. This belongs with SEC-027, not here, but it is the same "the escape assumes a live actor" gap as the runbook's termination assumption.

## Migration

| Change | Consequence |
|---|---|
| §1 alone: no new public input | `DerivedRoots`/`PublicInputs`/`publicCommitment` unchanged; guest ELF changes → **vkey re-pin** |
| §2 if adopted: price(s) as public input(s) | all three commitment definitions move in lock-step; KAT re-pins; contract redeploy |

**Encoding correction:** the first version said to reuse `_leWord`. That encodes **`uint64` only** (`DarkPerpSettlement.sol:619`), while engine prices are `i128` at `PRICE_SCALE = 1e8` (`fixed.rs:12`). §2 needs a byte-exact Solidity equivalent of Rust `word_i128`, or an explicitly bounded unsigned price type — not `_leWord`.

**Denomination, to decide explicitly:** markets are quoted `/USDC`, the gateway's current data is Crypto.com `/USDT` (`main.rs:340`), and feeds would be `/USD`. If `1 USDC = 1 USD` is an accepted invariant, say so. Otherwise §2 needs a USD/USDC conversion source — and an emergency wind-down is precisely when a stablecoin depeg cannot be waved away.

**Feed diligence, if §2 is ever adopted:** verify each proxy address, pair, decimals, real update cadence, deviation configuration, upgrade authority, `updatedAt` semantics, and Base L2 sequencer-uptime handling. Decimals `> 8` lose low digits into `PRICE_SCALE`; rounding must be specified. All paths need positive-answer and `i128` range checks.

## Testing

| Case | Expected |
|---|---|
| §1: settle with no price input at all | terminates; every position flat |
| §1: `Σ realized == 0` by construction (entry-price close) | no new deficit created |
| §1: pre-existing negative collateral and negative `vault_pool` | still reconciled by SEC-027's insurance + haircut |
| §1: funding disposition | matches the documented choice, deterministically |
| §2 (if adopted): settled price ≠ the recorded snapshot | proof rejected |
| §2: execution timing cannot change the price | pinned by the two-stage snapshot |
| §2: feed unavailable | §1 still terminates — **the exit never depends on the feed** |
| Phase 2 exits require no price | pinned |

The seventh row is the design: whatever happens to any oracle, the wind-down still ends.

## Status

**§1 is implementable now** and unblocks SEC-027 — subject to SEC-027's own open item, the wind-down batch grammar (see that spec's correction history). §2 remains blocked on feed diligence and is optional.
