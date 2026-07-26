# SEC-027a — The wind-down settlement price — Design

> Prerequisite for `2026-07-27-sec027-forced-settlement-design.md`, which is explicitly **not
> implementable** until this is decided. Threat model: `2026-07-26-sec02x-threat-model.md`.

**The problem.** SEC-027 closes every position at a settlement price. Where does that price come from?

The obvious answer — the existing `OracleTranscript` — fails on both halves of the requirement:

- **It is not current.** SEC-023 is unimplemented, so freshness is checked against a witness-supplied `now_ms` (`oracle.rs:93-97`) and `BatchManifest` has no clock (`order.rs:157-166`). A favourable historical signed transcript replays.
- **It is not independent.** Under Phase 1 the gateway holds the publisher key, pins every market to it, and re-signs (`2026-07-26-sec02x-threat-model.md:20-26`). It can mint any price.

And there is a timing contradiction that makes it worse rather than merely weak: **close-only may have triggered precisely because the gateway died** (`triggerCloseOnly` fires on liveness timeout, `DarkPerpSettlement.sol:406-413`). In that case governance holds no fresh signature at all. So today the escape works only by replaying a stale price — and once SEC-023 lands, replay stops working and **the escape becomes unusable exactly when it is needed**.

A wind-down that cannot obtain a trustworthy price is not a wind-down.

## Why this is tractable here even though the general problem is not

ZK-001 deferred removing operator trust from the price as a Phase-2 epic, and the objections were real: a third-party feed's cadence does not fit a 10-second staleness budget, `confidence`/`backup_twap` have no honest third-party analogue, and verifying a publisher's native scheme in-circuit is expensive.

**None of those bite here**, because a settlement price is structurally different from a mark:

| | Per-tick mark | Wind-down settlement price |
|---|---|---|
| Frequency | every 700 ms | **once** |
| Gas cost | prohibitive on-chain | irrelevant |
| Staleness budget | 10 s | minutes to hours is acceptable |
| Needs `confidence`/`twap` | yes (funding, margin bands) | **no** — a single close price |
| Who is in the loop | nobody | **governance already is** |

So the one place the system can afford an on-chain price read is exactly the place it most needs one.

## Design

### 1. The price comes from L1, not from the witness

`finalSettle` gains a settlement price per market. The circuit **binds to it as a public input** and uses it in place of `OracleTranscript::validate`, which is the only thing the settlement path needs a price for — `op_liquidate` already reduces the whole oracle machinery to a single `i128` at `engine.rs:656`.

This is not a new architectural pattern: `DarkPerpSettlement` already calls out to `ICollateralVault`, `IERC20Min` and `IZkVerifier` (`:206`, `:235`, `:304`).

Consequence: **the settlement path stops depending on `Market.oracle_pubkey` entirely.** The operator's key is out of the loop for the one transition where the operator may be the adversary or may be absent.

### 2. Where L1 gets it — tiered, because coverage is not universal

**Tier 1 — feed-backed markets: read an external feed in `finalSettle`.** The contract reads the price itself and rejects a submitted settlement price outside a tight band around it, plus a staleness bound on the feed's own timestamp. Governance supplies the value; the contract is what makes it unforgeable. No discretion.

**Tier 2 — markets with no feed: the last price L1 itself recorded, plus a timelock.** For this to exist, `settleBatch` must record a per-market reference price during normal operation. That is a new public input and therefore real scope — but it is the only adversary-independent price available when there is no feed and the gateway is gone. Stale by construction; a timelock between announcing and executing the settlement lets users react.

**The practical question this turns on, and it must be answered against reality rather than assumed:** which of the live markets actually have a usable feed on Base Sepolia? The current three are BTC, ETH and SOL (`main.rs:335-357`). BTC/USD and ETH/USD are well covered; **SOL/USD coverage on Base Sepolia must be verified against actual deployed feed addresses before this design is costed.** If a market has no feed, it is Tier 2 and pays for the extra machinery — or it should not be listed in an alpha that claims a guaranteed exit.

### 3. Bounds the contract enforces

- Feed staleness: reject if the feed's own `updatedAt` is older than a configured bound.
- Deviation: reject a submitted price outside a band around the feed value.
- Sanity: reject non-positive prices, and reject a feed answer of zero or a negative `answer` (Chainlink-style feeds return `int256`).
- **Fail closed:** if the feed reverts, returns stale data, or is unset, `finalSettle` reverts. It must never fall back to a witness-supplied price — that would reintroduce exactly the discretion this removes.

### 4. What this deliberately does not do

- **It does not touch the per-tick oracle path.** Normal operation keeps ZK-001's self-signed transcripts and its documented Phase-1 posture. This is scoped to wind-down only, and must not be read as delivering the Phase-2 anchor.
- **It does not remove governance.** Governance still decides *when* to wind down; the contract decides only that the *price* is honest.

## Migration

| Change | Consequence |
|---|---|
| Settlement price(s) as public input(s) | `DerivedRoots`, `prover::PublicInputs`, and `publicCommitment` at **both** Solidity entry points must move in lock-step; KAT re-pins; **vkey re-pin** |
| `finalSettle` signature + feed reads | contract redeploy |
| Tier 2's recorded reference price | a further `settleBatch` public input — **only if any Tier-2 market exists** |
| Circuit uses the L1 price instead of `validate()` on the settlement path | guest ELF changes |

The 8th-word lesson from SEC-023 applies: three definitions must agree byte-for-byte, and the encoding must use the existing little-endian `_leWord` convention (`DarkPerpSettlement.sol:619`, `hash.rs:202`), not Solidity's natural big-endian packing.

## Testing

| Case | Expected |
|---|---|
| Submitted price inside the band of a fresh feed | accepted |
| Submitted price outside the band | reverts |
| Feed stale beyond the bound | reverts |
| Feed reverts / unset / returns `answer <= 0` | **reverts — never falls back** |
| A witness-supplied `OracleTranscript` on the settlement path | ignored; the circuit uses the bound public input |
| The circuit's settled price ≠ the L1-verified price | proof rejected |
| Tier-2 market settled outside its timelock | reverts |
| Rust `commitment()`, `prover::PublicInputs`, Solidity `publicCommitment` | byte-identical over the extended word set |

The fourth row is the one that matters most: a fallback path would silently restore the discretion this design exists to remove.

## Status

**Blocked on one fact:** per-market feed availability on Base Sepolia, verified against deployed addresses. If all live markets are Tier 1, this is a contained change and SEC-027 becomes implementable. If any is Tier 2, the recorded-reference-price machinery roughly doubles the scope, and the honest alternative is to not list that market in an alpha that promises a guaranteed exit.
