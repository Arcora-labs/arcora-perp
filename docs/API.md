# External trading API (`/v1`)

A multi-tenant REST + WebSocket API over the real sequencer engine, so
market-makers, bots, and integrations can trade and read market data **without a
browser**. Every account is an independent trader on the **same shared order book
and engine**; accounts are isolated by a secret API key.

Base URL (testnet demo): the gateway's `http://<host>:<port>` (e.g. `:8088`).

> **Collateral = USDC.** Deposits and withdrawals settle in USDC on **Base Sepolia**
> (MockUSDC, 6 decimals, address in `contracts/deployments/base-sepolia.json`). USDC
> base units map 1:1 to the engine's quote units (both `1e6`), so amounts carry
> straight through.

> **Custody.** By default registration generates a wallet the gateway custodies (the
> CEX-style shape bots expect). An account can instead register a **caller-signed
> signer** (§ Caller-signed orders) so every order must carry the caller's own
> secp256k1 signature — a leaked API key alone then cannot place orders. The
> production version moves spend keys inside the TEE (see `docs/SECURITY.md`).
>
> **The API key alone can never move funds** (SEC-021): every withdrawal — both
> `POST /v1/accounts/withdraw` and `POST /v1/lp/withdraw` — must carry a
> strictly-increasing `nonce` and a secp256k1 `signature` from the account's
> **authorizing address** (the registered caller-signed `signer` if there is one,
> otherwise the bound deposit address). See § Withdrawal authorization.

## Auth

Authenticated endpoints require the header:

```
X-Api-Key: 0x<64 hex>
```

issued by `POST /v1/accounts`. A missing/invalid key returns `401`.

All token amounts are **decimal strings** of scaled integers: quote / USDC = `* 1e6`,
size = `* 1e8`, price = `* 1e8`.

A machine-readable **OpenAPI 3.1** spec is served at `GET /v1/openapi.json`.

## REST

| Method | Path | Auth | Body / notes |
|--------|------|------|--------------|
| POST | `/v1/accounts` | – | optional `{ signer }` → `{ apiKey, owner, callerSigned, recoveryNonce, chainId, vault }`; `503` `{ error }` once the account capacity or the soft admission cap (§ Admission cap) is reached |
| GET  | `/v1/accounts/me` | ✓ | `{ owner, settledBalance, marketFree[], positions[], nextNonce, depositAddress, callerSigned, nextWithdrawNonce, rebindCounter, chainId, vault }`, `marketFree` being `[{ marketId, free }]`, each market's free balance (the withdrawal minimum's exception, § Withdrawals); after close-only also `refundableDeposits[]` (§ Refunds after close-only) |
| POST | `/v1/accounts/deposit` | ✓ | `{ marketId, amount }` — demo/in-memory credit |
| POST | `/v1/accounts/deposit/address` | ✓ | `{ address, signature, currentSignature? }` — bind the EOA you fund from (ownership-proven; a **rebind** additionally requires `currentSignature`, § Withdrawal authorization) |
| POST | `/v1/accounts/deposit/authorize` | ✓ | `{ from, amount, marketId, purpose, reuseOwnerCommit? }` → `{ ownerCommit, sig, validUntil, marketId, purpose }` — durable permit with explicit routing and a deadline |
| POST | `/v1/accounts/deposit/route` | ✓ | `{ ownerCommit, from, amount, marketId, purpose }` — explicitly adopt a legacy pending permit |
| POST | `/v1/accounts/deposit/onchain` | ✓ | `{ txHash, marketId }` — optional finalized ingestion accelerator / durable receipt |
| POST | `/v1/accounts/withdraw` | ✓ | `{ marketId, amount, to, nonce, signature }` → authorized withdrawal (wallet-signed, § Withdrawal authorization) |
| GET  | `/v1/accounts/withdrawals` | ✓ | `{ vault, withdrawals[] }` with claim proofs |
| GET  | `/v1/lp` | ✓ | `{ tvl, navPerShare, totalShares, myShares, myValue }` — **demo build only** (see note below) |
| POST | `/v1/lp/deposit` | ✓ | `{ amount }` → `{ sharesMinted }` — stake into the counterparty pool — **demo build only** |
| POST | `/v1/lp/withdraw` | ✓ | `{ shares, nonce, signature }` → `{ withdrawnValue }` (wallet-signed, § Withdrawal authorization) — **demo build only** |
| POST | `/v1/orders` | ✓ | order body (below) → signed receipt, including `l1Challenge` (§ L1 inclusion challenges) |
| GET  | `/v1/orders` | ✓ | `{ orders[] }` (own orders + finality + the stored acceptance `receipt`, incl. its `windowId`) |
| DELETE | `/v1/orders/:orderId` | ✓ | cancel a pending order or live maker remainder (see the cancel note below) |
| GET  | `/v1/positions` | ✓ | `{ positions[] }` (own open positions) |
| GET  | `/v1/markets` | – | `{ markets[] }` |
| GET  | `/v1/markets/:id` | – | one market |
| GET  | `/v1/markets/:id/orderbook` | – | `{ marketId, bids[], asks[] }` |
| GET  | `/v1/markets/:id/oracle` | – | `{ marketId, price, confidence, publishTimeMs }` |
| GET  | `/v1/system/status` | – | `{ mode, insuranceFund, treasury, nextBatchId, openWindowId, accounts, chainId, vault, windDown }` — `mode` is `CloseOnly` once the engine or the L1 settlement is in close-only; `windDown` is described in § Wind-down status |
| POST | `/v1/admin/settlement/cancel-anchor` | admin | `{ batchId, phase, receipt }` — cancel a stale clock anchor (§ `POST /v1/admin/settlement/cancel-anchor`) |
| POST | `/v1/admin/bond/acknowledge-slash` | admin | `{ slashCount }` — resume bond top-ups after a slash (§ `POST /v1/admin/bond/acknowledge-slash`) |

**`/v1/lp*` is not mounted in production** (SEC-025-C): the demo LP pool credits
stakes through an unbacked mint, which would break settlement — the production
router omits all three routes (they 404) and the served OpenAPI document omits
them too.

**Cancellation uses the live remainder, not finality.** A pending order or a
resting maker remainder can be cancelled, including after a partial fill is
MATCHED or SETTLED. Prior fills and position balances are not reversed.
GET /v1/orders includes the authenticated owner's `cancellable` capability.
DELETE returns `{ orderId, cancelled: true, cancelledSize }`, with the exact
removed size as a decimal string. The cancelled row leaves the order list;
complete cancellation history and cumulative fill/VWAP accounting remain A05.

The gateway serializes cancellation and the entire matching tick under the
same state mutex. The existing Cancelled reason enters the current window
manifest. Proof-v1 replays accounting and commits that manifest; it does not
independently prove cancellation authorization or CLOB matching fairness.

Production without persistence refuses cancellation before mutation (503).
With persistence, success waits for a durable snapshot ACK. Write failure or
timeout returns 503 with `durability: "unknown"`; the in-memory quote remains
removed, but restart durability is unconfirmed. Do not infer safe replacement
from an empty order list after this error. Obtain confirmed durable state
before replacing the quote. Snapshot acknowledgement is not L1 settlement.

**Order body** (`POST /v1/orders`):

```json
{
  "marketId": 0,
  "side": "Buy",
  "size": "10000000",
  "limitPrice": "0",
  "tif": "Ioc",
  "reduceOnly": false
}
```

`tif`: `Ioc`/`Fok` are takers (crossed against resting liquidity, or killed);
`Gtc`/`PostOnly` rest in the matcher book so a maker can quote and be crossed
by later takers. `limitPrice: "0"` means market (crossed at the mark).

**Honesty note (market orders).** A taker order has **no guaranteed counterparty
in production**: the house market maker is funded by nothing there, so `Ioc`/`Fok`
fill only against genuine external resting liquidity and are otherwise killed. The
"resting market-maker" that reliably fills takers exists only in the demo build.
(§ Trading is gated until launch discusses the same gap.)

Opening orders
are margin-checked against the account's free balance; close-only mode blocks
openers (§6). Acceptance is not a fill guarantee: that margin check runs against the
**pre-batch** state, so an order can also be **rejected at settlement**, not just at
submission — the ordinary cause is two of your own orders that individually fit your
margin but together do not (each passes alone; the second fails initial margin when
the batch settles). A settlement-rejected order never rests or fills and receives no
further receipt — it stays `ACCEPTED` in `GET /v1/orders` and is resolved in the
batch manifest's **rejected** set. **Rate limit:** at most 10 orders/sec per account
— over that returns `429` `{ "error": "RATE_LIMIT: ..." }`.

**Minimum order size.** An order that opens, grows or flips a position needs at least
**$10 of notional** (10,000,000 quote units). Reduce-only orders, and orders that
only reduce an existing position, are exempt, and a resting remainder that falls
below $10 after a partial fill keeps matching. The notional is the whole order at
the market's validated oracle price, not its limit price; a flip is measured on the
whole order. An order below the minimum is refused at submission with `400`
`{ error }` and is never recorded. Submission applies the sequencer's own rule
(`sequencer::below_minimum_order_notional`) to the same position and the same
validated oracle price the sequencer measures the order against when it seals the
batch. The sequencer also measures it against the position after the owner's
earlier orders of the same batch fill in full, so an accepted order can still be
refused there for its size when the oracle price has moved since or when those
earlier orders change the position. Such an order is recorded in the batch manifest
with the reject reason `BelowMinimumSize`. While a market has no validated oracle price,
submission does not refuse an order for its size; the batch then rejects it as
`OracleUnavailable`.

**Margin.** Initial and maintenance margin are computed on the notional rounded up,
and the ratio product is rounded up too. Initial margin is never below **$1** for an
open position. The floor applies when an order opens, grows or flips a position, and
when an unbind leaves the position open; reductions, closes and liquidations are
checked against maintenance margin only. Submission computes the initial margin of
the order and of the open position with the engine's own rule
(`Position::initial_required`), so for an order that opens a position from flat at
the oracle price it admits exactly the orders the batch's initial-margin check
admits.

**Reject reasons.** A rejected order's `execution.reason` in `GET /v1/orders` names
the reason the batch manifest records for it (the manifest stores the numeric code):

| Code | Reason | Meaning |
|---|---|---|
| 1 | `Expired` | the order expired |
| 2 | `SelfTradePrevented` | it would have traded against the same account |
| 3 | `PostOnlyWouldTake` | a post-only order would have taken liquidity |
| 4 | `ReduceOnlyViolation` | a reduce-only order would have opened or grown a position |
| 5 | `InsufficientMargin` | not enough free margin for the initial-margin requirement |
| 6 | `MarketCloseOnly` | the system is close-only and the order would open, grow or flip a position (reductions still trade), or the order was in a window dropped by the wind-down |
| 7 | `OracleUnavailable` | no fresh validated price |
| 8 | `FillOrKillUnfillable` | a fill-or-kill order could not fill in full |
| 9 | `Cancelled` | the order expired before or at its matching instant |
| 10 | `InvalidOrder` | malformed, or could not be applied for a reason with no more specific code |
| 11 | `FillPriceOutOfBand` | the fill price lay outside the market's band around the oracle price |
| 12 | `FillWouldBankrupt` | the fill would have left a leg with negative collateral, or open below maintenance margin |
| 13 | `BelowMinimumSize` | the order adds exposure but its notional is below the minimum order size |

Rejection membership is proven; the truthfulness of a rejection reason is not
(`docs/SECURITY.md`).

## Faucet — get test USDC

The collateral asset is an **open-mint** MockUSDC (6 decimals) on Base Sepolia —
anyone may mint. Addresses live in `contracts/deployments/base-sepolia.json`
(`MockUSDC`, `CollateralVault`). Mint, approve the vault, then deposit with a
gateway permit (§ Real USDC deposits, step 2):

```bash
USDC=<MockUSDC from base-sepolia.json>
VAULT=<CollateralVault from base-sepolia.json>
RPC=https://sepolia.base.org

# 1,000 test USDC (6 decimals) to yourself
cast send $USDC "mint(address,uint256)" <YOUR_ADDR> 1000000000 --rpc-url $RPC --private-key <KEY>
# approve, then deposit with the ownerCommit / validUntil / sig from /v1/accounts/deposit/authorize
cast send $USDC "approve(address,uint256)" $VAULT 1000000000 --rpc-url $RPC --private-key <KEY>
cast send $VAULT "deposit(uint256,bytes32,uint64,bytes)" 1000000000 <ownerCommit> <validUntil> <sig> \
  --rpc-url $RPC --private-key <KEY>
```

The vault refuses a deposit without a valid permit, so bind your address and
authorize the deposit first (below). The UI exposes the same via the
**"Get test USDC"** button.

## Real USDC deposits (on-chain → engine)

A real deposit is funded on Base Sepolia and then attributed to your account:

1. `POST /v1/accounts/deposit/address { "address": "0x<your EOA>", "signature": "0x.." }`
   — bind the external wallet you will deposit from. The `signature` is a secp256k1
   signature **recovering to `address`** over `keccak256("dark-perp:bind-deposit:" ‖
   chainId (u64 BE, 8) ‖ vault (20) ‖ owner (32) ‖ address (20))`, with `chainId` and
   `vault` from `POST /v1/accounts` or `GET /v1/accounts/me` (so only the controller of
   the EOA can bind it, the proof is bound to this deployment, and an address binds to
   at most one account) — accepted over any of the three shapes in
   § Accepted signature shapes. Only `Deposit` logs whose `from` matches the bound
   address are credited to you. **Changing an existing binding (a rebind) requires
   the consent of the currently bound address** via `currentSignature` — see
   § Rebinding the deposit address. Re-binding the same address is an idempotent
   no-op (no `currentSignature` needed).
2. `POST /v1/accounts/deposit/authorize { "from": "0x<your EOA>", "amount": "<base units>", "marketId": 0, "purpose": "collateral" }`
   → `{ "ownerCommit": "0x..", "sig": "0x..", "validUntil": <unix seconds>, "marketId": 0, "purpose": "collateral" }`
   — the gateway records a secret blind and the route for this deposit, together with
   the permit deadline `validUntil` (now + `DEPOSIT_PERMIT_TTL_SECS`, 1,800 s by
   default), and only then signs the permit. The vault accepts **only** permitted
   deposits sent no later than `validUntil`, so this step is not optional. To retry a
   deposit you never sent (for example after rejecting the wallet prompt), pass the
   earlier `ownerCommit` as `reuseOwnerCommit`: the gateway re-issues that same permit
   (same `validUntil`, same signature) if it still holds it for exactly this request and
   at least 60 s remain, and issues a fresh one otherwise. Outstanding permits are
   limited per account and in total, and issuance is rate-limited per account
   (429 / 503 when exceeded).

   New permits are also refused:

   | Condition | Response |
   |---|---|
   | deposit ingestion is not ready, or is halted | `503` |
   | the settlement cannot be read at the latest block | `503`; retry |
   | `amount` exceeds the settlement's `depositCapacity()` at the gateway's latest read | `409` `{ error, capacity }`, `capacity` a decimal string of USDC base units |
   | `amount` is below the 10 USDC minimum (10,000,000 base units) | `400` `{ error, minimum }`, `minimum` the minimum in base units |
   | the settlement is in close-only | `409` `{ error }`; no further deposits are possible (§ Refunds after close-only) |
   | the engine is close-only (a liquidation's shortfall exceeded insurance, treasury and auto-deleverage) while the settlement is not yet | `409` `{ error }`; the gateway alerts governance to call `enterCloseOnly()` |
   | the settlement accepts no deposits (no paired vault) | `409` `{ error }` |
   | the gateway's state is at its soft admission cap (§ Admission cap) | `503` `{ error }`; below the hard cap a held permit can still be re-signed |
   | a held permit (`reuseOwnerCommit`) while the state is at its hard admission cap | `503` `{ error }`; its deposit would not be credited, so the permit is not re-signed |
   | the gateway's settles (keepalives included) are failing and less than two permit lifetimes of liveness remain | `503` `{ error }`, until settlement recovers |

   **Admission cap.** Every batch proof re-derives the whole note tree and the
   nullifier log, so the gateway bounds how much history the state accumulates
   (note-tree leaves plus spent nullifiers, open position entries, unspent notes).
   At 80% of any bound (the soft cap) it issues no new deposit permit and registers
   no new account, each refused with `503` `{ error }`, and raises the
   `admission_cap_reached` alert (§ Operational alerts). The soft cap counts what the
   outstanding permits will add once their deposits are credited (each one tree leaf
   and one spent nullifier, plus a position entry when the account holds none in that
   market yet), so the permits already signed fit below it and the margin up to the
   bound is left to exits. At the bound (the hard cap) it credits no further deposit
   and re-signs no held permit: ingestion stops at the page holding the deposit,
   `POST /v1/accounts/deposit/onchain` answers `503` `{ error, durability }` with the
   reason, and the `deposit_blocked_at_cap` alert is raised, because that deposit is
   now the oldest unconsumed one and the settlement's deposit-inclusion timeout runs
   from it. The gateway records each such deposit that landed under one of its
   permits; it is refunded by the vault once the settlement is in close-only, and
   the account view then lists it (§ Refunds after close-only). Withdrawals, closes
   and claims keep working at both levels.

   | Bound | Hard cap | Soft cap (80%) |
   |---|---:|---:|
   | history (note-tree leaves plus spent nullifiers) | 13,280 | 10,624 |
   | open position entries | 1,328 | 1,063 |
   | unspent notes | 2,656 | 2,125 |

   They are measured: the largest history at which the costliest batch, a
   wind-down with a shortfall, still fits one proof within the prover budget at an
   assumed proving rate (`docs/audits/2026-10-19-pkg3-measurement-gate/`). They are
   admission policy, re-derived from the measured proving rate before launch, and
   change without a new program key.

   The gateway reserves no capacity for a permit. The vault's bond-capacity gate
   decides when the deposit lands, first come first served, so a permitted deposit can
   still revert `BondCapacityExceeded` if other deposits filled the capacity first.
3. On Base Sepolia, from that EOA: `usdc.approve(vault, amount)` then
   `vault.deposit(amount, ownerCommit, validUntil, sig)` — four arguments, all from
   step 2, sent no later than `validUntil`. The permit is the gateway signer's `r‖s‖v`
   over:

   ```text
   keccak256(abi.encodePacked(
       keccak256("arcora:deposit-permit:v2"),   // DEPOSIT_PERMIT_TAG
       chainId, vault, from, ownerCommit, amount, uint256(validUntil)))   // 200 bytes
   ```

   The vault's own `permitDigest(from, ownerCommit, amount, validUntil)` returns the
   same value. A deposit reverts with, in this order of checks:

   | Error | Meaning |
   |---|---|
   | `BadAmount` | `amount` is zero or above `int128` max |
   | `InCloseOnly` | the settlement is in close-only |
   | `BondCapacityExceeded` | the deposit would raise the vault's TVL beyond what the sequencer bond covers (5%); see `depositCapacity()` |
   | `DepositsPaused` | the settlement does not accept deposits from this vault |
   | `PermitExpired` | the block time is past `validUntil` |
   | `BadGatewaySig` | the permit does not recover to the vault's gateway signer for this exact tuple |
   | `OwnerCommitUsed` | this `ownerCommit` already entered the deposit chain |

   **One owner commitment, one deposit (SEC-028).** Re-submitting a permit, or any
   permit for an `ownerCommit` already in the deposit chain (even one re-signed with a
   later deadline), reverts `OwnerCommitUsed`. Without single use, a replay would mint
   a second leaf that the gateway could never credit, and that would block the
   contiguous deposit queue for **every** user. Get a fresh authorization for each
   deposit. An expired permit reverts `PermitExpired`; authorize again. The gateway
   removes a permit that never landed once a finalized block's timestamp is past its
   `validUntil`. It never uses its own wall clock for this.
4. **No confirm call is required.** The gateway autonomously consumes finalized
   L1 blocks in deposit-ID order, using the market and purpose recorded at
   authorization. Closing the browser does not interrupt ingestion.
   `POST /v1/accounts/deposit/onchain { "txHash": "0x..", "marketId": 0 }` optionally
   accelerates that same serialized ingester and returns an owned durable receipt.
   It cannot skip earlier deposits, change their market, or divert insurance.

The permit's secret blind and route must be acknowledged by persistent storage
**before** any gateway signature is released. An applied block's engine state,
replay operations, consumed prefix, receipts and remaining permits are saved
in the same snapshot before success is reported. Identity is chain/vault/deposit ID,
not merely transaction hash: multiple accounts can deposit in one transaction.

**Confirm responses:** `200` with `status`, `credited`, `depositIds`,
`marketId`, `purpose`, `durability: "confirmed"`; `202` with
`status: "pendingFinalizedIngestion"` (not successful zero credit); `409` for a
market/purpose mismatch or a historical transaction without reconstructible new
receipts; `503` for RPC unavailability, blocked ordering, safety halt, uncertain
durability, or an intake that credits no deposit while the engine is in close-only or
the hard admission cap is reached (§ Admission cap). Pending / `503` is **not** an
instruction to send funds again.

`status` reports the least final state of the transaction's deposits:

| `status` | Meaning |
|---|---|
| `credited` | a settled batch consumed the deposit (or the gateway has not read `consumedDepositCount()` yet) |
| `credited_unsettled` | applied off-chain; no settled batch has consumed it yet |
| `refundable` | the settlement is in close-only and no settled batch consumed it; the body adds `refundable: [{ id, from, ownerCommit, amount }]` |

After close-only, a deposit the gateway never credited gets `409` with the
close-only intake error and `credited: "0"`; it is still refundable on L1.

**Deposits after an engine trip.** While the engine is close-only, the proven
transition refuses every deposit, so the gateway credits none. A deposit that lands
in that state stays unconsumed on L1. Once the settlement enters close-only (governance,
or anyone through the deposit-inclusion timeout), it is refunded at principal like any
other unconsumed deposit. Ingestion stays at the oldest such deposit and reads on past
it, recording each deposit that landed under one of the gateway's permits, so the
account view can list them once the settlement is in close-only.

**Credited is not yet settled.** The confirm and account views distinguish a credit
whose deposit id is at or above the settlement's `consumedDepositCount()`: it is
applied off-chain but no settled batch has consumed it yet. Once the settlement is
in close-only, such a deposit is reported as **refundable**, with
`{ id, from, ownerCommit, amount }` (`id` a JSON number, `amount` a decimal
string), which are exactly the arguments of `vault.refundDeposit` (§ Refunds after
close-only). Its off-chain credit, and any
trading in windows that never settled, is discarded; only settled state carries into
the wind-down.

**Legacy permits remain unresolved, not reset.** Snapshot v5 imports retain every
blind, account, nonce, note, replay operation and inherited consumed prefix. No
market or purpose is inferred for blind-only authorizations. The account explicitly
adopts each legacy permit through `/v1/accounts/deposit/route`, supplying all route
fields; insurance additionally requires operator authorization. Routing is then
immutable. A missing or mismatched route at the next L1 deposit stops the stream
with a visible error. Later deposits are never skipped. Do not delete the state,
invent an initial cursor, or fabricate missing historical receipts to bypass this.

**Provider requirements:** `finalized`, historical headers, block-hash
`eth_getLogs`, EIP-1898 hash-pinned `eth_call`, and historical `eth_getCode` before
contract deployment. There is no latest/receipt fallback. Complete log pages are
checked against contract deposit-count/prefix and canonical headers. Transient
errors pause ingestion; a contradiction of a persisted prefix or anchor causes a
durable safety halt. Trading, withdrawals and new settlement are paused while
prefix verification or deposit durability is unresolved. The public state's
`depositIngestion` object exposes readiness (paused while durability is dirty), count/tip, anchor, halt,
last error and unresolved-permit count without exposing secret routes.

RPC remains a trust boundary: consistency checks cannot authenticate a wholly
fabricated chain. A finalized reorg is not automatically rewound; operators must
reconcile trusted chain data and preserved state. v6 is an explicit snapshot format
upgrade; older binaries cannot safely read the new state. Preserve backups and do
not roll back the binary while discarding credits written after upgrade.

Snapshot v7 adds the permit deadline to every route. A v6 snapshot that still holds
outstanding permits is refused, because those permits were signed for the earlier
vault ABI; the settlement ABI version 3 stack starts from a fresh deployment. Route
identity (`/v1/accounts/deposit/route`, legacy adoption) is compared without
`validUntil`, and the route response echoes it. Ingestion checks each `Deposit` log's
payer against the `from` recorded in the permit, so rebinding the deposit address
later never fails ingestion of a deposit permitted earlier.

**Fresh stack.** The engine state now records funding rates, recorded prices, the last
withdrawal nonce and the wind-down recipient, so this source starts a fresh deployment
with a new genesis root. Its gateway refuses every snapshot and rollback-journal format
written before that change, by format magic, rather than migrating it. The v5–v7 notes
above describe how those older formats behaved.

## Trading is gated until launch (SEC-025-D)

On a fresh production deployment, **order submission is refused** until the deployment has
demonstrably settled a normal `settleBatch` over a capitalized insurance fund. Every order
path returns an error naming the **launch gate**.

Do not confuse this with close-only, which is a different condition with a different remedy:

| | launch gate closed | `Mode::CloseOnly` |
|---|---|---|
| means | the deployment has not opened yet | a wind-down is under way |
| blocks | **all** order ingress | *opening/increasing* orders and new deposits; reduce-only, cancels and withdrawals still pass, and unconsumed deposits become refundable |
| clears when | a proven, block-pinned settle shows the fund capitalized | never — it is terminal on-chain |

The gate opens **once** and does not re-close. It is a launch gate, not a circuit breaker:
re-closing a blunt ingress gate would also block reduce-only **exits**, trapping users exactly
when they most need to leave.

**What the gate does not do.** It makes a deployment safe to *open*, not safe to trade on. In
particular the house market maker is funded by nothing in production, so a market order does
not get a guaranteed counterparty — it fills only against genuine external resting liquidity.
See the honesty note under § REST.

## Operator insurance bootstrap (SEC-025-A) — admin only

The operator first authorizes a fresh one-shot permit with
`POST /v1/accounts/deposit/authorize { "from": "0x<operator>", "amount": "<base units>",
"marketId": 0, "purpose": "insuranceBootstrap" }`.
This requires the operator account's `X-Api-Key`, `X-Admin-Key` matching
`FIN_ADMIN_KEY`, and a bound payer equal to `INSURANCE_OPERATOR_ADDRESS`.
All requirements also apply to explicit legacy insurance-route adoption.

The finalized ingester applies `Deposit` and `FundInsurance` atomically. It never
uses a later confirm request to decide purpose. A bootstrap deposit cannot become
user collateral, even when manual confirm races automatic processing.

`POST /v1/admin/insurance/bootstrap { "txHash": "0x..", "marketId": 0 }` with those
credentials is now an **optional receipt/acceleration endpoint**, not a routing
command. Its `200`, `202`, `409`, `503` meanings match the shared ingester. Repeated
confirmation is idempotent. A separately authorized insurance contribution uses a
fresh permit; do not authorize another contribution because a receipt is pending.

The compile-time insurance minimum remains **10,000 USDC**. Insurance routes record
an explicit existing market ID for audit consistency, but `FundInsurance` targets
the global fund, not a market position. This is a **one-way** transfer to protocol
ownership; there is no operator withdrawal or unfund path.

A pre-v6 `Bootstrap::DepositApplied` record is preserved. After verifying its
inherited L1 prefix, ingestion resumes **only** the recorded `FundInsurance`,
without minting another deposit or crediting collateral. Failed application leaves
the recorded note and state retriable. Bootstrap completion still follows
settlement of the window containing the insurance operation.

These checks are gateway custody policy, not a new ZK guarantee. A compromised
sequencer custodies spend keys and the engine's `FundInsurance` operation does not
prove this API authorization policy. A10 remains open.

## Withdrawals + claiming USDC on Base Sepolia (§3)

Funds release only from **settled** state, via the vault, never by the sequencer
directly:

1. `POST /v1/accounts/withdraw { "marketId": 0, "amount": "40000000", "to": "0x<dest>",
   "nonce": 1, "signature": "0x<130 hex>" }` — debits the engine immediately (so it
   can't be double-spent) and records an authorized withdrawal leaf
   `keccak256(to, amount, nonce)`. `nonce` + `signature` are **required** — see
   § Withdrawal authorization for who must sign, what they sign, and the `to` rule.
   The minimum is **1 USDC** (1,000,000 base units), unless `amount` is the entire
   free balance in that market (`marketFree` in `GET /v1/accounts/me`, not the
   account-wide `settledBalance`); a smaller request is a `400`.
2. After the containing batch is proven and finalized (no accepted time bound) the gateway publishes the **cumulative** withdrawals
   root (every still-unclaimed leaf) to the vault.
3. `GET /v1/accounts/withdrawals` → `{ vault, withdrawals: [{ to, amount, nonce, leaf,
   root, claimable, proof }] }`. Once `claimable` is `true`, `proof` is the Merkle path
   and `root` is the published root that path verifies against. Pass that `root` to
   `claim`, not the vault's current `withdrawalsRoot()`: a later published root can
   differ, and a proof checked against the wrong root reverts `BadWithdrawalProof`.
   The leaf's `nonce` is not your authorization nonce (§ Withdrawal authorization):
   the gateway assigns it, and it is strictly increasing across every withdrawal of
   the deployment. The proven state records the last leaf nonce, and the proof refuses
   a withdrawal whose nonce is not above it (by at most `2^32`), so no two leaves ever
   share a nonce, including the wind-down's reserve payout.
4. On Base Sepolia: `vault.claim(to, amount, nonce, root, proof)`, with `root` and
   `proof` from step 3, releases the USDC.
   The leaf is single-claim (`AlreadyClaimed` on replay). A claim never draws on the
   principal of deposits that no settled batch has consumed: if paying it would leave
   the vault holding less than `refundableOutstanding()`, it reverts
   `ReservedForUncredited`.

Existing published withdrawal leaves are claimable with their Merkle data even
when the gateway is offline. Account balances and positions are not withdrawal
leaves: new withdrawals still need operator/prover service and final wind-down
requires governance. Custody keys and oracle authority remain trusted alpha
components; proof validity does not establish independent user authorization.

## Refunds after close-only

A deposit that no settled batch has consumed (deposit id at or above the
settlement's `consumedDepositCount()`) is refunded at principal from the vault once
the settlement is in close-only. No gateway, prover or governance action is needed.

1. **Close-only.** It starts on any of three triggers:
   - anyone calls `settlement.triggerCloseOnly()` after the root has not progressed
     for `livenessTimeoutBlocks`;
   - anyone calls it when the oldest unconsumed deposit landed more than
     `livenessTimeoutBlocks` ago, even while batches keep settling;
   - governance calls `enterCloseOnly()`.

   `settlement.closeOnly()` reports the state. From then on `consumedDepositCount()`
   never changes.
2. **Refund.** Anyone may call
   `vault.refundDeposit(id, from, ownerCommit, amount, to)`, using the fields of the
   deposit's `Deposit(from, ownerCommit, amount, id, newTip)` event. The vault checks
   them against its deposit chain link at `id`. It pays `from`; `to` may differ from
   `from` only when `from` itself sends the call (for a payer the token refuses to
   pay). Each id is refunded once and emits `DepositRefunded(id, from, to, amount)`.

```bash
cast send $VAULT "refundDeposit(uint64,address,bytes32,uint256,address)" \
  <id> <from> <ownerCommit> <amount> <from> --rpc-url $RPC --private-key <KEY>
```

| Error | Meaning |
|---|---|
| `NotPaired` | the settlement does not name this vault |
| `NotCloseOnly` | the settlement is not in close-only yet |
| `NotRefundable` | the id is below `consumedDepositCount()` (the settled state credited it; exit through a withdrawal) or does not exist |
| `AlreadyRefunded` | this id was refunded already |
| `BadRefundRecipient` | `to` is zero, or differs from `from` while someone other than `from` sends the call |
| `BadDepositPreimage` | the arguments do not reproduce the deposit chain link at `id` |

Once the gateway has seen close-only at a finalized block, `GET /v1/accounts/me`
adds `refundableDeposits: [{ id, from, ownerCommit, amount }]`, ordered by `id`, for
the account's credits that no settled batch consumed and for the deposits that
landed under one of the account's permits and were never credited (while the engine
was close-only, at the hard admission cap, or once the settlement was in close-only).
`mode` in `/api/state` and `/v1/system/status` reads `CloseOnly`. The list survives
the wind-down's rebase and restarts. A deposit the gateway did not record does not
appear in it, for example one sent without a permit this gateway holds, or one that
landed after the rebase dropped the outstanding permits; the tool below finds any
deposit from the chain.

`scripts/claim/refund_deposit.py --rpc <RPC> --vault <VAULT> --from <payer>` (or
`--tx <hash>`, `--id <n>`) finds the `Deposit` log, checks it against the vault's
deposit chain and the settlement state, and prints the `triggerCloseOnly` and
`refundDeposit` calls. Like `claim_withdrawal.py`, it never signs or sends.

## L1 inclusion challenges

Every receipt (the `POST /v1/orders` response and each stored `receipt` in
`GET /v1/orders`) carries `l1Challenge`, an enclave-signed authorization to
challenge that order on L1:

```json
"l1Challenge": {
  "chainId": 84532,
  "settlement": "0x<DarkPerpSettlement>",
  "beneficiary": "0x<the account's bound deposit address>",
  "signature": "0x<130 hex, r‖s‖v>"
}
```

The beneficiary is the account's bound deposit address when the receipt is
served: the `POST /v1/orders` response names the address bound at acceptance, while
`GET /v1/orders` signs for the address bound at the time of the read, so keep the
kit from the accept response. It is `null` when the account has no bound deposit
address or the gateway has no settlement configured. The signature is the enclave signer's over the settlement's
`challengeAuthDigest(orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary)`:

```text
keccak256(abi.encode(
    keccak256("arcora:l1-inclusion-challenge:v1"),   // CHALLENGE_AUTH_TAG
    chainId, settlement, orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary))
```

The receipt's own `signature` (over the perp-core receipt digest) is not accepted
on L1, and an authorization for one chain or settlement is useless on another.

**Opening.** Once `recvTimeMs / 1000 + inclusionDeadlineSecs` has passed
(3,600 s at the launch defaults), anyone may open the challenge, staking exactly
`challengeBond()` wei:

```bash
# cast prints a decoded uint with a suffix ("10000000000000000 [1e16]"); keep the integer.
BOND=$(cast call $SETTLEMENT "challengeBond()(uint256)" --rpc-url $RPC | cut -d' ' -f1)
cast send $SETTLEMENT "challengeInclusion(bytes32,uint64,uint64,uint64,address,bytes)" \
  <orderHash> <seqNo> <recvTimeMs> <batchIdHint> <beneficiary> <l1Challenge.signature> \
  --value "$BOND" --rpc-url $RPC --private-key <KEY>
```

Each order hash can be challenged once; it is refused in close-only.

**Outcomes.**

- **Answered.** Anyone proves the order is in a settled batch's ordered or rejected
  root. The stake returns to the submitter when that batch settled after the
  challenge opened, otherwise it goes to the sequencer.
- **Slashed.** If no answer lands, `slashUnanswered(orderHash)` becomes available
  once `progressBatches` batches have settled since the challenge opened, plus
  `challengeGraceBlocks`. It credits the beneficiary with
  `min(sequencerBond, slashPayoutCap)` USDC (`claimUsdc()`, or `claimUsdcTo(to)` to
  pay another address) and returns the stake to the submitter (`claimEth()` /
  `claimEthTo(to)`). Settlement continues. When the bond is below the cap, only the
  beneficiary may trigger the reduced fine at first.
- **Released.** If close-only begins before the progress gate can be reached,
  `releaseStaleChallenge(orderHash)` returns the stake.

`scripts/claim/challenge_inclusion.py <receipt.json> --rpc <RPC>` checks a saved
receipt's `l1Challenge` without the gateway: it recomputes the digest, recovers the
signer, reads the challenge state from the settlement, and prints the `cast send`
for the current stage (open, slash, release, or claim the credited fine or stake).
It never signs or sends.

**Privacy.** The beneficiary is an indexed event topic, so opening a challenge
publicly links that address to the order hash. Keep the authorization private
unless you intend to use it.

## Withdrawal authorization (SEC-021)

Every withdrawal — `POST /v1/accounts/withdraw` **and** `POST /v1/lp/withdraw` —
must carry a strictly-increasing `nonce` and a 65-byte secp256k1 `signature`
(`r‖s‖v` hex). A request without them is a `400`; the API key alone can never
move funds.

**Who must sign.** The account's *authorizing address*:

- a **caller-signed** account's registered `signer` — always, even if the account
  has *also* bound a deposit address (the signer takes precedence deliberately, so
  registering a signer **narrows** authorization to that one key);
- otherwise the **bound deposit address**;
- an account with neither cannot withdraw at all (bind an address first).

**Destination rule.** A server-custody account (no registered signer) may only
withdraw **to its bound deposit address** — `to` must equal it exactly. A
caller-signed account keeps a free `to` (it consented cryptographically: deposit
from a hot wallet, withdraw to a cold one).

**Nonce.** One counter per account, shared by both withdraw endpoints. It must
strictly increase; read the next acceptable value as `nextWithdrawNonce` from
`GET /v1/accounts/me`. The nonce commits only when the withdrawal fully succeeds
— a rejected request (bad balance, bad signature, …) does not burn it, so the
same signed request can be retried.

**Digest layouts** — every field fixed-width big-endian, no length prefixes, no
separators; `chainId`, `vault`, and your 32-byte `owner` come from
`GET /v1/accounts/me` (never hardcode them — the digest binds the deployment, so
a signature for one deployment is not portable to another):

`POST /v1/accounts/withdraw` signs `keccak256` of the 131-byte preimage:

```text
offset  len  field
     0   19  "dark-perp:withdraw:"  (ASCII, no trailing space)
    19    8  chainId    u64 BE
    27   20  vault
    47   32  owner
    79    8  marketId   u64 BE
    87   16  amount     i128 BE (two's complement)
   103   20  to
   123    8  nonce      u64 BE
```

`POST /v1/lp/withdraw` signs `keccak256` of the 106-byte preimage (no `to`: LP
value lands in the account's **own** market-0 balance, never on L1):

```text
offset  len  field
     0   22  "dark-perp:lp-withdraw:"  (ASCII, no trailing space)
    22    8  chainId    u64 BE
    30   20  vault
    50   32  owner
    82   16  shares     u128 BE
    98    8  nonce      u64 BE
```

### Accepted signature shapes

Withdrawal, bind, and rebind signatures are accepted over any of **three**
deterministic shapes of the digest, tried in order:

1. the **raw 32-byte digest** itself (CLI signers: `cast wallet sign --no-hash`);
2. EIP-191 `personal_sign` over the 32 digest bytes:
   `keccak256("\x19Ethereum Signed Message:\n32" ‖ digest)`;
3. EIP-191 over the digest's ASCII hex string:
   `keccak256("\x19Ethereum Signed Message:\n66" ‖ "0x<64 lowercase hex>")` —
   some wallets sign the hex string's UTF-8 bytes instead of decoding it. Note
   the server computes this shape with **lowercase** hex, so pass the digest to
   `personal_sign` as lowercase `0x…`.

All three commit to the same fields, so this widens signer ergonomics, never
authorization. `v` ∈ {27, 28} as wallets produce it; the gateway actually
accepts any `v` in {0, 1, 2, 3} (raw recovery ids) or {27, 28, 29, 30} (their
27-shifted forms) and rejects everything else. High-`s` (malleable) signatures
are rejected.

**⚠ Order signatures are different.** A caller-signed **order** signature is over
the **raw** 32-byte order hash only — no EIP-191 prefix, and the EIP-191 shapes
are *not* accepted there (§ Caller-signed orders). A browser wallet's
`personal_sign` therefore cannot produce a valid *order* signature, while it can
produce a valid *withdrawal* one.

### Rebinding the deposit address

The first bind only proves control of the address being bound. **Changing** an
existing binding additionally requires `currentSignature` — a signature from the
address **currently bound** — over `keccak256` of the 133-byte preimage:

```text
offset  len  field
     0   25  "dark-perp:rebind-deposit:"  (ASCII, no trailing space)
    25    8  chainId        u64 BE
    33   20  vault
    53   32  owner
    85    8  rebindCounter  u64 BE
    93   20  oldAddr
   113   20  newAddr
```

`rebindCounter` is the account's rebind generation: `0` at creation, `+1` on
every **accepted** rebind (a first-time bind and rejected attempts don't touch
it). Read the current value as `rebindCounter` from `GET /v1/accounts/me`. It
makes every rebind signature single-use: an old rotation signature can never be
replayed after the binding has moved again.

A rebind is refused while the account holds deposit permits that have neither
landed nor expired at a finalized block.

### ⚠ Consequences you must plan for (deliberate design decisions)

- **There is no recovery path for a lost bound-address key.** The binding moves
  only with a signature from the address currently bound — no timelock, no
  operator unbind, no admin escape hatch. Because a server-custody account can
  also only withdraw *to* that address, losing that key makes the account's
  funds **permanently unwithdrawable**. Keep the key you deposited from.
- **First bind wins, permanently.** An attacker holding only your API key can
  bind *their* address to your account **if you never bound one**, and you
  cannot overwrite it. Such an account holds no funds (crediting requires the
  deposit to come *from* the bound address), so this is griefing, not theft —
  but you cannot rebind your way out of it. Bind your deposit address
  immediately after registering.
- **Registering a caller-signed `signer` makes it the only withdrawal key.**
  Even with a deposit address bound, withdrawals must be signed by the `signer`.
  Losing the signer key strands the funds even though the deposit-address key is
  safe.

### One field, two spellings: `vault`

`GET /v1/accounts/me` serves `vault` **normalized to lowercase** `0x` + 40 hex —
these are the exact bytes hashed into the digests above, so it is the
authoritative value for signing. `GET /v1/accounts/withdrawals` echoes the raw
`L1_VAULT` environment string, which may be EIP-55 mixed-case. Same address,
same source of truth — but don't compare the two as strings, and don't build
digests from the withdrawals endpoint's spelling.

## Caller-signed orders

Register with a signer to require the caller's own key on every order:

```json
POST /v1/accounts        { "signer": "0x<40 hex eth address>" }
→ { "apiKey": "0x..", "owner": "0x..", "callerSigned": true }
```

Then each `POST /v1/orders` must include a strictly-increasing `nonce` and a 65-byte
`signature` (`r‖s‖v`, secp256k1) over the engine **order hash** of the exact order:

```json
{ "marketId": 0, "side": "Buy", "size": "10000000", "limitPrice": "5957500000000",
  "tif": "Ioc", "reduceOnly": false, "nonce": 1, "signature": "0x<130 hex>" }
```

The order `signature` is over the **raw 32-byte order hash** — no EIP-191
`"\x19Ethereum Signed Message"` prefix. This is *unlike* withdrawal and bind
signatures, which also accept the EIP-191 `personal_sign` shapes (§ Accepted
signature shapes): a browser wallet's `personal_sign` cannot produce a valid
order signature — use a signer that signs raw digests (e.g.
`cast wallet sign --no-hash`). The gateway recovers the signer with standard
secp256k1 recovery and rejects the order unless it matches the registered
address; the nonce must exceed the last accepted one (replay protection).
Caller-signed orders must carry a **limit price** (the gateway-filled market
price isn't pre-signable). Server-custody accounts (registered with no signer)
are unchanged.

**Withdrawals from a caller-signed account must be signed by this same `signer`
key** — it takes precedence over a bound deposit address, deliberately, so
registering a signer *narrows* authorization to that one key (a caller-signed
account does keep a free withdrawal `to`). Losing the signer key strands the
account's funds even if the deposit-address key is safe — see § Withdrawal
authorization.

## WebSocket

`GET /v1/ws` — public live-market data, plus authenticated per-account events.

On connect (and every engine tick) it pushes the public market snapshot:

```json
{ "type": "markets", "markets": [{ "id": 0, "symbol": "BTC/USDC", "price": "...", "book": { "marketId": 0, "bids": [...], "asks": [...] } }], "tsMs": 1719446400000 }
```

To also receive **your own** events, send `{ "type": "auth", "apiKey": "0x<64 hex>" }`
→ `{ "type": "authOk", "owner": "0x..." }`. After auth, filtered to your account:

- `{ "type": "order", "orderId": "o1", "finality": "MATCHED", "marketId": 0 }`
- `{ "type": "fill", "orderId": "o1", "marketId": 0, "side": "Buy", "size": "...", "price": "..." }`
- `{ "type": "adl", "clawed": "..." }` (your position was auto-deleveraged, audit Q2)

An unauthenticated connection sees only public market data.

## Example (curl)

```bash
B=http://localhost:8088
KEY=$(curl -s -XPOST $B/v1/accounts | jq -r .apiKey)
# server-custody demo credit + trade
curl -s -XPOST $B/v1/accounts/deposit -H "X-Api-Key: $KEY" \
  -d '{"marketId":0,"amount":"20000000000"}'
curl -s -XPOST $B/v1/orders -H "X-Api-Key: $KEY" \
  -d '{"marketId":0,"side":"Buy","size":"10000000","limitPrice":"0","tif":"Ioc","reduceOnly":false}'
curl -s $B/v1/accounts/me -H "X-Api-Key: $KEY"      # balance + positions + withdrawal-auth state
# withdraw → claim on Base Sepolia (SEC-021: wallet-signed, § Withdrawal authorization)
# Build the 131-byte withdraw preimage (chainId/vault/owner + nextWithdrawNonce from
# /v1/accounts/me), keccak256 it, and sign the raw digest with the bound EOA's key:
SIG=$(cast wallet sign --no-hash <0xdigest> --private-key <BOUND_EOA_KEY>)
curl -s -XPOST $B/v1/accounts/withdraw -H "X-Api-Key: $KEY" \
  -d '{"marketId":0,"amount":"40000000","to":"0x<bound EOA>","nonce":1,"signature":"'$SIG'"}'
curl -s $B/v1/accounts/withdrawals -H "X-Api-Key: $KEY"   # → proof once published
```

## Status

Built and verified: per-account + per-IP rate limiting, per-account authenticated WS
channels, the OpenAPI spec, **real on-chain USDC deposits**, **real withdrawals with
cumulative Merkle roots claimable on Base Sepolia** (every withdrawal wallet-signed,
SEC-021), and **caller-signed orders**.
The full deposit → withdraw → claim flow is verified live on Base Sepolia. Remaining
toward fully non-custodial: on-chain enclave custody of spend keys (the TEE
milestone) — see `docs/NEXT_STEPS.md`.

### `POST /v1/admin/wind-down` — A06 terminal CloseOnly settlement

Operator-only (`X-Admin-Key` / `FIN_ADMIN_KEY`). Requires durable snapshots, the proof path,
an empty ordinary window, and a block-pinned L1 observation with `closeOnly == true`. Queues
the one-shot `SettleAll`, which carries no time and no oracle transcript; the proof-derived
phase routes to governance `finalSettle`. After phase 1 lands, normal account withdrawal
requests in proven CloseOnly use price-free `WindDownUnbind`/`WindDownWithdraw` and land
through repeatable `finalExit`. A 202 means phase 1 was durably queued, not that an L1
transaction has already finalized.

`SettleAll` closes every open position at its market's last price recorded in the settled
state (its own entry price when the market never recorded one), covers deficits from the
clearing pool, insurance and the treasury, haircuts pro rata only what remains, and pays the
reserves left over as one withdrawal leaf to the deployment's wind-down recipient. The 202
body then also carries that leaf's claim data as `reserveSink`, an `arcora.claim-bundle.v1`
object `{ schema, chainId, vault, to, amount, nonce, leaf, root, proof }` (`null` when no
reserves are left); `root` is the leaf and `proof` is empty, because the phase-1 root holds
only that leaf. Saved to a file, it is a bundle `scripts/claim/claim_withdrawal.py` checks
as it is. `GET /v1/system/status` shows the same leaf under `windDown.reserveSink`, with
`claimable` once the root is published; no account lists it. Anyone may send the claim
once `finalSettle` lands. See `docs/FINAL_SETTLE_RUNBOOK.md`.

When the gateway observes close-only it first rebases to the L1-settled state: it
drops the open window and any sealed window that never settled, drops credits for
deposits at or above `consumedDepositCount()` (they are refundable on L1) and every
outstanding permit, keeps its record of the permitted deposits that landed and were
never credited, and checks that its root equals `currentStateRoot()` and its consumed
count equals `consumedDepositCount()`. Order hashes from the dropped windows enter the `SettleAll`
manifest as rejected (`MarketCloseOnly`). The wind-down then starts from exactly the
settled state. See `docs/FINAL_SETTLE_RUNBOOK.md`.

### Wind-down status

`GET /v1/system/status` carries `windDown`:

```json
{
  "started": false,
  "engineCloseOnly": false,
  "recipient": "0x<20-byte wind-down recipient bound in the genesis root>",
  "reserveSink": [],
  "markets": [{ "marketId": 0, "lastPrice": "5957514000000", "lastPriceMs": 1767225600000 }]
}
```

- `started`: the operator has started the wind-down (`POST /v1/admin/wind-down`).
- `engineCloseOnly`: the engine is in close-only, which a liquidation's shortfall can
  cause before the settlement is (§ Deposits after an engine trip).
- `recipient`: the wind-down recipient the genesis root binds. It is all zero only
  when none is configured, which a production gateway with real proofs refuses to
  boot with; `SettleAll` then leaves the reserves in place.
- `markets[]`: per market, the last signed oracle price the engine state recorded
  (`lastPrice`, a decimal string, 1e8-scaled) and its publish time (`lastPriceMs`).
  `SettleAll` closes open positions at the price recorded in the settled state it
  starts from; `"0"` and `0` mean the market never recorded one, and its positions
  then close at their own entry price.
- `reserveSink`: empty, or the one reserve leaf once the wind-down has produced it:
  the `arcora.claim-bundle.v1` object `{ schema, chainId, vault, to, amount, nonce,
  leaf, root, proof }` plus `claimable`. Until the phase-1 root is published
  `claimable` is `false`, `root` is the leaf and `proof` is empty; after that `root`
  and `proof` are the published claim data.

### Operational alerts

`GET /api/state` lists the operational alerts currently active in `opsAlerts`, by
the same snake_case names the gateway delivers to its alert collector
(`FIN_ALERT_NTFY_TOPIC` or `FIN_ALERT_LOCAL_URL`, schema `arcora.ops-alert.v1`).
Each is raised once when it becomes active and once when it recovers:

| Alert | Active while |
|---|---|
| `settlement_held` | the settle loop is held after repeated settle failures |
| `persistence_failed` | a durable state snapshot could not be written |
| `deposit_halted` | deposit ingestion is stopped by a safety halt |
| `archive_pressure` | the configured price-report archive is under storage pressure, or a checkpoint with it could not be written |
| `bond_shortfall` | the bond is below its target and could not be topped up, or top-ups are paused after an unacknowledged slash |
| `unanswerable_challenge` | an open inclusion challenge names an order no settled batch can prove |
| `challenge_discovery_failed` | the open-challenge set could not be read for several ticks in a row |
| `stale_anchor` | the current batch's clock anchor is older than `anchorTimeoutMs` |
| `liveness_low` | half of the settlement's liveness window has passed without progress |
| `permit_gc_stalled` | finalized block headers have not re-hashed for a long stretch, so expired permits are not removed |
| `engine_close_only` | the engine is in close-only while the settlement is not; governance should call `enterCloseOnly()` (§ Deposits after an engine trip) |
| `admission_cap_reached` | the soft admission cap is reached; new permits and registrations are refused (§ Admission cap) |
| `withdraw_nonce_repaired` | at boot the withdrawal-leaf counter was at or behind the engine's last withdrawal nonce and was moved forward; find out which snapshot was restored |
| `deposit_blocked_at_cap` | a deposit that landed under a permit is not credited because the hard admission cap is reached; it is the oldest unconsumed deposit, and once it is older than `livenessTimeoutBlocks` anyone can put the settlement in close-only (§ Admission cap) |

### `POST /v1/admin/settlement/cancel-anchor` — cancel a stale clock anchor

Operator-only (`X-Admin-Key` / `FIN_ADMIN_KEY`). Body
`{ "batchId": <n>, "phase": 0 | 1 | 2, "receipt": "0x<32-byte clock receipt>" }`.
Sends `ClockBoundVerifier.cancel(batchId, phase, receipt)` from the gateway's L1
key, which must hold the role that registers that phase: the sequencer for phase 0,
governance for phases 1 and 2.

The gateway refuses the request:

- while a local settle for that receipt is still in flight;
- before the anchor is `anchorTimeoutMs()` old, measured against the latest block
  time.

On-chain, the call also requires that `batchId` is the current `batchCount()`, that
`phase` is the current phase, and that `receipt` matches the stored anchor.
Afterwards `cancelledReceipt(receipt)` is true and `ClockCancelled` is emitted; a
proof bound to that receipt can never verify again. When to use it, and how to
recover the batch afterwards, is in `docs/PROVING-RUNBOOK.md`.

| Response | Meaning |
|---|---|
| `200` `{ tx, batchId, phase, receipt }` | the cancel transaction landed |
| `409` `{ error }` | a precondition failed, or the settle loop is working on that window |
| `502` `{ error, confirm }` | the send's outcome is unknown; check `cancelledReceipt(receipt)` before retrying |
| `503` | no L1 key or no clock verifier is configured |
| `400` | malformed body |

The endpoint is exempt from the clock-admission gate. Cancelling does not resolve
the local window: restart the gateway, and boot recovery classifies it.

### `POST /v1/admin/bond/acknowledge-slash` — resume bond top-ups after a slash

Operator-only (`X-Admin-Key` / `FIN_ADMIN_KEY`). Body `{ "slashCount": <n> }`.
Automatic bond top-ups stop while the settlement's `slashCount()` is above the
acknowledged count, and a `bond_shortfall` alert is raised. The request is accepted
only when `n` equals the current `slashCount()`: `200 { acknowledgedSlashCount }`,
`409 { error }` otherwise, `503` without `FIN_ADMIN_KEY` or an L1 bridge. The
acknowledgement lasts until restart; `L1_BOND_ACKED_SLASH_COUNT` sets it at boot.
