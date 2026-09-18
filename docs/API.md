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
| POST | `/v1/accounts` | – | optional `{ signer }` → `{ apiKey, owner, callerSigned }` |
| GET  | `/v1/accounts/me` | ✓ | `{ owner, settledBalance, positions[], nextNonce, depositAddress, callerSigned, nextWithdrawNonce, rebindCounter, chainId, vault }` |
| POST | `/v1/accounts/deposit` | ✓ | `{ marketId, amount }` — demo/in-memory credit |
| POST | `/v1/accounts/deposit/address` | ✓ | `{ address, signature, currentSignature? }` — bind the EOA you fund from (ownership-proven; a **rebind** additionally requires `currentSignature`, § Withdrawal authorization) |
| POST | `/v1/accounts/deposit/authorize` | ✓ | `{ from, amount, marketId, purpose }` — durable permit with explicit routing |
| POST | `/v1/accounts/deposit/route` | ✓ | `{ ownerCommit, from, amount, marketId, purpose }` — explicitly adopt a legacy pending permit |
| POST | `/v1/accounts/deposit/onchain` | ✓ | `{ txHash, marketId }` — optional finalized ingestion accelerator / durable receipt |
| POST | `/v1/accounts/withdraw` | ✓ | `{ marketId, amount, to, nonce, signature }` → authorized withdrawal (wallet-signed, § Withdrawal authorization) |
| GET  | `/v1/accounts/withdrawals` | ✓ | `{ vault, withdrawals[] }` with claim proofs |
| GET  | `/v1/lp` | ✓ | `{ tvl, navPerShare, totalShares, myShares, myValue }` — **demo build only** (see note below) |
| POST | `/v1/lp/deposit` | ✓ | `{ amount }` → `{ sharesMinted }` — stake into the counterparty pool — **demo build only** |
| POST | `/v1/lp/withdraw` | ✓ | `{ shares, nonce, signature }` → `{ withdrawnValue }` (wallet-signed, § Withdrawal authorization) — **demo build only** |
| POST | `/v1/orders` | ✓ | order body (below) → signed receipt |
| GET  | `/v1/orders` | ✓ | `{ orders[] }` (own orders + finality + the stored acceptance `receipt`, incl. its `windowId`) |
| DELETE | `/v1/orders/:orderId` | ✓ | cancel a still-`ACCEPTED` order **that has not yet sealed into a batch** (see the cancel note below) |
| GET  | `/v1/positions` | ✓ | `{ positions[] }` (own open positions) |
| GET  | `/v1/markets` | – | `{ markets[] }` |
| GET  | `/v1/markets/:id` | – | one market |
| GET  | `/v1/markets/:id/orderbook` | – | `{ marketId, bids[], asks[] }` |
| GET  | `/v1/markets/:id/oracle` | – | `{ marketId, price, confidence, publishTimeMs }` |
| GET  | `/v1/system/status` | – | `{ mode, insuranceFund, nextBatchId, accounts }` |

**`/v1/lp*` is not mounted in production** (SEC-025-C): the demo LP pool credits
stakes through an unbacked mint, which would break settlement — the production
router omits all three routes (they 404) and the served OpenAPI document omits
them too.

**Cancel is effectively pre-seal only.** `DELETE /v1/orders/:orderId` refuses any
order already **sealed** into a batch — even while its finality is still
`ACCEPTED` — and every resting order seals within one sequencer tick (~700 ms).
So in practice only an order cancelled immediately after submission succeeds;
cancelling a resting order returns the refusal until cancel-inside-the-window
lands (SEC-025-E2).

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

## Faucet — get test USDC

The collateral asset is an **open-mint** MockUSDC (6 decimals) on Base Sepolia —
anyone may mint. Addresses live in `contracts/deployments/base-sepolia.json`
(`MockUSDC`, `CollateralVault`). Mint, then approve + deposit into the vault:

```bash
USDC=0xF9bd3AD70bA831b92e9F07D08121c6A750B3612a   # MockUSDC (base-sepolia.json)
VAULT=0x3A3939E1C5De10D41942a85D4A14ac8160779bF4  # CollateralVault
RPC=https://sepolia.base.org

# 1,000 test USDC (6 decimals) to yourself
cast send $USDC "mint(address,uint256)" <YOUR_ADDR> 1000000000 --rpc-url $RPC --private-key <KEY>
# approve + deposit into the vault
cast send $USDC "approve(address,uint256)" $VAULT 1000000000 --rpc-url $RPC --private-key <KEY>
cast send $VAULT "deposit(uint256)" 1000000000 --rpc-url $RPC --private-key <KEY>
```

Then attribute the deposit to your API account (below). The UI exposes the same
via the **"Get test USDC"** button.

## Real USDC deposits (on-chain → engine)

A real deposit is funded on Base Sepolia and then attributed to your account:

1. `POST /v1/accounts/deposit/address { "address": "0x<your EOA>", "signature": "0x.." }`
   — bind the external wallet you will deposit from. The `signature` is a secp256k1
   signature **recovering to `address`** over `keccak256("dark-perp:bind-deposit:" ‖
   owner ‖ address)` (so only the controller of the EOA can bind it, and an address
   binds to at most one account) — accepted over any of the three shapes in
   § Accepted signature shapes. Only `Deposit` logs whose `from` matches the bound
   address are credited to you. **Changing an existing binding (a rebind) requires
   the consent of the currently bound address** via `currentSignature` — see
   § Rebinding the deposit address. Re-binding the same address is an idempotent
   no-op (no `currentSignature` needed).
2. `POST /v1/accounts/deposit/authorize { "from": "0x<your EOA>", "amount": "<base units>", "marketId": 0, "purpose": "collateral" }`
   — the gateway records a secret blind for this deposit and returns its `ownerCommit`
   plus a signature. The vault accepts **only** pre-authorized deposits, so this step is
   not optional.
3. On Base Sepolia, from that EOA: `usdc.approve(vault, amount)` then
   `vault.deposit(amount, ownerCommit, signature)` — three arguments, all from step 2.

   **The authorization is one-shot on-chain (SEC-028).** Re-submitting the same
   `(from, ownerCommit, amount)` reverts `AuthorizationAlreadyUsed`. Before that guard,
   a replay minted a second leaf that the gateway could never credit — which blocked the
   contiguous deposit queue for **every** user, permanently. Get a fresh authorization
   for each deposit.
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

**Confirm responses:** `200` with `status: "credited"`, `credited`, `depositIds`,
`marketId`, `purpose`, `durability: "confirmed"`; `202` with
`status: "pendingFinalizedIngestion"` (not successful zero credit); `409` for a
market/purpose mismatch or a historical transaction without reconstructible new
receipts; `503` for RPC unavailability, blocked ordering, safety halt or uncertain
durability. Pending / `503` is **not** an instruction to send funds again.

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

## Trading is gated until launch (SEC-025-D)

On a fresh production deployment, **order submission is refused** until the deployment has
demonstrably settled a normal `settleBatch` over a capitalized insurance fund. Every order
path returns an error naming the **launch gate**.

Do not confuse this with close-only, which is a different condition with a different remedy:

| | launch gate closed | `Mode::CloseOnly` |
|---|---|---|
| means | the deployment has not opened yet | a wind-down is under way |
| blocks | **all** order ingress | only *opening/increasing*; reduce-only, cancels, deposits and withdrawals still pass |
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
2. On the next L1 settle (~30s) the gateway publishes the **cumulative** withdrawals
   root (every still-unclaimed leaf) to the vault.
3. `GET /v1/accounts/withdrawals` → `{ vault, withdrawals: [{ to, amount, nonce, leaf,
   claimable, proof }] }`. Once `claimable` is `true`, `proof` is the Merkle path.
4. On Base Sepolia: `vault.claim(to, amount, nonce, proof)` releases the USDC. The
   leaf is single-claim (`AlreadyClaimed` on replay).

This is the forced-exit path too (§6): even in close-only the authority is the
settled root, so funds can be stalled but not stolen.

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
