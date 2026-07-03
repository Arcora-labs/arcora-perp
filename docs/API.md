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
| GET  | `/v1/accounts/me` | ✓ | `{ owner, settledBalance, positions[], nextNonce }` |
| POST | `/v1/accounts/deposit` | ✓ | `{ marketId, amount }` — demo/in-memory credit |
| POST | `/v1/accounts/deposit/address` | ✓ | `{ address, signature }` — bind the EOA you fund from (ownership-proven) |
| POST | `/v1/accounts/deposit/onchain` | ✓ | `{ txHash, marketId }` — credit a real USDC deposit |
| POST | `/v1/accounts/withdraw` | ✓ | `{ marketId, amount, to }` → authorized withdrawal |
| GET  | `/v1/accounts/withdrawals` | ✓ | `{ vault, withdrawals[] }` with claim proofs |
| POST | `/v1/orders` | ✓ | order body (below) → signed receipt |
| GET  | `/v1/orders` | ✓ | `{ orders[] }` (own orders + finality) |
| DELETE | `/v1/orders/:orderId` | ✓ | cancel a still-`ACCEPTED` order |
| GET  | `/v1/positions` | ✓ | `{ positions[] }` (own open positions) |
| GET  | `/v1/markets` | – | `{ markets[] }` |
| GET  | `/v1/markets/:id` | – | one market |
| GET  | `/v1/markets/:id/orderbook` | – | `{ marketId, bids[], asks[] }` |
| GET  | `/v1/markets/:id/oracle` | – | `{ marketId, price, confidence, publishTimeMs }` |
| GET  | `/v1/system/status` | – | `{ mode, insuranceFund, nextBatchId, accounts }` |

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

`tif`: `Ioc`/`Fok` are takers (crossed against the resting market-maker, guaranteed
fill); `Gtc`/`PostOnly` rest in the matcher book so a maker can quote and be crossed
by later takers. `limitPrice: "0"` means market (filled at the mark). Opening orders
are margin-checked against the account's free balance; close-only mode blocks
openers (§6). **Rate limit:** at most 10 orders/sec per account — over that returns
`429` `{ "error": "RATE_LIMIT: ..." }`.

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
   binds to at most one account). Only `Deposit` logs whose `from` matches the bound
   address are credited to you.
2. On Base Sepolia, from that EOA: `usdc.approve(vault, amount)` then
   `vault.deposit(amount)`.
3. `POST /v1/accounts/deposit/onchain { "txHash": "0x..", "marketId": 0 }` — the
   gateway verifies the `vault.Deposit(from, amount)` log, checks the binding,
   canonicalizes + dedups the tx hash, and credits `amount` (USDC base units) to the
   market bucket.

## Withdrawals + claiming USDC on Base Sepolia (§3)

Funds release only from **settled** state, via the vault, never by the sequencer
directly:

1. `POST /v1/accounts/withdraw { "marketId": 0, "amount": "40000000", "to": "0x<dest>" }`
   — debits the engine immediately (so it can't be double-spent) and records an
   authorized withdrawal leaf `keccak256(to, amount, nonce)`.
2. On the next L1 settle (~30s) the gateway publishes the **cumulative** withdrawals
   root (every still-unclaimed leaf) to the vault.
3. `GET /v1/accounts/withdrawals` → `{ vault, withdrawals: [{ to, amount, nonce, leaf,
   claimable, proof }] }`. Once `claimable` is `true`, `proof` is the Merkle path.
4. On Base Sepolia: `vault.claim(to, amount, nonce, proof)` releases the USDC. The
   leaf is single-claim (`AlreadyClaimed` on replay).

This is the forced-exit path too (§6): even in close-only the authority is the
settled root, so funds can be stalled but not stolen.

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

The gateway recovers the signer (the same `ecrecover` the contracts use) and rejects
the order unless it matches the registered address; the nonce must exceed the last
accepted one (replay protection). Caller-signed orders must carry a **limit price**
(the gateway-filled market price isn't pre-signable). Server-custody accounts
(registered with no signer) are unchanged.

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
curl -s $B/v1/accounts/me -H "X-Api-Key: $KEY"      # balance + positions
# withdraw → claim on Base Sepolia
curl -s -XPOST $B/v1/accounts/withdraw -H "X-Api-Key: $KEY" \
  -d '{"marketId":0,"amount":"40000000","to":"0x<dest>"}'
curl -s $B/v1/accounts/withdrawals -H "X-Api-Key: $KEY"   # → proof once published
```

## Status

Built and verified: per-account + per-IP rate limiting, per-account authenticated WS
channels, the OpenAPI spec, **real on-chain USDC deposits**, **real withdrawals with
cumulative Merkle roots claimable on Base Sepolia**, and **caller-signed orders**.
The full deposit → withdraw → claim flow is verified live on Base Sepolia. Remaining
toward fully non-custodial: on-chain enclave custody of spend keys (the TEE
milestone) — see `docs/NEXT_STEPS.md`.
