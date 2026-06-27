# External trading API (`/v1`)

A multi-tenant REST + WebSocket API over the real sequencer engine, so
market-makers, bots, and integrations can trade and read market data **without a
browser**. Every account is an independent trader on the **same shared order book
and engine**; accounts are isolated by a secret API key.

Base URL (testnet demo): the gateway's `http://<host>:<port>` (e.g. `:8088`).

> **Phase 0 custody.** Registration generates a wallet the gateway custodies; the
> API key authenticates the caller and the server acts for them — the CEX-style
> shape bots expect. The production version moves spend keys inside the TEE and
> supports caller-signed orders (see `docs/SECURITY.md`, `docs/NEXT_STEPS.md`).

## Auth

Authenticated endpoints require the header:

```
X-Api-Key: 0x<64 hex>
```

issued by `POST /v1/accounts`. A missing/invalid key returns `401`.

All token amounts are **decimal strings** of scaled integers: quote = micro-USD
(`* 1e6`), size = `* 1e8`, price = `* 1e8`.

A machine-readable **OpenAPI 3.1** spec is served at `GET /v1/openapi.json` (point
Swagger UI / a codegen at it).

## REST

| Method | Path | Auth | Body / notes |
|--------|------|------|--------------|
| POST | `/v1/accounts` | – | none → `{ apiKey, owner }` |
| GET  | `/v1/accounts/me` | ✓ | `{ owner, settledBalance, positions[], nextNonce }` |
| POST | `/v1/accounts/deposit` | ✓ | `{ marketId, amount }` |
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

## WebSocket

`GET /v1/ws` — public live-market data, plus authenticated per-account events.

On connect (and every engine tick) it pushes the public market snapshot:

```json
{ "type": "markets", "markets": [{ "id": 0, "symbol": "BTC/USDC", "price": "...", "book": { "marketId": 0, "bids": [...], "asks": [...] } }], "tsMs": 1719446400000 }
```

To also receive **your own** events, send:

```json
{ "type": "auth", "apiKey": "0x<64 hex>" }
```

→ `{ "type": "authOk", "owner": "0x..." }`. After auth the connection also gets,
filtered to your account:

- `{ "type": "order", "orderId": "o1", "finality": "MATCHED", "marketId": 0 }`
- `{ "type": "fill", "orderId": "o1", "marketId": 0, "side": "Buy", "size": "...", "price": "..." }`
- `{ "type": "adl", "clawed": "..." }` (your position was auto-deleveraged, audit Q2)

An unauthenticated connection sees only public market data.

## Example (curl)

```bash
B=http://localhost:8088
KEY=$(curl -s -XPOST $B/v1/accounts | jq -r .apiKey)
curl -s -XPOST $B/v1/accounts/deposit -H "X-Api-Key: $KEY" \
  -d '{"marketId":0,"amount":"20000000000"}'
curl -s -XPOST $B/v1/orders -H "X-Api-Key: $KEY" \
  -d '{"marketId":0,"side":"Buy","size":"10000000","limitPrice":"0","tif":"Ioc","reduceOnly":false}'
curl -s $B/v1/accounts/me -H "X-Api-Key: $KEY"      # balance + positions
curl -s $B/v1/orders      -H "X-Api-Key: $KEY"      # your orders + finality
curl -s $B/v1/markets/0/orderbook                    # public book
```

## Follow-ons

Done: per-account order rate limiting + per-account authenticated WS channels.
Still tracked in `docs/NEXT_STEPS.md`: per-IP rate limiting on registration,
OpenAPI/AsyncAPI spec, caller-signed orders + on-chain enclave custody, and real
deposit/withdraw L1 flows.
