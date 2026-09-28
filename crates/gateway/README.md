# gateway — web API over the real engine

An axum **HTTP + WebSocket** server that holds the real dark-perp `Sequencer`
engine in memory and exposes it to the web client, replacing the in-browser
`MockDarkPerpClient`. Every position, fill, finality step, funding, and
liquidation is driven by the real protocol crates (`perp-core` + `sequencer` +
`note-archive`) — the same flow `crates/demo` narrates, served over HTTP.

## Run

```bash
cargo run -p gateway              # serves on 0.0.0.0:8080
PORT=8088 cargo run -p gateway    # override the port (8080 may be taken)
```

Then point the frontend at it:

```bash
cd frontend
VITE_API_URL=http://localhost:8088 pnpm dev   # store.tsx switches Mock → Real
```

With `VITE_API_URL` unset the UI keeps using the in-browser mock, so the design
work and tests stay independent of the backend.

## Browser origins and WebSocket limits

`GATEWAY_ALLOWED_ORIGINS` is a comma-separated list of exact browser origins,
including the scheme and any nondefault port, without paths or trailing slashes:

```bash
GATEWAY_ALLOWED_ORIGINS=https://app.example.com,http://127.0.0.1:4173 cargo run -p gateway
```

In development, an unset list permits `http://localhost:5173`,
`http://127.0.0.1:5173`, `http://localhost:4173` and `http://127.0.0.1:4173`.
Production has no implicit allowed browser origins: configure the frontend's
origin explicitly, including for a frontend served through the same reverse
proxy. Setting the variable to an empty string permits no browser origins.
Wildcard, opaque `null`, malformed and duplicate request origins are rejected.
An unapproved supplied `Origin` returns 403 before a handler reads a body or
mutates state. CORS response headers use the same explicit list.

Native clients that omit `Origin` remain supported. Origin checks supplement
the existing account, signature and admin checks; they do not authenticate a
native client. Configuring another frontend port requires adding its exact
origin to the list. Invalid resource settings fail startup.

Both `/ws` and `/v1/ws` share the following per-process limits:

| Variable | Default | Accepted range |
| --- | ---: | ---: |
| `GATEWAY_WS_MAX_CONNECTIONS` | 256 | 1–10,000 |
| `GATEWAY_WS_MAX_MESSAGE_BYTES` | 16,384 | 1–1,048,576 |
| `GATEWAY_WS_MAX_FRAME_BYTES` | 16,384 | 1–1,048,576; no larger than message cap |
| `GATEWAY_WS_WRITE_BUFFER_BYTES` | 16,384 | 1–1,048,576 |
| `GATEWAY_WS_MAX_WRITE_BUFFER_BYTES` | 1,048,576 | 1–16,777,216; larger than write-buffer target |
| `GATEWAY_WS_SEND_TIMEOUT_MS` | 2,000 | 1–30,000 |
| `GATEWAY_WS_MESSAGES_PER_SECOND` | 32 | 1–1,000 |

The message/frame caps apply to incoming data; the write-buffer cap bounds
Tungstenite's outgoing buffering. A full connection pool rejects upgrades with
503. All incoming messages, including malformed JSON and control messages, use
a per-connection one-second budget; exhaustion closes that connection. A send
failure or deadline closes the socket without flushing it again. Private writes
retain the account's credential fence through the bounded send. Legacy sockets
also read disconnects, so an idle peer can release its connection slot.

HTTP body intake and handler admission also have per-process bounds:

| Variable | Default | Accepted range |
| --- | ---: | ---: |
| `GATEWAY_HTTP_MAX_IN_FLIGHT` | 64 | 1–4,096 |
| `GATEWAY_HTTP_MAX_BODY_BYTES` | 2,097,152 | 1–8,388,608 |
| `GATEWAY_HTTP_BODY_TIMEOUT_MS` | 5,000 | 1–60,000 |

Capacity or draining returns 503 before polling the body. A body deadline returns
408, while an oversized/invalid body returns 413 before handler mutation. The
permit remains held through the handler; HTTP mutation/durability is not cancelled
by the body deadline. The body is buffered within these bounds. WebSocket streams
use their separate connection pool after the HTTP upgrade finishes.

SIGTERM/SIGINT closes admission and the listener, drops both WebSocket streams,
and waits for accepted HTTP work. Background workers stop between operations;
an already-running ingestion/proof/broadcast is awaited, not aborted or retried.
The snapshot writer remains active for those operations' durability ACKs. Once
handlers, upgraded sockets and workers have drained, the writer is stopped and
the final frozen snapshot is persisted. Keystore cleanup and exit happen last.
This also handles memory-only demo servers (without a final snapshot).

A stuck backend can delay shutdown indefinitely: there is deliberately no forced
success or silent cancellation of possibly-broadcast work. An external hard kill
is crash recovery, not a clean drain. A failed final snapshot or worker produces
exit 1. Transport disconnect does not guarantee that the client received a reply;
unknown outcomes still require original-operation reconciliation.

These controls do not bound pre-header TCP/HTTP connection counts or idle time,
account/rate-limit table cardinality, snapshot serialization memory or all request
rates. Production still needs appropriate reverse-proxy connection/request limits
and capacity measurements. Ordinary graceful-drain tests do not establish these
remaining limits.

## API (wire contract)

Every fixed-point amount (`i128` in Rust) is serialized as a **decimal string**
so the TypeScript side keeps exact `BigInt` math. The shapes match
`frontend/src/api/realClient.ts` exactly.

- `GET  /api/state` → full `WireState` (markets, selected market, mode, oracle,
  book, marks, account, orders, batches).
- `POST /api/order` `{marketId, side, size, limitPrice, tif, reduceOnly}` → the
  `Receipt`; `400 {error}` on a rejected order.
- `POST /api/deposit` / `POST /api/withdraw` `{amount}` → `{}`.
- `POST /api/close` `{marketId}` · `POST /api/cancel` `{orderId}`.
- `POST /api/mode` `{mode}` · `POST /api/select-market` `{marketId}`.
- `POST /api/recover` `{seed}` → `[{batchId, amount, spent}]`.
- `GET  /ws` → WebSocket; pushes `{type:"state", state}` on every change and
  `{type:"event", event}` on order-lifecycle transitions (for toasts).

## How it maps to the engine

- **Boot**: `EnclaveIdentity::from_seed` → `Sequencer::new(.., 24)`; adds 3 markets
  (`Market::conservative`) seeded from real-ish prices; funds a deep market-maker
  and the demo user (≈ $5k into each of the 3 markets → `settledBalance` ≈ $15k).
- **Order → fill**: `accept_order` issues the ACCEPTED receipt immediately. A
  ~700ms tick walks the oracles, then `seal_batch`es each pending user order
  together with a resting market-maker counter-order (`Gtc` maker first, user
  `Ioc` taker second) so it crosses and fills — finality advances ACCEPTED →
  MATCHED. After `SETTLE_TICKS` the batch is `mark_settled` → SETTLED.
- **Accounting**: free/withdrawable `settledBalance` = each market's funded
  `Position.collateral` minus the margin locked by its open position (plus any
  un-funded notes). Deposits `FundPosition` into the selected market; withdrawals
  `Unbind` + `Withdraw`. Displayed position `collateral` is the locked initial
  margin (mock parity); the real engine holds the full per-market bucket.
- **Recovery**: `Wallet::from_seed(seed)` → `NoteArchive::scan(view_key)`. For the
  demo, any seed falls back to the gateway user's archive so a recoverable balance
  always surfaces.

## Differs from the mock

It is the **real engine**, so exact numbers differ from the JS mock (real VWAP
entry, real funding/liquidation, real margin). Collateral lives per-market
(`(owner, market_id)` buckets), so deposit/withdraw act on the **selected**
market; one position per market. TEE attestation and ZK proving stay simulated
(the same Phase-0 stand-ins the rest of the workspace uses).
