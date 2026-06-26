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

- **Boot**: `EnclaveIdentity::from_seed` → `Sequencer::new(.., 24)`; adds 5 markets
  (`Market::conservative`) seeded from real-ish prices; funds a deep market-maker
  and the demo user (≈ $5k into each of the 5 markets → `settledBalance` ≈ $25k).
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
