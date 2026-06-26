import { useState } from "react";
import { useStore } from "../store";
import { formatPrice, formatSignedSize, formatUsd, shortHash } from "../domain/format";
import { FinalityBadge, FinalityProgress } from "./FinalityTracker";

/// Liquidation-proximity bar: the cushion (in %) between the mark and the
/// position's liquidation price. Safety-critical, so it's loud and colour-coded.
/// `Number()` is used only for the bar geometry, never for money math.
function HealthCell({ liq, mark, long }: { liq: bigint; mark: bigint; long: boolean }) {
  if (mark <= 0n) return <span className="muted">—</span>;
  const cushion = long ? mark - liq : liq - mark; // healthy when positive
  const bps = Number((cushion * 10_000n) / mark); // cushion in basis points
  const pct = Math.max(0, Math.min(100, (bps / 1200) * 100)); // 12% cushion = full bar
  const tone = bps <= 300 ? "danger" : bps <= 800 ? "warn" : "ok";
  const pctLabel = (bps / 100).toFixed(1);
  return (
    <div className="health" title={`${pctLabel}% cushion to liquidation`} aria-label={`${pctLabel}% to liquidation`}>
      <span className="health__track">
        <span className={`health__fill health__fill--${tone}`} style={{ width: `${pct}%` }} />
      </span>
      <span className={`health__label health__label--${tone}`}>{pctLabel}%</span>
    </div>
  );
}

/** Positions table body (no card chrome) — shared by the standalone card and the tabbed card. */
function PositionsBody() {
  const { client, state } = useStore();
  const positions = state.account.positions;
  const symbolOf = (marketId: number) =>
    state.markets.find((m) => m.id === marketId)?.symbol ?? state.market.symbol;
  const markOf = (marketId: number) => state.marks[marketId] ?? state.oracle.price;
  if (positions.length === 0) return <p className="empty">No open positions. Place an order to open one.</p>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Market</th>
          <th>Size</th>
          <th className="num">Entry</th>
          <th className="num">Liq.</th>
          <th>Health</th>
          <th className="num">Margin</th>
          <th className="num">uPnL</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {positions.map((p) => (
          <tr key={p.marketId}>
            <td>
              <span className="cell-market">
                <span className="glyph glyph--sm" aria-hidden>{symbolOf(p.marketId).slice(0, 1)}</span>
                {symbolOf(p.marketId)}
                <span className={`badge ${p.size >= 0n ? "badge--long" : "badge--short"}`}>{p.size >= 0n ? "Long" : "Short"}</span>
              </span>
            </td>
            <td className={p.size >= 0n ? "pos" : "neg"}>{formatSignedSize(p.size)}</td>
            <td className="num">{formatPrice(p.entryPrice)}</td>
            <td className="num neg">{formatPrice(p.liquidationPrice)}</td>
            <td><HealthCell liq={p.liquidationPrice} mark={markOf(p.marketId)} long={p.size >= 0n} /></td>
            <td className="num muted">{formatUsd(p.collateral)}</td>
            <td className={`num ${p.unrealizedPnl >= 0n ? "pos" : "neg"}`}>{formatUsd(p.unrealizedPnl)}</td>
            <td className="num">
              <button className="btn btn--tiny" onClick={() => void client.closePosition(p.marketId)}>Close</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Orders table body (no card chrome). */
function OrdersBody() {
  const { client, state } = useStore();
  if (state.orders.length === 0) return <p className="empty">No orders yet. Place one to watch the finality lifecycle.</p>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Order</th>
          <th>Side</th>
          <th className="num">Size</th>
          <th>Receipt</th>
          <th>Finality</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {state.orders.map((o) => (
          <tr key={o.id}>
            <td className="cell-id">{shortHash(o.receipt.orderHash)}</td>
            <td><span className={`badge ${o.input.side === "Buy" ? "badge--buy" : "badge--sell"}`}>{o.input.side}</span></td>
            <td className="num">{formatSignedSize(o.input.side === "Buy" ? o.input.size : -o.input.size)}</td>
            <td className="muted" title={`seq ${o.receipt.seqNo}`}>#{o.receipt.seqNo}</td>
            <td>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 9 }}>
                <FinalityBadge finality={o.finality} />
                <FinalityProgress finality={o.finality} />
              </span>
            </td>
            <td className="num">
              {o.finality === "ACCEPTED" && (
                <button className="btn btn--tiny" onClick={() => void client.cancelOrder(o.id)}>Cancel</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/// Standalone Positions card (reused on the Account page).
export function PositionsTable() {
  return (
    <div className="card card--flush">
      <h3 className="card__title" style={{ padding: "16px 16px 0", margin: "0 0 8px" }}>Positions</h3>
      <PositionsBody />
    </div>
  );
}

/// Standalone Orders card.
export function OrdersTable() {
  return (
    <div className="card card--flush">
      <h3 className="card__title" style={{ padding: "16px 16px 0", margin: "0 0 8px" }}>Orders</h3>
      <OrdersBody />
    </div>
  );
}

/// Combined Positions / Orders card with tabs (Celari trade layout).
export function PositionsOrders() {
  const { state } = useStore();
  const [tab, setTab] = useState<"positions" | "orders">("positions");
  return (
    <div className="card card--flush">
      <div className="tabs">
        <button className={`tab ${tab === "positions" ? "is-active" : ""}`} onClick={() => setTab("positions")}>
          Positions · {state.account.positions.length}
        </button>
        <button className={`tab ${tab === "orders" ? "is-active" : ""}`} onClick={() => setTab("orders")}>
          Orders · {state.orders.length}
        </button>
      </div>
      {tab === "positions" ? <PositionsBody /> : <OrdersBody />}
    </div>
  );
}
