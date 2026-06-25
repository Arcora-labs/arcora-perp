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

export function PositionsTable() {
  const { client, state } = useStore();
  const positions = state.account.positions;
  const mark = state.oracle.price;
  return (
    <div className="card">
      <h3 className="card__title">Positions</h3>
      {positions.length === 0 ? (
        <p className="muted">No open positions.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Market</th>
              <th>Size</th>
              <th>Entry</th>
              <th>Liq. price</th>
              <th>Health</th>
              <th>Margin</th>
              <th>uPnL</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {positions.map((p) => (
              <tr key={p.marketId}>
                <td>{state.market.symbol}</td>
                <td className={p.size >= 0n ? "pos" : "neg"}>{formatSignedSize(p.size)}</td>
                <td>{formatPrice(p.entryPrice)}</td>
                <td>{formatPrice(p.liquidationPrice)}</td>
                <td>
                  <HealthCell liq={p.liquidationPrice} mark={mark} long={p.size >= 0n} />
                </td>
                <td>{formatUsd(p.collateral)}</td>
                <td className={p.unrealizedPnl >= 0n ? "pos" : "neg"}>{formatUsd(p.unrealizedPnl)}</td>
                <td>
                  <button className="btn btn--tiny" onClick={() => void client.closePosition(p.marketId)}>
                    Close
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function OrdersTable() {
  const { client, state } = useStore();
  return (
    <div className="card">
      <h3 className="card__title">Orders</h3>
      {state.orders.length === 0 ? (
        <p className="muted">No orders yet. Place one to see the finality lifecycle.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Order</th>
              <th>Side</th>
              <th>Size</th>
              <th>Receipt</th>
              <th>Finality</th>
              <th></th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {state.orders.map((o) => (
              <tr key={o.id}>
                <td className="mono">{shortHash(o.receipt.orderHash)}</td>
                <td className={o.input.side === "Buy" ? "pos" : "neg"}>{o.input.side}</td>
                <td>{formatSignedSize(o.input.side === "Buy" ? o.input.size : -o.input.size)}</td>
                <td className="mono" title={`seq ${o.receipt.seqNo}`}>#{o.receipt.seqNo}</td>
                <td>
                  <FinalityBadge finality={o.finality} />
                </td>
                <td>
                  <FinalityProgress finality={o.finality} />
                </td>
                <td>
                  {o.finality === "ACCEPTED" && (
                    <button className="btn btn--tiny" onClick={() => void client.cancelOrder(o.id)}>
                      Cancel
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
