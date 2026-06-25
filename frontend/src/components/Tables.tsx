import { useStore } from "../store";
import { formatPrice, formatSignedSize, formatUsd, shortHash } from "../domain/format";
import { FinalityBadge, FinalityProgress } from "./FinalityTracker";

export function PositionsTable() {
  const { state } = useStore();
  const positions = state.account.positions;
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
              <th>Margin</th>
              <th>uPnL</th>
            </tr>
          </thead>
          <tbody>
            {positions.map((p) => (
              <tr key={p.marketId}>
                <td>{state.market.symbol}</td>
                <td className={p.size >= 0n ? "pos" : "neg"}>{formatSignedSize(p.size)}</td>
                <td>{formatPrice(p.entryPrice)}</td>
                <td>{formatPrice(p.liquidationPrice)}</td>
                <td>{formatUsd(p.collateral)}</td>
                <td className={p.unrealizedPnl >= 0n ? "pos" : "neg"}>{formatUsd(p.unrealizedPnl)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function OrdersTable() {
  const { state } = useStore();
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
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
