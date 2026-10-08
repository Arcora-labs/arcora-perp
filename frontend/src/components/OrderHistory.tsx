import { useState } from "react";
import { useStore } from "../store";
import { formatPrice, formatSize, shortHash } from "../domain/format";
import { Dialog } from "./Dialog";
import { FinalityBadge } from "./FinalityTracker";

export function OrderHistory() {
  const { state } = useStore();
  const [selected, setSelected] = useState<string | null>(null);
  const order = state.orders.find(o => o.id === selected);
  if (state.accountUnavailable) return <p className="empty neg">Order history could not be read. Reload to try again.</p>;
  return <>
    {state.orders.length === 0 ? <p className="empty">No receipts yet. Submitted orders appear here with their execution and finality.</p> : <ul className="receipt-list">
      {[...state.orders].sort((a, b) => Number(b.receipt.seqNo) - Number(a.receipt.seqNo)).map(o => <li key={o.id}>
        <div><strong>{state.markets.find(m => m.id === o.input.marketId)?.symbol ?? `Market ${o.input.marketId}`}</strong><small>{o.input.side} · {formatSize(o.input.size)} · Receipt #{String(o.receipt.seqNo)}</small></div>
        <FinalityBadge finality={o.finality} /><button className="btn btn--tiny" onClick={() => setSelected(o.id)}>View receipt</button>
      </li>)}
    </ul>}
    {order && <Dialog title={`Receipt #${order.receipt.seqNo}`} onClose={() => setSelected(null)}>
      <FinalityBadge finality={order.finality} />
      <dl className="review-rows">
        <div><dt>Order</dt><dd className="mono">{shortHash(order.id)}</dd></div>
        <div><dt>Order hash</dt><dd className="mono">{order.receipt.orderHash}</dd></div>
        <div><dt>Direction</dt><dd>{order.input.side}</dd></div>
        <div><dt>Requested size</dt><dd>{formatSize(order.input.size)}</dd></div>
        <div><dt>Execution</dt><dd>{order.execution?.status ?? "Unavailable"}</dd></div>
        <div><dt>Filled</dt><dd>{order.execution?.available ? formatSize(order.filledSize) : "Unavailable"}</dd></div>
        <div><dt>Average fill price</dt><dd>{order.execution?.available && order.filledSize > 0n ? formatPrice(order.avgFillPrice) : "Unavailable"}</dd></div>
      </dl>
      <p className="notice notice--warn">A receipt acknowledges the order. Matching is provisional. Check Explorer for settlement evidence.</p>
      <a className="btn btn--ghost receipt-explorer" href="#/explorer" onClick={() => setSelected(null)}>Open Explorer</a>
    </Dialog>}
  </>;
}
