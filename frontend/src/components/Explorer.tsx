import { useStore } from "../store";
import { formatPrice, formatSignedSize, shortHash } from "../domain/format";
import { FinalityBadge } from "./FinalityTracker";
import type { Finality, TrackedOrder } from "../domain/types";

const FINALITIES: Finality[] = ["ACCEPTED", "MATCHED", "SETTLED"];

/// A protocol / block explorer for dark-perp: browse the order-commitment log and the
/// batches it settles into (§2/§3), live per-market index marks, and the system mode.
/// Read-only, Etherscan-style — distinct from the trading UI and the API console. Reads
/// the same ClientState, so against a real backend it shows the real on-chain activity.
export function Explorer() {
  const { state } = useStore();
  const orders = state.orders;

  // group the order-commitment log by the batch that settles each order (§2)
  const batches = new Map<number, TrackedOrder[]>();
  for (const o of orders) {
    const b = o.receipt.batchIdHint;
    const arr = batches.get(b);
    if (arr) arr.push(o);
    else batches.set(b, [o]);
  }
  const batchRows = [...batches.entries()].sort((a, b) => b[0] - a[0]);
  const settled = orders.filter((o) => o.finality === "SETTLED").length;
  const symbolOf = (id: number) => state.markets.find((m) => m.id === id)?.symbol ?? `#${id}`;

  return (
    <div className="col">
      <div className="card">
        <h3 className="card__title">Protocol</h3>
        <div className="summary">
          <Stat label="Mode" value={state.mode} tone={state.mode === "CloseOnly" ? "neg" : "pos"} />
          <Stat label="Markets" value={String(state.markets.length)} />
          <Stat label="Orders logged" value={String(orders.length)} />
          <Stat label="Settled (§3)" value={`${settled} / ${orders.length}`} />
        </div>
      </div>

      <div className="card">
        <h3 className="card__title">Index marks · live oracle (§8)</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Market</th>
              <th>Index</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {state.markets.map((m) => (
              <tr key={m.id}>
                <td>{m.symbol}</td>
                <td className="num mono">{formatPrice(state.marks[m.id] ?? 0n)}</td>
                <td>{m.live ? <span className="pos">live</span> : <span className="muted">sim</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3 className="card__title">Batches (§2/§3)</h3>
        {batchRows.length === 0 ? (
          <p className="muted">No batches yet — place an order to populate the order-commitment log.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Batch</th>
                <th>Orders</th>
                <th>ACCEPTED</th>
                <th>MATCHED</th>
                <th>SETTLED</th>
              </tr>
            </thead>
            <tbody>
              {batchRows.map(([bid, os]) => {
                const [a, m, s] = FINALITIES.map((f) => os.filter((o) => o.finality === f).length);
                return (
                  <tr key={bid}>
                    <td className="mono">#{bid}</td>
                    <td>{os.length}</td>
                    <td>{a}</td>
                    <td>{m}</td>
                    <td className={s === os.length ? "pos" : ""}>{s}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3 className="card__title">Order-commitment log (§2)</h3>
        {orders.length === 0 ? (
          <p className="muted">No orders yet. Each accepted order is an append-only, signed-receipt entry.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Seq</th>
                <th>Order hash</th>
                <th>Batch</th>
                <th>Market</th>
                <th>Size</th>
                <th>Finality</th>
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <tr key={o.id}>
                  <td className="mono">#{o.receipt.seqNo}</td>
                  <td className="mono" title={o.receipt.orderHash}>
                    {shortHash(o.receipt.orderHash)}
                  </td>
                  <td className="mono">#{o.receipt.batchIdHint}</td>
                  <td>{symbolOf(o.input.marketId)}</td>
                  <td className={`num ${o.input.side === "Buy" ? "pos" : "neg"}`}>
                    {formatSignedSize(o.input.side === "Buy" ? o.input.size : -o.input.size)}
                  </td>
                  <td>
                    <FinalityBadge finality={o.finality} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="summary__stat">
      <span className="summary__label">{label}</span>
      <span className={`summary__value mono ${tone ?? ""}`}>{value}</span>
    </div>
  );
}
