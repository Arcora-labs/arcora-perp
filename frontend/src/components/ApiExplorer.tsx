import { useEffect, useState } from "react";
import { useStore } from "../store";
import { parseSize, parsePrice, parseUsd, shortHash } from "../domain/format";
import type { OrderEvent } from "../api/client";
import type { Side, TimeInForce } from "../domain/types";

/// JSON with bigints rendered as decimal strings (never NaN-coerced).
const json = (v: unknown) =>
  JSON.stringify(v, (_k, val) => (typeof val === "bigint" ? val.toString() : val), 2);

const TIFS: TimeInForce[] = ["Gtc", "Ioc", "Fok", "PostOnly"];

/// Interactive explorer for the `DarkPerpClient` API — the UI↔backend seam. Every
/// method can be invoked with live inputs; the response (Receipt / notes / void) and
/// the resulting account/order state are shown as JSON, and the `onOrderEvent` stream
/// is tailed. Works against the mock today and the real client unchanged. Token-styled.
export function ApiExplorer() {
  const { client, state } = useStore();
  const [out, setOut] = useState("// call a DarkPerpClient method to see the live response");
  const [err, setErr] = useState<string | null>(null);
  const [events, setEvents] = useState<OrderEvent[]>([]);

  useEffect(() => client.onOrderEvent((e) => setEvents((xs) => [e, ...xs].slice(0, 12))), [client]);

  async function call(label: string, fn: () => unknown) {
    setErr(null);
    try {
      const r = await fn();
      setOut(`// ${label} →\n${r === undefined ? "(void · ok)" : json(r)}`);
    } catch (e) {
      setErr(`${label}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // placeOrder inputs
  const [side, setSide] = useState<Side>("Buy");
  const [size, setSize] = useState("0.10");
  const [limit, setLimit] = useState("");
  const [tif, setTif] = useState<TimeInForce>("Gtc");
  const [reduceOnly, setReduceOnly] = useState(false);
  // shared inputs
  const [amount, setAmount] = useState("1000");
  const [seed, setSeed] = useState("alice");
  const [orderId, setOrderId] = useState("");

  const openOrders = state.orders.filter((o) => o.finality === "ACCEPTED");

  return (
    <div className="grid grid--two">
      <div className="col">
        <div className="card">
          <h3 className="card__title">placeOrder(input) → Receipt</h3>
          <div className="seg">
            <button
              type="button"
              className={`seg__btn ${side === "Buy" ? "is-active seg__btn--buy" : ""}`}
              aria-pressed={side === "Buy"}
              onClick={() => setSide("Buy")}
            >
              Buy
            </button>
            <button
              type="button"
              className={`seg__btn ${side === "Sell" ? "is-active seg__btn--sell" : ""}`}
              aria-pressed={side === "Sell"}
              onClick={() => setSide("Sell")}
            >
              Sell
            </button>
          </div>
          <label className="field">
            <span className="field__label">size</span>
            <input className="field__input" value={size} onChange={(e) => setSize(e.target.value)} inputMode="decimal" />
          </label>
          <label className="field">
            <span className="field__label">limitPrice (blank = market)</span>
            <input className="field__input" value={limit} onChange={(e) => setLimit(e.target.value)} placeholder="market" inputMode="decimal" />
          </label>
          <label className="field">
            <span className="field__label">tif</span>
            <select className="field__input" value={tif} onChange={(e) => setTif(e.target.value as TimeInForce)}>
              {TIFS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="field field--check">
            <input type="checkbox" checked={reduceOnly} onChange={(e) => setReduceOnly(e.target.checked)} />
            <span>reduceOnly</span>
          </label>
          <button
            className="btn btn--ghost"
            onClick={() =>
              call("placeOrder", () =>
                client.placeOrder({
                  marketId: state.selectedMarketId,
                  side,
                  size: parseSize(size) ?? 0n,
                  limitPrice: limit.trim() === "" ? 0n : (parsePrice(limit) ?? 0n),
                  tif,
                  reduceOnly,
                }),
              )
            }
          >
            Call placeOrder · market {state.selectedMarketId}
          </button>
        </div>

        <div className="card">
          <h3 className="card__title">deposit / requestWithdrawal(amount)</h3>
          <label className="field">
            <span className="field__label">amount (USD)</span>
            <input className="field__input" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
          </label>
          <div className="row">
            <button className="btn btn--ghost" onClick={() => call("deposit", () => client.deposit(parseUsd(amount) ?? 0n))}>
              deposit
            </button>
            <button className="btn btn--ghost" onClick={() => call("requestWithdrawal", () => client.requestWithdrawal(parseUsd(amount) ?? 0n))}>
              requestWithdrawal
            </button>
          </div>
        </div>

        <div className="card">
          <h3 className="card__title">recover(seed) → RecoveredNote[]</h3>
          <label className="field">
            <span className="field__label">seed</span>
            <input className="field__input" value={seed} onChange={(e) => setSeed(e.target.value)} />
          </label>
          <button className="btn btn--ghost" onClick={() => call("recover", () => client.recover(seed))}>
            Call recover
          </button>
        </div>

        <div className="card">
          <h3 className="card__title">positions / orders / mode</h3>
          <div className="row">
            <button className="btn btn--ghost" onClick={() => call("closePosition", () => client.closePosition(state.selectedMarketId))}>
              closePosition({state.selectedMarketId})
            </button>
            <button
              className="btn btn--ghost"
              onClick={() => call(state.mode === "CloseOnly" ? "resumeNormal" : "triggerCloseOnly", () => (state.mode === "CloseOnly" ? client.resumeNormal() : client.triggerCloseOnly()))}
            >
              {state.mode === "CloseOnly" ? "resumeNormal" : "triggerCloseOnly"}
            </button>
          </div>
          <label className="field">
            <span className="field__label">orderId to cancel (ACCEPTED only)</span>
            <select className="field__input" value={orderId} onChange={(e) => setOrderId(e.target.value)}>
              <option value="">— select —</option>
              {openOrders.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.id} · {o.input.side} · {shortHash(o.receipt.orderHash)}
                </option>
              ))}
            </select>
          </label>
          <button className="btn btn--ghost" disabled={orderId === ""} onClick={() => call("cancelOrder", () => client.cancelOrder(orderId))}>
            cancelOrder
          </button>
        </div>
      </div>

      <div className="col">
        <div className="card">
          <h3 className="card__title">Response</h3>
          {err && (
            <p className="notice notice--error" role="alert">
              {err}
            </p>
          )}
          {/* announce the response so a screen-reader user gets feedback after a call */}
          <pre className="mono api-explorer__out" aria-live="polite" aria-label="API response">
            {out}
          </pre>
        </div>
        <div className="card">
          <h3 className="card__title">onOrderEvent stream (newest first)</h3>
          {events.length === 0 ? (
            <p className="muted">No events yet — call placeOrder to see ACCEPTED → MATCHED → SETTLED.</p>
          ) : (
            <ul className="activity" aria-label="API event stream">
              {events.map((e, i) => (
                <li key={i} className="activity__row">
                  <span className={`activity__kind badge badge--${e.kind.toLowerCase()}`}>{e.kind}</span>
                  <span className="activity__msg mono">{e.orderId}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="card">
          <h3 className="card__title">getState() snapshot</h3>
          <pre className="mono api-explorer__out">
            {json({
              selectedMarketId: state.selectedMarketId,
              mode: state.mode,
              settledBalance: state.account.settledBalance,
              positions: state.account.positions,
              orders: state.orders.map((o) => ({ id: o.id, side: o.input.side, finality: o.finality })),
            })}
          </pre>
        </div>
      </div>
    </div>
  );
}
