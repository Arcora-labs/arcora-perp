import { useEffect, useState } from "react";
import { useStore } from "../store";
import { IS_LIVE } from "../api/apiBase";
import { formatPrice } from "../domain/format";
import { OrderBook } from "./OrderBook";

export function MarketPulse() {
  const { state } = useStore();
  const [book, setBook] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const id = window.setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(id); }, []);
  const age = Math.max(0, Math.floor((now - state.oracle.publishTimeMs) / 1000));
  const stale = age > 30 || state.oracle.price <= 0n;
  return <div className="pulse-stack">
    <section className="card market-pulse" aria-label="Market pulse">
      <div className="pulse-heading"><h2>Market pulse</h2><span className={`badge ${stale ? "badge--cancelled" : "badge--settled"}`}>{stale ? "Stale" : "Updating"}</span></div>
      <div className="pulse-price"><span className="muted">Reference price</span><strong>{formatPrice(state.oracle.price)}</strong><small className="muted">{IS_LIVE ? "Gateway oracle" : "Demo environment"}</small></div>
      <dl className="pulse-metrics"><div><dt>Updated</dt><dd>{age}s ago</dd></div><div><dt>Max leverage</dt><dd>{state.market.maxLeverage}×</dd></div><div><dt>Initial margin</dt><dd>{(state.market.initialMarginRatio * 100).toFixed(1)}%</dd></div><div><dt>Settlement</dt><dd>{state.settlement?.health ?? "No live evidence"}</dd></div></dl>
      {stale && <p role="status" className="notice notice--warn">Price data is stale. Check Health before placing an order.</p>}
      <div className="private-note"><span className="private-note__icon" aria-hidden>⌑</span><h3>Your activity.<br />Your space.</h3><p>Follow your own orders and receipts. Public depth may be unavailable on private markets.</p></div>
      <button className="btn btn--ghost" aria-expanded={book} onClick={() => setBook(!book)}>{book ? "Hide order book" : "View order book"}</button>
    </section>
    {book && <OrderBook />}
  </div>;
}
