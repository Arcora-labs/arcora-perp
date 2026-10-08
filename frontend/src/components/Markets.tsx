import { useState } from "react";
import { useStore } from "../store";
import { baseAsset, formatPrice } from "../domain/format";
import { Dialog } from "./Dialog";

export function Markets({ onSelect }: { onSelect?: () => void }) {
  const { client, state } = useStore();
  const [query, setQuery] = useState("");
  const matches = state.markets.filter(m => m.symbol.toLowerCase().includes(query.toLowerCase().trim()));
  return <div className="markets-panel">
    <label className="field"><span className="field__label">Find your market</span><input className="field__input" type="search" placeholder="Search BTC, ETH, SOL…" value={query} onChange={e => setQuery(e.target.value)} autoFocus={!!onSelect} /></label>
    <div className="market-list" aria-label="Available markets">
      {matches.map(m => <button className={`market-row ${m.id === state.selectedMarketId ? "is-active" : ""}`} key={m.id} onClick={() => { client.selectMarket(m.id); onSelect?.(); }}>
        <span className={`coin coin--${baseAsset(m.symbol).toLowerCase()}`} aria-hidden>{baseAsset(m.symbol) === "BTC" ? "₿" : baseAsset(m.symbol) === "ETH" ? "Ξ" : "≋"}</span>
        <span className="market-row__main"><strong>{m.symbol}</strong><small className="muted">Perpetual · up to {m.maxLeverage}×</small></span>
        <span className="market-row__right"><strong>{formatPrice(state.marks[m.id] ?? m.referencePrice)}</strong><small className="muted">Reference price</small></span>
      </button>)}
    </div>
    {!matches.length && <p className="empty" role="status">No markets match “{query}”. Try a symbol such as BTC.</p>}
  </div>;
}
export function MarketSearch({ onClose }: { onClose: () => void }) {
  return <Dialog title="Find your market" onClose={onClose}><Markets onSelect={onClose} /></Dialog>;
}
