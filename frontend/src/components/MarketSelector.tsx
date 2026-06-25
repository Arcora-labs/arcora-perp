import { useStore } from "../store";

/// Switch the active market. The protocol is multi-market (per-MarketId state);
/// this picks which one the trade panel, book, and stats reflect.
export function MarketSelector() {
  const { client, state } = useStore();
  return (
    <div className="market-selector" role="tablist" aria-label="Markets">
      {state.markets.map((m) => {
        const active = m.id === state.selectedMarketId;
        return (
          <button
            key={m.id}
            role="tab"
            aria-selected={active}
            className={`market-chip ${active ? "is-active" : ""}`}
            onClick={() => client.selectMarket(m.id)}
          >
            {m.symbol}
          </button>
        );
      })}
    </div>
  );
}
