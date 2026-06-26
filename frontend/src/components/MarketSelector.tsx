import { useStore } from "../store";
import { baseAsset, formatPrice } from "../domain/format";

/// Switch the active market. The protocol is multi-market (per-MarketId state);
/// this picks which one the trade panel, book, and stats reflect. Rendered as the
/// instrument list in the sidebar (Celari design): glyph · base · PERP/leverage,
/// with the market's own mark price + 24h change on the right.
export function MarketSelector() {
  const { client, state } = useStore();
  return (
    <div className="market-list" role="tablist" aria-label="Markets">
      {state.markets.map((m) => {
        const active = m.id === state.selectedMarketId;
        const base = baseAsset(m.symbol);
        const mark = state.marks[m.id] ?? m.referencePrice;
        const ref = m.referencePrice;
        const chg = ref > 0n ? Number(mark - ref) / Number(ref) : 0;
        const chgStr = `${chg >= 0 ? "+" : ""}${(chg * 100).toFixed(2)}%`;
        const chgColor = chg > 0 ? "var(--buy)" : chg < 0 ? "var(--sell)" : "var(--text-dim)";
        return (
          <button
            key={m.id}
            role="tab"
            aria-selected={active}
            aria-label={m.symbol}
            className={`market-row ${active ? "is-active" : ""}`}
            onClick={() => client.selectMarket(m.id)}
          >
            <span className="glyph glyph--sm" aria-hidden>{base.slice(0, 1)}</span>
            <span className="market-row__main">
              <span className="market-row__base">{base}</span>
              <span className="market-row__tag">PERP · {m.maxLeverage}×</span>
            </span>
            <span className="market-row__right">
              <span className="market-row__price">{formatPrice(mark)}</span>
              <span className="market-row__chg" style={{ color: chgColor }}>{chgStr}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
