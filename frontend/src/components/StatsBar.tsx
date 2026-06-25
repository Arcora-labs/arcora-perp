import { useStore } from "../store";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "../domain/types";
import { formatPrice, formatUsd } from "../domain/format";
import { useFlash } from "../hooks/useFlash";

/// Live market stats strip. Values are mock-derived; the design restyles the
/// presentation, the data stays.
export function StatsBar() {
  const { state } = useStore();
  const mark = state.oracle.price;
  const flash = useFlash(mark);

  // 24h change vs the market's reference price (the real 24h open once the live
  // oracle reports it, else the session seed).
  const baseline = state.market.referencePrice > 0n ? state.market.referencePrice : mark;
  const changePct = Number(((mark - baseline) * 10_000n) / baseline) / 100;

  // funding rate (mock): premium of mark over baseline, clamped
  const fundingPct = Math.max(-5, Math.min(5, changePct / 10));

  // open interest for THIS market = Σ |size| · mark over its positions
  const oi = state.account.positions
    .filter((p) => p.marketId === state.selectedMarketId)
    .reduce((acc, p) => {
      const abs = p.size < 0n ? -p.size : p.size;
      return acc + (abs * mark) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
    }, 0n);

  const up = changePct >= 0;

  return (
    <div className="statsbar">
      <div className="statsbar__market">
        <span className="statsbar__symbol">{state.market.symbol}</span>
        <span className={`statsbar__price ${up ? "pos" : "neg"} ${flash}`}>{formatPrice(mark)}</span>
        <span
          className={`oracle-tag ${state.market.live ? "oracle-tag--live" : "oracle-tag--sim"}`}
          title={state.market.live ? "Tracking the live Crypto.com index" : "No external feed — simulated walk"}
        >
          <span className="dot" /> {state.market.live ? "live oracle" : "sim"}
        </span>
      </div>
      <Stat label="24h" value={`${up ? "+" : ""}${changePct.toFixed(2)}%`} tone={up ? "pos" : "neg"} />
      <Stat label="Index" value={formatPrice(state.oracle.price)} />
      <Stat label="Funding / 1h" value={`${fundingPct >= 0 ? "+" : ""}${fundingPct.toFixed(3)}%`} tone={fundingPct >= 0 ? "pos" : "neg"} />
      <Stat label="Open interest" value={formatUsd(oi, 0)} />
      <Stat label="Max leverage" value={`${state.market.maxLeverage}×`} />
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="statsbar__stat">
      <span className="statsbar__label">{label}</span>
      <span className={`statsbar__value ${tone ?? ""}`}>{value}</span>
    </div>
  );
}
