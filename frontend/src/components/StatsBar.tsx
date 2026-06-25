import { useStore } from "../store";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "../domain/types";
import { formatPrice, formatUsd } from "../domain/format";

/// Live market stats strip. Values are mock-derived; the design restyles the
/// presentation, the data stays.
export function StatsBar() {
  const { state } = useStore();
  const mark = state.oracle.price;

  // 24h change vs a $100k baseline (mock reference)
  const baseline = 100_000n * PRICE_SCALE;
  const changeBps = Number(((mark - baseline) * 10_000n) / baseline) / 100;

  // funding rate (mock): premium of mark over baseline, clamped
  const fundingBps = Math.max(-5, Math.min(5, changeBps / 10));

  // open interest = Σ |size| · mark
  const oi = state.account.positions.reduce((acc, p) => {
    const abs = p.size < 0n ? -p.size : p.size;
    return acc + (abs * mark) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
  }, 0n);

  const up = changeBps >= 0;

  return (
    <div className="statsbar">
      <div className="statsbar__market">
        <span className="statsbar__symbol">{state.market.symbol}</span>
        <span className={`statsbar__price ${up ? "pos" : "neg"}`}>{formatPrice(mark)}</span>
      </div>
      <Stat label="24h" value={`${up ? "+" : ""}${changeBps.toFixed(2)}%`} tone={up ? "pos" : "neg"} />
      <Stat label="Index" value={formatPrice(state.oracle.price)} />
      <Stat label="Funding / 1h" value={`${fundingBps >= 0 ? "+" : ""}${fundingBps.toFixed(3)}%`} tone={fundingBps >= 0 ? "pos" : "neg"} />
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
