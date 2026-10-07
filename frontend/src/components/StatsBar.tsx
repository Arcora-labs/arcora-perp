import { useStore } from "../store";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "../domain/types";
import { formatPrice, formatUsd } from "../domain/format";
import { useFlash } from "../hooks/useFlash";

/// Live market stats strip. Values are mock-derived; the design restyles the
/// presentation, the data stays.
export function StatsBar({ onSelect }: { onSelect?: () => void }) {
  const { state } = useStore();
  const mark = state.oracle.price;
  const flash = useFlash(mark);

  // 24h change vs the market's reference price (the real 24h open once the live
  // oracle reports it, else the session seed).
  const baseline = state.market.referencePrice > 0n ? state.market.referencePrice : mark;
  const changePct = Number(((mark - baseline) * 10_000n) / (baseline || 1n)) / 100;

  // YOUR notional in this market = Σ |size| · mark over your positions. (True
  // market-wide open interest needs every trader's positions, which a single-user
  // mock doesn't have — so label this honestly as the user's own exposure.)
  const myNotional = state.account.positions
    .filter((p) => p.marketId === state.selectedMarketId)
    .reduce((acc, p) => {
      const abs = p.size < 0n ? -p.size : p.size;
      return acc + (abs * mark) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
    }, 0n);

  const up = changePct >= 0;

  return (
    <div className="statsbar">
      <div className="statsbar__market">
        <button className="statsbar__symbol" onClick={onSelect} aria-label="Select market">{state.market.symbol} <span aria-hidden>⌄</span></button>
        <span className={`statsbar__price ${up ? "pos" : "neg"} ${flash}`}>{formatPrice(mark)}</span>
        <span
          className={`oracle-tag ${state.market.live ? "oracle-tag--live" : "oracle-tag--sim"}`}
          title={state.market.live ? "Tracking the live Crypto.com index" : "No external feed — simulated walk"}
        >
          <span className="dot" /> {state.market.live ? "live oracle" : "sim"}
        </span>
      </div>
      <Stat label="Since reference" value={`${up ? "+" : ""}${changePct.toFixed(2)}%`} tone={up ? "pos" : "neg"} />
      <Stat label="Index" value={formatPrice(state.oracle.price)} />
      <Stat label="Funding rate" value="Not published" />
      {/* SEC-025-E1 fix-wave-2 G2: `accountUnavailable` means the account is
          an EMPTY PLACEHOLDER (read failure, realClient emit()) — "$0" here
          would present the placeholder as the caller's actual exposure. */}
      <Stat
        label="Your notional"
        value={state.accountUnavailable ? "unreadable" : formatUsd(myNotional, 0)}
        tone={state.accountUnavailable ? "neg" : undefined}
      />
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
