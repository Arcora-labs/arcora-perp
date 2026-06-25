import { useEffect, useRef, useState } from "react";
import { useStore } from "../store";
import { formatPrice } from "../domain/format";

/// A dependency-free SVG sparkline of the live index price. It buffers the oracle
/// ticks the mock client emits (the real client streams the same OracleQuote), so
/// it works unchanged against a real backend. Colour follows direction over the
/// window and is driven entirely by design tokens, so a reskin restyles it for free.
const CAP = 90; // ticks retained in the rolling window

export function PriceChart() {
  const { state } = useStore();
  const { oracle, selectedMarketId, market } = state;
  const [history, setHistory] = useState<bigint[]>([oracle.price]);
  const marketRef = useRef(selectedMarketId);

  useEffect(() => {
    if (marketRef.current !== selectedMarketId) {
      // switching markets resets the series so we never plot BTC ticks under ETH
      marketRef.current = selectedMarketId;
      setHistory([oracle.price]);
      return;
    }
    setHistory((h) => {
      if (h.length && h[h.length - 1] === oracle.price) return h;
      const next = [...h, oracle.price];
      return next.length > CAP ? next.slice(next.length - CAP) : next;
    });
  }, [oracle.price, selectedMarketId]);

  const W = 640;
  const H = 168;
  const PAD = 10;

  if (history.length < 2) {
    return (
      <div className="card chart">
        <div className="chart__head">
          <h3 className="card__title">{market.symbol} · index</h3>
          <span className="chart__price mono">{formatPrice(oracle.price)}</span>
        </div>
        <div className="chart__empty">collecting ticks…</div>
      </div>
    );
  }

  // geometry only — Number() is fine for pixel coords (never for money math).
  const nums = history.map(Number);
  const min = Math.min(...nums);
  const max = Math.max(...nums);
  const span = max - min || 1;
  const x = (i: number) => PAD + (i / (history.length - 1)) * (W - 2 * PAD);
  const y = (v: number) => PAD + (1 - (v - min) / span) * (H - 2 * PAD);
  const pts = nums.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  const line = `M ${pts.join(" L ")}`;
  const area = `${line} L ${x(history.length - 1).toFixed(1)},${H - PAD} L ${x(0).toFixed(1)},${H - PAD} Z`;
  const up = nums[nums.length - 1] >= nums[0];
  const tone = up ? "var(--buy)" : "var(--sell)";
  const changePct = ((nums[nums.length - 1] - nums[0]) / nums[0]) * 100;

  return (
    <div className="card chart">
      <div className="chart__head">
        <h3 className="card__title">{market.symbol} · index</h3>
        <span className={`chart__price mono ${up ? "pos" : "neg"}`}>
          {formatPrice(oracle.price)}
          <span className="chart__delta">
            {up ? "▲" : "▼"} {Math.abs(changePct).toFixed(2)}%
          </span>
        </span>
      </div>
      <svg
        className="chart__svg"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${market.symbol} index price over the last ${history.length} ticks`}
      >
        <defs>
          <linearGradient id="chartfill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={tone} stopOpacity="0.26" />
            <stop offset="1" stopColor={tone} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={area} fill="url(#chartfill)" />
        <path
          d={line}
          fill="none"
          stroke={tone}
          strokeWidth="1.6"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
        <circle cx={x(history.length - 1)} cy={y(nums[nums.length - 1])} r="2.8" fill={tone} />
      </svg>
      <div className="chart__axis mono">
        <span>{formatPrice(BigInt(Math.round(min)))}</span>
        <span className="chart__axislabel">last {history.length} ticks · mock feed</span>
        <span>{formatPrice(BigInt(Math.round(max)))}</span>
      </div>
    </div>
  );
}
