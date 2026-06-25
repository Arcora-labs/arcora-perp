import { useEffect, useState } from "react";
import { useStore } from "../store";
import { formatPrice, formatSize, formatUsd, parsePrice, parseSize } from "../domain/format";
import { maxOrderSize, orderRisk } from "../domain/risk";
import type { OrderInput, Side, TimeInForce } from "../domain/types";

const TIFS: TimeInForce[] = ["Gtc", "Ioc", "Fok", "PostOnly"];

/// Pre-trade preview: notional, required initial margin, resulting leverage, and
/// an estimated liquidation price — matching the values the position will show once
/// it fills, so the trader sees the risk before committing. Math lives in
/// `domain/risk` (pure + unit-tested).
function OrderPreview({ size, mark, side, imr }: { size: bigint; mark: bigint; side: Side; imr: number }) {
  if (size <= 0n || mark <= 0n) return null;
  const r = orderRisk(size, mark, side, imr);
  return (
    <dl className="preview">
      <div className="preview__row">
        <dt>Notional</dt>
        <dd className="mono">{formatUsd(r.notional)}</dd>
      </div>
      <div className="preview__row">
        <dt>Margin required</dt>
        <dd className="mono">{formatUsd(r.margin)}</dd>
      </div>
      <div className="preview__row">
        <dt>Leverage</dt>
        <dd className="mono">{r.leverage.toFixed(1)}×</dd>
      </div>
      <div className="preview__row">
        <dt>Est. liquidation</dt>
        <dd className="mono">{formatPrice(r.liquidationPrice)}</dd>
      </div>
    </dl>
  );
}

export function OrderTicket() {
  const { client, state, prefillPrice, setPrefillPrice } = useStore();
  const [side, setSide] = useState<Side>("Buy");
  const [sizeStr, setSizeStr] = useState("0.10");
  const [priceStr, setPriceStr] = useState("");

  // adopt a price clicked in the order book, then clear the signal
  useEffect(() => {
    if (prefillPrice !== null) {
      setPriceStr(formatPrice(prefillPrice));
      setPrefillPrice(null);
    }
  }, [prefillPrice, setPrefillPrice]);
  const [tif, setTif] = useState<TimeInForce>("Gtc");
  const [reduceOnly, setReduceOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const closeOnly = state.mode === "CloseOnly";
  // preview inputs: parsed size, and the entry estimate (limit price, else mark)
  const previewSize = parseSize(sizeStr) ?? 0n;
  const parsedPrice = priceStr.trim() === "" ? null : parsePrice(priceStr);
  const previewMark = parsedPrice && parsedPrice > 0n ? parsedPrice : state.oracle.price;
  // buying power for the quick-size buttons (free balance × max leverage / mark)
  const maxSize = maxOrderSize(state.account.settledBalance, previewMark, state.market.maxLeverage);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const size = parseSize(sizeStr);
    if (size === null || size <= 0n) return setError("Enter a valid size.");
    const isMarket = priceStr.trim() === "";
    const limitPrice = isMarket ? 0n : parsePrice(priceStr);
    if (!isMarket && (limitPrice === null || limitPrice <= 0n)) return setError("Enter a valid price.");
    const input: OrderInput = {
      marketId: state.market.id,
      side,
      size,
      limitPrice: limitPrice ?? 0n,
      tif: isMarket ? "Ioc" : tif,
      reduceOnly,
    };
    setPending(true);
    try {
      await client.placeOrder(input);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="card order-ticket" onSubmit={submit}>
      <h3 className="card__title">{state.market.symbol}</h3>

      <div className="seg">
        <button
          type="button"
          className={`seg__btn ${side === "Buy" ? "is-active seg__btn--buy" : ""}`}
          aria-pressed={side === "Buy"}
          onClick={() => setSide("Buy")}
        >
          Buy / Long
        </button>
        <button
          type="button"
          className={`seg__btn ${side === "Sell" ? "is-active seg__btn--sell" : ""}`}
          aria-pressed={side === "Sell"}
          onClick={() => setSide("Sell")}
        >
          Sell / Short
        </button>
      </div>

      <label className="field">
        <span className="field__label">Size (BTC)</span>
        <input className="field__input" value={sizeStr} onChange={(e) => setSizeStr(e.target.value)} inputMode="decimal" />
      </label>

      <div className="quicksize" role="group" aria-label="Size as a fraction of buying power">
        {([25, 50, 75, 100] as const).map((pct) => (
          <button
            key={pct}
            type="button"
            className="quicksize__btn"
            disabled={maxSize <= 0n}
            onClick={() => setSizeStr(formatSize((maxSize * BigInt(pct)) / 100n))}
          >
            {pct === 100 ? "Max" : `${pct}%`}
          </button>
        ))}
      </div>

      <label className="field">
        <span className="field__label">Limit price (blank = market)</span>
        <input
          className="field__input"
          value={priceStr}
          onChange={(e) => setPriceStr(e.target.value)}
          placeholder="market"
          inputMode="decimal"
        />
      </label>

      <label className="field">
        <span className="field__label">Time in force</span>
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
        <span>Reduce-only</span>
      </label>

      {!reduceOnly && (
        <OrderPreview size={previewSize} mark={previewMark} side={side} imr={state.market.initialMarginRatio} />
      )}

      {closeOnly && (
        <p className="notice notice--warn">Close-only mode: opening/increasing is blocked (§6).</p>
      )}
      {error && <p className="notice notice--error">{error}</p>}

      <button className={`btn btn--${side === "Buy" ? "buy" : "sell"}`} disabled={pending}>
        {pending ? "Submitting…" : `${side} ${state.market.symbol}`}
      </button>
      <p className="order-ticket__foot">
        Your order returns a signed receipt (ACCEPTED). It is binding only when SETTLED.
      </p>
    </form>
  );
}
