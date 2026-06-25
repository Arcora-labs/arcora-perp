import { useState } from "react";
import { useStore } from "../store";
import { formatPrice, formatUsd, parsePrice, parseSize } from "../domain/format";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE, type OrderInput, type Side, type TimeInForce } from "../domain/types";

const TIFS: TimeInForce[] = ["Gtc", "Ioc", "Fok", "PostOnly"];

/// Pre-trade preview: notional, required initial margin, resulting leverage, and
/// an estimated liquidation price — computed in bigint and matching the values the
/// position will show once it fills, so the trader sees the risk before committing.
function OrderPreview({ size, mark, side, imr }: { size: bigint; mark: bigint; side: Side; imr: number }) {
  if (size <= 0n || mark <= 0n) return null;
  const DIV = (SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE;
  const notional = (size * mark) / DIV;
  const imrBp = BigInt(Math.round(imr * 10_000));
  const margin = (notional * imrBp) / 10_000n;
  const leverage = imr > 0 ? 1 / imr : 0;
  // est. liq mirrors the client's liqPrice (entry ± 9% buffer)
  const delta = (mark * 9n) / 100n;
  const liq = side === "Buy" ? mark - delta : mark + delta;
  return (
    <dl className="preview">
      <div className="preview__row">
        <dt>Notional</dt>
        <dd className="mono">{formatUsd(notional)}</dd>
      </div>
      <div className="preview__row">
        <dt>Margin required</dt>
        <dd className="mono">{formatUsd(margin)}</dd>
      </div>
      <div className="preview__row">
        <dt>Leverage</dt>
        <dd className="mono">{leverage.toFixed(1)}×</dd>
      </div>
      <div className="preview__row">
        <dt>Est. liquidation</dt>
        <dd className="mono">{formatPrice(liq)}</dd>
      </div>
    </dl>
  );
}

export function OrderTicket() {
  const { client, state } = useStore();
  const [side, setSide] = useState<Side>("Buy");
  const [sizeStr, setSizeStr] = useState("0.10");
  const [priceStr, setPriceStr] = useState("");
  const [tif, setTif] = useState<TimeInForce>("Gtc");
  const [reduceOnly, setReduceOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const closeOnly = state.mode === "CloseOnly";
  // preview inputs: parsed size, and the entry estimate (limit price, else mark)
  const previewSize = parseSize(sizeStr) ?? 0n;
  const parsedPrice = priceStr.trim() === "" ? null : parsePrice(priceStr);
  const previewMark = parsedPrice && parsedPrice > 0n ? parsedPrice : state.oracle.price;

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
