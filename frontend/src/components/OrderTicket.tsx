import { useEffect, useRef, useState } from "react";
import { Dialog } from "./Dialog";
import { IS_LIVE } from "../api/apiBase";
import { useStore } from "../store";
import { baseAsset, formatPrice, formatSize, formatUsd, parsePrice, parseSize } from "../domain/format";
import { maxOrderSize, orderRisk } from "../domain/risk";
import type { OrderInput, Side, TimeInForce } from "../domain/types";

const TIFS: TimeInForce[] = ["Gtc", "Ioc", "Fok", "PostOnly"];

/// Pre-trade preview: notional, required initial margin, resulting leverage, and
/// an estimated liquidation price — matching the values the position will show once
/// it fills, so the trader sees the risk before committing. Math lives in
/// `domain/risk` (pure + unit-tested).
function OrderPreview({ size, mark, side, imr, mmr, takerFeeBps }: { size: bigint; mark: bigint; side: Side; imr: number; mmr: number; takerFeeBps: number }) {
  if (size <= 0n || mark <= 0n) return null;
  const r = orderRisk(size, mark, side, imr, mmr);
  // a marketable order crosses the book and pays the taker fee on its notional
  // (audit Q4); a resting maker would instead earn the rebate.
  const takerFee = (r.notional * BigInt(takerFeeBps)) / 10_000n;
  return (
    <dl className="preview">
      <div className="preview__row">
        <dt>Notional</dt>
        <dd className="mono">{formatUsd(r.notional)}</dd>
      </div>
      <div className="preview__row">
        <dt>Taker fee ({(takerFeeBps / 100).toFixed(2)}%)</dt>
        <dd className="mono">{formatUsd(takerFee)}</dd>
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

  const [review, setReview] = useState<{ input: OrderInput; mark: bigint; symbol: string } | null>(null);
  const [accepted, setAccepted] = useState<string | null>(null);
  const submitting = useRef(false);
  const lastMarket = useRef(state.selectedMarketId);
  useEffect(() => {
    if (lastMarket.current !== state.selectedMarketId) {
      lastMarket.current = state.selectedMarketId;
      setPriceStr(""); setError(null); setAccepted(null); setReview(null);
    }
  }, [state.selectedMarketId]);
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
    if (state.accountUnavailable) return setError("Your account could not be read. Reload before placing an order.");
    if (closeOnly && !reduceOnly) return setError("Close-only mode: use reduce-only to decrease an existing position.");
    if (IS_LIVE && (state.oracle.price <= 0n || Date.now() - state.oracle.publishTimeMs > 30_000)) return setError("Price data is stale. Check Health and wait for a fresh price.");
    setAccepted(null);
    setReview({ input, mark: previewMark, symbol: state.market.symbol });
  }

  async function confirm() {
    if (!review || submitting.current) return;
    const current = client.getState();
    if (current.selectedMarketId !== review.input.marketId || current.accountUnavailable) {
      setReview(null); setError("Market or account changed. Review the order again."); return;
    }
    if (current.mode === "CloseOnly" && !review.input.reduceOnly) {
      setReview(null); setError("Close-only mode: this order can no longer be submitted."); return;
    }
    if (IS_LIVE && (current.oracle.price <= 0n || Date.now() - current.oracle.publishTimeMs > 30_000)) {
      setReview(null); setError("Price data is stale. Review the order again after it updates."); return;
    }
    submitting.current = true; setPending(true); setError(null);
    try {
      const receipt = await client.placeOrder(review.input);
      setAccepted(`Order accepted · receipt #${receipt.seqNo}. Follow its execution and settlement below.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      submitting.current = false; setPending(false); setReview(null);
    }
  }

  return (
    <form className="card order-ticket" onSubmit={submit}>
      <h3 className="card__title">Make your move</h3>

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

      <div className="ticket-types" role="group" aria-label="Order type">
        <button type="button" aria-pressed={!priceStr.trim()} onClick={() => setPriceStr("")}>Market</button>
        <button type="button" aria-pressed={!!priceStr.trim()} onClick={() => setPriceStr(formatPrice(state.oracle.price))}>Limit</button>
      </div>
      <p className="ticket-balance"><span>Available</span><strong>{state.accountUnavailable ? "Unreadable" : formatUsd(state.account.settledBalance)} <small>USDC</small></strong></p>
      <label className="field">
        <span className="field__label">Size ({baseAsset(state.market.symbol)})</span>
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
        <select className="field__input" value={priceStr.trim() ? tif : "Ioc"} disabled={!priceStr.trim()} onChange={(e) => setTif(e.target.value as TimeInForce)}>
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
        <OrderPreview size={previewSize} mark={previewMark} side={side} imr={state.market.initialMarginRatio} mmr={state.market.maintenanceMarginRatio} takerFeeBps={state.market.takerFeeBps} />
      )}

      {closeOnly && (
        <p className="notice notice--warn">Close-only mode: opening/increasing is blocked (§6).</p>
      )}
      {error && <p className="notice notice--error" role="alert">{error}</p>}
      {accepted && <p className="notice notice--ok" role="status">{accepted}</p>}

      <button className={`btn btn--${side === "Buy" ? "buy" : "sell"}`} disabled={pending}>
        {pending ? "Submitting…" : `Preview ${side.toLowerCase()} ${state.market.symbol}`}
      </button>
      <p className="order-ticket__foot">
        Review before submitting. Acceptance and matching are provisional; only settlement establishes binding finality.
      </p>
      {review && <Dialog title={`Review ${review.input.side === "Buy" ? "long" : "short"} order`} onClose={() => setReview(null)} busy={pending}>
        <p className="muted small">{IS_LIVE ? "Test gateway · Base Sepolia" : "Browser simulation · no real funds"}</p>
        <dl className="review-rows">
          <div><dt>Market</dt><dd>{review.symbol}</dd></div>
          <div><dt>Direction</dt><dd>{review.input.side === "Buy" ? "Buy / Long" : "Sell / Short"}</dd></div>
          <div><dt>Quantity</dt><dd>{formatSize(review.input.size)} {baseAsset(review.symbol)}</dd></div>
          <div><dt>Order type</dt><dd>{review.input.limitPrice === 0n ? "Market · IOC" : `Limit · ${review.input.tif}`}</dd></div>
          <div><dt>{review.input.limitPrice === 0n ? "Reference price" : "Limit price"}</dt><dd>{formatPrice(review.mark)}</dd></div>
          <div><dt>Reduce-only</dt><dd>{review.input.reduceOnly ? "Yes" : "No"}</dd></div>
        </dl>
        {!review.input.reduceOnly && <OrderPreview size={review.input.size} mark={review.mark} side={review.input.side} imr={state.market.initialMarginRatio} mmr={state.market.maintenanceMarginRatio} takerFeeBps={state.market.takerFeeBps} />}
        <p className="notice notice--warn">Execution price and fees can change. Liquidation is an estimate; funding and price movement can change your risk.</p>
        <button type="button" className="btn btn--buy" disabled={pending} onClick={() => void confirm()}>{pending ? "Submitting…" : IS_LIVE ? "Confirm order" : "Confirm demo order"}</button>
      </Dialog>}
    </form>
  );
}
