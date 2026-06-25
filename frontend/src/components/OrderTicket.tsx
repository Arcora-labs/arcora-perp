import { useState } from "react";
import { useStore } from "../store";
import { parsePrice, parseSize } from "../domain/format";
import type { OrderInput, Side, TimeInForce } from "../domain/types";

const TIFS: TimeInForce[] = ["Gtc", "Ioc", "Fok", "PostOnly"];

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
