import { useStore } from "../store";
import { formatPrice, formatSize } from "../domain/format";
import { useFlash } from "../hooks/useFlash";
import type { BookLevel } from "../domain/types";

/// Cumulative depth, for the background depth bars.
function cumulative(levels: BookLevel[]): { level: BookLevel; cum: bigint }[] {
  let cum = 0n;
  return levels.map((level) => {
    cum += level.size;
    return { level, cum };
  });
}

export function OrderBook() {
  const { state, setPrefillPrice } = useStore();
  const { book, oracle } = state;
  const flash = useFlash(oracle.price);

  const bids = cumulative(book.bids);
  const asks = cumulative(book.asks);
  const max = [...bids, ...asks].reduce((m, r) => (r.cum > m ? r.cum : m), 1n);
  const pct = (cum: bigint) => Number((cum * 100n) / max);

  return (
    <div className="card orderbook">
      <div className="orderbook__head">
        <h3 className="card__title">Order book</h3>
        <span className="orderbook__cols">
          <span>Price</span>
          <span>Size</span>
        </span>
      </div>
      <div className="orderbook__rows">
        {[...asks].reverse().map((r, i) => (
          <Row key={`a${i}`} kind="ask" level={r.level} width={pct(r.cum)} onPick={setPrefillPrice} />
        ))}
        <div className="orderbook__mid">
          <span className={`orderbook__midprice ${flash}`}>{formatPrice(oracle.price)}</span>
          <span className="orderbook__midlabel">index price</span>
        </div>
        {bids.map((r, i) => (
          <Row key={`b${i}`} kind="bid" level={r.level} width={pct(r.cum)} onPick={setPrefillPrice} />
        ))}
      </div>
      <p className="orderbook__note">
        Dark book — resting orders are operator-blind in production. Depth here is the
        internal market-maker seed (§15).
      </p>
    </div>
  );
}

function Row({
  kind,
  level,
  width,
  onPick,
}: {
  kind: "bid" | "ask";
  level: BookLevel;
  width: number;
  onPick: (p: bigint) => void;
}) {
  return (
    <button
      type="button"
      className={`orderbook__row orderbook__row--${kind}`}
      onClick={() => onPick(level.price)}
      title={`Use ${formatPrice(level.price)} as limit price`}
    >
      <span className={`orderbook__depth orderbook__depth--${kind}`} style={{ width: `${width}%` }} />
      <span className="orderbook__price">{formatPrice(level.price)}</span>
      <span className="orderbook__size">{formatSize(level.size)}</span>
    </button>
  );
}
