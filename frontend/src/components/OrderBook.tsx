import { useStore } from "../store";
import { formatPrice, formatSize } from "../domain/format";

export function OrderBook() {
  const { state } = useStore();
  const { book, oracle } = state;
  return (
    <div className="card orderbook">
      <h3 className="card__title">Order book</h3>
      <div className="orderbook__rows">
        {[...book.asks].reverse().map((l, i) => (
          <div className="orderbook__row orderbook__row--ask" key={`a${i}`}>
            <span className="orderbook__price">{formatPrice(l.price)}</span>
            <span className="orderbook__size">{formatSize(l.size)}</span>
          </div>
        ))}
        <div className="orderbook__mid">
          <span>Index</span>
          <strong>{formatPrice(oracle.price)}</strong>
        </div>
        {book.bids.map((l, i) => (
          <div className="orderbook__row orderbook__row--bid" key={`b${i}`}>
            <span className="orderbook__price">{formatPrice(l.price)}</span>
            <span className="orderbook__size">{formatSize(l.size)}</span>
          </div>
        ))}
      </div>
      <p className="orderbook__note">
        Dark book: resting orders are operator-blind in production. Depth shown here is
        the internal market-maker seed (§15).
      </p>
    </div>
  );
}
