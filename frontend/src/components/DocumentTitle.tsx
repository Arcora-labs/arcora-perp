import { useEffect } from "react";
import { useStore } from "../store";
import { formatPrice } from "../domain/format";

/// Reflects the selected market + live index price in the browser tab title, so a
/// trader watching several tabs sees the price at a glance (a standard trading-UI
/// touch). Renders nothing.
export function DocumentTitle() {
  const { state } = useStore();
  const symbol = state.market.symbol;
  const price = formatPrice(state.oracle.price);
  useEffect(() => {
    document.title = `${symbol} ${price} · Arcora Perp`;
  }, [symbol, price]);
  return null;
}
