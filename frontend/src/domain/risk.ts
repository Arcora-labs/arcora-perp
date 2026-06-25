// Pure pre-trade risk math, mirroring the protocol's fixed-point conventions and
// the mock client's position formulas. Kept here (not inline in components) so it
// is unit-testable without a DOM and reusable across the ticket preview and any
// future risk surfaces. All values are scaled bigints; no floats in money math.

import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE, type Side } from "./types";

export interface OrderRisk {
  /// Position notional at `mark`, quote-scaled (micro-USD).
  notional: bigint;
  /// Required initial margin, quote-scaled.
  margin: bigint;
  /// Resulting leverage (notional / margin), as a plain number for display.
  leverage: number;
  /// Estimated liquidation price, price-scaled (matches the client's liq formula).
  liquidationPrice: bigint;
}

/// The scale divisor that turns a raw `size * price` product into quote units.
/// Matches `perp-core::fixed::notional_quote`.
const NOTIONAL_DIV = (SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE;

/// Liquidation cushion used by the mock client (entry ± 9%). Centralized so the
/// preview and any health display stay consistent with the post-fill value.
export const LIQ_BUFFER_PCT = 9n;

/// Compute the pre-trade risk of opening `size` at `mark` on `side` under a market
/// with initial-margin ratio `imr` (e.g. 0.1 for 10×). Returns zeroed risk for a
/// non-positive size or mark so callers can render nothing.
export function orderRisk(size: bigint, mark: bigint, side: Side, imr: number): OrderRisk {
  if (size <= 0n || mark <= 0n) {
    return { notional: 0n, margin: 0n, leverage: 0, liquidationPrice: 0n };
  }
  const notional = (size * mark) / NOTIONAL_DIV;
  const imrBp = BigInt(Math.round(imr * 10_000));
  const margin = (notional * imrBp) / 10_000n;
  const leverage = imr > 0 ? 1 / imr : 0;
  const delta = (mark * LIQ_BUFFER_PCT) / 100n;
  const liquidationPrice = side === "Buy" ? mark - delta : mark + delta;
  return { notional, margin, leverage, liquidationPrice };
}
