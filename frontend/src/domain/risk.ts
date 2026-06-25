// Pure pre-trade risk math, mirroring the protocol's fixed-point conventions and
// the mock client's position formulas. Kept here (not inline in components) so it
// is unit-testable without a DOM and reusable across the ticket preview and any
// future risk surfaces. All values are scaled bigints; no floats in money math.

import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE, type Position, type Side } from "./types";

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

/// Liquidation buffer (in basis points of entry) IMPLIED by the margin model: a
/// position is liquidated once its loss eats the gap between the initial margin it
/// was opened with and the maintenance margin it must keep. Deriving it from the
/// market's own ratios — rather than a magic constant — keeps the displayed liq
/// price financially consistent with the advertised leverage/maintenance, and is
/// the single source of truth shared by the preview and the mock client's fills.
export function liqBufferBp(imr: number, mmr: number): bigint {
  const bp = Math.round((imr - mmr) * 10_000);
  return BigInt(bp > 0 ? bp : 0);
}

/// Liquidation price for a position entered at `entry`. Long liquidates below
/// entry, short above, by the margin-implied buffer.
export function liquidationPrice(entry: bigint, long: boolean, imr: number, mmr: number): bigint {
  const delta = (entry * liqBufferBp(imr, mmr)) / 10_000n;
  return long ? entry - delta : entry + delta;
}

/// Compute the pre-trade risk of opening `size` at `mark` on `side` under a market
/// with initial-margin ratio `imr` (e.g. 0.1 for 10×). Returns zeroed risk for a
/// non-positive size or mark so callers can render nothing.
export interface AccountSummary {
  /// Free, withdrawable settled balance (quote).
  freeBalance: bigint;
  /// Margin locked in open positions (Σ collateral, quote).
  usedMargin: bigint;
  /// Σ unrealized PnL across positions (quote).
  upnl: bigint;
  /// Account equity = freeBalance + usedMargin + uPnL (quote).
  equity: bigint;
  /// Σ |size| · mark notional (quote). Exact for a single-market account; uses the
  /// supplied `mark` for every position, so cross-market totals are approximate.
  notional: bigint;
  /// Account-wide leverage = notional / equity (0 when flat or non-positive equity).
  leverage: number;
}

/// Aggregate a free balance and open positions into an account-health summary.
/// `freeBalance`, `collateral`, and `unrealizedPnl` are used verbatim (exact); only
/// notional/leverage depend on `mark`.
export function accountSummary(positions: Position[], freeBalance: bigint, mark: bigint): AccountSummary {
  let usedMargin = 0n;
  let upnl = 0n;
  let notional = 0n;
  for (const p of positions) {
    usedMargin += p.collateral;
    upnl += p.unrealizedPnl;
    const abs = p.size < 0n ? -p.size : p.size;
    notional += (abs * mark) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
  }
  const equity = freeBalance + usedMargin + upnl;
  const leverage = equity > 0n ? Number(notional) / Number(equity) : 0;
  return { freeBalance, usedMargin, upnl, equity, notional, leverage };
}

/// Maximum openable position size (base, size-scaled) given a free `settledBalance`
/// (quote), the current `mark`, and the market's `maxLeverage`. Inverts the notional
/// relation: buying power = balance × leverage, max size = buyingPower / mark.
export function maxOrderSize(settledBalance: bigint, mark: bigint, maxLeverage: number): bigint {
  if (mark <= 0n || maxLeverage <= 0 || settledBalance <= 0n) return 0n;
  const buyingPower = settledBalance * BigInt(Math.round(maxLeverage));
  return (buyingPower * NOTIONAL_DIV) / mark;
}

export function orderRisk(size: bigint, mark: bigint, side: Side, imr: number, mmr: number): OrderRisk {
  if (size <= 0n || mark <= 0n) {
    return { notional: 0n, margin: 0n, leverage: 0, liquidationPrice: 0n };
  }
  const notional = (size * mark) / NOTIONAL_DIV;
  const imrBp = BigInt(Math.round(imr * 10_000));
  const margin = (notional * imrBp) / 10_000n;
  const leverage = imr > 0 ? 1 / imr : 0;
  return { notional, margin, leverage, liquidationPrice: liquidationPrice(mark, side === "Buy", imr, mmr) };
}
