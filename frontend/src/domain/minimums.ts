// Size minimums the protocol applies to orders, deposits and withdrawals.
//
// Two kinds, mirrored here so the UI can explain a refusal before the round trip:
//
//  - The initial-margin floor is part of the proven engine transition
//    (`perp-core::position::MIN_INITIAL_MARGIN`): every open position needs at
//    least $1 of initial margin.
//  - The order, deposit and withdrawal minimums are gateway/sequencer admission
//    policy. The gateway stays authoritative: these checks only predict its
//    answer, and an order it refuses for size is reported with the manifest
//    reject reason `BelowMinimumSize`.
//
// All values are quote-scaled bigints (micro-USD = USDC base units).

import { QUOTE_SCALE, type AccountState, type Side } from "./types";

/// Smallest initial margin an open position requires (engine rule): $1.
export const MIN_INITIAL_MARGIN = QUOTE_SCALE;

/// Smallest notional of an order that opens, grows or flips a position: $10.
/// Reduce-only orders and orders that only reduce a position are exempt.
export const MIN_ORDER_NOTIONAL = 10n * QUOTE_SCALE;

/// Smallest deposit the gateway issues a permit for: 10 USDC.
export const MIN_DEPOSIT = 10n * QUOTE_SCALE;

/// Smallest balance of a market's position entry (audit G1-1): 100 USDC. A market
/// held flat (no open position) with less is dust, which the gateway may exit to
/// your bound address to make room for a new entry; a withdrawal leaves at least
/// this much unless it takes the market's entire balance.
export const MIN_ENTRY_BALANCE = 100n * QUOTE_SCALE;

/// Smallest deposit into a market where you hold no balance, or less than
/// `MIN_ENTRY_BALANCE` with no open position: 100 USDC (it may open an entry).
export const MIN_ENTRY_DEPOSIT = MIN_ENTRY_BALANCE;

/// Smallest withdrawal: 10 USDC, unless it takes the entire free balance in its
/// market.
export const MIN_WITHDRAWAL = 10n * QUOTE_SCALE;

/// Does an order of `side`/`size` against a current signed position `positionSize`
/// add exposure: open from flat, grow the position, or flip it (even to a smaller
/// opposite position)? Mirrors `perp-core::position::Position::increases_exposure`.
/// A pure reduction or an exact close does not.
export function increasesExposure(positionSize: bigint, side: Side, size: bigint): boolean {
  if (size <= 0n) return false;
  const delta = side === "Buy" ? size : -size;
  if (positionSize === 0n) return true;
  if ((positionSize > 0n) === (delta > 0n)) return true;
  const after = positionSize + delta;
  return after !== 0n && (after > 0n) !== (positionSize > 0n);
}

/// The minimum-order refusal for an order, or null when it is allowed.
/// `notional` is the whole order's notional at the market's oracle price, never its
/// limit price: the gateway and the sequencer measure it that way.
export function orderMinimumError(notional: bigint, reduceOnly: boolean, addsExposure: boolean): string | null {
  if (reduceOnly || !addsExposure || notional >= MIN_ORDER_NOTIONAL) return null;
  return "Minimum order size is $10 of notional for an order that opens or increases a position. Reduce-only orders are exempt.";
}

/// Whether a deposit into `marketId` may open a position entry, so needs
/// `MIN_ENTRY_DEPOSIT`: the account holds no open position there and the market's
/// free balance (a flat market's whole balance) is below `MIN_ENTRY_BALANCE`.
/// Mirrors the gateway's `BELOW_ENTRY_MINIMUM` rule.
export function depositOpensEntry(account: AccountState, marketId: number): boolean {
  const open = account.positions.some((p) => p.marketId === marketId && p.size !== 0n);
  return !open && marketFreeBalance(account, marketId) < MIN_ENTRY_BALANCE;
}

/// The deposit-minimum refusal, or null when `amount` meets it. `opensEntry`
/// (`depositOpensEntry`) raises the minimum to the entry minimum.
export function depositMinimumError(amount: bigint, opensEntry = false): string | null {
  if (opensEntry && amount < MIN_ENTRY_DEPOSIT) {
    return "Minimum deposit into this market is 100 USDC: you hold no balance in it, or less than 100 USDC with no open position. A top-up of a market holding at least 100 USDC or an open position needs 10 USDC.";
  }
  return amount < MIN_DEPOSIT ? "Minimum deposit is 10 USDC." : null;
}

/// The withdrawal-minimum refusal, or null. A withdrawal below 10 USDC is allowed
/// only when it takes the entire free balance of the market it withdraws from:
/// pass that market's free balance (`marketFreeBalance`), not the account-wide one.
export function withdrawalMinimumError(amount: bigint, marketFree: bigint): string | null {
  if (amount >= MIN_WITHDRAWAL || amount === marketFree) return null;
  return "Minimum withdrawal is 10 USDC, unless you withdraw your entire free balance in the selected market.";
}

/// The entry-balance refusal for a withdrawal from a market held flat, or null: the
/// gateway accepts it only when it leaves at least `MIN_ENTRY_BALANCE` there or
/// takes the market's whole balance (`marketFree`, a flat market's whole balance).
/// With an open position (`openPosition`) the gateway alone judges it, against the
/// position's collateral, and its answer is shown as is.
export function withdrawalEntryBalanceError(amount: bigint, marketFree: bigint, openPosition: boolean): string | null {
  if (openPosition || amount === marketFree || marketFree - amount >= MIN_ENTRY_BALANCE) return null;
  return "A withdrawal must leave at least 100 USDC in the selected market, unless you withdraw its entire balance.";
}

/// The free balance a withdrawal from `marketId` takes from, which the gateway
/// judges the minimum's exception against: that market's own free balance when
/// the account reports one per market (0 for a market it does not list), else the
/// settled balance of a single-pool account (the demo mock).
export function marketFreeBalance(account: AccountState, marketId: number): bigint {
  if (account.marketFree === undefined) return account.settledBalance;
  return account.marketFree[marketId] ?? 0n;
}
