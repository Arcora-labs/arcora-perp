import { describe, it, expect } from "vitest";
import {
  MIN_DEPOSIT,
  MIN_INITIAL_MARGIN,
  MIN_ORDER_NOTIONAL,
  MIN_WITHDRAWAL,
  depositMinimumError,
  increasesExposure,
  marketFreeBalance,
  orderMinimumError,
  withdrawalMinimumError,
} from "./minimums";
import { QUOTE_SCALE, SIZE_SCALE } from "./types";

describe("minimum values", () => {
  it("are $1 initial margin, $10 order notional, 10 USDC deposit, 1 USDC withdrawal", () => {
    expect(MIN_INITIAL_MARGIN).toBe(1n * QUOTE_SCALE);
    expect(MIN_ORDER_NOTIONAL).toBe(10n * QUOTE_SCALE);
    expect(MIN_DEPOSIT).toBe(10n * QUOTE_SCALE);
    expect(MIN_WITHDRAWAL).toBe(1n * QUOTE_SCALE);
  });
});

describe("increasesExposure (mirrors perp-core Position::increases_exposure)", () => {
  const one = SIZE_SCALE;
  it("is true when opening from flat, either side", () => {
    expect(increasesExposure(0n, "Buy", one)).toBe(true);
    expect(increasesExposure(0n, "Sell", one)).toBe(true);
  });
  it("is true when growing in the same direction", () => {
    expect(increasesExposure(one, "Buy", one)).toBe(true);
    expect(increasesExposure(-one, "Sell", one)).toBe(true);
  });
  it("is false for a pure reduction or an exact close", () => {
    expect(increasesExposure(2n * one, "Sell", one)).toBe(false);
    expect(increasesExposure(one, "Sell", one)).toBe(false);
    expect(increasesExposure(-one, "Buy", one)).toBe(false);
  });
  it("is true for a flip, even to a smaller opposite position", () => {
    expect(increasesExposure(one, "Sell", one + 1n)).toBe(true);
    expect(increasesExposure(-2n * one, "Buy", 3n * one)).toBe(true);
  });
  it("is false for a non-positive size", () => {
    expect(increasesExposure(0n, "Buy", 0n)).toBe(false);
  });
});

describe("orderMinimumError", () => {
  it("refuses an exposure-adding order below $10 of notional", () => {
    expect(orderMinimumError(MIN_ORDER_NOTIONAL - 1n, false, true)).toMatch(/minimum order size is \$10/i);
  });
  it("accepts exactly $10 and above", () => {
    expect(orderMinimumError(MIN_ORDER_NOTIONAL, false, true)).toBeNull();
    expect(orderMinimumError(MIN_ORDER_NOTIONAL * 100n, false, true)).toBeNull();
  });
  it("exempts reduce-only orders and orders that only reduce", () => {
    expect(orderMinimumError(1n, true, true)).toBeNull();
    expect(orderMinimumError(1n, false, false)).toBeNull();
  });
});

describe("depositMinimumError", () => {
  it("refuses less than 10 USDC and accepts 10 USDC", () => {
    expect(depositMinimumError(MIN_DEPOSIT - 1n)).toMatch(/minimum deposit is 10 USDC/i);
    expect(depositMinimumError(MIN_DEPOSIT)).toBeNull();
  });
});

describe("withdrawalMinimumError", () => {
  const balance = 500n * QUOTE_SCALE;
  it("refuses less than 1 USDC that is not the whole free balance", () => {
    expect(withdrawalMinimumError(MIN_WITHDRAWAL - 1n, balance)).toMatch(/minimum withdrawal is 1 USDC/i);
  });
  it("accepts 1 USDC and above", () => {
    expect(withdrawalMinimumError(MIN_WITHDRAWAL, balance)).toBeNull();
  });
  it("accepts a sub-dollar amount that empties the free balance", () => {
    expect(withdrawalMinimumError(400_000n, 400_000n)).toBeNull();
  });
});

describe("marketFreeBalance (what the withdrawal minimum is judged against)", () => {
  const account = {
    settledBalance: 25_400_000n,
    marketFree: { 0: 25_000_000n, 1: 400_000n },
    positions: [],
  };
  it("is the selected market's own free balance, not the account-wide one", () => {
    expect(marketFreeBalance(account, 1)).toBe(400_000n);
    expect(marketFreeBalance(account, 0)).toBe(25_000_000n);
    expect(marketFreeBalance(account, 2)).toBe(0n);
  });
  it("lets the whole of one market leave below a dollar while another market holds more", () => {
    expect(withdrawalMinimumError(400_000n, marketFreeBalance(account, 1))).toBeNull();
  });
  it("refuses a sub-dollar amount equal to the account-wide balance but not to the market's", () => {
    const thin = { settledBalance: 700_000n, marketFree: { 0: 300_000n, 1: 400_000n }, positions: [] };
    expect(withdrawalMinimumError(700_000n, marketFreeBalance(thin, 1))).toMatch(/in the selected market/);
  });
  it("is the settled balance of a single-pool account (the demo mock)", () => {
    expect(marketFreeBalance({ settledBalance: 400_000n, positions: [] }, 1)).toBe(400_000n);
  });
});
