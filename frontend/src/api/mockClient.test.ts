import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { MockDarkPerpClient } from "./mockClient";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "../domain/types";

// The mock advances finality on timers (MATCH at 900ms); drive it deterministically.
const MATCH_MS = 900;

function pos(c: MockDarkPerpClient, marketId = 0) {
  return c.getState().account.positions.find((p) => p.marketId === marketId);
}

describe("MockDarkPerpClient position lifecycle", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("opens a long with entry = fill price and 10% initial margin", async () => {
    const c = new MockDarkPerpClient();
    await c.placeOrder({
      marketId: 0,
      side: "Buy",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    const p = pos(c)!;
    expect(p.size).toBe(SIZE_SCALE);
    expect(p.entryPrice).toBe(100_000n * PRICE_SCALE);
    // 1 BTC @ $100k, 10× max leverage ⇒ $10,000 initial margin
    expect(p.collateral).toBe(10_000n * QUOTE_SCALE);
  });

  it("resets entry price and exposure when a fill FLIPS the position", async () => {
    const c = new MockDarkPerpClient();
    await c.placeOrder({
      marketId: 0,
      side: "Buy",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    // sell 2 BTC @ $90k against a +1 long → flips to short 1
    await c.placeOrder({
      marketId: 0,
      side: "Sell",
      size: 2n * SIZE_SCALE,
      limitPrice: 90_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    const p = pos(c)!;
    expect(p.size).toBe(-SIZE_SCALE); // now short 1
    // entry must be the NEW fill price, not the stale long entry
    expect(p.entryPrice).toBe(90_000n * PRICE_SCALE);
    // liq line for a short sits ABOVE entry
    expect(p.liquidationPrice > p.entryPrice).toBe(true);
    // margin re-derived against the new 1-BTC exposure at $90k ⇒ $9,000
    expect(p.collateral).toBe(9_000n * QUOTE_SCALE);
  });

  it("closes the position to flat when reduced to zero", async () => {
    const c = new MockDarkPerpClient();
    await c.placeOrder({
      marketId: 0,
      side: "Buy",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    await c.placeOrder({
      marketId: 0,
      side: "Sell",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: true,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    expect(pos(c)).toBeUndefined();
  });

  it("blocks opening in close-only mode but allows reducing", async () => {
    const c = new MockDarkPerpClient();
    await c.placeOrder({
      marketId: 0,
      side: "Buy",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    c.triggerCloseOnly();
    // opening (increasing the long) is blocked
    await expect(
      c.placeOrder({
        marketId: 0,
        side: "Buy",
        size: SIZE_SCALE,
        limitPrice: 100_000n * PRICE_SCALE,
        tif: "Gtc",
        reduceOnly: false,
      }),
    ).rejects.toThrow(/close-only/i);
    // reducing the long is still allowed
    await expect(c.closePosition(0)).resolves.toBeUndefined();
  });

  it("enforces reduce-only: rejects orders that would increase, flip, or have nothing to reduce", async () => {
    const c = new MockDarkPerpClient();
    // reduce-only with no position → nothing to reduce
    await expect(
      c.placeOrder({ marketId: 0, side: "Sell", size: SIZE_SCALE, limitPrice: 0n, tif: "Ioc", reduceOnly: true }),
    ).rejects.toThrow(/reduce-only/i);

    // open a long 1
    await c.placeOrder({
      marketId: 0,
      side: "Buy",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);

    // reduce-only BUY (same side → would increase the long) → rejected
    await expect(
      c.placeOrder({ marketId: 0, side: "Buy", size: SIZE_SCALE, limitPrice: 0n, tif: "Ioc", reduceOnly: true }),
    ).rejects.toThrow(/reduce-only/i);
    // reduce-only SELL 2 (would flip long-1 → short-1) → rejected
    await expect(
      c.placeOrder({ marketId: 0, side: "Sell", size: 2n * SIZE_SCALE, limitPrice: 0n, tif: "Ioc", reduceOnly: true }),
    ).rejects.toThrow(/reduce-only/i);
    // reduce-only SELL 0.5 (pure reduce) → allowed
    await expect(
      c.placeOrder({ marketId: 0, side: "Sell", size: SIZE_SCALE / 2n, limitPrice: 0n, tif: "Ioc", reduceOnly: true }),
    ).resolves.toBeDefined();
    // position is still open and reduced — closePosition (exact close) still works
    await expect(c.closePosition(0)).resolves.toBeUndefined();
  });

  it("blocks a FLIP (oversized opposite order) in close-only mode (§6)", async () => {
    const c = new MockDarkPerpClient();
    await c.placeOrder({
      marketId: 0,
      side: "Buy",
      size: SIZE_SCALE,
      limitPrice: 100_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: false,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    c.triggerCloseOnly();
    // a long-1 holder selling 2 would flip to short-1: that OPENS fresh exposure on
    // the other side, so close-only must reject it (it is not a pure reduce).
    await expect(
      c.placeOrder({
        marketId: 0,
        side: "Sell",
        size: 2n * SIZE_SCALE,
        limitPrice: 100_000n * PRICE_SCALE,
        tif: "Gtc",
        reduceOnly: false,
      }),
    ).rejects.toThrow(/close-only/i);
    // but a partial reduce (sell 0.5 of the long-1) is still allowed
    await expect(
      c.placeOrder({
        marketId: 0,
        side: "Sell",
        size: SIZE_SCALE / 2n,
        limitPrice: 100_000n * PRICE_SCALE,
        tif: "Ioc",
        reduceOnly: true,
      }),
    ).resolves.toBeDefined();
  });
});

describe("MockDarkPerpClient withdrawals", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("rejects withdrawing more than the settled balance", async () => {
    const c = new MockDarkPerpClient();
    const bal = c.getState().account.settledBalance;
    await expect(c.requestWithdrawal(bal + 1n)).rejects.toThrow(/exceeds SETTLED/i);
    await expect(c.requestWithdrawal(0n)).rejects.toThrow(/positive/i);
  });
});
