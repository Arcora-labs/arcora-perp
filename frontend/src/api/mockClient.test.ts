import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { MockDarkPerpClient } from "./mockClient";
import type { OrderEvent } from "./client";
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

  it("resumeNormal clears close-only and lets opening resume (toggle, not a dead-end)", async () => {
    const c = new MockDarkPerpClient();
    c.triggerCloseOnly();
    expect(c.getState().mode).toBe("CloseOnly");
    await expect(
      c.placeOrder({ marketId: 0, side: "Buy", size: SIZE_SCALE, limitPrice: 100_000n * PRICE_SCALE, tif: "Gtc", reduceOnly: false }),
    ).rejects.toThrow(/close-only/i);
    c.resumeNormal();
    expect(c.getState().mode).toBe("Normal");
    // opening works again
    await expect(
      c.placeOrder({ marketId: 0, side: "Buy", size: SIZE_SCALE, limitPrice: 100_000n * PRICE_SCALE, tif: "Gtc", reduceOnly: false }),
    ).resolves.toBeDefined();
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

describe("MockDarkPerpClient collateral accounting", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const openLong = async (c: MockDarkPerpClient, px: bigint, size = SIZE_SCALE) => {
    await c.placeOrder({ marketId: 0, side: "Buy", size, limitPrice: px, tif: "Gtc", reduceOnly: false });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
  };

  it("locks margin out of the free balance when a position opens", async () => {
    const c = new MockDarkPerpClient();
    const before = c.getState().account.settledBalance; // 25k
    await openLong(c, 100_000n * PRICE_SCALE); // 1 BTC @ $100k ⇒ $10k margin
    // free balance dropped by exactly the locked margin
    expect(c.getState().account.settledBalance).toBe(before - 10_000n * QUOTE_SCALE);
    expect(pos(c)!.collateral).toBe(10_000n * QUOTE_SCALE);
  });

  it("releases margin AND realizes PnL back to the balance on close", async () => {
    const c = new MockDarkPerpClient();
    const before = c.getState().account.settledBalance; // 25k
    await openLong(c, 100_000n * PRICE_SCALE); // free → 15k, $10k margin locked
    // close the long at $110k (a +$10k gain on 1 BTC) via an explicit reduce
    await c.placeOrder({
      marketId: 0,
      side: "Sell",
      size: SIZE_SCALE,
      limitPrice: 110_000n * PRICE_SCALE,
      tif: "Gtc",
      reduceOnly: true,
    });
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    expect(pos(c)).toBeUndefined();
    // balance = initial 25k + 10k realized profit (margin returned, gain realized)
    expect(c.getState().account.settledBalance).toBe(before + 10_000n * QUOTE_SCALE);
  });

  it("does not let a withdrawal drain margin backing an open position", async () => {
    const c = new MockDarkPerpClient();
    await openLong(c, 100_000n * PRICE_SCALE); // free balance now 15k, 10k locked
    // 20k exceeds the 15k free balance (the other 10k backs the position)
    await expect(c.requestWithdrawal(20_000n * QUOTE_SCALE)).rejects.toThrow(/exceeds SETTLED/i);
    // withdrawing exactly the free balance is fine
    await expect(c.requestWithdrawal(15_000n * QUOTE_SCALE)).resolves.toBeUndefined();
  });

  it("rejects an open that exceeds free margin (buying-power guard)", async () => {
    const c = new MockDarkPerpClient();
    // 3 BTC @ $100k ⇒ $30k margin > $25k free balance
    await expect(
      c.placeOrder({ marketId: 0, side: "Buy", size: 3n * SIZE_SCALE, limitPrice: 100_000n * PRICE_SCALE, tif: "Gtc", reduceOnly: false }),
    ).rejects.toThrow(/insufficient free margin/i);
  });

  it("counts in-flight (still-ACCEPTED) opens against buying power — no double-spend", async () => {
    const c = new MockDarkPerpClient();
    const open = (size: bigint) =>
      c.placeOrder({ marketId: 0, side: "Buy", size, limitPrice: 100_000n * PRICE_SCALE, tif: "Gtc", reduceOnly: false });
    // first 1.5 BTC open ($15k margin) is accepted but NOT yet matched (margin locks
    // at MATCH, 900ms out). A second 1.5 BTC open ($15k) would total $30k > $25k free.
    await open(15n * SIZE_SCALE / 10n);
    await expect(open(15n * SIZE_SCALE / 10n)).rejects.toThrow(/insufficient free margin/i);
    // and once the first matches and its margin is truly locked, the picture is
    // consistent: free balance dropped by exactly the first order's $15k.
    await vi.advanceTimersByTimeAsync(MATCH_MS);
    expect(c.getState().account.settledBalance).toBe(25_000n * QUOTE_SCALE - 15_000n * QUOTE_SCALE);
  });
});

describe("MockDarkPerpClient collateral conservation through a journey", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  // The frontend analog of perp-core's conservation_holds: across an arbitrary
  // sequence of ops, free balance + locked margin must only change by deposits,
  // withdrawals, and REALIZED PnL — never leak. We drive fills at explicit limit
  // prices so realized PnL is deterministic regardless of the oracle walk.
  it("free balance + locked margin is conserved across deposit/open/reduce/flip/close", async () => {
    const c = new MockDarkPerpClient();
    const lockedMargin = () =>
      c.getState().account.positions.reduce((s, p) => s + p.collateral, 0n);
    // capital(account) = withdrawable free balance + margin locked in positions.
    const capital = () => c.getState().account.settledBalance + lockedMargin();

    let expected = capital(); // starts at the seed balance, no positions

    const fill = async (side: "Buy" | "Sell", size: bigint, px: bigint, reduceOnly = false) => {
      await c.placeOrder({ marketId: 0, side, size, limitPrice: px, tif: "Gtc", reduceOnly });
      await vi.advanceTimersByTimeAsync(MATCH_MS);
    };

    // deposit moves capital up by exactly the deposit
    await c.deposit(5_000n * QUOTE_SCALE);
    expected += 5_000n * QUOTE_SCALE;
    expect(capital()).toBe(expected);

    // open long 1 @ $100k — capital unchanged (margin just moves free→locked)
    await fill("Buy", SIZE_SCALE, 100_000n * PRICE_SCALE);
    expect(capital()).toBe(expected);

    // add 1 more @ $100k (increase) — still no realized PnL, capital unchanged
    await fill("Buy", SIZE_SCALE, 100_000n * PRICE_SCALE);
    expect(capital()).toBe(expected);

    // partial reduce 0.5 @ $120k — realizes +$10k on the closed 0.5 (entry 100k)
    await fill("Sell", SIZE_SCALE / 2n, 120_000n * PRICE_SCALE, true);
    expected += 10_000n * QUOTE_SCALE;
    expect(capital()).toBe(expected);

    // flip: sell 2.5 @ $100k against the long 1.5 → realizes 1.5×(100k−100k)=0, opens short 1
    await fill("Sell", (SIZE_SCALE * 5n) / 2n, 100_000n * PRICE_SCALE);
    expect(pos(c)!.size).toBe(-SIZE_SCALE);
    expect(capital()).toBe(expected);

    // close the short 1 @ $100k — realizes 0, position gone
    await fill("Buy", SIZE_SCALE, 100_000n * PRICE_SCALE, true);
    expect(pos(c)).toBeUndefined();
    expect(lockedMargin()).toBe(0n);
    expect(capital()).toBe(expected);

    // withdraw moves capital down by exactly the withdrawal
    await c.requestWithdrawal(1_000n * QUOTE_SCALE);
    expected -= 1_000n * QUOTE_SCALE;
    expect(capital()).toBe(expected);
  });
});

describe("MockDarkPerpClient cancelOrder", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const place = (c: MockDarkPerpClient) =>
    c.placeOrder({ marketId: 0, side: "Buy", size: SIZE_SCALE, limitPrice: 100_000n * PRICE_SCALE, tif: "Gtc", reduceOnly: false });

  it("cancels an ACCEPTED order and emits a CANCELLED event", async () => {
    const c = new MockDarkPerpClient();
    const events: OrderEvent[] = [];
    c.onOrderEvent((e) => events.push(e));
    await place(c);
    const id = c.getState().orders[0].id;
    await c.cancelOrder(id);
    expect(c.getState().orders.find((o) => o.id === id)).toBeUndefined();
    expect(events.some((e) => e.kind === "CANCELLED" && e.orderId === id)).toBe(true);
  });

  it("rejects cancelling an unknown order", async () => {
    const c = new MockDarkPerpClient();
    await expect(c.cancelOrder("does-not-exist")).rejects.toThrow(/not found/i);
  });

  it("rejects cancelling once the order is MATCHED (binding)", async () => {
    const c = new MockDarkPerpClient();
    await place(c);
    const id = c.getState().orders[0].id;
    await vi.advanceTimersByTimeAsync(MATCH_MS); // ACCEPTED → MATCHED
    expect(c.getState().orders.find((o) => o.id === id)?.finality).toBe("MATCHED");
    await expect(c.cancelOrder(id)).rejects.toThrow(/only an accepted order/i);
  });
});

describe("MockDarkPerpClient selectMarket", () => {
  it("switches the selected market and ignores an unknown id", () => {
    const c = new MockDarkPerpClient();
    expect(c.getState().selectedMarketId).toBe(0);
    c.selectMarket(2);
    expect(c.getState().selectedMarketId).toBe(2);
    expect(c.getState().market.id).toBe(2);
    // unknown id is a no-op (guarded), not a crash or a switch to nothing
    c.selectMarket(999);
    expect(c.getState().selectedMarketId).toBe(2);
  });
});

describe("MockDarkPerpClient recover (§7)", () => {
  it("is deterministic per seed and the recoverable total excludes spent notes", async () => {
    const c = new MockDarkPerpClient();
    const a = await c.recover("alice-seed");
    const b = await c.recover("alice-seed");
    expect(a).toEqual(b); // same seed → same view-key scan (deterministic)
    expect(a.length).toBeGreaterThan(0);
    expect(a.every((n) => n.amount > 0n)).toBe(true);
    // the recoverable total counts only unspent notes
    const recoverable = a.filter((n) => !n.spent).reduce((s, n) => s + n.amount, 0n);
    const all = a.reduce((s, n) => s + n.amount, 0n);
    if (a.some((n) => n.spent)) expect(recoverable).toBeLessThan(all);
    else expect(recoverable).toBe(all);
  });
});

describe("MockDarkPerpClient batch summary (§2/§3)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("seals orders into a batch with a manifest hash + ordered root, settling when all do", async () => {
    const c = new MockDarkPerpClient();
    await c.placeOrder({ marketId: 0, side: "Buy", size: SIZE_SCALE, limitPrice: 100_000n * PRICE_SCALE, tif: "Gtc", reduceOnly: false });
    const b = c.getState().batches;
    expect(b.length).toBe(1);
    expect(b[0].orderCount).toBe(1);
    expect(b[0].manifestHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(b[0].orderedRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(b[0].finality).toBe("ACCEPTED"); // not settled until the order settles
    // advance past MATCH (900ms) and SETTLE (4500ms)
    await vi.advanceTimersByTimeAsync(5000);
    expect(c.getState().batches[0].finality).toBe("SETTLED");
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
