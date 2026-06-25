import { describe, it, expect } from "vitest";
import { orderRisk, maxOrderSize, accountSummary } from "./risk";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE, type Position } from "./types";

const MARK = 100_000n * PRICE_SCALE; // $100k

function position(size: bigint, collateral: bigint, upnl: bigint): Position {
  return { marketId: 0, size, entryPrice: MARK, collateral, unrealizedPnl: upnl, liquidationPrice: 0n };
}

describe("accountSummary", () => {
  it("aggregates free balance, used margin, uPnL into equity", () => {
    const positions = [
      position(SIZE_SCALE, 10_000n * QUOTE_SCALE, 2_000n * QUOTE_SCALE),
      position(-SIZE_SCALE / 2n, 5_000n * QUOTE_SCALE, -500n * QUOTE_SCALE),
    ];
    const s = accountSummary(positions, 8_000n * QUOTE_SCALE, MARK);
    expect(s.usedMargin).toBe(15_000n * QUOTE_SCALE);
    expect(s.upnl).toBe(1_500n * QUOTE_SCALE);
    expect(s.freeBalance).toBe(8_000n * QUOTE_SCALE);
    // equity = 8k free + 15k margin + 1.5k uPnL
    expect(s.equity).toBe(24_500n * QUOTE_SCALE);
    // notional = (1 + 0.5) BTC × $100k = $150k
    expect(s.notional).toBe(150_000n * QUOTE_SCALE);
    expect(s.leverage).toBeCloseTo(150_000 / 24_500, 4);
  });

  it("is flat (zero leverage) with no positions", () => {
    const s = accountSummary([], 10_000n * QUOTE_SCALE, MARK);
    expect(s.equity).toBe(10_000n * QUOTE_SCALE);
    expect(s.notional).toBe(0n);
    expect(s.leverage).toBe(0);
  });
});

describe("maxOrderSize", () => {
  it("is buying power (balance × leverage) divided by mark", () => {
    // $25k free × 10x = $250k buying power at $100k ⇒ 2.5 BTC
    expect(maxOrderSize(25_000n * QUOTE_SCALE, MARK, 10)).toBe((SIZE_SCALE * 5n) / 2n);
    // opening that exact size needs margin == the whole balance
    const r = orderRisk(maxOrderSize(25_000n * QUOTE_SCALE, MARK, 10), MARK, "Buy", 0.1);
    expect(r.margin).toBe(25_000n * QUOTE_SCALE);
  });

  it("returns 0 for empty balance, zero mark, or non-positive leverage", () => {
    expect(maxOrderSize(0n, MARK, 10)).toBe(0n);
    expect(maxOrderSize(10_000n * QUOTE_SCALE, 0n, 10)).toBe(0n);
    expect(maxOrderSize(10_000n * QUOTE_SCALE, MARK, 0)).toBe(0n);
  });
});

describe("orderRisk", () => {
  it("computes notional, margin, leverage, and liq for a long at 10x", () => {
    // 0.25 BTC at $100k, initial-margin ratio 0.1 (10x)
    const r = orderRisk(SIZE_SCALE / 4n, MARK, "Buy", 0.1);
    expect(r.notional).toBe(25_000n * QUOTE_SCALE);
    expect(r.margin).toBe(2_500n * QUOTE_SCALE);
    expect(r.leverage).toBeCloseTo(10, 5);
    // long liquidation sits 9% below the entry
    expect(r.liquidationPrice).toBe(91_000n * PRICE_SCALE);
  });

  it("places a short's liquidation ABOVE entry", () => {
    const r = orderRisk(SIZE_SCALE, MARK, "Sell", 0.1);
    expect(r.liquidationPrice).toBe(109_000n * PRICE_SCALE);
    expect(r.liquidationPrice > MARK).toBe(true);
  });

  it("scales margin with the initial-margin ratio (leverage)", () => {
    const r20 = orderRisk(SIZE_SCALE, MARK, "Buy", 0.05); // 20x
    expect(r20.margin).toBe(5_000n * QUOTE_SCALE); // 5% of $100k
    expect(r20.leverage).toBeCloseTo(20, 5);
  });

  it("returns zeroed risk for non-positive size or mark (nothing to render)", () => {
    for (const [s, m] of [
      [0n, MARK],
      [-SIZE_SCALE, MARK],
      [SIZE_SCALE, 0n],
    ] as [bigint, bigint][]) {
      const r = orderRisk(s, m, "Buy", 0.1);
      expect(r).toEqual({ notional: 0n, margin: 0n, leverage: 0, liquidationPrice: 0n });
    }
  });

  it("notional is exact for fractional sizes (no float drift)", () => {
    // 1.5 BTC at $100k = $150k
    const r = orderRisk(SIZE_SCALE + SIZE_SCALE / 2n, MARK, "Buy", 0.1);
    expect(r.notional).toBe(150_000n * QUOTE_SCALE);
  });
});
