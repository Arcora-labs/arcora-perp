import { describe, it, expect } from "vitest";
import { orderRisk } from "./risk";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "./types";

const MARK = 100_000n * PRICE_SCALE; // $100k

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
