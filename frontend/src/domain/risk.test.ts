import { describe, it, expect } from "vitest";
import { orderRisk, maxOrderSize, accountSummary, liqBufferBp, liquidationPrice } from "./risk";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE, type Position } from "./types";

const MARK = 100_000n * PRICE_SCALE; // $100k

function position(size: bigint, collateral: bigint, upnl: bigint, marketId = 0): Position {
  return { marketId, size, entryPrice: MARK, collateral, unrealizedPnl: upnl, liquidationPrice: 0n };
}

const flat = () => MARK; // single-market mark lookup

describe("accountSummary", () => {
  it("aggregates free balance, used margin, uPnL into equity", () => {
    const positions = [
      position(SIZE_SCALE, 10_000n * QUOTE_SCALE, 2_000n * QUOTE_SCALE),
      position(-SIZE_SCALE / 2n, 5_000n * QUOTE_SCALE, -500n * QUOTE_SCALE),
    ];
    const s = accountSummary(positions, 8_000n * QUOTE_SCALE, flat);
    expect(s.usedMargin).toBe(15_000n * QUOTE_SCALE);
    expect(s.upnl).toBe(1_500n * QUOTE_SCALE);
    expect(s.freeBalance).toBe(8_000n * QUOTE_SCALE);
    // equity = 8k free + 15k margin + 1.5k uPnL
    expect(s.equity).toBe(24_500n * QUOTE_SCALE);
    // notional = (1 + 0.5) BTC × $100k = $150k
    expect(s.notional).toBe(150_000n * QUOTE_SCALE);
    expect(s.leverage).toBeCloseTo(150_000 / 24_500, 4);
  });

  it("marks each position at ITS OWN market price (cross-market notional)", () => {
    // long 1 in market 0 @ $100k, long 1 in market 1 @ $2k
    const positions = [
      position(SIZE_SCALE, 10_000n * QUOTE_SCALE, 0n, 0),
      position(SIZE_SCALE, 200n * QUOTE_SCALE, 0n, 1),
    ];
    const marks: Record<number, bigint> = { 0: 100_000n * PRICE_SCALE, 1: 2_000n * PRICE_SCALE };
    const s = accountSummary(positions, 0n, (id) => marks[id]);
    // notional = 1×$100k + 1×$2k = $102k (NOT 2×selected-market price)
    expect(s.notional).toBe(102_000n * QUOTE_SCALE);
  });

  it("is flat (zero leverage) with no positions", () => {
    const s = accountSummary([], 10_000n * QUOTE_SCALE, flat);
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
    const r = orderRisk(maxOrderSize(25_000n * QUOTE_SCALE, MARK, 10), MARK, "Buy", 0.1, 0.05);
    expect(r.margin).toBe(25_000n * QUOTE_SCALE);
  });

  it("returns 0 for empty balance, zero mark, or non-positive leverage", () => {
    expect(maxOrderSize(0n, MARK, 10)).toBe(0n);
    expect(maxOrderSize(10_000n * QUOTE_SCALE, 0n, 10)).toBe(0n);
    expect(maxOrderSize(10_000n * QUOTE_SCALE, MARK, 0)).toBe(0n);
  });
});

describe("liquidation buffer is derived from the margin model", () => {
  it("is the gap between initial and maintenance margin, in bp", () => {
    expect(liqBufferBp(0.1, 0.05)).toBe(500n); // 10% initial − 5% maint = 5%
    expect(liqBufferBp(0.05, 0.0)).toBe(500n); // 20x with 0 maint = 5% too
    expect(liqBufferBp(0.1, 0.1)).toBe(0n); // no gap ⇒ no buffer
  });

  it("never goes negative if maintenance exceeds initial (degenerate config)", () => {
    expect(liqBufferBp(0.05, 0.1)).toBe(0n);
  });

  it("puts a long's liq below entry and a short's above, by the buffer", () => {
    expect(liquidationPrice(MARK, true, 0.1, 0.05)).toBe(95_000n * PRICE_SCALE);
    expect(liquidationPrice(MARK, false, 0.1, 0.05)).toBe(105_000n * PRICE_SCALE);
  });
});

describe("orderRisk", () => {
  it("computes notional, margin, leverage, and liq for a long at 10x", () => {
    // 0.25 BTC at $100k, initial 0.1 (10x) / maintenance 0.05
    const r = orderRisk(SIZE_SCALE / 4n, MARK, "Buy", 0.1, 0.05);
    expect(r.notional).toBe(25_000n * QUOTE_SCALE);
    expect(r.margin).toBe(2_500n * QUOTE_SCALE);
    expect(r.leverage).toBeCloseTo(10, 5);
    // liq sits at the margin-implied buffer (10%−5% = 5%) below entry
    expect(r.liquidationPrice).toBe(95_000n * PRICE_SCALE);
  });

  it("places a short's liquidation ABOVE entry", () => {
    const r = orderRisk(SIZE_SCALE, MARK, "Sell", 0.1, 0.05);
    expect(r.liquidationPrice).toBe(105_000n * PRICE_SCALE);
    expect(r.liquidationPrice > MARK).toBe(true);
  });

  it("scales margin with the initial-margin ratio (leverage)", () => {
    const r20 = orderRisk(SIZE_SCALE, MARK, "Buy", 0.05, 0.025); // 20x
    expect(r20.margin).toBe(5_000n * QUOTE_SCALE); // 5% of $100k
    expect(r20.leverage).toBeCloseTo(20, 5);
  });

  it("returns zeroed risk for non-positive size or mark (nothing to render)", () => {
    for (const [s, m] of [
      [0n, MARK],
      [-SIZE_SCALE, MARK],
      [SIZE_SCALE, 0n],
    ] as [bigint, bigint][]) {
      const r = orderRisk(s, m, "Buy", 0.1, 0.05);
      expect(r).toEqual({ notional: 0n, margin: 0n, leverage: 0, liquidationPrice: 0n });
    }
  });

  it("notional is exact for fractional sizes (no float drift)", () => {
    // 1.5 BTC at $100k = $150k
    const r = orderRisk(SIZE_SCALE + SIZE_SCALE / 2n, MARK, "Buy", 0.1, 0.05);
    expect(r.notional).toBe(150_000n * QUOTE_SCALE);
  });
});
