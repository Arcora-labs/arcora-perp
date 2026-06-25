import { describe, it, expect } from "vitest";
import { scalePrice } from "./oracleFeed";
import { PRICE_SCALE } from "../domain/types";

describe("scalePrice (oracle feed)", () => {
  it("scales whole and fractional decimal strings to PRICE_SCALE bigints", () => {
    expect(scalePrice("59575.14")).toBe(5_957_514_000_000n); // 59575.14 × 1e8
    expect(scalePrice("66.44")).toBe(66n * PRICE_SCALE + 44_000_000n);
    expect(scalePrice("1")).toBe(PRICE_SCALE);
    expect(scalePrice("0.00000001")).toBe(1n); // 1 satoshi-equivalent tick
  });

  it("truncates beyond 8 decimals and tolerates trailing fraction", () => {
    expect(scalePrice("1.123456789")).toBe(PRICE_SCALE + 12_345_678n); // 9th digit dropped
    expect(scalePrice("100.")).toBe(100n * PRICE_SCALE);
  });

  it("handles negative strings", () => {
    expect(scalePrice("-2.5")).toBe(-(2n * PRICE_SCALE + 50_000_000n));
  });
});
