import { describe, it, expect } from "vitest";
import {
  formatUsd,
  formatPrice,
  formatSize,
  formatSignedSize,
  parsePrice,
  parseSize,
  parseUsd,
  parseScaled,
  shortHash,
} from "./format";
import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "./types";

describe("fixed-point formatting", () => {
  it("formats whole and fractional quote amounts", () => {
    expect(formatUsd(20_000n * QUOTE_SCALE)).toBe("$20000.00");
    expect(formatUsd(1_234_560n)).toBe("$1.23"); // 1.23456 truncated to 2dp
    expect(formatUsd(0n)).toBe("$0.00");
  });

  it("formats prices at the requested precision", () => {
    expect(formatPrice(100_000n * PRICE_SCALE)).toBe("100000.00");
    expect(formatPrice(99_999_500_000n, 2)).toBe("999.99"); // 999.995 truncates, not rounds
  });

  it("formats sizes with 4 decimals by default", () => {
    expect(formatSize(SIZE_SCALE)).toBe("1.0000");
    expect(formatSize(SIZE_SCALE / 2n)).toBe("0.5000");
  });

  it("signs sizes explicitly (long +, short -, flat unsigned)", () => {
    expect(formatSignedSize(SIZE_SCALE)).toBe("+1.0000");
    expect(formatSignedSize(-SIZE_SCALE)).toBe("-1.0000");
    expect(formatSignedSize(0n)).toBe("0.0000");
  });

  it("renders negative quote amounts with a single leading minus", () => {
    expect(formatUsd(-5n * QUOTE_SCALE)).toBe("$-5.00");
  });
});

describe("fixed-point parsing", () => {
  it("parses integers and decimals to scaled bigints", () => {
    expect(parseUsd("20000")).toBe(20_000n * QUOTE_SCALE);
    expect(parsePrice("100000.50")).toBe(100_000n * PRICE_SCALE + 50_000_000n);
    expect(parseSize("0.5")).toBe(SIZE_SCALE / 2n);
  });

  it("accepts leading/trailing-dot forms", () => {
    expect(parseUsd(".5")).toBe(QUOTE_SCALE / 2n);
    expect(parseUsd("5.")).toBe(5n * QUOTE_SCALE);
  });

  it("truncates excess fractional digits to the scale precision", () => {
    // QUOTE_SCALE has 6 decimals; the 7th digit is dropped, not rounded.
    expect(parseScaled("1.1234567", QUOTE_SCALE)).toBe(1_123_456n);
  });

  it("rejects malformed input", () => {
    for (const bad of ["", ".", "abc", "1.2.3", "-5", "1,000", " "]) {
      expect(parseScaled(bad, QUOTE_SCALE)).toBeNull();
    }
  });

  it("round-trips format → parse for representative values", () => {
    const cases: [bigint, bigint][] = [
      [20_000n * QUOTE_SCALE, QUOTE_SCALE],
      [100_000n * PRICE_SCALE, PRICE_SCALE],
      [3n * SIZE_SCALE + SIZE_SCALE / 4n, SIZE_SCALE],
    ];
    for (const [value, scale] of cases) {
      const decimals = scale.toString().length - 1;
      const shown =
        scale === PRICE_SCALE
          ? formatPrice(value, decimals)
          : scale === SIZE_SCALE
            ? formatSize(value, decimals)
            : `${value / scale}.${(value % scale).toString().padStart(decimals, "0")}`;
      expect(parseScaled(shown, scale)).toBe(value);
    }
  });
});

describe("shortHash", () => {
  it("abbreviates long hashes and leaves short ones intact", () => {
    expect(shortHash("0x1234567890abcdef")).toBe("0x1234…cdef");
    expect(shortHash("0xabcd")).toBe("0xabcd");
  });
});
