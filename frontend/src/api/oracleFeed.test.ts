import { describe, it, expect, vi, afterEach } from "vitest";
import { scalePrice, fetchLiveQuotes } from "./oracleFeed";
import { PRICE_SCALE } from "../domain/types";

afterEach(() => vi.unstubAllGlobals());

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mockFetchOk(rows: any[]) {
  return vi.fn(async () => ({ ok: true, json: async () => ({ result: { data: rows } }) }));
}

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

describe("fetchLiveQuotes — graceful degradation on a messy feed", () => {
  it("falls a missing bid/ask back to last, and skips malformed / non-positive / unrequested rows", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchOk([
        { i: "BTCUSD-PERP", a: "100.5", b: "", k: "", c: "0.01" }, // both book sides absent
        { i: "ETHUSD-PERP", a: "abc", b: "1", k: "2", c: "0" }, // unparseable last → skipped, not thrown
        { i: "SOLUSD-PERP", a: "0", b: "1", k: "2", c: "0" }, // non-positive last → skipped
        { i: "XRPUSD-PERP", a: "9", b: "8", k: "10", c: "0" }, // not requested → filtered out
      ]),
    );
    const q = await fetchLiveQuotes(["BTCUSD-PERP", "ETHUSD-PERP", "SOLUSD-PERP"]);

    const btc = q.get("BTCUSD-PERP");
    expect(btc).toBeTruthy();
    // an absent side must fall back to `last`, never read as 0 — the §8 parity with
    // the Rust adapter's one-sided-outage fix
    expect(btc!.price).toBe(scalePrice("100.5"));
    expect(btc!.bid).toBe(btc!.price);
    expect(btc!.ask).toBe(btc!.price);
    // a single malformed row must not poison the whole feed
    expect(q.has("ETHUSD-PERP")).toBe(false);
    expect(q.has("SOLUSD-PERP")).toBe(false);
    expect(q.has("XRPUSD-PERP")).toBe(false);
  });

  it("throws on HTTP failure so the caller falls back to the internal walk", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 503 })));
    await expect(fetchLiveQuotes(["BTCUSD-PERP"])).rejects.toThrow(/HTTP 503/);
  });
});
