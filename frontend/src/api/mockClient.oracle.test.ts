import { describe, it, expect, vi, beforeEach } from "vitest";
import type { LiveQuote } from "./oracleFeed";

// Control the live feed so we can drive go-live → outage → recover deterministically.
vi.mock("./oracleFeed", () => ({ fetchLiveQuotes: vi.fn() }));
import { fetchLiveQuotes } from "./oracleFeed";
import { MockDarkPerpClient } from "./mockClient";

const mockFeed = fetchLiveQuotes as unknown as ReturnType<typeof vi.fn>;

function btcQuote(price: bigint): Map<string, LiveQuote> {
  return new Map([["BTCUSD-PERP", { price, bid: price - 1n, ask: price + 1n, change24h: 0 }]]);
}

// pollOracle is private + network-gated (skipped under MODE==='test'); reach it directly.
function poll(c: MockDarkPerpClient): Promise<void> {
  return (c as unknown as { pollOracle(): Promise<void> }).pollOracle();
}

describe("live-oracle fallback is self-healing", () => {
  beforeEach(() => mockFeed.mockReset());

  it("marks a market live on a successful poll", async () => {
    const c = new MockDarkPerpClient();
    mockFeed.mockResolvedValueOnce(btcQuote(60_000n * 100_000_000n));
    await poll(c);
    const btc = c.getState().markets.find((m) => m.id === 0)!;
    expect(btc.live).toBe(true);
    expect(c.getState().oracle.price).toBe(60_000n * 100_000_000n);
  });

  it("demotes a live market back to the walk on a feed OUTAGE (no freeze)", async () => {
    const c = new MockDarkPerpClient();
    mockFeed.mockResolvedValueOnce(btcQuote(60_000n * 100_000_000n));
    await poll(c); // → live
    expect(c.getState().markets.find((m) => m.id === 0)!.live).toBe(true);

    mockFeed.mockRejectedValueOnce(new Error("network down"));
    await poll(c); // outage → must hand back to the walk
    expect(c.getState().markets.find((m) => m.id === 0)!.live).toBe(false);
  });

  it("demotes a market that drops out of the feed even when others stay live", async () => {
    const c = new MockDarkPerpClient();
    mockFeed.mockResolvedValueOnce(btcQuote(60_000n * 100_000_000n));
    await poll(c);
    // next poll returns an empty map: BTC dropped out → it alone resumes the walk
    mockFeed.mockResolvedValueOnce(new Map());
    await poll(c);
    expect(c.getState().markets.find((m) => m.id === 0)!.live).toBe(false);
  });

  it("re-anchors and re-marks live after the feed recovers", async () => {
    const c = new MockDarkPerpClient();
    mockFeed.mockResolvedValueOnce(btcQuote(60_000n * 100_000_000n));
    await poll(c);
    mockFeed.mockRejectedValueOnce(new Error("blip"));
    await poll(c); // demoted
    mockFeed.mockResolvedValueOnce(btcQuote(61_234n * 100_000_000n));
    await poll(c); // recovered
    const btc = c.getState().markets.find((m) => m.id === 0)!;
    expect(btc.live).toBe(true);
    expect(c.getState().oracle.price).toBe(61_234n * 100_000_000n);
  });
});
