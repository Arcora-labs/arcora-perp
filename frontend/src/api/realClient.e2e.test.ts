// @vitest-environment happy-dom
//
// LIVE end-to-end proof of the sealed-order contracts (Task 11 ↔ Tasks 9/10):
// against a REAL running gateway, the client fetches + verifies the enclave
// epoch, seals an order, and the enclave DECRYPTS and accepts it. This is the
// round trip the unit tests can only pin with vectors.
//
// Skipped unless GATEWAY_URL is set. Run with:
//   PORT=18080 cargo run -p gateway            # in the repo root
//   GATEWAY_URL=http://127.0.0.1:18080 pnpm vitest run src/api/realClient.e2e.test.ts
import { describe, it, expect, vi, beforeAll } from "vitest";
import { RealDarkPerpClient } from "./realClient";

const GATEWAY_URL = process.env.GATEWAY_URL;

// The HTTP sealing path is under test — keep the client's WebSocket out of it.
class NullWebSocket {
  onmessage: unknown = null;
  onclose: unknown = null;
  onerror: unknown = null;
  constructor(_url: string) {}
  close() {}
}

describe.runIf(!!GATEWAY_URL)("sealed order round trip against a live gateway", () => {
  beforeAll(() => {
    vi.stubGlobal("WebSocket", NullWebSocket);
  });

  it("bootstrap verifies the epoch, deposit funds the /v1 account, and a SEALED order is decrypted + ACCEPTED by the enclave", async () => {
    const client = await RealDarkPerpClient.bootstrap(GATEWAY_URL!);

    // Fund the /v1 sealing account (Task 3: deposit is /v1-only — the legacy
    // demo route is gone; a PRODUCTION gateway would refuse this unbacked
    // credit, so this e2e runs against the demo `cargo run -p gateway`).
    await client.deposit(20_000n * 1_000_000n); // $20k in µUSD

    // Market-buy 0.1 BTC, sealed end-to-end. An ACCEPTED receipt proves the
    // gateway decrypted the canonical terms (a layout/AAD/key mismatch 400s).
    const receipt = await client.placeOrder({
      marketId: 0,
      side: "Buy",
      size: 10_000_000n, // 0.1 BTC (size-scaled 1e8)
      limitPrice: 0n, // market order
      tif: "Ioc",
      reduceOnly: false,
    });
    expect(receipt.orderHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(receipt.seqNo).toBeGreaterThanOrEqual(0); // first order on a fresh gateway is seq 0
    expect(receipt.recvTimeMs).toBeGreaterThan(0);
  }, 30_000);
});
