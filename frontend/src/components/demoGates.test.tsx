// @vitest-environment happy-dom
//
// SEC-025-E1 Task 3 — the UI half of removing the dead demo mutation surface:
//
//  - the demo-only client methods (closePosition / simulateAdl /
//    triggerCloseOnly / resumeNormal / recover) are now OPTIONAL on
//    DarkPerpClient; the REAL client deletes them (their /api/* routes 404 in
//    production), so components must PRESENCE-GATE — the buttons exist with
//    the mock client and are honestly absent (or replaced with an honest
//    explanation) with the real one;
//  - a cancel refusal must SURFACE to the user (Tables used to
//    `void client.cancelOrder(...)`, reporting failure as success);
//  - LpVault's `POST /api/lp/*` writes are gone for every client (SEC-025-C
//    unmounted LP staking in production; in mock mode the buttons never worked).
//
// The store is module-mocked so each test picks exactly which client shape it
// renders — a REAL-shaped client (methods absent) vs a MOCK-shaped one
// (methods present). That difference IS the discriminator: un-gating any
// button makes the "absent" cases fail.
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import type { ClientState, DarkPerpClient } from "../api/client";
import type { Market } from "../domain/types";
import { ModeBanner } from "./ModeBanner";
import { RecoveryPanel } from "./RecoveryPanel";
import { PositionsOrders } from "./Tables";
import { LpVault } from "./LpVault";
import { HealthPanel } from "./HealthPanel";
import { AccountPanel } from "./AccountPanel";

// ── module-mocked store: each test injects its client + state ────────────────
const injected: { client: Partial<DarkPerpClient>; state: ClientState | null } = {
  client: {},
  state: null,
};
vi.mock("../store", () => ({
  useStore: () => ({
    client: injected.client,
    state: injected.state,
    prefillPrice: null,
    setPrefillPrice: () => {},
  }),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const market: Market = {
  id: 0, symbol: "BTC/USDC", maxLeverage: 20, maintenanceMarginRatio: 0.05,
  initialMarginRatio: 0.1, referencePrice: 64_500_000_000_00n, live: false,
  takerFeeBps: 8, makerRebateBps: 2,
};

function baseState(overrides: Partial<ClientState> = {}): ClientState {
  return {
    markets: [market],
    selectedMarketId: 0,
    market,
    mode: "Normal",
    oracle: { marketId: 0, price: 64_500_000_000_00n, confidence: 1n, publishTimeMs: 0 },
    book: { marketId: 0, bids: [], asks: [] },
    marks: { 0: 64_500_000_000_00n },
    account: {
      settledBalance: 1_000_000_000n,
      positions: [
        {
          marketId: 0, size: 100_000_000n, entryPrice: 6_400_000_000_000n,
          collateral: 32_000_000_000n, unrealizedPnl: 5_000_000_000n,
          liquidationPrice: 6_100_000_000_000n,
        },
      ],
    },
    orders: [
      {
        id: "o42",
        input: { marketId: 0, side: "Buy", size: 100_000_000n, limitPrice: 6_400_000_000_000n, tif: "Gtc", reduceOnly: false },
        receipt: { orderHash: "0x" + "a1".repeat(32), seqNo: 5, recvTimeMs: 1, batchIdHint: 0 },
        finality: "ACCEPTED",
        filledSize: 0n,
        avgFillPrice: 0n,
        createdMs: 1,
      },
    ],
    batches: [],
    insuranceFund: 0n,
    treasury: 0n,
    lp: { tvl: 30_000_000_000_000n, navPerShare: "1.000000", totalShares: 30_000_000n, myShares: 0n, myValue: 0n },
    userAdlClawed: 0n,
    mmHedge: [],
    l1: null,
    attestation: null,
    settlement: null,
    ...overrides,
  };
}

/** The REAL client's post-Task-3 shape: no demo mutation methods. */
const realShaped = (extra: Partial<DarkPerpClient> = {}): Partial<DarkPerpClient> => ({
  cancelOrder: vi.fn(async () => {}),
  listWithdrawals: vi.fn(async () => null),
  ...extra,
});

/** The MOCK client's shape: the demo surface exists. */
const mockShaped = (): Partial<DarkPerpClient> => ({
  cancelOrder: vi.fn(async () => {}),
  listWithdrawals: vi.fn(async () => null),
  closePosition: vi.fn(async () => {}),
  simulateAdl: vi.fn(async () => 0n),
  triggerCloseOnly: vi.fn(),
  resumeNormal: vi.fn(),
  recover: vi.fn(async () => []),
});

describe("ModeBanner demo controls are presence-gated", () => {
  it("REAL client (no demo methods): the simulate buttons are absent, the mode banner stays", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<ModeBanner />);
    expect(screen.getByText(/normal/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /simulate adl/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /simulate forced exit/i })).toBeNull();
  });

  it("REAL client in CloseOnly: the close-only warning stays, without a fake 'Resume normal' button", () => {
    injected.client = realShaped();
    injected.state = baseState({ mode: "CloseOnly" });
    render(<ModeBanner />);
    expect(screen.getByText(/close-only mode/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /resume normal/i })).toBeNull();
  });

  it("MOCK client: the demo controls exist and dispatch", () => {
    const client = mockShaped();
    injected.client = client;
    injected.state = baseState();
    render(<ModeBanner />);
    fireEvent.click(screen.getByRole("button", { name: /simulate forced exit/i }));
    expect(client.triggerCloseOnly).toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /simulate adl/i }));
    expect(client.simulateAdl).toHaveBeenCalled();
  });
});

describe("RecoveryPanel is presence-gated", () => {
  it("REAL client (no recover): an honest unavailability note, no scan form", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<RecoveryPanel />);
    expect(screen.getByText(/not available on the live gateway/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /scan/i })).toBeNull();
  });

  it("MOCK client: the scan form exists and dispatches", async () => {
    const client = mockShaped();
    injected.client = client;
    injected.state = baseState();
    render(<RecoveryPanel />);
    fireEvent.change(screen.getByLabelText(/recovery seed/i), { target: { value: "alice-seed" } });
    fireEvent.click(screen.getByRole("button", { name: /scan/i }));
    expect(client.recover).toHaveBeenCalledWith("alice-seed");
  });
});

describe("Tables: cancel surfaces refusals; close is presence-gated", () => {
  it("a cancel refusal (the gateway's `sealed` answer) is SHOWN to the user, not swallowed", async () => {
    const refusal = "Only an ACCEPTED order can be cancelled (matched/settled are binding).";
    injected.client = realShaped({ cancelOrder: vi.fn(async () => { throw new Error(refusal); }) });
    injected.state = baseState();
    render(<PositionsOrders />);
    fireEvent.click(screen.getByRole("button", { name: /orders/i }));
    fireEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
    // the gateway's own wording must reach the user (E2 later makes resting-
    // order cancels effective; until then the refusal is the honest answer)
    expect(await screen.findByText(refusal)).toBeTruthy();
  });

  it("a successful cancel shows no error", async () => {
    const client = realShaped();
    injected.client = client;
    injected.state = baseState();
    render(<PositionsOrders />);
    fireEvent.click(screen.getByRole("button", { name: /orders/i }));
    fireEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
    expect(client.cancelOrder).toHaveBeenCalledWith("o42");
    expect(screen.queryByText(/only an accepted order/i)).toBeNull();
  });

  it("REAL client (no closePosition): the Close button is honestly absent", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<PositionsOrders />);
    // positions tab is the default; the row renders without a Close action
    expect(screen.getByText(/long/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /^close$/i })).toBeNull();
  });

  it("MOCK client: Close exists and dispatches", () => {
    const client = mockShaped();
    injected.client = client;
    injected.state = baseState();
    render(<PositionsOrders />);
    fireEvent.click(screen.getByRole("button", { name: /^close$/i }));
    expect(client.closePosition).toHaveBeenCalledWith(0);
  });
});

describe("LpVault no longer offers staking writes", () => {
  it("renders the pool stats read-only with an honest note — no deposit/withdraw buttons for ANY client", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<LpVault />);
    expect(screen.getByText(/pool tvl/i)).toBeTruthy();
    expect(screen.getByText(/staking is not available/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /deposit/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /withdraw/i })).toBeNull();
  });
});

// ── review F6: "Your …" claims sourced from the PUBLIC feed are demo-gated ───
// `state.userAdlClawed` and `state.lp.myShares/myValue` are the SHARED DEMO
// WALLET's numbers (the public /api/state feed — the LIQ-001 invariant keeps
// real /v1 tenants off it). Labelling them "Your …" on a live gateway presents
// a stranger's state as the caller's — beside a /v1/ws `adl` toast that just
// told the caller their REAL haircut. Gate: `simulateAdl` presence, the
// branch's established live/demo discriminator (on the mock the demo wallet
// IS the caller's account, so the labels are truthful there).
describe("public-feed 'Your …' stats are presence-gated (review F6)", () => {
  it("REAL client: the 'Your ADL haircuts' stat is absent (public-feed number)", () => {
    injected.client = realShaped();
    injected.state = baseState({ userAdlClawed: 5_000_000n });
    render(<HealthPanel />);
    expect(screen.queryByText(/your adl haircuts/i)).toBeNull();
    // the card's other stats stay (exact-case: the prose also says "insurance fund")
    expect(screen.getByText("Insurance fund")).toBeTruthy();
  });

  it("MOCK client: 'Your ADL haircuts' renders (the demo wallet IS the account)", () => {
    injected.client = mockShaped();
    injected.state = baseState({ userAdlClawed: 5_000_000n });
    render(<HealthPanel />);
    expect(screen.getByText(/your adl haircuts/i)).toBeTruthy();
  });

  it("REAL client: the 'Your LP position' card is absent (public-feed stake)", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<LpVault />);
    expect(screen.queryByText(/your lp position/i)).toBeNull();
    expect(screen.getByText(/pool tvl/i)).toBeTruthy(); // pool stats stay
  });

  it("MOCK client: 'Your LP position' renders", () => {
    injected.client = mockShaped();
    injected.state = baseState();
    render(<LpVault />);
    expect(screen.getByText(/your lp position/i)).toBeTruthy();
  });
});

// ── review F5: no recovery assurance the API-key custody model cannot honor ──
describe("RecoveryPanel does not overpromise recovery (review F5)", () => {
  it("REAL client: says device loss STRANDS the account; only already-requested withdrawals stay claimable", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<RecoveryPanel />);
    expect(screen.getByText(/stranded/i)).toBeTruthy();
    expect(screen.getByText(/already requested/i)).toBeTruthy();
    // the refuted claim must be gone: a withdrawal REQUEST needs the
    // browser-held API key, so funds are NOT generally recoverable on-chain
    expect(screen.queryByText(/funds are\s+recoverable through the on-chain claim path/i)).toBeNull();
  });
});

// ── review F1: the unavailable-account placeholder is SAID, not silent ───────
describe("AccountPanel surfaces the unavailable own-account placeholder (review F1)", () => {
  it("accountUnavailable ⇒ an explicit 'could not be read / placeholders' notice", () => {
    injected.client = realShaped();
    injected.state = baseState({
      accountUnavailable: true,
      account: { settledBalance: 0n, positions: [] },
      orders: [],
    });
    render(<AccountPanel />);
    expect(screen.getByText(/could not be read/i)).toBeTruthy();
    expect(screen.getByText(/placeholders/i)).toBeTruthy();
  });

  it("a readable account shows no such notice", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<AccountPanel />);
    expect(screen.queryByText(/could not be read/i)).toBeNull();
  });
});
