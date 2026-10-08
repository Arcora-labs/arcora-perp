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
import { AccountPanel, AccountSummary } from "./AccountPanel";
import { StatsBar } from "./StatsBar";

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

describe("RecoveryPanel live recovery is capability-gated", () => {
  it("without recoverAccount fails closed", () => {
    injected.client = realShaped(); injected.state = baseState(); render(<RecoveryPanel />);
    expect(screen.getByText(/unavailable on this gateway build/i)).toBeTruthy();
  });
  it("with recoverAccount exposes owner-id recovery", () => {
    injected.client = realShaped({ recoverAccount: vi.fn(async () => ({ owner: "0x"+"22".repeat(32), recoveryNonce: 1 })) });
    injected.state = baseState(); render(<RecoveryPanel />);
    expect(screen.getByLabelText(/account owner id/i)).toBeTruthy();
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
describe("RecoveryPanel A07 claims", () => {
  it("does not promise recovery when unsupported", () => {
    injected.client = realShaped(); injected.state = baseState(); render(<RecoveryPanel />);
    expect(screen.getByText(/unavailable on this gateway build/i)).toBeTruthy();
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

// ── fix-wave-2 G2: the TRADE screen says "unreadable" too, not just Account ──
// `accountUnavailable` was consumed only by AccountPanel (the account tab);
// StatsBar / PositionsOrders / HealthPanel rendered the zero placeholder as
// fact — a user with a live leveraged position saw "Positions · 0" and an
// empty orders table and could not tell that from being flat. The flag's
// emit()-side contract: when it is set, account/orders are ALWAYS the empty
// placeholder, so the empty-state branches below are the reachable ones.
const unavailableState = () =>
  baseState({
    accountUnavailable: true,
    account: { settledBalance: 0n, positions: [] },
    orders: [],
  });

describe("trade-screen surfaces distinguish 'unreadable' from 'flat' (fix-wave-2 G2)", () => {
  it("StatsBar: 'Your notional' says unreadable, never a factual $0", () => {
    injected.client = realShaped();
    injected.state = unavailableState();
    render(<StatsBar />);
    expect(screen.getByText("Your notional")).toBeTruthy();
    expect(screen.getByText(/unreadable/i)).toBeTruthy();
    expect(screen.queryByText("$0")).toBeNull();
  });

  it("StatsBar: a readable account shows the notional value, unflagged", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<StatsBar />);
    expect(screen.getByText("Your notional")).toBeTruthy();
    expect(screen.queryByText(/unreadable/i)).toBeNull();
  });

  it("PositionsOrders: both tabs carry the could-not-read notice and the counts show — not 0", () => {
    injected.client = realShaped();
    injected.state = unavailableState();
    render(<PositionsOrders />);
    expect(screen.getByText(/positions · —/i)).toBeTruthy();
    expect(screen.getByText(/orders · —/i)).toBeTruthy();
    // positions tab (default): the placeholder is SAID, not shown as flatness
    expect(screen.getByText(/positions could not be read/i)).toBeTruthy();
    expect(screen.queryByText(/no open positions/i)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /orders/i }));
    expect(screen.getByText(/orders could not be read/i)).toBeTruthy();
    expect(screen.queryByText(/no orders yet/i)).toBeNull();
  });

  it("PositionsOrders: a READABLE empty account keeps the plain empty message — no scare notice", () => {
    injected.client = realShaped();
    injected.state = baseState({
      account: { settledBalance: 1_000_000_000n, positions: [] },
      orders: [],
    });
    render(<PositionsOrders />);
    expect(screen.getByText(/positions · 0/i)).toBeTruthy();
    expect(screen.getByText(/no open positions/i)).toBeTruthy();
    expect(screen.queryByText(/could not be read/i)).toBeNull();
  });

  it("HealthPanel: the conservation check SUSPENDS over an unreadable account — no vacuous 'solvent ✓'", () => {
    injected.client = realShaped();
    injected.state = unavailableState();
    render(<HealthPanel />);
    expect(screen.getByText(/collateral conservation/i)).toBeTruthy();
    expect(screen.getByText(/unreadable — check suspended/i)).toBeTruthy();
    expect(screen.queryByText(/solvent ✓/i)).toBeNull();
  });

  it("HealthPanel: a readable account keeps the live conservation verdict", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<HealthPanel />);
    expect(screen.getByText(/solvent ✓/i)).toBeTruthy();
    expect(screen.queryByText(/check suspended/i)).toBeNull();
  });
});

// ── fix-wave-3 H1/H2: no false recovery promise; no "$0.00" stated as fact ───
// H1: the unavailable notices said "recovers automatically once the connection
// does" — false in two of the flag's states (the F7 auth-error reset and a
// boot-time registration failure): tryAuthV1 early-returns without `sealing`,
// deliberately never auto-retries, and the only timer refreshes market data.
// H2: HealthPanel's Accounting card rendered the placeholder as Equity/Free/
// Used margin/uPnL "$0.00" — a dollar claim louder than the "Positions · 0"
// G2 fixed, in a card separate from the suspended verdict row.
describe("unavailable-state honesty (fix-wave-3 H1/H2)", () => {
  /** The four Accounting-card tile values, in render order. */
  function accountingValues(): (string | null)[] {
    const card = screen.getByText("Accounting").closest(".card");
    expect(card).toBeTruthy();
    return Array.from(card!.querySelectorAll(".summary__value")).map((el) => el.textContent);
  }

  it("H1 Tables: the notice points at 'reload the page' and no longer promises automatic recovery", () => {
    injected.client = realShaped();
    injected.state = unavailableState();
    render(<PositionsOrders />);
    expect(screen.getByText(/positions could not be read/i)).toBeTruthy();
    expect(screen.getByText(/reload the page/i)).toBeTruthy();
    expect(screen.queryByText(/recovers automatically/i)).toBeNull();
  });

  it("H1 AccountPanel: same — the reload escape hatch, no automatic-recovery promise", () => {
    injected.client = realShaped();
    injected.state = unavailableState();
    render(<AccountPanel />);
    expect(screen.getByText(/could not be read/i)).toBeTruthy();
    expect(screen.getByText(/reload the page/i)).toBeTruthy();
    expect(screen.queryByText(/recovers automatically/i)).toBeNull();
  });

  it("H2 HealthPanel: all four Accounting tiles dash out over an unreadable account — never '$0.00' as fact", () => {
    injected.client = realShaped();
    injected.state = unavailableState();
    render(<HealthPanel />);
    // toEqual over ALL FOUR: a ternary applied to only some tiles fails here.
    expect(accountingValues()).toEqual(["—", "—", "—", "—"]);
  });

  it("H2 HealthPanel: a readable account keeps the four dollar tiles", () => {
    injected.client = realShaped();
    injected.state = baseState();
    render(<HealthPanel />);
    const values = accountingValues();
    expect(values).toHaveLength(4);
    for (const v of values) expect(v).toMatch(/^\$/); // formatUsd output, not "—"
  });
});

// A04: protocol finality is not the same as cancellation eligibility.
describe("Tables use the gateway remainder capability", () => {
  it.each(["MATCHED", "SETTLED"] as const)("permits cancelling a live %s remainder", (finality) => {
    const client = realShaped();
    injected.client = client;
    const state = baseState();
    state.orders[0].finality = finality;
    state.orders[0].cancellable = true;
    injected.state = state;
    render(<PositionsOrders />);
    fireEvent.click(screen.getByRole("button", { name: /orders/i }));
    fireEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
    expect(client.cancelOrder).toHaveBeenCalledWith("o42");
  });
  it("hides cancellation for an ACCEPTED order explicitly reported as non-cancellable", () => {
    injected.client = realShaped();
    const state = baseState();
    state.orders[0].cancellable = false;
    injected.state = state;
    render(<PositionsOrders />);
    fireEvent.click(screen.getByRole("button", { name: /orders/i }));
    expect(screen.queryByRole("button", { name: /^cancel$/i })).toBeNull();
  });
  it("keeps a durability failure visible when the cancelled row has disappeared", async () => {
    const refusal = "Cancellation durability unconfirmed";
    injected.state = baseState();
    injected.client = realShaped({ cancelOrder: vi.fn(async () => {
      injected.state = baseState({ orders: [] });
      throw new Error(refusal);
    }) });
    render(<PositionsOrders />);
    fireEvent.click(screen.getByRole("button", { name: /orders/i }));
    fireEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", refusal);
  });
});

it("Portfolio summary never presents unreadable placeholders as zero balances", () => {
  injected.client = realShaped(); injected.state = unavailableState();
  const { container } = render(<AccountSummary />);
  expect(Array.from(container.querySelectorAll(".statcard__value")).map(el => el.textContent)).toEqual(["—", "—", "—", "—", "—"]);
});
