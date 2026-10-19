// @vitest-environment happy-dom
//
// The withdrawal minimum's exception is per market: the gateway lets a request
// below 1 USDC through only when it takes the selected market's whole free
// balance. The Account tab predicts that answer with the same per-market amount.
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MockDarkPerpClient } from "../api/mockClient";
import { AccountPanel } from "./AccountPanel";

const store = vi.hoisted(() => ({ value: null as any }));
vi.mock("../store", () => ({ useStore: () => store.value }));
afterEach(cleanup);

/// `market0` free in market 0 and $0.40 in market 1, with market `selected`
/// chosen.
function setup(selected: number, market0 = 25_000_000n) {
  const client = new MockDarkPerpClient();
  const state = {
    ...client.getState(),
    selectedMarketId: selected,
    account: {
      settledBalance: market0 + 400_000n,
      marketFree: { 0: market0, 1: 400_000n },
      positions: [],
    },
  };
  const withdraw = vi.spyOn(client, "requestWithdrawal").mockResolvedValue(undefined);
  store.value = { client, state, prefillPrice: null, setPrefillPrice: vi.fn() };
  render(<AccountPanel />);
  return { withdraw };
}

function withdrawAmount(value: string) {
  fireEvent.change(screen.getByLabelText(/amount/i), { target: { value } });
  fireEvent.click(screen.getByRole("button", { name: /^withdraw$/i }));
}

describe("AccountPanel withdrawal minimum across two markets", () => {
  it("sends the whole $0.40 of the selected market although another market holds more", async () => {
    const { withdraw } = setup(1);
    withdrawAmount("0.40");
    await waitFor(() => expect(withdraw).toHaveBeenCalledWith(400_000n));
  });

  it("refuses a sub-dollar amount that is not the selected market's whole free balance", async () => {
    const { withdraw } = setup(0);
    withdrawAmount("0.40");
    const refusal = await screen.findByText(/minimum withdrawal is 1 usdc/i);
    expect(refusal.textContent).toMatch(/entire free balance in the selected market/i);
    expect(withdraw).not.toHaveBeenCalled();
  });

  it("refuses a sub-dollar account-wide total that is more than the selected market holds", async () => {
    // $0.30 + $0.40: the gateway would refuse $0.70 from market 1.
    const { withdraw } = setup(1, 300_000n);
    withdrawAmount("0.70");
    expect(await screen.findByText(/minimum withdrawal is 1 usdc/i)).toBeTruthy();
    expect(withdraw).not.toHaveBeenCalled();
  });

  it("says the exception is per market", () => {
    setup(1);
    expect(screen.getByText(/unless you withdraw your entire free balance in the selected market/i)).toBeTruthy();
  });
});
