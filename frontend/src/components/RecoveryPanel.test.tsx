// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { RecoveryPanel } from "./RecoveryPanel";

const injected: { client: any } = { client: {} };
vi.mock("../store", () => ({ useStore: () => injected }));
vi.mock("../api/wallet", () => ({
  connect: vi.fn(async () => {}),
  hasInjected: () => true,
  useWalletAddress: () => "0x" + "11".repeat(20),
}));

afterEach(() => { cleanup(); injected.client = {}; });

describe("RecoveryPanel A07", () => {
  it("dispatches live owner-id credential recovery", async () => {
    const owner = "0x" + "22".repeat(32);
    const recoverAccount = vi.fn(async () => ({ owner, recoveryNonce: 2 }));
    injected.client = { recoverAccount };
    render(<RecoveryPanel />);
    fireEvent.change(screen.getByLabelText(/account owner id/i), { target: { value: owner } });
    fireEvent.click(screen.getByRole("button", { name: /sign & recover/i }));
    expect(await screen.findByText(/credential generation is now #2/i)).toBeTruthy();
    expect(recoverAccount).toHaveBeenCalledWith(owner);
  });

  it("fails closed when the gateway client lacks live recovery", () => {
    render(<RecoveryPanel />);
    expect(screen.getByText(/unavailable on this gateway build/i)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });
});


it("warns that confirmed recovery is session-only when browser persistence fails", async () => {
  const owner = "0x" + "22".repeat(32);
  injected.client = { recoverAccount: vi.fn(async () => ({ owner, recoveryNonce: 3, credentialStorage: "session" })) };
  render(<RecoveryPanel />);
  fireEvent.change(screen.getByLabelText(/account owner id/i), { target: { value: owner } });
  fireEvent.click(screen.getByRole("button", { name: /sign & recover/i }));
  expect(await screen.findByRole("status")).toHaveProperty("textContent", expect.stringMatching(/this tab only.*old saved key may no longer work/i));
});
