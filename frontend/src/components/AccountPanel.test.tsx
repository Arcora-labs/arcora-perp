// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { AccountPanel, buildClaimCommand } from "./AccountPanel";
import type { WithdrawalEntry } from "../domain/types";

afterEach(() => {
  cleanup();
  localStorage.clear();
});

const renderPanel = () =>
  render(
    <StoreProvider>
      <AccountPanel />
    </StoreProvider>,
  );

// SEC-021: the free-text destination is GONE — on the real gateway withdrawals
// always pay the bound deposit address (signed by its key); the mock has no
// binding concept, so the panel shows no destination UI at all in mock mode.
describe("AccountPanel deposit/withdraw", () => {
  it("rejects withdrawing more than the settled balance (§3)", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: "999999999" } });
    fireEvent.click(screen.getByRole("button", { name: /^withdraw$/i }));
    expect(await screen.findByText(/exceeds SETTLED/i)).toBeTruthy();
  });

  it("accepts a deposit and confirms a note was minted", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/deposited/i)).toBeTruthy();
  });

  it("rejects a non-positive amount", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: "0" } });
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/valid amount/i)).toBeTruthy();
  });

  it("hides the withdrawals section in mock mode (listWithdrawals → null)", async () => {
    renderPanel();
    // Let the mount fetch resolve; the mock client returns null ⇒ no section.
    await screen.findByText(/settled balance/i);
    expect(screen.queryByText(/^withdrawals$/i)).toBeNull();
  });

  it("shows no destination UI in mock mode (no binding concept) and no free-text address field", async () => {
    renderPanel();
    await screen.findByText(/settled balance/i);
    expect(screen.queryByLabelText(/withdrawal address/i)).toBeNull();
    expect(screen.queryByText(/bound deposit address/i)).toBeNull();
  });

  it("double-click guard: the Withdraw button disables while a withdrawal is in flight (one debit, not two)", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: /^withdraw$/i }));
    // In flight: disabled + relabeled (the WalletDepositCard `running` convention)…
    const working = screen.getByRole("button", { name: /working/i }) as HTMLButtonElement;
    expect(working.disabled).toBe(true);
    // …so the second click of a double-click is a no-op, not a second request
    // (two in flight would reuse the same nextWithdrawNonce on a real gateway).
    fireEvent.click(working);
    expect(await screen.findByText(/Settling on-chain/i)).toBeTruthy();
    // Exactly ONE $100 debit landed: 25,000 → 24,900 (a leaked second one ⇒ 24,800).
    expect(screen.getByText("$24,900.00")).toBeTruthy();
    // And the control is live again for the next withdrawal.
    const again = screen.getByRole("button", { name: /^withdraw$/i }) as HTMLButtonElement;
    expect(again.disabled).toBe(false);
  });

  it("on success: sets the settling→claimable expectation", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: /^withdraw$/i }));
    expect(await screen.findByText(/Settling on-chain/i)).toBeTruthy();
    expect(screen.getByText(/Claimable in ~10–20 min/i)).toBeTruthy();
    // SEC-021 removed the free-text destination — nothing address-like persists.
    expect(localStorage.getItem("darkperp.withdrawTo")).toBeNull();
  });
});

describe("buildClaimCommand", () => {
  const vault = "0x" + "22".repeat(20);
  const entry: WithdrawalEntry = {
    to: "0x" + "11".repeat(20),
    amount: 100_000_000n, // 100 USDC in base units (6 dp)
    nonce: 3,
    leaf: "0x" + "aa".repeat(32),
    root: "0x" + "bb".repeat(32),
    claimable: true,
    proof: ["0x" + "cc".repeat(32), "0x" + "dd".repeat(32)],
  };

  it("builds the exact cast claim call (proof comma-joined, base units verbatim)", () => {
    expect(buildClaimCommand(entry, vault)).toBe(
      `cast send ${vault} ` +
        '"claim(address,uint256,uint256,bytes32,bytes32[])" ' +
        `${entry.to} 100000000 3 ${entry.root} ` +
        `"[${entry.proof[0]},${entry.proof[1]}]" ` +
        "--rpc-url https://sepolia.base.org --private-key <YOUR_KEY>",
    );
  });

  it('renders an empty proof as "[]"', () => {
    const cmd = buildClaimCommand({ ...entry, proof: [] }, vault);
    expect(cmd).toContain('"[]"');
  });

  it("never embeds a key — only the <YOUR_KEY> placeholder", () => {
    expect(buildClaimCommand(entry, vault)).toContain("--private-key <YOUR_KEY>");
  });
});
