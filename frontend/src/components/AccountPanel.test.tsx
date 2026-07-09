// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { AccountPanel, buildClaimCommand } from "./AccountPanel";
import type { WithdrawalEntry } from "../domain/types";

afterEach(cleanup);

const renderPanel = () =>
  render(
    <StoreProvider>
      <AccountPanel />
    </StoreProvider>,
  );

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
