// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { AccountPanel } from "./AccountPanel";

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
});
