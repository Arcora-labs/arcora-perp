// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import App from "./App";

afterEach(cleanup);

describe("App smoke", () => {
  it("mounts the full app (store + every panel) without crashing", () => {
    // render() throws if any component faults on mount — so this alone is the
    // integration smoke test the per-module unit tests can't provide.
    render(<App />);
    // brand + primary nav are always present (Arcora sidebar)
    expect(screen.getByText("ARCORA")).toBeTruthy();
    expect(screen.getByText("Trade")).toBeTruthy();
    // the default trade view shows the selected market and the book
    expect(screen.getAllByText(/BTC\/USDC/).length).toBeGreaterThan(0);
    expect(screen.getByText(/order book/i)).toBeTruthy();
  });

  it("renders every market in the selector (multi-market)", () => {
    render(<App />);
    // sidebar market list — each market is a selectable tab (accessible name = symbol)
    for (const sym of ["BTC/USDC", "ETH/USDC", "SOL/USDC"]) {
      expect(screen.getByRole("tab", { name: sym })).toBeTruthy();
    }
  });

  it("reflects the §6 close-only toggle across the UI (banner + ticket block)", () => {
    render(<App />);
    // normal mode: the forced-exit simulate button is offered, no close-only copy yet
    expect(screen.queryByText(/close-only mode/i)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /simulate forced exit/i }));
    // close-only now surfaced loudly: the banner AND the order ticket's block notice
    expect(screen.getAllByText(/close-only mode/i).length).toBeGreaterThanOrEqual(2);
    // and it is reversible (not a dead end)
    fireEvent.click(screen.getByRole("button", { name: /resume normal/i }));
    expect(screen.queryByText(/close-only mode/i)).toBeNull();
    expect(screen.getByText(/^normal\.?$/i)).toBeTruthy();
  });

  it("navigates between the trade / account / recover tabs", () => {
    render(<App />);
    // Account tab → deposit/withdraw surface
    fireEvent.click(screen.getByRole("button", { name: /^account$/i }));
    expect(screen.getByRole("button", { name: /^deposit$/i })).toBeTruthy();
    // Recover tab → A07 account-recovery surface. The default mock client does
    // not expose live credential rotation, so the UI must fail closed rather
    // than pretending seed scanning can recover gateway account access.
    fireEvent.click(screen.getByRole("button", { name: /^recover$/i }));
    expect(screen.getByText(/account recovery/i)).toBeTruthy();
    expect(screen.getByText(/unavailable on this gateway build/i)).toBeTruthy();
    // back to Trade → the order ticket's submit button returns
    fireEvent.click(screen.getByRole("button", { name: /^trade$/i }));
    expect(screen.getByRole("button", { name: /buy btc\/usdc/i })).toBeTruthy();
  });

  it("click-to-price: clicking an order-book level fills the ticket's limit price", () => {
    render(<App />);
    const limit = screen.getByLabelText(/limit price/i) as HTMLInputElement;
    expect(limit.value).toBe(""); // starts as a market order (blank)
    // each book level is a button titled "Use <price> as limit price"
    const levels = screen.getAllByTitle(/as limit price/i);
    expect(levels.length).toBeGreaterThan(0);
    fireEvent.click(levels[0]);
    // the ticket adopted the clicked price (cross-component via store.prefillPrice)
    expect(limit.value).not.toBe("");
  });
});
