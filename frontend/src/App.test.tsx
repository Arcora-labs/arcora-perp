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
    // header is always present
    expect(screen.getByText("dark-perp")).toBeTruthy();
    expect(screen.getByText("Trade")).toBeTruthy();
    // the default trade view shows the market and the book
    expect(screen.getAllByText(/BTC\/USDC/).length).toBeGreaterThan(0);
    expect(screen.getByText(/order book/i)).toBeTruthy();
  });

  it("renders every market in the selector (multi-market)", () => {
    render(<App />);
    for (const sym of ["BTC/USDC", "ETH/USDC", "SOL/USDC", "HYPE/USDC", "LIT/USDC"]) {
      expect(screen.getAllByText(new RegExp(sym.replace("/", "\\/"))).length).toBeGreaterThan(0);
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
});
