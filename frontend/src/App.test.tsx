// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
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
});
