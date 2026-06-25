// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { Explorer } from "./Explorer";

afterEach(cleanup);

describe("Explorer", () => {
  it("shows protocol summary, live index marks, batches, and the order-commitment log", () => {
    render(
      <StoreProvider>
        <Explorer />
      </StoreProvider>,
    );
    // section headings (use role to avoid matching body copy that mentions the same terms)
    expect(screen.getByRole("heading", { name: /^Protocol$/ })).toBeTruthy();
    expect(screen.getByRole("heading", { name: /index marks/i })).toBeTruthy();
    expect(screen.getByRole("heading", { name: /^Batches/i })).toBeTruthy();
    expect(screen.getByRole("heading", { name: /order-commitment log/i })).toBeTruthy();
    // every market appears in the marks table
    for (const sym of ["BTC/USDC", "ETH/USDC", "SOL/USDC", "HYPE/USDC", "LIT/USDC"]) {
      expect(screen.getAllByText(new RegExp(sym.replace("/", "\\/"))).length).toBeGreaterThan(0);
    }
  });
});
