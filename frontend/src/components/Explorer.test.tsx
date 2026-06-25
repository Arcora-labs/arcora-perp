// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { StoreProvider, useStore } from "../store";
import { Explorer } from "./Explorer";
import { useEffect } from "react";

afterEach(cleanup);

/// Seeds one order through the live mock client so the order-log filter UI mounts
/// (the filters only render once there is at least one logged order).
function SeedOneOrder() {
  const { client, state } = useStore();
  useEffect(() => {
    void client.placeOrder({
      marketId: state.selectedMarketId,
      side: "Buy",
      size: 1_00000000n,
      limitPrice: state.marks[state.selectedMarketId] ?? 100_000_00000000n,
      tif: "Gtc",
      reduceOnly: false,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return null;
}

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

  it("renders the order-log search + finality filter once an order is logged, and filters it out", async () => {
    render(
      <StoreProvider>
        <SeedOneOrder />
        <Explorer />
      </StoreProvider>,
    );
    // the filter UI mounts only after the seeded order lands in the log
    const search = await screen.findByLabelText(/search order log/i);
    expect(screen.getByRole("group", { name: /filter by finality/i })).toBeTruthy();

    // the finality chips are an exclusive toggle (aria-pressed tracks selection)
    const allChip = screen.getByRole("button", { name: /^All$/ });
    const matchedChip = screen.getByRole("button", { name: /^Matched$/ });
    expect(allChip.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(matchedChip);
    expect(matchedChip.getAttribute("aria-pressed")).toBe("true");
    expect(allChip.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(allChip);

    // a non-matching search term empties the table → empty-state copy shows
    fireEvent.change(search, { target: { value: "zzzz-no-such-hash" } });
    await waitFor(() =>
      expect(screen.getByText(/no orders match the current search\/filter/i)).toBeTruthy(),
    );
  });
});
