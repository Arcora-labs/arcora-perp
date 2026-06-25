// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen, cleanup, act } from "@testing-library/react";
import { StoreProvider } from "../store";
import { PriceChart } from "./PriceChart";

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

// The chart does real geometry on the price series (min/max/span, SVG coords).
// These lock the degenerate-input guards a reskin must not break.

describe("PriceChart robustness", () => {
  it("shows the collecting state with a single tick (no path math on length < 2)", () => {
    render(
      <StoreProvider>
        <PriceChart />
      </StoreProvider>,
    );
    // a fresh series holds exactly one tick → the collecting state, no <path> drawn
    expect(screen.getByText(/collecting ticks/i)).toBeTruthy();
    expect(document.querySelector("path")).toBeNull();
  });

  it("draws a path with only finite coordinates once ticks accumulate", async () => {
    render(
      <StoreProvider>
        <PriceChart />
      </StoreProvider>,
    );
    // the mock client walks the price on a 1.5s interval; advance a few ticks so the
    // series grows past the length-2 threshold and the SVG path renders.
    for (let i = 0; i < 4; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1500);
      });
    }
    const path = document.querySelector("path");
    expect(path, "a path should render once >= 2 ticks are buffered").not.toBeNull();
    const d = path!.getAttribute("d") ?? "";
    // the span/coord math must never emit NaN/Infinity (a flat or single-point
    // series would otherwise poison the path and break the chart silently)
    expect(d).not.toMatch(/NaN|Infinity/);
    expect(d.length).toBeGreaterThan(0);
  });
});
