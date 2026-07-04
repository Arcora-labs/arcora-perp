// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen, cleanup, act } from "@testing-library/react";
import { StoreProvider } from "../store";
import { PriceChart, mapWireCandles } from "./PriceChart";

describe("mapWireCandles", () => {
  it("maps the gateway's 1e8-scaled string candles to chart numbers", () => {
    const out = mapWireCandles([
      { t: 60000, o: "6221252000000", h: "6223300000000", l: "6218000000000", c: "6220000000000" },
    ]);
    expect(out).toEqual([{ o: 62212.52, h: 62233, l: 62180, c: 62200 }]);
  });
});

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

// The chart builds candles client-side from the oracle tick stream and renders them on
// a <canvas> with drawing tools. happy-dom has no 2d context, so these lock the
// design-independent contract: it mounts, renders its chrome (symbol, timeframe tabs,
// drawing tools), and survives ticks + its pulse interval without throwing — the
// degenerate-input guards a reskin must not break.

describe("PriceChart robustness", () => {
  it("mounts and renders the chart chrome (canvas + timeframe tabs + tools) on first paint", () => {
    const { container } = render(
      <StoreProvider>
        <PriceChart />
      </StoreProvider>,
    );
    expect(container.querySelector("canvas")).not.toBeNull();
    // timeframe controls + the four drawing tools are present
    expect(screen.getByRole("button", { name: "15m" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /trend line/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /erase/i })).toBeTruthy();
  });

  it("survives accumulating ticks and the pulse interval without crashing", async () => {
    const { container } = render(
      <StoreProvider>
        <PriceChart />
      </StoreProvider>,
    );
    // the mock walks the price on a 1.5s interval; advance several ticks + the chart's
    // own pulse interval. The canvas-draw guards must keep this from throwing.
    for (let i = 0; i < 5; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1500);
      });
    }
    expect(container.querySelector("canvas")).not.toBeNull();
  });
});
