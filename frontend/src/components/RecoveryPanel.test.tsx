// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { RecoveryPanel } from "./RecoveryPanel";

afterEach(cleanup);

const renderPanel = () =>
  render(
    <StoreProvider>
      <RecoveryPanel />
    </StoreProvider>,
  );

describe("RecoveryPanel (§7)", () => {
  it("does nothing for an empty seed", () => {
    renderPanel();
    fireEvent.click(screen.getByRole("button", { name: /scan/i }));
    expect(screen.queryByText(/recoverable balance/i)).toBeNull();
  });

  it("recovers notes from a seed and shows the recoverable balance", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText(/recovery seed/i), {
      target: { value: "alice-seed" },
    });
    fireEvent.click(screen.getByRole("button", { name: /scan/i }));
    expect(await screen.findByText(/recoverable balance/i)).toBeTruthy();
    // at least one recovered (unspent) note row is shown
    expect(screen.getAllByText(/^recovered$/i).length).toBeGreaterThan(0);
  });
});
