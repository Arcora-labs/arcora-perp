// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { TestnetNotice } from "./TestnetNotice";

afterEach(cleanup);
beforeEach(() => localStorage.clear());

describe("TestnetNotice", () => {
  it("describes a test environment without asserting deployment capabilities", () => {
    render(<TestnetNotice />);
    const notice = screen.getByRole("note");
    expect(notice.textContent).toContain("Test environment — test assets only.");
    expect(notice.textContent).toContain("Order acceptance does not mean on-chain settlement.");
    expect(notice.textContent).toContain("Health");
    expect(notice.textContent).toContain("Explorer");
    expect(notice.textContent).not.toMatch(/Azure|TDX|Groth16|TLS|10–20|real zk|confirm instantly/i);
  });

  it("reveals the test-USDC mint instructions on demand", () => {
    render(<TestnetNotice />);
    expect(screen.queryByText(/mint\(address,uint256\)/)).toBeNull();
    fireEvent.click(screen.getByText(/get test usdc/i));
    expect(screen.getByText(/mint\(address,uint256\)/)).toBeTruthy();
    // SEC-019: the bare-cast deposit command is GONE (the vault would revert
    // it) — the notice must point at the gateway-authorized in-app flow instead.
    expect(screen.queryByText(/deposit\(uint256\)/)).toBeNull();
    expect(screen.getByText(/deposit\/authorize/)).toBeTruthy();
    expect(screen.getByText(/original deposit transaction hash/i)).toBeTruthy();
    expect(screen.getByText(/do not send another deposit/i)).toBeTruthy();
    expect(screen.queryByText(/register an API key/i)).toBeNull();
  });

  it("stays dismissed once acknowledged", () => {
    const { unmount } = render(<TestnetNotice />);
    fireEvent.click(screen.getByText(/got it/i));
    expect(screen.queryByText(/test assets only/i)).toBeNull();
    unmount();
    render(<TestnetNotice />);
    expect(screen.queryByText(/test assets only/i)).toBeNull();
  });
});


it("resurfaces the corrected notice after the old version was dismissed", () => {
  localStorage.setItem("dp_testnet_notice_dismissed_v5", "1");
  render(<TestnetNotice />);
  expect(screen.getByRole("note")).toBeTruthy();
  fireEvent.click(screen.getByText(/got it/i));
  expect(localStorage.getItem("dp_testnet_notice_dismissed_v6")).toBe("1");
});
