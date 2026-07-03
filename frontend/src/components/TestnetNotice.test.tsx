// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { TestnetNotice } from "./TestnetNotice";

afterEach(cleanup);
beforeEach(() => localStorage.clear());

describe("TestnetNotice", () => {
  it("discloses that funds are not real and proofs are mocked", () => {
    render(<TestnetNotice />);
    expect(screen.getByText(/funds are not real/i)).toBeTruthy();
    expect(screen.getByText(/mocked/i)).toBeTruthy();
  });

  it("reveals the test-USDC mint instructions on demand", () => {
    render(<TestnetNotice />);
    expect(screen.queryByText(/mint\(address,uint256\)/)).toBeNull();
    fireEvent.click(screen.getByText(/get test usdc/i));
    expect(screen.getByText(/mint\(address,uint256\)/)).toBeTruthy();
  });

  it("stays dismissed once acknowledged", () => {
    const { unmount } = render(<TestnetNotice />);
    fireEvent.click(screen.getByText(/got it/i));
    expect(screen.queryByText(/funds are not real/i)).toBeNull();
    unmount();
    render(<TestnetNotice />);
    expect(screen.queryByText(/funds are not real/i)).toBeNull();
  });
});
