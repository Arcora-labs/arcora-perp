// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ErrorBoundary } from "./ErrorBoundary";

function Boom(): never {
  throw new Error("kaboom");
}

describe("ErrorBoundary", () => {
  it("renders children when there is no error", () => {
    render(
      <ErrorBoundary>
        <div>safe content</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText("safe content")).toBeTruthy();
  });

  it("catches a child render error and shows the contained fallback", () => {
    // React logs the caught error; silence that expected noise for a clean run
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    // role=alert fallback is shown, with the title and the error message
    expect(screen.getByRole("alert")).toBeTruthy();
    expect(screen.getByText(/something went wrong/i)).toBeTruthy();
    expect(screen.getByText(/kaboom/)).toBeTruthy();
    // the careful copy: a UI fault is not a protocol action
    expect(screen.getByText(/not a protocol action/i)).toBeTruthy();
    spy.mockRestore();
  });
});
