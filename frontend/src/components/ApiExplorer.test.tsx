// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { ApiExplorer } from "./ApiExplorer";

afterEach(cleanup);

const renderEx = () =>
  render(
    <StoreProvider>
      <ApiExplorer />
    </StoreProvider>,
  );

describe("ApiExplorer", () => {
  it("renders cards for the core DarkPerpClient methods", () => {
    renderEx();
    expect(screen.getByText(/placeOrder\(input\)/)).toBeTruthy();
    expect(screen.getByText(/deposit \/ requestWithdrawal/)).toBeTruthy();
    expect(screen.getByText(/recover\(seed\)/)).toBeTruthy();
  });

  it("invokes placeOrder and shows the Receipt response", async () => {
    renderEx();
    fireEvent.click(screen.getByRole("button", { name: /call placeorder/i }));
    // the response panel shows the call label and the returned Receipt's fields
    expect(await screen.findByText(/placeOrder →/)).toBeTruthy();
    expect(await screen.findByText(/orderHash/)).toBeTruthy();
  });

  it("surfaces an API error in the response panel (withdraw beyond balance)", async () => {
    renderEx();
    fireEvent.change(screen.getByLabelText(/amount/i), { target: { value: "999999999" } });
    fireEvent.click(screen.getByRole("button", { name: /requestWithdrawal/i }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/exceeds SETTLED/i);
  });

  it("announces responses via a polite live region (a11y)", () => {
    renderEx();
    // the response output is a labelled live region, so a screen-reader user hears
    // the result after invoking a method (it updates silently otherwise)
    const out = screen.getByLabelText(/api response/i);
    expect(out.getAttribute("aria-live")).toBe("polite");
  });
});
