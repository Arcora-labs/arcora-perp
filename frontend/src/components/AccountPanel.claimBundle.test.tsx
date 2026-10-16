// @vitest-environment happy-dom
//
// Claim bundles in the withdrawals list: every claimable entry is kept in this
// browser and can be downloaded, so the user can claim without the operator.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { WithdrawalsSection } from "./AccountPanel";
import { COLLATERAL_VAULT } from "../api/wallet";
import type { DarkPerpClient } from "../api/client";
import type { WithdrawalEntry } from "../domain/types";
import { CLAIM_BUNDLE_STORAGE_KEY } from "../domain/claimBundle";

const claimable: WithdrawalEntry = {
  to: "0x" + "11".repeat(20),
  amount: 100_000_000n,
  nonce: 3,
  leaf: "0x" + "aa".repeat(32),
  root: "0x" + "bb".repeat(32),
  claimable: true,
  proof: ["0x" + "cc".repeat(32)],
};
const pending: WithdrawalEntry = {
  ...claimable,
  nonce: 4,
  leaf: "0x" + "ee".repeat(32),
  root: "0x" + "00".repeat(32),
  claimable: false,
  proof: [],
};

function client(withdrawals: WithdrawalEntry[]) {
  return {
    listWithdrawals: async () => ({ withdrawals, vault: COLLATERAL_VAULT }),
  } as unknown as DarkPerpClient;
}

function saved() {
  return JSON.parse(localStorage.getItem(CLAIM_BUNDLE_STORAGE_KEY) ?? "[]") as Array<{ nonce: number }>;
}

let downloads: Array<{ name: string; blob: Blob }>;
beforeEach(() => {
  localStorage.clear();
  downloads = [];
  let lastBlob: Blob | undefined;
  vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
    lastBlob = blob as Blob;
    return "blob:claim";
  });
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    downloads.push({ name: this.download, blob: lastBlob! });
  });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("WithdrawalsSection claim bundles", () => {
  it("keeps a bundle for each claimable entry only", async () => {
    render(<WithdrawalsSection client={client([claimable, pending])} />);
    await screen.findByText(/^Claimable$/);
    await waitFor(() => expect(saved().map((b) => b.nonce)).toEqual([3]));
  });

  it("downloads the entry's bundle as a JSON file", async () => {
    render(<WithdrawalsSection client={client([claimable])} />);
    fireEvent.click(await screen.findByRole("button", { name: /download claim file/i }));
    expect(downloads).toHaveLength(1);
    expect(downloads[0].name).toBe("arcora-claim-84532-3-aaaaaaaa.json");
    const body = JSON.parse(await downloads[0].blob.text());
    expect(body).toMatchObject({
      schema: "arcora.claim-bundle.v1",
      chainId: 84532,
      vault: COLLATERAL_VAULT,
      amount: "100000000",
      nonce: 3,
      root: claimable.root,
      proof: claimable.proof,
    });
  });

  it("exports every saved bundle, including ones no longer listed", async () => {
    const earlier = { ...claimable, nonce: 1, leaf: "0x" + "ab".repeat(32) };
    const first = render(<WithdrawalsSection client={client([earlier])} />);
    await waitFor(() => expect(saved()).toHaveLength(1));
    first.unmount();

    render(<WithdrawalsSection client={client([claimable])} />);
    fireEvent.click(await screen.findByRole("button", { name: /export all claim files \(2\)/i }));
    const body = JSON.parse(await downloads[0].blob.text());
    expect(body.map((b: { nonce: number }) => b.nonce).sort()).toEqual([1, 3]);
  });

  it("explains that the file allows claiming without the operator", async () => {
    render(<WithdrawalsSection client={client([claimable])} />);
    expect(await screen.findByText(/without the operator/i)).toBeTruthy();
  });

  it("still works when browser storage is denied", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("denied"); });
    render(<WithdrawalsSection client={client([claimable])} />);
    fireEvent.click(await screen.findByRole("button", { name: /download claim file/i }));
    expect(downloads).toHaveLength(1);
  });
});
