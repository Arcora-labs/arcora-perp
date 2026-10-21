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
import {
  CLAIM_BUNDLE_STORAGE_KEY,
  buildClaimBundle,
  loadClaimBundles,
  rememberClaimBundles,
  type ClaimBundleStorage,
} from "../domain/claimBundle";

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
const later: WithdrawalEntry = { ...claimable, nonce: 5, leaf: "0x" + "ab".repeat(32) };

function client(withdrawals: WithdrawalEntry[]) {
  return {
    listWithdrawals: async () => ({ withdrawals, vault: COLLATERAL_VAULT }),
  } as unknown as DarkPerpClient;
}

function saved() {
  return JSON.parse(localStorage.getItem(CLAIM_BUNDLE_STORAGE_KEY) ?? "[]") as Array<{ nonce: number }>;
}

/// Storage the browser refuses (blocked site data): every access throws, and
/// each attempt is counted so the test proves the denial was exercised.
function deniedStorage() {
  const attempts = { get: 0, set: 0 };
  const storage: ClaimBundleStorage = {
    getItem: () => { attempts.get++; throw new DOMException("denied", "SecurityError"); },
    setItem: () => { attempts.set++; throw new DOMException("denied", "SecurityError"); },
  };
  return { storage, attempts };
}

/// Storage that reads but, while `full`, refuses every write for quota, holding
/// the bundles of `seed`.
function fullStorage(seed: WithdrawalEntry[] = []) {
  const map = new Map<string, string>();
  const state = { full: false };
  const storage: ClaimBundleStorage = {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      if (state.full) throw new DOMException("quota exceeded", "QuotaExceededError");
      map.set(k, v);
    },
  };
  expect(rememberClaimBundles(seed.map((w) => buildClaimBundle(w, COLLATERAL_VAULT, 84532)), storage)).toBe(true);
  state.full = true;
  return { storage, state };
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
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("WithdrawalsSection claim bundles", () => {
  it("keeps a bundle for each claimable entry only", async () => {
    render(<WithdrawalsSection client={client([claimable, pending])} />);
    await screen.findByText(/^Claimable$/);
    await waitFor(() => expect(saved().map((b) => b.nonce)).toEqual([3]));
    expect(screen.queryByRole("alert")).toBeNull();
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
    const denied = deniedStorage();
    render(<WithdrawalsSection client={client([claimable])} storage={denied.storage} />);
    fireEvent.click(await screen.findByRole("button", { name: /download claim file/i }));
    // The section really ran against the refusing storage, and nothing leaked
    // into the page's own localStorage.
    expect(denied.attempts.get).toBeGreaterThan(0);
    expect(saved()).toEqual([]);
    expect(downloads).toHaveLength(1);
    expect(JSON.parse(await downloads[0].blob.text())).toMatchObject({ nonce: 3, leaf: claimable.leaf });
  });
});

describe("WithdrawalsSection when this browser does not keep a claim file", () => {
  it("warns when browser storage is denied, and says how to get the claim data", async () => {
    render(<WithdrawalsSection client={client([later, claimable, pending])} storage={deniedStorage().storage} />);
    const warning = (await screen.findByRole("alert")).textContent;
    expect(warning).toMatch(/did not keep the claim files of 2 claimable withdrawals \(its storage is blocked or full\)/i);
    expect(warning).toMatch(/download claim file/i);
    expect(warning).toMatch(/offered again only while the gateway still lists the withdrawal/i);
  });

  it("counts only what a full storage does not already hold, and clears once it is kept", async () => {
    const { storage, state } = fullStorage([claimable]);
    const { rerender } = render(<WithdrawalsSection client={client([later, claimable])} storage={storage} />);
    expect((await screen.findByRole("alert")).textContent)
      .toMatch(/did not keep the claim file of 1 claimable withdrawal \(its storage is blocked or full\)/i);
    // Room again: the next listing keeps it and the warning goes.
    state.full = false;
    rerender(<WithdrawalsSection client={client([later, claimable])} storage={storage} />);
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(loadClaimBundles(storage).map((b) => b.nonce).sort()).toEqual([3, 5]);
  });

  it("warns the same way when this origin's localStorage itself throws", async () => {
    const refuse = () => { throw new DOMException("denied", "SecurityError"); };
    vi.stubGlobal("localStorage", { getItem: refuse, setItem: refuse, removeItem: refuse, clear: refuse });
    expect(() => localStorage.getItem(CLAIM_BUNDLE_STORAGE_KEY)).toThrow(/denied/);
    render(<WithdrawalsSection client={client([claimable])} />);
    expect((await screen.findByRole("alert")).textContent)
      .toMatch(/did not keep the claim file of 1 claimable withdrawal \(its storage is blocked or full\)/i);
    fireEvent.click(screen.getByRole("button", { name: /download claim file/i }));
    expect(downloads).toHaveLength(1);
  });

  it("does not warn while no withdrawal is claimable", async () => {
    const denied = deniedStorage();
    render(<WithdrawalsSection client={client([pending])} storage={denied.storage} />);
    await screen.findByText(/awaiting on-chain settlement/i);
    expect(denied.attempts.get).toBeGreaterThan(0);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
