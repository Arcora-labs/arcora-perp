// @vitest-environment happy-dom
//
// L1 challenge kits in the account panel: every accepted order whose receipt
// carries an authorization is kept in this browser and can be downloaded, so
// the user can challenge its inclusion without the operator.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AccountPanel, ChallengeKitSection, RefundsSection } from "./AccountPanel";
import { StoreProvider } from "../store";
import { COLLATERAL_VAULT } from "../api/wallet";
import type { DarkPerpClient } from "../api/client";
import type { Receipt, TrackedOrder } from "../domain/types";
import { CHALLENGE_KIT_STORAGE_KEY, type ChallengeKit } from "../domain/challengeKit";
import { CHALLENGE_KIT_VECTORS } from "../testSupport/challengeKitVectors";

const KIT = CHALLENGE_KIT_VECTORS.kit;
const ACCEPTED: Receipt = CHALLENGE_KIT_VECTORS.acceptReceipt;

function order(id: string, receipt: Receipt): TrackedOrder {
  return {
    id,
    input: { marketId: 0, side: "Buy", size: 1n, limitPrice: 0n, tif: "Gtc", reduceOnly: false },
    receipt, finality: "ACCEPTED", filledSize: 0n, avgFillPrice: 0n, createdMs: 0,
  };
}
const withKit = order("o1", ACCEPTED);
const unbound = order("o2", { ...ACCEPTED, orderHash: "0x" + "ab".repeat(32), l1Challenge: null });
const tampered = order("o3", { ...ACCEPTED, orderHash: "0x" + "cd".repeat(32) });
/// A stored kit for an order the gateway no longer lists.
const earlier: ChallengeKit = { ...KIT, orderHash: "0x" + "ef".repeat(32), seqNo: 9, recvTimeMs: 500 };

function saved() {
  return JSON.parse(localStorage.getItem(CHALLENGE_KIT_STORAGE_KEY) ?? "[]") as ChallengeKit[];
}

let downloads: Array<{ name: string; blob: Blob }>;
beforeEach(() => {
  localStorage.clear();
  downloads = [];
  let lastBlob: Blob | undefined;
  vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
    lastBlob = blob as Blob;
    return "blob:kit";
  });
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    downloads.push({ name: this.download, blob: lastBlob! });
  });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

describe("ChallengeKitSection", () => {
  it("stays hidden with no kit to offer", () => {
    render(<ChallengeKitSection orders={[unbound]} />);
    expect(screen.queryByText(/challenge kits/i)).toBeNull();
  });

  it("keeps a kit only for orders whose authorization verifies", async () => {
    render(<ChallengeKitSection orders={[withKit, unbound, tampered]} />);
    await waitFor(() => expect(saved().map((k) => k.orderHash)).toEqual([KIT.orderHash]));
    expect(screen.getAllByRole("button", { name: /download challenge kit/i })).toHaveLength(1);
  });

  it("downloads the order's kit as the file the challenge tool reads", async () => {
    render(<ChallengeKitSection orders={[withKit]} />);
    fireEvent.click(await screen.findByRole("button", { name: /download challenge kit/i }));
    expect(downloads).toHaveLength(1);
    expect(downloads[0].name).toBe("arcora-challenge-84532-0-0c164689.json");
    expect(JSON.parse(await downloads[0].blob.text())).toEqual({ ...KIT, createdAt: expect.any(String) });
  });

  it("exports every saved kit, including orders no longer listed", async () => {
    localStorage.setItem(CHALLENGE_KIT_STORAGE_KEY, JSON.stringify([earlier]));
    render(<ChallengeKitSection orders={[withKit]} />);
    fireEvent.click(await screen.findByRole("button", { name: /export all challenge kits \(2\)/i }));
    const body = JSON.parse(await downloads[0].blob.text()) as ChallengeKit[];
    expect(body.map((k) => k.seqNo).sort()).toEqual([0, 9]);
    expect(downloads[0].name).toBe("arcora-challenge-kits.json");
  });

  it("explains what the kit is for and which tool checks it", async () => {
    render(<ChallengeKitSection orders={[withKit]} />);
    expect(await screen.findByText(/without the operator/i)).toBeTruthy();
    expect(screen.getByText("scripts/claim/challenge_inclusion.py")).toBeTruthy();
  });

  it("still offers the kits of listed orders when browser storage is denied", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("denied"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("denied"); });
    render(<ChallengeKitSection orders={[withKit]} />);
    fireEvent.click(await screen.findByRole("button", { name: /download challenge kit/i }));
    expect(downloads).toHaveLength(1);
    expect(screen.getByRole("button", { name: /export all challenge kits \(1\)/i })).toBeTruthy();
  });
});

describe("AccountPanel challenge kits", () => {
  it("shows the kits kept in this browser", async () => {
    localStorage.setItem(CHALLENGE_KIT_STORAGE_KEY, JSON.stringify([KIT]));
    render(<StoreProvider><AccountPanel /></StoreProvider>);
    expect(await screen.findByRole("heading", { name: /challenge kits/i })).toBeTruthy();
  });
});

describe("RefundsSection gateway-free path", () => {
  it("names the tool that finds a refundable deposit without the gateway", async () => {
    const refund = { id: 5, from: "0x" + "11".repeat(20), ownerCommit: "0x" + "ab".repeat(32), amount: 2_500_000n };
    const client = {
      listRefundableDeposits: async () => ({ deposits: [refund], vault: COLLATERAL_VAULT }),
    } as unknown as DarkPerpClient;
    render(<RefundsSection client={client} closeOnly />);
    expect(await screen.findByText("scripts/claim/refund_deposit.py")).toBeTruthy();
  });
});
