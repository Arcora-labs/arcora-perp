// @vitest-environment happy-dom
//
// L1 challenge kits in the account panel: every listed order whose receipt
// carries an authorization is kept in this browser and can be downloaded, so
// the user can challenge its inclusion without the operator.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AccountPanel, ChallengeKitSection, RefundsSection } from "./AccountPanel";
import { StoreProvider } from "../store";
import { COLLATERAL_VAULT } from "../api/wallet";
import type { DarkPerpClient } from "../api/client";
import type { Finality, TrackedOrder } from "../domain/types";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import {
  CHALLENGE_KIT_STORAGE_KEY,
  challengeAuthDigest,
  loadChallengeKits,
  rememberChallengeKits,
  type ChallengeKit,
  type ChallengeKitStorage,
  type ReceiptWithChallenge,
} from "../domain/challengeKit";

// Shared with scripts/challenge/test_challenge_kit.py; read at test time so the
// production build never depends on a file outside frontend/.
const VECTORS: { acceptReceipt: ReceiptWithChallenge; kit: ChallengeKit } = JSON.parse(readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../scripts/challenge/fixtures/challenge-kit-vectors.json"),
  "utf8",
));
const KIT = VECTORS.kit;
const ACCEPTED = VECTORS.acceptReceipt;

function order(id: string, receipt: ReceiptWithChallenge, finality: Finality = "ACCEPTED"): TrackedOrder {
  return {
    id,
    input: { marketId: 0, side: "Buy", size: 1n, limitPrice: 0n, tif: "Gtc", reduceOnly: false },
    receipt, finality, filledSize: 0n, avgFillPrice: 0n, createdMs: 0,
  };
}
const withKit = order("o1", ACCEPTED);
const unbound = order("o2", { ...ACCEPTED, orderHash: "0x" + "ab".repeat(32), l1Challenge: null });
const tampered = order("o3", { ...ACCEPTED, orderHash: "0x" + "cd".repeat(32) });
/// Another accepted order whose authorization verifies: the fixture holds one
/// signed vector, so this one is signed by a test enclave key.
function signedReceipt(hashByte: string, seqNo: number): ReceiptWithChallenge {
  const key = new Uint8Array(32).fill(9);
  const enclaveSigner = "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(key, false).subarray(1)).subarray(12));
  const fields = { ...ACCEPTED, orderHash: "0x" + hashByte.repeat(32), seqNo, recvTimeMs: ACCEPTED.recvTimeMs + seqNo, enclaveSigner };
  const auth = ACCEPTED.l1Challenge!;
  const sig = secp256k1.sign(challengeAuthDigest({ ...auth, ...fields }), key);
  return { ...fields, l1Challenge: { ...auth, signature: "0x" + sig.toCompactHex() + (27 + sig.recovery).toString(16) } };
}
/// A stored kit for an order the gateway no longer lists.
const earlier: ChallengeKit = { ...KIT, orderHash: "0x" + "ef".repeat(32), seqNo: 9, recvTimeMs: 500 };

/// Storage the browser refuses (blocked site data): every access throws, and
/// each attempt is counted so the test proves the denial was exercised.
function deniedStorage() {
  const attempts = { get: 0, set: 0 };
  const storage: ChallengeKitStorage = {
    getItem: () => { attempts.get++; throw new DOMException("denied", "SecurityError"); },
    setItem: () => { attempts.set++; throw new DOMException("denied", "SecurityError"); },
  };
  return { storage, attempts };
}

/// Storage that reads but, while `full`, refuses every write for quota.
function fullStorage(seed: ChallengeKit[] = []) {
  const map = new Map<string, string>();
  const state = { full: false };
  const storage: ChallengeKitStorage = {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      if (state.full) throw new DOMException("quota exceeded", "QuotaExceededError");
      map.set(k, v);
    },
  };
  expect(rememberChallengeKits(seed, storage)).toBe(true);
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
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("ChallengeKitSection", () => {
  it("stays hidden with no kit to offer", () => {
    render(<ChallengeKitSection orders={[unbound]} />);
    expect(screen.queryByText(/challenge kits/i)).toBeNull();
  });

  it("keeps a kit only for orders whose authorization verifies", async () => {
    render(<ChallengeKitSection orders={[withKit, unbound, tampered]} />);
    await waitFor(() => expect(loadChallengeKits().map((k) => k.orderHash)).toEqual([KIT.orderHash]));
    expect(screen.getAllByRole("button", { name: /download challenge kit/i })).toHaveLength(1);
  });

  it("keeps no kit for an order that is already settled", async () => {
    render(<ChallengeKitSection orders={[order("o4", ACCEPTED, "SETTLED")]} />);
    await new Promise((r) => setTimeout(r, 0));
    expect(loadChallengeKits()).toEqual([]);
    expect(screen.queryByText(/challenge kits/i)).toBeNull();
  });

  it("downloads the order's kit as the file the challenge tool reads", async () => {
    render(<ChallengeKitSection orders={[withKit]} />);
    fireEvent.click(await screen.findByRole("button", { name: /download challenge kit/i }));
    expect(downloads).toHaveLength(1);
    expect(downloads[0].name).toBe("arcora-challenge-84532-0-0c164689.json");
    expect(JSON.parse(await downloads[0].blob.text())).toEqual(KIT);
  });

  it("exports every saved kit, including orders no longer listed", async () => {
    expect(rememberChallengeKits([earlier])).toBe(true);
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

  it("still offers the kits of listed orders when browser storage is denied, and says they are not kept", async () => {
    const denied = deniedStorage();
    render(<ChallengeKitSection orders={[withKit]} storage={denied.storage} />);
    fireEvent.click(await screen.findByRole("button", { name: /download challenge kit/i }));
    // The section really ran against the refusing storage, and nothing leaked
    // into the page's own localStorage.
    expect(denied.attempts.get).toBeGreaterThan(0);
    expect(loadChallengeKits()).toEqual([]);
    expect(downloads).toHaveLength(1);
    expect(JSON.parse(await downloads[0].blob.text())).toEqual(KIT);
    expect(screen.getByRole("button", { name: /export all challenge kits \(1\)/i })).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toMatch(/did not keep this kit \(its storage is blocked or full\)/i);
  });

  it("falls back the same way when this origin's localStorage itself throws", async () => {
    const refuse = () => { throw new DOMException("denied", "SecurityError"); };
    vi.stubGlobal("localStorage", { getItem: refuse, setItem: refuse, removeItem: refuse, clear: refuse });
    expect(() => localStorage.getItem(CHALLENGE_KIT_STORAGE_KEY)).toThrow(/denied/);
    render(<ChallengeKitSection orders={[withKit]} />);
    fireEvent.click(await screen.findByRole("button", { name: /download challenge kit/i }));
    expect(JSON.parse(await downloads[0].blob.text())).toEqual(KIT);
    expect(screen.getByRole("alert").textContent).toMatch(/did not keep this kit \(its storage is blocked or full\)/i);
  });

  it("says how many kits a full storage did not keep, and stores them once there is room", async () => {
    const { storage, state } = fullStorage([earlier]);
    const { rerender } = render(<ChallengeKitSection orders={[withKit]} storage={storage} />);
    expect(await screen.findByRole("button", { name: /export all challenge kits \(2\)/i })).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toMatch(/did not keep 1 of these kits/i);
    expect(loadChallengeKits(storage).map((k) => k.seqNo)).toEqual([9]);
    // Room again: the next listed order stores its kit and the session's unsaved one.
    state.full = false;
    const next = order("o5", signedReceipt("ab", 7));
    rerender(<ChallengeKitSection orders={[withKit, next]} storage={storage} />);
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(loadChallengeKits(storage).map((k) => k.seqNo)).toEqual([7, 0, 9]);
    expect(screen.getByRole("button", { name: /export all challenge kits \(3\)/i })).toBeTruthy();
  });

  it("drops an order's kit once the gateway lists the order as SETTLED", async () => {
    const { rerender } = render(<ChallengeKitSection orders={[withKit]} />);
    await waitFor(() => expect(loadChallengeKits()).toHaveLength(1));
    rerender(<ChallengeKitSection orders={[order("o1", ACCEPTED, "SETTLED")]} />);
    await waitFor(() => expect(loadChallengeKits()).toEqual([]));
    expect(screen.queryByText(/challenge kits/i)).toBeNull();
  });
});

describe("AccountPanel challenge kits", () => {
  it("shows the kits kept in this browser", async () => {
    expect(rememberChallengeKits([KIT])).toBe(true);
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
