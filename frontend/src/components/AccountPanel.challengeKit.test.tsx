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
import { MockDarkPerpClient } from "../api/mockClient";
import type { DarkPerpClient } from "../api/client";
import type { Finality, TrackedOrder } from "../domain/types";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import {
  CHALLENGE_KIT_STORAGE_KEY,
  MAX_STORED_CHALLENGE_KITS,
  challengeAuthDigest,
  loadChallengeKits,
  rememberChallengeKits,
  type ChallengeKit,
  type ChallengeKitStorage,
  type ReceiptWithChallenge,
} from "../domain/challengeKit";

/// The store the account panel reads when a test sets one; otherwise the provider's.
const store = vi.hoisted(() => ({ value: null as unknown }));
vi.mock("../store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../store")>();
  type Store = ReturnType<typeof actual.useStore>;
  return { ...actual, useStore: (): Store => (store.value as Store | null) ?? actual.useStore() };
});

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
/// signed vector, so this one is signed by a test enclave key. It is newer than
/// the fixture order by `seqNo` milliseconds.
const TEST_ENCLAVE_KEY = new Uint8Array(32).fill(9);
const TEST_ENCLAVE_SIGNER = "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(TEST_ENCLAVE_KEY, false).subarray(1)).subarray(12));
function signedReceiptFor(orderHash: string, seqNo: number, beneficiary = ACCEPTED.l1Challenge!.beneficiary): ReceiptWithChallenge {
  const fields = { ...ACCEPTED, orderHash, seqNo, recvTimeMs: ACCEPTED.recvTimeMs + seqNo, enclaveSigner: TEST_ENCLAVE_SIGNER };
  const auth = { ...ACCEPTED.l1Challenge!, beneficiary };
  const sig = secp256k1.sign(challengeAuthDigest({ ...auth, ...fields }), TEST_ENCLAVE_KEY);
  return { ...fields, l1Challenge: { ...auth, signature: "0x" + sig.toCompactHex() + (27 + sig.recovery).toString(16) } };
}
const signedReceipt = (hashByte: string, seqNo: number) => signedReceiptFor("0x" + hashByte.repeat(32), seqNo);
const hashN = (n: number) => "0x" + (0x5000 + n).toString(16).padStart(64, "0");
/// `n` listed ACCEPTED orders with verifying authorizations, seqNo 1..n (signed once per file).
const signedListed: TrackedOrder[] = [];
function listedOrders(n: number): TrackedOrder[] {
  for (let i = signedListed.length + 1; i <= n; i++) signedListed.push(order(`l${i}`, signedReceiptFor(hashN(i), i)));
  return signedListed.slice(0, n);
}
/// The kit the panel builds from a listed order's receipt (no re-verification:
/// storage never re-verifies).
function kitOf(o: TrackedOrder): ChallengeKit {
  const { orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner, l1Challenge } = o.receipt as ReceiptWithChallenge;
  return { schema: KIT.schema, orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner: enclaveSigner!, l1Challenge: l1Challenge! };
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

/// Storage that accepts every write (no quota), holding `seed`.
function memoryStorage(seed: ChallengeKit[] = []) {
  const map = new Map<string, string>();
  const storage: ChallengeKitStorage = { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => { map.set(k, v); } };
  rememberChallengeKits(seed, storage);
  expect(loadChallengeKits(storage)).toHaveLength(seed.length);
  return storage;
}

async function exportedKits(count: number): Promise<ChallengeKit[]> {
  fireEvent.click(await screen.findByRole("button", { name: new RegExp(`export all challenge kits \\(${count}\\)`, "i") }));
  return JSON.parse(await downloads[downloads.length - 1].blob.text()) as ChallengeKit[];
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
  store.value = null;
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

describe("ChallengeKitSection after the account binds another deposit address", () => {
  // The gateway signs every listed order's authorization for the address bound
  // now, so a fine pays the address the account chose last.
  const OLD_BENEFICIARY = ACCEPTED.l1Challenge!.beneficiary;
  const NEW_BENEFICIARY = "0x" + "34".repeat(20);
  const before = order("o6", signedReceipt("a6", 6));
  const after = order("o6", signedReceiptFor("0x" + "a6".repeat(32), 6, NEW_BENEFICIARY));
  const beneficiaries = (kits: ChallengeKit[]) => kits.map((k) => k.l1Challenge.beneficiary);
  /// The bound address as a read sent now finds it (the account panel polls it).
  const boundNow = (depositAddress: string) => ({ depositAddress, readAtMs: performance.now() });

  /// Open the panel on `orders`, then hand it the bound address from a read
  /// sent after it opened, as the account panel does.
  function openThenRead(orders: TrackedOrder[], depositAddress: string, storage?: ChallengeKitStorage) {
    const view = render(<ChallengeKitSection orders={orders} storage={storage} />);
    const bound = boundNow(depositAddress);
    view.rerender(<ChallengeKitSection orders={orders} storage={storage} bound={bound} />);
    return { ...view, bound };
  }

  async function expectNewBeneficiaryExported() {
    await waitFor(() => expect(beneficiaries(loadChallengeKits())).toEqual([NEW_BENEFICIARY]));
    fireEvent.click(await screen.findByRole("button", { name: /export all challenge kits \(1\)/i }));
    expect(JSON.parse(await downloads[downloads.length - 1].blob.text())).toEqual(kitOf(after));
  }

  it("replaces the kit it keeps for an order with the new beneficiary's, and exports that one", async () => {
    expect(rememberChallengeKits([kitOf(before)])).toBe(true);
    openThenRead([after], NEW_BENEFICIARY);
    await expectNewBeneficiaryExported();
  });

  it("replaces it only after a read of the bound address sent after the panel opened", async () => {
    expect(rememberChallengeKits([kitOf(before)])).toBe(true);
    // A read sent earlier may be older than the kit the panel finds stored.
    const early = boundNow(NEW_BENEFICIARY);
    const { rerender } = render(<ChallengeKitSection orders={[after]} bound={early} />);
    expect(await exportedKits(1)).toEqual(kitOf(before));
    expect(loadChallengeKits()).toEqual([kitOf(before)]);
    rerender(<ChallengeKitSection orders={[after]} bound={boundNow(NEW_BENEFICIARY)} />);
    await expectNewBeneficiaryExported();
  });

  it("does the same while the panel is open, once a read finds the new address bound", async () => {
    const oldRead = boundNow(OLD_BENEFICIARY);
    const { rerender } = render(<ChallengeKitSection orders={[before]} bound={oldRead} />);
    await waitFor(() => expect(beneficiaries(loadChallengeKits())).toEqual([OLD_BENEFICIARY]));
    // The listing after the rebind arrives before the next read of the bound address.
    rerender(<ChallengeKitSection orders={[after]} bound={oldRead} />);
    expect(await exportedKits(1)).toEqual(kitOf(before));
    expect(beneficiaries(loadChallengeKits())).toEqual([OLD_BENEFICIARY]);
    rerender(<ChallengeKitSection orders={[after]} bound={boundNow(NEW_BENEFICIARY)} />);
    await expectNewBeneficiaryExported();
  });

  it("keeps the kit another tab stored for the new address when it opens with a listing from before the rebind", async () => {
    // Another tab listed the order after the account bound the new address.
    expect(rememberChallengeKits([kitOf(after)])).toBe(true);
    // This tab's listing is older than that rebind.
    openThenRead([before], NEW_BENEFICIARY);
    expect(await exportedKits(1)).toEqual(kitOf(after));
    expect(loadChallengeKits()).toEqual([kitOf(after)]);
  });

  it("does not put this tab's kit for the old address back over the one another tab stored since", async () => {
    const bound = boundNow(OLD_BENEFICIARY);
    const { rerender } = render(<ChallengeKitSection orders={[before]} bound={bound} />);
    await waitFor(() => expect(loadChallengeKits()).toEqual([kitOf(before)]));
    // Another tab: the account binds the new address, and that tab stores the order's new kit.
    expect(rememberChallengeKits([kitOf(after)])).toBe(true);
    // This tab's next listing, from before that rebind, adds an order, so the panel stores again.
    rerender(<ChallengeKitSection orders={[before, order("o7", signedReceipt("a7", 7))]} bound={bound} />);
    await screen.findByRole("button", { name: /export all challenge kits \(2\)/i });
    expect(loadChallengeKits().find((k) => k.seqNo === 6)).toEqual(kitOf(after));
    expect((await exportedKits(2)).find((k) => k.seqNo === 6)).toEqual(kitOf(after));
  });

  it("offers the new beneficiary's kit and warns when a full storage still holds the old one", async () => {
    const { storage } = fullStorage([kitOf(before)]);
    const { rerender, bound } = openThenRead([after], NEW_BENEFICIARY, storage);
    fireEvent.click(await screen.findByRole("button", { name: /export all challenge kits \(1\)/i }));
    expect(JSON.parse(await downloads[0].blob.text())).toEqual(kitOf(after));
    expect(beneficiaries(loadChallengeKits(storage))).toEqual([OLD_BENEFICIARY]);
    expect(screen.getByRole("alert").textContent).toMatch(/did not keep this kit \(its storage is blocked or full\)/i);
    // The next listing does not bring the old kit back into the offer.
    rerender(<ChallengeKitSection orders={[after, withKit]} storage={storage} bound={bound} />);
    expect(await exportedKits(2)).toContainEqual(kitOf(after));
    expect(screen.getByRole("alert").textContent).toMatch(/did not keep these kits/i);
  });

  it("keeps the kit it holds when a listing names the order with another enclave signer or settlement", async () => {
    /// The order signed by `key`, also its receipt's enclave signer, for `settlement`.
    function resigned(key: Uint8Array, settlement = ACCEPTED.l1Challenge!.settlement): TrackedOrder {
      const r = before.receipt as ReceiptWithChallenge;
      const enclaveSigner = "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(key, false).subarray(1)).subarray(12));
      const auth = { ...r.l1Challenge!, beneficiary: NEW_BENEFICIARY, settlement };
      const sig = secp256k1.sign(challengeAuthDigest({ ...r, ...auth }), key);
      return order("o6", { ...r, enclaveSigner, l1Challenge: { ...auth, signature: "0x" + sig.toCompactHex() + (27 + sig.recovery).toString(16) } });
    }
    for (const listing of [resigned(new Uint8Array(32).fill(12)), resigned(TEST_ENCLAVE_KEY, "0x" + "23".repeat(20))]) {
      const storage = memoryStorage([kitOf(before)]);
      openThenRead([listing], NEW_BENEFICIARY, storage);
      expect(await exportedKits(1)).toEqual(kitOf(before));
      expect(loadChallengeKits(storage)).toEqual([kitOf(before)]);
      expect(screen.queryByRole("alert")).toBeNull();
      cleanup();
    }
  });

  it("a panel open for another account in this browser does not put the old kit back", async () => {
    const storage = memoryStorage([kitOf(before)]);
    // Another tab, another account: its panel offers the stored kit too.
    const { rerender } = render(<ChallengeKitSection orders={[withKit]} storage={storage} />);
    await screen.findByRole("button", { name: /export all challenge kits \(2\)/i });
    // The first account's tab stores the kit for its new deposit address.
    expect(rememberChallengeKits([kitOf(after)], storage)).toBe(true);
    // This account's next listing stores its new order's kit.
    rerender(<ChallengeKitSection orders={[withKit, order("o7", signedReceipt("a7", 7))]} storage={storage} />);
    await screen.findByRole("button", { name: /export all challenge kits \(3\)/i });
    expect(loadChallengeKits(storage).find((k) => k.seqNo === 6)).toEqual(kitOf(after));
    expect((await exportedKits(3)).find((k) => k.seqNo === 6)).toEqual(kitOf(after));
  });

  /// The account panel on `orders`, with a client whose account read finds
  /// `depositAddress` bound.
  function openAccountPanel(orders: TrackedOrder[], depositAddress: string) {
    const client = new MockDarkPerpClient() as MockDarkPerpClient & Pick<DarkPerpClient, "withdrawAuthInfo">;
    client.withdrawAuthInfo = async () => ({ depositAddress, callerSigned: false });
    store.value = { client, state: { ...client.getState(), orders }, prefillPrice: null, setPrefillPrice: () => {} };
    render(<AccountPanel />);
  }

  it("the account panel replaces the kept kit once it reads the new address bound", async () => {
    expect(rememberChallengeKits([kitOf(before)])).toBe(true);
    openAccountPanel([after], NEW_BENEFICIARY);
    await expectNewBeneficiaryExported();
  });

  it("the account panel keeps another tab's kit for the bound address over a listing from before the rebind", async () => {
    expect(rememberChallengeKits([kitOf(after)])).toBe(true);
    openAccountPanel([before], NEW_BENEFICIARY);
    await screen.findByText(NEW_BENEFICIARY); // the bound address, read
    expect(loadChallengeKits()).toEqual([kitOf(after)]);
    expect(await exportedKits(1)).toEqual(kitOf(after));
  });
});

describe("ChallengeKitSection past the browser's kit bound", () => {
  // An order that never gets a settled fill (unfilled, cancelled) stays listed
  // as ACCEPTED, so an account can list more kits than this browser keeps.
  it("offers and exports the kit of every listed order that is not settled, and warns about the ones it did not keep", async () => {
    const orders = listedOrders(MAX_STORED_CHALLENGE_KITS + 20);
    const storage = memoryStorage();
    render(<ChallengeKitSection orders={orders} storage={storage} />);
    const body = await exportedKits(MAX_STORED_CHALLENGE_KITS + 20);
    expect(body.map((k) => k.seqNo).sort((a, b) => a - b))
      .toEqual(Array.from({ length: MAX_STORED_CHALLENGE_KITS + 20 }, (_, i) => i + 1));
    // The browser keeps its bound, newest first...
    const stored = loadChallengeKits(storage).map((k) => k.seqNo);
    expect(stored).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(Math.min(...stored)).toBe(21);
    // ...and says what it did not keep, and why.
    expect(screen.getByRole("alert").textContent)
      .toMatch(new RegExp(`did not keep 20 of these kits \\(it keeps at most ${MAX_STORED_CHALLENGE_KITS}\\)`, "i"));
    expect(screen.getByRole("alert").textContent).toMatch(/export now/i);
  }, 30_000);

  it("warns when another account's stored kit must go to keep this account's new one", async () => {
    const other = otherAccountKits();
    const storage = memoryStorage(other);
    render(<ChallengeKitSection orders={[withKit]} storage={storage} />);
    await expectOtherAccountKitEvicted(storage, other);
  }, 30_000);

  it("also warns when the kit that must go was stored by another tab after the panel opened", async () => {
    const other = otherAccountKits();
    const storage = memoryStorage();
    const { rerender } = render(<ChallengeKitSection orders={[unbound]} storage={storage} />);
    expect(rememberChallengeKits(other, storage)).toBe(true); // another tab, another account
    rerender(<ChallengeKitSection orders={[withKit]} storage={storage} />);
    await expectOtherAccountKitEvicted(storage, other);
  }, 30_000);

  /// Kits another account placed in this browser: a different beneficiary, all
  /// older than this account's order, none of them listed here.
  function otherAccountKits(): ChallengeKit[] {
    return Array.from({ length: MAX_STORED_CHALLENGE_KITS }, (_, i): ChallengeKit => ({
      ...KIT, orderHash: hashN(10_000 + i), seqNo: 100 + i, recvTimeMs: 1 + i,
      l1Challenge: { ...KIT.l1Challenge, beneficiary: "0x" + "77".repeat(20) },
    }));
  }

  async function expectOtherAccountKitEvicted(storage: ChallengeKitStorage, other: ChallengeKit[]) {
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(new RegExp(`did not keep 1 of these kits \\(it keeps at most ${MAX_STORED_CHALLENGE_KITS}\\)`, "i"));
    expect(alert.textContent).toMatch(/another account/i);
    // This account's kit is stored; the other account's oldest is the one that
    // went, and it is still in this session's export.
    const stored = loadChallengeKits(storage).map((k) => k.orderHash);
    expect(stored).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(stored).toContain(KIT.orderHash);
    expect(stored).not.toContain(other[0].orderHash);
    const body = await exportedKits(MAX_STORED_CHALLENGE_KITS + 1);
    expect(body.map((k) => k.orderHash)).toContain(other[0].orderHash);
    expect(body.map((k) => k.orderHash)).toContain(KIT.orderHash);
  }

  it("offers and exports a listed order whose authorization arrives after the store is full of newer kits", async () => {
    const newer = listedOrders(MAX_STORED_CHALLENGE_KITS);
    const storage = memoryStorage(newer.map(kitOf));
    // Listed before the account bound a deposit address: no authorization yet.
    const late = order("late", { ...ACCEPTED, l1Challenge: null });
    const { rerender } = render(<ChallengeKitSection orders={[...newer, late]} storage={storage} />);
    await screen.findByRole("button", { name: new RegExp(`export all challenge kits \\(${MAX_STORED_CHALLENGE_KITS}\\)`, "i") });
    expect(screen.queryByRole("alert")).toBeNull();
    // The authorization arrives; the order is older than every stored kit.
    rerender(<ChallengeKitSection orders={[...newer, withKit]} storage={storage} />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(new RegExp(`did not keep 1 of these kits \\(it keeps at most ${MAX_STORED_CHALLENGE_KITS}\\)`, "i"));
    expect(alert.textContent).not.toMatch(/another account/i); // it is this account's listed order
    const body = await exportedKits(MAX_STORED_CHALLENGE_KITS + 1);
    expect(body.find((k) => k.orderHash === KIT.orderHash)).toEqual(KIT);
  }, 30_000);

  it("stores a late listed order's kit ahead of newer kits of orders it no longer lists, and says one of those went", async () => {
    const unlisted = listedOrders(MAX_STORED_CHALLENGE_KITS).map(kitOf);
    const storage = memoryStorage(unlisted);
    const { rerender } = render(<ChallengeKitSection orders={[order("late", { ...ACCEPTED, l1Challenge: null })]} storage={storage} />);
    await screen.findByRole("button", { name: new RegExp(`export all challenge kits \\(${MAX_STORED_CHALLENGE_KITS}\\)`, "i") });
    rerender(<ChallengeKitSection orders={[withKit]} storage={storage} />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/did not keep 1 of these kits/i);
    expect(alert.textContent).toMatch(/another account/i);
    const stored = loadChallengeKits(storage).map((k) => k.orderHash);
    expect(stored).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(stored).toContain(KIT.orderHash);
    expect(stored).not.toContain(unlisted[0].orderHash); // the oldest kit of an order no longer listed went
    expect((await exportedKits(MAX_STORED_CHALLENGE_KITS + 1)).map((k) => k.orderHash)).toContain(unlisted[0].orderHash);
  }, 30_000);
});

describe("ChallengeKitSection opened again in this page", () => {
  // A kit the browser did not keep (storage blocked, or past its bound) is
  // built again from the listing each time the panel opens. The signatures
  // here are this describe's own, so the recoveries counted are too.
  const recoveries = () => vi.spyOn(secp256k1.Signature.prototype, "recoverPublicKey");
  const seqNos = (kits: ChallengeKit | ChallengeKit[]) => [kits].flat().map((k) => k.seqNo);
  /// The order's authorization, signed by another key than its receipt's enclave signer.
  function forged(o: TrackedOrder): TrackedOrder {
    const r = o.receipt as ReceiptWithChallenge;
    const sig = secp256k1.sign(challengeAuthDigest({ ...r, ...r.l1Challenge! }), new Uint8Array(32).fill(11));
    return order(o.id, { ...r, l1Challenge: { ...r.l1Challenge!, signature: "0x" + sig.toCompactHex() + (27 + sig.recovery).toString(16) } });
  }

  it("does not verify a listed order's authorization again", async () => {
    const orders = [order("o8", signedReceipt("b8", 8)), order("o9", signedReceipt("b9", 9))];
    const { storage } = deniedStorage();
    const recover = recoveries();
    const first = render(<ChallengeKitSection orders={orders} storage={storage} />);
    expect(seqNos(await exportedKits(2))).toEqual([9, 8]);
    expect(recover).toHaveBeenCalledTimes(2);
    first.unmount();
    render(<ChallengeKitSection orders={orders} storage={storage} />);
    expect(seqNos(await exportedKits(2))).toEqual([9, 8]);
    expect(recover).toHaveBeenCalledTimes(2);
  });

  it("verifies an authorization for another beneficiary, and offers its kit", async () => {
    const hash = "0x" + "ba".repeat(32);
    const before = order("o10", signedReceiptFor(hash, 10));
    const after = order("o10", signedReceiptFor(hash, 10, "0x" + "35".repeat(20)));
    const { storage } = deniedStorage();
    const recover = recoveries();
    const first = render(<ChallengeKitSection orders={[before]} storage={storage} />);
    expect(await exportedKits(1)).toEqual(kitOf(before));
    first.unmount();
    render(<ChallengeKitSection orders={[after]} storage={storage} />);
    expect(await exportedKits(1)).toEqual(kitOf(after));
    expect(recover).toHaveBeenCalledTimes(2);
  });

  it("verifies another signature over the same authorization, and offers no kit when it is not the enclave's", async () => {
    const genuine = order("o11", signedReceipt("bb", 11));
    const { storage } = deniedStorage();
    const recover = recoveries();
    const first = render(<ChallengeKitSection orders={[genuine]} storage={storage} />);
    expect(await exportedKits(1)).toEqual(kitOf(genuine));
    first.unmount();
    render(<ChallengeKitSection orders={[forged(genuine)]} storage={storage} />);
    await waitFor(() => expect(recover).toHaveBeenCalledTimes(2));
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
