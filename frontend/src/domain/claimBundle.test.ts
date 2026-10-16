import { describe, expect, it } from "vitest";
import {
  CLAIM_BUNDLE_SCHEMA,
  CLAIM_BUNDLE_STORAGE_KEY,
  buildClaimBundle,
  claimBundleFileName,
  loadClaimBundles,
  rememberClaimBundles,
  serializeClaimBundles,
  type ClaimBundle,
} from "./claimBundle";
import type { WithdrawalEntry } from "./types";

const VAULT = "0x57e951F6a378E00e4F1b26510380E089D7c07b8B";
const entry: WithdrawalEntry = {
  to: "0x" + "11".repeat(20),
  amount: (1n << 200n) + 7n,
  nonce: 3,
  leaf: "0x" + "aa".repeat(32),
  root: "0x" + "bb".repeat(32),
  claimable: true,
  proof: ["0x" + "cc".repeat(32), "0x" + "dd".repeat(32)],
};
const NOW = new Date("2026-10-16T12:00:00.000Z");

/// In-memory Storage with optional failure injection.
function memoryStorage(fail: { get?: boolean; set?: boolean } = {}) {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k: string) => { if (fail.get) throw new Error("denied"); return map.get(k) ?? null; },
    setItem: (k: string, v: string) => { if (fail.set) throw new Error("quota"); map.set(k, v); },
  };
}

describe("claim bundle", () => {
  it("carries exactly what CollateralVault.claim needs, amount as an exact decimal string", () => {
    const b = buildClaimBundle(entry, VAULT, 84532, NOW);
    expect(b).toEqual({
      schema: CLAIM_BUNDLE_SCHEMA,
      chainId: 84532,
      vault: VAULT,
      to: entry.to,
      amount: ((1n << 200n) + 7n).toString(),
      nonce: 3,
      leaf: entry.leaf,
      root: entry.root,
      proof: entry.proof,
      createdAt: "2026-10-16T12:00:00.000Z",
    });
  });

  it("refuses entries that are not claimable yet or carry invalid data", () => {
    expect(() => buildClaimBundle({ ...entry, claimable: false }, VAULT, 84532, NOW)).toThrow();
    expect(() => buildClaimBundle({ ...entry, root: "0x" + "00".repeat(32) }, VAULT, 84532, NOW)).toThrow();
    expect(() => buildClaimBundle({ ...entry, to: "$(echo x)" }, VAULT, 84532, NOW)).toThrow();
    expect(() => buildClaimBundle(entry, VAULT, 0, NOW)).toThrow();
  });

  it("names files by chain, nonce and leaf prefix", () => {
    expect(claimBundleFileName(buildClaimBundle(entry, VAULT, 84532, NOW)))
      .toBe("arcora-claim-84532-3-aaaaaaaa.json");
  });

  it("serializes one bundle as an object and several as an array", () => {
    const b = buildClaimBundle(entry, VAULT, 84532, NOW);
    expect(JSON.parse(serializeClaimBundles([b]))).toEqual(b);
    expect(JSON.parse(serializeClaimBundles([b, { ...b, nonce: 4 }]))).toHaveLength(2);
  });
});

describe("claim bundle storage", () => {
  const first = buildClaimBundle(entry, VAULT, 84532, NOW);
  const second: ClaimBundle = { ...first, nonce: 4, leaf: "0x" + "ee".repeat(32) };

  it("remembers by leaf, never drops earlier bundles and keeps the first copy", () => {
    const storage = memoryStorage();
    expect(rememberClaimBundles([first], storage)).toBe(true);
    expect(rememberClaimBundles([second, { ...first, createdAt: "later" }], storage)).toBe(true);
    const saved = loadClaimBundles(storage);
    expect(saved.map((b) => b.nonce).sort()).toEqual([3, 4]);
    expect(saved.find((b) => b.nonce === 3)?.createdAt).toBe(first.createdAt);
    expect(JSON.parse(storage.map.get(CLAIM_BUNDLE_STORAGE_KEY)!)).toHaveLength(2);
  });

  it("denied or full storage never throws", () => {
    expect(rememberClaimBundles([first], memoryStorage({ set: true }))).toBe(false);
    expect(rememberClaimBundles([first], memoryStorage({ get: true }))).toBe(false);
    expect(loadClaimBundles(memoryStorage({ get: true }))).toEqual([]);
    expect(rememberClaimBundles([first], undefined)).toBe(false);
  });

  it("ignores corrupt stored data instead of trusting it", () => {
    const storage = memoryStorage();
    storage.map.set(CLAIM_BUNDLE_STORAGE_KEY, JSON.stringify([{ schema: "x" }, first, "junk"]));
    expect(loadClaimBundles(storage)).toEqual([first]);
    storage.map.set(CLAIM_BUNDLE_STORAGE_KEY, "{not json");
    expect(loadClaimBundles(storage)).toEqual([]);
    expect(rememberClaimBundles([second], storage)).toBe(true);
    expect(loadClaimBundles(storage)).toEqual([second]);
  });
});
