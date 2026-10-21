import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  CHALLENGE_KIT_SCHEMA,
  CHALLENGE_KIT_STORAGE_KEY,
  MAX_STORED_CHALLENGE_KITS,
  buildChallengeKit,
  challengeAuthDigest,
  challengeKitFileName,
  loadChallengeKits,
  mergeChallengeKits,
  newChallengeKits,
  parseL1Challenge,
  recoverChallengeSigner,
  rememberChallengeKits,
  seenChallengeKits,
  serializeChallengeKits,
  settledOrderHashes,
  unsettledOrderHashes,
  withL1Challenge,
  type ChallengeKit,
  type ReceiptWithChallenge,
} from "./challengeKit";
import { buildClaimBundle, loadClaimBundles, rememberClaimBundles } from "./claimBundle";

// Shared with scripts/challenge/test_challenge_kit.py, which runs the same kit
// through scripts/claim/challenge_inclusion.py: the file this module produces is
// exactly what the gateway-free tool checks. Read at test time, so the
// production build never depends on a file outside frontend/.
interface Vectors {
  enclaveSigner: string;
  digestVectors: Array<{
    name: string; chainId: number; settlement: string; orderHash: string; seqNo: number;
    recvTimeMs: number; batchIdHint: number; beneficiary: string; digest: string;
  }>;
  acceptReceipt: ReceiptWithChallenge;
  kit: ChallengeKit;
}
const V: Vectors = JSON.parse(readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "../../../scripts/challenge/fixtures/challenge-kit-vectors.json"),
  "utf8",
));

const receipt = (): ReceiptWithChallenge => structuredClone(V.acceptReceipt);
const SIG = V.kit.l1Challenge.signature;
/// The fixture enclave's key (seed 0x07..07), to sign the fixture order for
/// another beneficiary, as the gateway does once the account binds another
/// deposit address.
const FIXTURE_ENCLAVE_KEY = new Uint8Array(32).fill(7);
const NEW_BENEFICIARY = "0x" + "34".repeat(20);
function reboundReceipt(beneficiary = NEW_BENEFICIARY): ReceiptWithChallenge {
  const r = receipt();
  const auth = { ...r.l1Challenge!, beneficiary };
  const sig = secp256k1.sign(challengeAuthDigest({ ...r, ...auth }), FIXTURE_ENCLAVE_KEY);
  return { ...r, l1Challenge: { ...auth, signature: "0x" + sig.toCompactHex() + (27 + sig.recovery).toString(16) } };
}

function memoryStorage(fail: { get?: boolean; set?: boolean } = {}) {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k: string) => { if (fail.get) throw new Error("denied"); return map.get(k) ?? null; },
    setItem: (k: string, v: string) => { if (fail.set) throw new Error("quota"); map.set(k, v); },
  };
}

/// A browser-like localStorage: keys and values count against one quota, and a
/// write that would exceed it throws, as `QuotaExceededError` does.
function quotaStorage(quota: number) {
  const map = new Map<string, string>();
  const used = () => [...map].reduce((n, [k, v]) => n + k.length + v.length, 0);
  return {
    map,
    used,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => {
      if (used() - (map.has(k) ? k.length + map.get(k)!.length : 0) + k.length + v.length > quota) {
        throw new DOMException("quota exceeded", "QuotaExceededError");
      }
      map.set(k, v);
    },
  };
}

/// A distinct, well-formed kit (shape only: storage never re-verifies), with
/// realistically sized numbers (a millisecond clock, a large sequence number).
function kitN(n: number): ChallengeKit {
  return {
    ...V.kit, orderHash: "0x" + n.toString(16).padStart(64, "0"), seqNo: 1_000_000 + n,
    recvTimeMs: 1_760_000_000_000 + n, batchIdHint: 10_000 + n,
  };
}
const seqOf = (k: ChallengeKit) => k.seqNo - 1_000_000;

describe("challenge authorization digest and signer", () => {
  it("matches the Solidity/Rust vectors A and B", () => {
    for (const v of V.digestVectors) {
      expect("0x" + bytesToHex(challengeAuthDigest(v)), v.name).toBe(v.digest);
    }
  });

  it("recovers authorization A to the fixture enclave signer", () => {
    expect(recoverChallengeSigner(V.digestVectors[0], SIG)).toBe(V.enclaveSigner);
  });

  it("refuses signatures the settlement refuses (high s, v not 27/28, zero r)", () => {
    const sig = hexToBytes(SIG.slice(2));
    const s = BigInt("0x" + bytesToHex(sig.subarray(32, 64)));
    const highS = new Uint8Array(sig);
    highS.set(hexToBytes((secp256k1.CURVE.n - s).toString(16).padStart(64, "0")), 32);
    highS[64] = sig[64] === 27 ? 28 : 27;
    const badV = new Uint8Array(sig); badV[64] = 1;
    const zeroR = new Uint8Array(sig); zeroR.fill(0, 0, 32);
    for (const bad of [highS, badV, zeroR]) {
      expect(recoverChallengeSigner(V.digestVectors[0], "0x" + bytesToHex(bad))).toBeNull();
    }
  });
});

describe("parseL1Challenge", () => {
  it("keeps exactly the four authorization fields", () => {
    expect(parseL1Challenge({ ...V.kit.l1Challenge, extra: "x" })).toEqual(V.kit.l1Challenge);
  });

  it("separates 'no authorization' (null) from absent or malformed (undefined)", () => {
    expect(parseL1Challenge(null)).toBeNull();
    expect(parseL1Challenge(undefined)).toBeUndefined();
    const good = V.kit.l1Challenge;
    for (const bad of [
      "x", [], { ...good, chainId: 0 }, { ...good, chainId: "84532" }, { ...good, chainId: 2 ** 53 },
      { ...good, settlement: "0x12" }, { ...good, beneficiary: "0x" + "00".repeat(20) },
      { ...good, beneficiary: "$(id)" }, { ...good, signature: "0x" + "11".repeat(64) },
    ]) {
      expect(parseL1Challenge(bad)).toBeUndefined();
    }
  });
});

describe("withL1Challenge (realClient's stored-receipt decoding)", () => {
  const base = { orderHash: "0x" + "a1".repeat(32), seqNo: 3, recvTimeMs: 7, batchIdHint: 2 };

  it("keeps a well-formed authorization with its four fields only", () => {
    expect(withL1Challenge(base, { ...V.kit.l1Challenge, extra: 1 })).toEqual({ ...base, l1Challenge: V.kit.l1Challenge });
  });

  it("keeps the gateway's explicit null and leaves out an absent or malformed one", () => {
    expect(withL1Challenge(base, null)).toEqual({ ...base, l1Challenge: null });
    for (const raw of [undefined, { ...V.kit.l1Challenge, chainId: "84532" }, "x"]) {
      const r = withL1Challenge(base, raw);
      expect(r).toEqual(base);
      expect("l1Challenge" in r).toBe(false);
    }
  });
});

describe("challenge kit", () => {
  it("is exactly the shared vector built from the accept receipt", () => {
    expect(buildChallengeKit(receipt())).toEqual(V.kit);
    expect(V.kit.schema).toBe(CHALLENGE_KIT_SCHEMA);
  });

  it("refuses a receipt without a usable authorization", () => {
    const cases: Array<(r: ReceiptWithChallenge) => void> = [
      (r) => { delete r.l1Challenge; },
      (r) => { r.l1Challenge = null; },
      (r) => { delete r.enclaveSigner; },
      (r) => { r.seqNo = -1; },
      (r) => { r.recvTimeMs = 2 ** 53; },
      (r) => { r.orderHash = "0x12"; },
    ];
    for (const mutate of cases) {
      const r = receipt();
      mutate(r);
      expect(() => buildChallengeKit(r)).toThrow();
    }
    for (const raw of [null, "x", 7, [], {}]) expect(() => buildChallengeKit(raw)).toThrow();
  });

  it("refuses an authorization that does not recover to the receipt's enclave signer", () => {
    const cases: Array<(r: ReceiptWithChallenge) => void> = [
      (r) => { r.orderHash = "0x" + "12".repeat(32); },
      (r) => { r.seqNo = 1; },
      (r) => { r.recvTimeMs = 1001; },
      (r) => { r.batchIdHint = 1; },
      (r) => { r.enclaveSigner = "0x" + "44".repeat(20); },
      (r) => { r.l1Challenge!.chainId = 84533; },
      (r) => { r.l1Challenge!.settlement = "0x" + "23".repeat(20); },
      (r) => { r.l1Challenge!.beneficiary = "0x" + "34".repeat(20); },
      (r) => { r.l1Challenge!.signature = SIG.slice(0, 10) + (SIG[10] === "0" ? "1" : "0") + SIG.slice(11); },
    ];
    for (const mutate of cases) {
      const r = receipt();
      mutate(r);
      expect(() => buildChallengeKit(r)).toThrow(/does not verify|Invalid/);
    }
  });

  it("names files by chain, sequence number and order hash prefix", () => {
    expect(challengeKitFileName(V.kit)).toBe("arcora-challenge-84532-0-0c164689.json");
  });

  it("serializes one kit as an object and several as an array", () => {
    expect(JSON.parse(serializeChallengeKits([V.kit]))).toEqual(V.kit);
    expect(JSON.parse(serializeChallengeKits([V.kit, V.kit]))).toHaveLength(2);
  });
});

describe("newChallengeKits", () => {
  const listed = (r: unknown, finality = "ACCEPTED") => ({ receipt: r, finality });

  it("builds kits only for orders not seen yet, and tries each authorization once", () => {
    const seen = new Map([["0x" + "ee".repeat(32), SIG.toLowerCase()]]);
    const known = { ...receipt(), orderHash: "0x" + "EE".repeat(32) };
    const unbound = { ...receipt(), orderHash: "0x" + "ab".repeat(32), l1Challenge: null };
    const broken = { ...receipt(), orderHash: "0x" + "cd".repeat(32) };
    expect(newChallengeKits([known, unbound, broken, receipt()].map((r) => listed(r)), seen)).toEqual([V.kit]);
    expect(seen.has(V.kit.orderHash)).toBe(true);
    expect(seen.has(broken.orderHash)).toBe(true); // unusable: not retried on every state push
    expect(seen.has(unbound.orderHash)).toBe(false); // may gain a kit once an address is bound
    expect(newChallengeKits([listed(receipt())], seen)).toEqual([]);
  });

  it("keeps no kit for an order that is already settled", () => {
    const seen = new Map<string, string>();
    expect(newChallengeKits([listed(receipt(), "SETTLED")], seen)).toEqual([]);
    expect(seen.has(V.kit.orderHash)).toBe(true); // SETTLED never reverts: not retried
    expect(newChallengeKits([listed(reboundReceipt(), "SETTLED")], seen)).toEqual([]);
    expect(newChallengeKits([listed(receipt(), "MATCHED")], new Map())).toEqual([V.kit]);
  });

  it("builds an order's kit again when the gateway lists it with another authorization", () => {
    // The account bound another deposit address: the gateway signs the order
    // for the new beneficiary, so the kept kit no longer pays the address the
    // account chose.
    const seen = new Map<string, string>();
    expect(newChallengeKits([listed(receipt())], seen)).toEqual([V.kit]);
    const rebound = reboundReceipt();
    expect(newChallengeKits([listed(rebound)], seen)).toEqual([buildChallengeKit(rebound)]);
    expect(buildChallengeKit(rebound).l1Challenge.beneficiary).toBe(NEW_BENEFICIARY);
    expect(newChallengeKits([listed(rebound)], seen)).toEqual([]); // tried once
    // The same from the kits a browser kept: only another authorization is built.
    expect(newChallengeKits([listed(receipt())], seenChallengeKits([V.kit]))).toEqual([]);
    expect(newChallengeKits([listed(rebound)], seenChallengeKits([V.kit]))).toEqual([buildChallengeKit(rebound)]);
  });

  it("names the settled orders by lowercase hash", () => {
    const upper = { ...receipt(), orderHash: "0x" + "AB".repeat(32) };
    expect(settledOrderHashes([listed(upper, "SETTLED"), listed(receipt(), "ACCEPTED"), listed(null, "SETTLED")]))
      .toEqual(new Set(["0x" + "ab".repeat(32)]));
  });

  it("names the listed orders that are not settled by lowercase hash", () => {
    const upper = { ...receipt(), orderHash: "0x" + "AB".repeat(32) };
    const unbound = { ...receipt(), orderHash: "0x" + "cd".repeat(32), l1Challenge: null };
    expect(unsettledOrderHashes([
      listed(upper, "MATCHED"), listed(receipt(), "SETTLED"), listed(unbound, "ACCEPTED"), listed(null, "ACCEPTED"),
    ])).toEqual(new Set(["0x" + "ab".repeat(32), "0x" + "cd".repeat(32)]));
  });
});

describe("challenge kit storage", () => {
  const first = V.kit;
  const second: ChallengeKit = { ...first, orderHash: "0x" + "ee".repeat(32), seqNo: 9 };

  it("remembers by order hash, never drops earlier kits, and a later copy of an order replaces the stored one", () => {
    const storage = memoryStorage();
    expect(rememberChallengeKits([first], storage)).toBe(true);
    // The account bound another deposit address: the order's new kit pays it.
    const later = {
      ...first, orderHash: first.orderHash.toUpperCase().replace("0X", "0x"),
      l1Challenge: { ...first.l1Challenge, beneficiary: NEW_BENEFICIARY },
    };
    expect(rememberChallengeKits([second, later], storage)).toBe(true);
    const saved = loadChallengeKits(storage);
    expect(saved.map((k) => k.seqNo).sort()).toEqual([0, 9]);
    expect(saved.find((k) => k.seqNo === 0)).toEqual(later);
    expect(JSON.parse(storage.map.get(CHALLENGE_KIT_STORAGE_KEY)!)).toHaveLength(2);
  });

  it("storing the same kit again changes nothing", () => {
    const storage = memoryStorage();
    expect(rememberChallengeKits([first, second], storage)).toBe(true);
    const raw = storage.map.get(CHALLENGE_KIT_STORAGE_KEY);
    expect(rememberChallengeKits([first], storage)).toBe(true);
    expect(storage.map.get(CHALLENGE_KIT_STORAGE_KEY)).toBe(raw);
  });

  it("stores kits compactly: no schema, no timestamps, no indentation", () => {
    const storage = memoryStorage();
    rememberChallengeKits([first], storage);
    const raw = storage.map.get(CHALLENGE_KIT_STORAGE_KEY)!;
    expect(raw).not.toContain("schema");
    expect(raw).not.toContain("createdAt");
    expect(raw).not.toContain("\n");
    expect(raw.length).toBeLessThan(400);
    expect(loadChallengeKits(storage)).toEqual([first]);
  });

  it("drops the kits of orders the gateway lists as SETTLED", () => {
    const storage = memoryStorage();
    expect(rememberChallengeKits([kitN(1), kitN(2), kitN(3)], storage)).toBe(true);
    const settled = new Set([kitN(2).orderHash.toLowerCase()]);
    expect(rememberChallengeKits([], storage, settled)).toBe(true);
    expect(loadChallengeKits(storage).map(seqOf)).toEqual([3, 1]);
    // A settled order's kit is not stored again either.
    expect(rememberChallengeKits([kitN(2), kitN(4)], storage, settled)).toBe(true);
    expect(loadChallengeKits(storage).map(seqOf)).toEqual([4, 3, 1]);
  });

  it("keeps at most MAX_STORED_CHALLENGE_KITS, evicting the oldest, and reports that not every kit is stored", () => {
    const storage = memoryStorage();
    const kits = Array.from({ length: MAX_STORED_CHALLENGE_KITS + 20 }, (_, i) => kitN(i + 1));
    expect(rememberChallengeKits(kits, storage)).toBe(false); // 20 kits are not stored
    const kept = loadChallengeKits(storage).map(seqOf);
    expect(kept).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(kept[0]).toBe(MAX_STORED_CHALLENGE_KITS + 20); // newest first
    expect(Math.min(...kept)).toBe(21); // kits 1..20, the oldest, went
    // Exactly the bound is every kit.
    expect(rememberChallengeKits(kits.slice(0, MAX_STORED_CHALLENGE_KITS), memoryStorage())).toBe(true);
  });

  it("past the bound, evicts kits of orders no longer listed before kits of listed ones", () => {
    const storage = memoryStorage();
    // Stored earlier: newer kits whose orders this account no longer lists (or
    // another account's).
    const unlisted = Array.from({ length: MAX_STORED_CHALLENGE_KITS }, (_, i) => kitN(1_000 + i));
    expect(rememberChallengeKits(unlisted, storage)).toBe(true);
    // Listed, not settled, and older than every stored kit.
    const listedKits = [kitN(1), kitN(2), kitN(3)];
    const listed = new Set(listedKits.map((k) => k.orderHash.toLowerCase()));
    expect(rememberChallengeKits(listedKits, storage, new Set(), listed)).toBe(false);
    const kept = loadChallengeKits(storage).map(seqOf);
    expect(kept).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(kept.slice(0, 3)).toEqual([3, 2, 1]); // listed first, newest first
    // The three oldest unlisted kits went.
    expect(kept).not.toContain(1_000);
    expect(kept).not.toContain(1_002);
    expect(kept).toContain(1_003);
    // Among listed kits, the oldest goes first.
    const many = Array.from({ length: MAX_STORED_CHALLENGE_KITS + 1 }, (_, i) => kitN(i + 1));
    expect(rememberChallengeKits(many, storage, new Set(), new Set(many.map((k) => k.orderHash.toLowerCase())))).toBe(false);
    const after = loadChallengeKits(storage).map(seqOf);
    expect(after).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(after).not.toContain(1);
    expect(after.every((n) => n <= MAX_STORED_CHALLENGE_KITS + 1)).toBe(true); // no unlisted kit left
  });

  it("on a refused write, also evicts kits of orders no longer listed first", () => {
    const storage = quotaStorage(4_000);
    // The quota holds only the newest of these kits, whose orders are no longer listed.
    expect(rememberChallengeKits(Array.from({ length: 30 }, (_, i) => kitN(200 + i)), storage)).toBe(false);
    // Two listed orders, older than every stored kit.
    const older = [kitN(1), kitN(2)];
    const listed = new Set(older.map((k) => k.orderHash.toLowerCase()));
    expect(rememberChallengeKits(older, storage, new Set(), listed)).toBe(false);
    const kept = loadChallengeKits(storage).map(seqOf);
    expect(kept.slice(0, 2)).toEqual([2, 1]);
    expect(kept.slice(2)).toEqual(Array.from({ length: kept.length - 2 }, (_, i) => 229 - i)); // then the newest
  });

  it("merges every kit, past the storage bound too (the session offer is not bounded)", () => {
    const kits = Array.from({ length: MAX_STORED_CHALLENGE_KITS + 20 }, (_, i) => kitN(i + 1));
    expect(mergeChallengeKits([], kits)).toHaveLength(MAX_STORED_CHALLENGE_KITS + 20);
  });

  it("merges by order hash: a later copy replaces an earlier one, settled and malformed kits are left out", () => {
    const copy = { ...kitN(1), l1Challenge: { ...kitN(1).l1Challenge, beneficiary: NEW_BENEFICIARY } };
    const merged = mergeChallengeKits(
      [kitN(1), kitN(2)],
      [copy, kitN(3), { schema: "x" }, kitN(4)],
      new Set([kitN(3).orderHash.toLowerCase()]),
    );
    expect(merged).toEqual([kitN(4), kitN(2), copy]);
  });

  it("evicts the oldest kits until the rest fits when the browser refuses the write, and reports it", () => {
    const storage = quotaStorage(4_000);
    const kits = Array.from({ length: 40 }, (_, i) => kitN(i + 1));
    expect(rememberChallengeKits(kits, storage)).toBe(false); // not every kit is stored
    const kept = loadChallengeKits(storage).map(seqOf);
    expect(kept.length).toBeGreaterThan(0);
    expect(kept).toEqual(Array.from({ length: kept.length }, (_, i) => 40 - i)); // the newest
    // As many as fit: one more stored entry (the same size) would not.
    const raw = storage.map.get(CHALLENGE_KIT_STORAGE_KEY)!;
    const entries = JSON.parse(raw) as unknown[];
    const entry = JSON.stringify(entries[entries.length - 1]);
    expect(CHALLENGE_KIT_STORAGE_KEY.length + raw.length + 1 + entry.length).toBeGreaterThan(4_000);
  });

  it("never fills the origin's shared quota: after 9,000 orders a new kit, a claim bundle and a deposit journal still save", () => {
    const QUOTA = 5_000_000; // a typical browser localStorage quota, in UTF-16 code units
    const storage = quotaStorage(QUOTA);
    for (let batch = 0; batch < 90; batch++) {
      const kits = Array.from({ length: 100 }, (_, i) => kitN(batch * 100 + i + 1));
      // Past the bound the oldest kits go, and the caller is told.
      expect(rememberChallengeKits(kits, storage), `batch ${batch}`).toBe((batch + 1) * 100 <= MAX_STORED_CHALLENGE_KITS);
    }
    const newest = kitN(9_001);
    expect(rememberChallengeKits([newest], storage)).toBe(false);
    const kept = loadChallengeKits(storage);
    expect(kept).toHaveLength(MAX_STORED_CHALLENGE_KITS);
    expect(kept[0]).toEqual(newest);
    expect(storage.map.get(CHALLENGE_KIT_STORAGE_KEY)!.length).toBeLessThan(190_000);
    // The gateway-free withdrawal claim data is still kept...
    const bundle = buildClaimBundle({
      to: "0x" + "11".repeat(20), amount: 2_500_000n, nonce: 3, leaf: "0x" + "aa".repeat(32),
      root: "0x" + "bb".repeat(32), claimable: true, proof: ["0x" + "cc".repeat(32)],
    }, "0x57e951F6a378E00e4F1b26510380E089D7c07b8B", 84532);
    expect(rememberClaimBundles([bundle], storage)).toBe(true);
    expect(loadClaimBundles(storage)).toEqual([bundle]);
    // ...and depositFlow.saveJournal's write lands and reads back intact.
    const key = 'darkperp.deposit.v1:["0x' + "11".repeat(32) + '",0]';
    const journal = JSON.stringify({
      version: 1, owner: "0x" + "22".repeat(32), marketId: 0, recoveryNonce: 0, amount: "2500000",
      txs: { mint: "0x" + "33".repeat(32), approve: "0x" + "44".repeat(32) }, done: ["chain", "mint"],
      sending: "deposit", validUntil: 1_760_001_800,
    });
    storage.setItem(key, journal);
    expect(storage.getItem(key)).toBe(journal);
  });

  it("keeps a new order's kit when other data has filled the quota, evicting older kits", () => {
    const QUOTA = 200_000;
    const storage = quotaStorage(QUOTA);
    expect(rememberChallengeKits(Array.from({ length: 100 }, (_, i) => kitN(i + 1)), storage)).toBe(true);
    // Other stores grow until little room is left.
    storage.setItem("arcora.claimBundles.v1", "x".repeat(QUOTA - storage.used() - 100));
    const newest = kitN(101);
    expect(rememberChallengeKits([newest], storage)).toBe(false); // older kits had to go
    const kept = loadChallengeKits(storage);
    expect(kept[0]).toEqual(newest);
    expect(kept.length).toBeLessThan(101);
  });

  it("denied or full storage never throws", () => {
    expect(rememberChallengeKits([first], memoryStorage({ set: true }))).toBe(false);
    expect(rememberChallengeKits([first], memoryStorage({ get: true }))).toBe(false);
    expect(loadChallengeKits(memoryStorage({ get: true }))).toEqual([]);
    expect(rememberChallengeKits([first], undefined)).toBe(false);
    expect(loadChallengeKits(undefined)).toEqual([]);
  });

  it("ignores corrupt stored data instead of trusting it", () => {
    const storage = memoryStorage();
    rememberChallengeKits([first], storage);
    const [entry] = JSON.parse(storage.map.get(CHALLENGE_KIT_STORAGE_KEY)!) as unknown[][];
    const tampered = (i: number, value: unknown) => entry.map((v, j) => (j === i ? value : v));
    storage.map.set(CHALLENGE_KIT_STORAGE_KEY, JSON.stringify([
      { schema: "x" }, entry, "junk", tampered(1, "0"), tampered(7, "0x" + "00".repeat(20)),
      tampered(8, "0x12"), entry.slice(0, 8),
    ]));
    expect(loadChallengeKits(storage)).toEqual([first]);
    storage.map.set(CHALLENGE_KIT_STORAGE_KEY, "{not json");
    expect(loadChallengeKits(storage)).toEqual([]);
    expect(rememberChallengeKits([second], storage)).toBe(true);
    expect(loadChallengeKits(storage)).toEqual([second]);
  });
});
