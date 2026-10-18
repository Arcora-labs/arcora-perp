import { describe, expect, it } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  CHALLENGE_KIT_SCHEMA,
  CHALLENGE_KIT_STORAGE_KEY,
  buildChallengeKit,
  challengeAuthDigest,
  challengeKitFileName,
  loadChallengeKits,
  newChallengeKits,
  parseL1Challenge,
  recoverChallengeSigner,
  rememberChallengeKits,
  rememberReceiptChallengeKit,
  serializeChallengeKits,
  type ChallengeKit,
} from "./challengeKit";
import type { Receipt } from "./types";
import { CHALLENGE_KIT_VECTORS as V } from "../testSupport/challengeKitVectors";

// V is shared with scripts/challenge/test_challenge_kit.py, which runs the same
// kit through scripts/claim/challenge_inclusion.py: the file this module
// produces is exactly what the gateway-free tool checks.
const NOW = new Date(V.kit.createdAt);
const receipt = (): Receipt => structuredClone(V.acceptReceipt);
const SIG = V.kit.l1Challenge.signature;

function memoryStorage(fail: { get?: boolean; set?: boolean } = {}) {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k: string) => { if (fail.get) throw new Error("denied"); return map.get(k) ?? null; },
    setItem: (k: string, v: string) => { if (fail.set) throw new Error("quota"); map.set(k, v); },
  };
}

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

describe("challenge kit", () => {
  it("is exactly the shared vector built from the accept receipt", () => {
    expect(buildChallengeKit(receipt(), NOW)).toEqual(V.kit);
    expect(V.kit.schema).toBe(CHALLENGE_KIT_SCHEMA);
  });

  it("refuses a receipt without a usable authorization", () => {
    const cases: Array<(r: Receipt) => void> = [
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
      expect(() => buildChallengeKit(r, NOW)).toThrow();
    }
  });

  it("refuses an authorization that does not recover to the receipt's enclave signer", () => {
    const cases: Array<(r: Receipt) => void> = [
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
      expect(() => buildChallengeKit(r, NOW)).toThrow(/does not verify|Invalid/);
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
  it("builds kits only for receipts not seen yet, and tries each order once", () => {
    const seen = new Set<string>(["0x" + "ee".repeat(32)]);
    const known = { ...receipt(), orderHash: "0x" + "EE".repeat(32) };
    const unbound = { ...receipt(), orderHash: "0x" + "ab".repeat(32), l1Challenge: null };
    const broken = { ...receipt(), orderHash: "0x" + "cd".repeat(32) };
    expect(newChallengeKits([known, unbound, broken, receipt()], seen, NOW)).toEqual([V.kit]);
    expect(seen.has(V.kit.orderHash)).toBe(true);
    expect(seen.has(broken.orderHash)).toBe(true); // unusable: not retried on every state push
    expect(seen.has(unbound.orderHash)).toBe(false); // may gain a kit once an address is bound
    expect(newChallengeKits([receipt()], seen, NOW)).toEqual([]);
  });
});

describe("challenge kit storage", () => {
  const first = V.kit;
  const second: ChallengeKit = { ...first, orderHash: "0x" + "ee".repeat(32), seqNo: 9 };

  it("remembers by order hash, never drops earlier kits and keeps the first copy", () => {
    const storage = memoryStorage();
    expect(rememberChallengeKits([first], storage)).toBe(true);
    const later = { ...first, orderHash: first.orderHash.toUpperCase().replace("0X", "0x"), createdAt: "later" };
    expect(rememberChallengeKits([second, later], storage)).toBe(true);
    const saved = loadChallengeKits(storage);
    expect(saved.map((k) => k.seqNo).sort()).toEqual([0, 9]);
    expect(saved.find((k) => k.seqNo === 0)?.createdAt).toBe(first.createdAt);
    expect(JSON.parse(storage.map.get(CHALLENGE_KIT_STORAGE_KEY)!)).toHaveLength(2);
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
    storage.map.set(CHALLENGE_KIT_STORAGE_KEY, JSON.stringify([
      { schema: "x" }, first, "junk", { ...first, seqNo: "0" }, { ...first, l1Challenge: null },
    ]));
    expect(loadChallengeKits(storage)).toEqual([first]);
    storage.map.set(CHALLENGE_KIT_STORAGE_KEY, "{not json");
    expect(loadChallengeKits(storage)).toEqual([]);
    expect(rememberChallengeKits([second], storage)).toBe(true);
    expect(loadChallengeKits(storage)).toEqual([second]);
  });

  it("keeps the kit of an accepted receipt and never throws on anything else", () => {
    const storage = memoryStorage();
    expect(rememberReceiptChallengeKit(V.acceptReceipt, storage, NOW)).toBe(true);
    expect(loadChallengeKits(storage)).toEqual([V.kit]);
    for (const raw of [null, "x", 7, {}, { ...V.acceptReceipt, l1Challenge: null }, { ...V.acceptReceipt, seqNo: 3 }]) {
      expect(rememberReceiptChallengeKit(raw, memoryStorage(), NOW)).toBe(false);
    }
    expect(rememberReceiptChallengeKit(V.acceptReceipt, memoryStorage({ set: true }), NOW)).toBe(false);
  });
});
