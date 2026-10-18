/// User-held L1 inclusion-challenge kits. An accepted order's receipt carries
/// `l1Challenge`, the enclave's authorization for
/// `DarkPerpSettlement.challengeInclusion`. A kit is that authorization plus the
/// receipt fields the call takes, so the user can challenge an order that no
/// settled batch includes or rejects WITHOUT the operator
/// (scripts/claim/challenge_inclusion.py checks a saved kit and prints the call).
/// Kits stay with the user: they are kept in this browser's storage and offered
/// as a download, never sent anywhere. Opening a challenge publishes the
/// beneficiary next to the order hash on L1.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import type { L1Challenge, Receipt } from "./types";

export const CHALLENGE_KIT_SCHEMA = "arcora.challenge-kit.v1";
export const CHALLENGE_KIT_STORAGE_KEY = "arcora.challengeKits.v1";

/// Receipt-shaped on purpose: the challenge tool reads a kit like a receipt.
export interface ChallengeKit {
  schema: typeof CHALLENGE_KIT_SCHEMA;
  orderHash: string;
  seqNo: number;
  recvTimeMs: number;
  batchIdHint: number;
  /// The receipt's enclave signer; the authorization recovers to it.
  enclaveSigner: string;
  l1Challenge: L1Challenge;
  createdAt: string;
}

/// Every field `challengeAuthDigest` binds.
export interface ChallengeAuthFields {
  chainId: number;
  settlement: string;
  orderHash: string;
  seqNo: number;
  recvTimeMs: number;
  batchIdHint: number;
  beneficiary: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ZERO_ADDRESS = /^0x0{40}$/;
const DIGEST = /^0x[0-9a-fA-F]{64}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
/// `DarkPerpSettlement.CHALLENGE_AUTH_TAG`.
const CHALLENGE_AUTH_TAG = keccak_256(utf8ToBytes("arcora:l1-inclusion-challenge:v1"));

/// A uint64 field as a JS number: larger values cannot be held exactly.
const isU64 = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

function uintWord(n: number): Uint8Array {
  const w = new Uint8Array(32);
  let v = BigInt(n);
  for (let i = 31; v > 0n; i--, v >>= 8n) w[i] = Number(v & 0xffn);
  return w;
}

function addressWord(a: string): Uint8Array {
  const w = new Uint8Array(32);
  w.set(hexToBytes(a.slice(2)), 12);
  return w;
}

/// keccak256(abi.encode(CHALLENGE_AUTH_TAG, chainId, settlement, orderHash, seqNo,
/// recvTimeMs, batchIdHint, beneficiary)), as crates/gateway/src/challenge_auth.rs
/// and the settlement compute it. Fields must already be validated.
export function challengeAuthDigest(f: ChallengeAuthFields): Uint8Array {
  const words = [
    CHALLENGE_AUTH_TAG, uintWord(f.chainId), addressWord(f.settlement), hexToBytes(f.orderHash.slice(2)),
    uintWord(f.seqNo), uintWord(f.recvTimeMs), uintWord(f.batchIdHint), addressWord(f.beneficiary),
  ];
  const preimage = new Uint8Array(32 * words.length);
  words.forEach((w, i) => preimage.set(w, 32 * i));
  return keccak_256(preimage);
}

/// The lowercase address that signed the authorization, or null when the
/// signature is one the settlement refuses (high s, v not 27/28, r or s out of
/// range) or does not recover.
export function recoverChallengeSigner(f: ChallengeAuthFields, signature: string): string | null {
  if (!SIGNATURE.test(signature)) return null;
  const sig = hexToBytes(signature.slice(2));
  const v = sig[64];
  if (v !== 27 && v !== 28) return null;
  try {
    const parsed = secp256k1.Signature.fromCompact(sig.subarray(0, 64));
    if (parsed.hasHighS()) return null;
    const pub = parsed.addRecoveryBit(v - 27).recoverPublicKey(challengeAuthDigest(f)).toRawBytes(false);
    return "0x" + bytesToHex(keccak_256(pub.subarray(1)).subarray(12));
  } catch {
    return null;
  }
}

/// The receipt's `l1Challenge`: null when the gateway issued none (no bound
/// deposit address), undefined when absent or malformed. Never throws.
export function parseL1Challenge(raw: unknown): L1Challenge | null | undefined {
  if (raw === null) return null;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const c = raw as Record<string, unknown>;
  if (
    typeof c.chainId !== "number" || !Number.isSafeInteger(c.chainId) || c.chainId <= 0 ||
    typeof c.settlement !== "string" || !ADDRESS.test(c.settlement) ||
    typeof c.beneficiary !== "string" || !ADDRESS.test(c.beneficiary) || ZERO_ADDRESS.test(c.beneficiary) ||
    typeof c.signature !== "string" || !SIGNATURE.test(c.signature)
  ) {
    return undefined;
  }
  return { chainId: c.chainId, settlement: c.settlement, beneficiary: c.beneficiary, signature: c.signature };
}

function validReceiptFields(r: Receipt): boolean {
  return typeof r.orderHash === "string" && DIGEST.test(r.orderHash) &&
    isU64(r.seqNo) && isU64(r.recvTimeMs) && isU64(r.batchIdHint) &&
    typeof r.enclaveSigner === "string" && ADDRESS.test(r.enclaveSigner);
}

/// The kit for one accepted order. Throws unless the receipt carries an
/// authorization that recovers to its own enclave signer.
export function buildChallengeKit(receipt: Receipt, now: Date = new Date()): ChallengeKit {
  const auth = parseL1Challenge(receipt.l1Challenge);
  if (!auth) throw new Error("No L1 challenge authorization in this receipt");
  if (!validReceiptFields(receipt)) throw new Error("Invalid challenge kit receipt fields");
  const { orderHash, seqNo, recvTimeMs, batchIdHint } = receipt;
  const enclaveSigner = receipt.enclaveSigner!;
  const signer = recoverChallengeSigner({ ...auth, orderHash, seqNo, recvTimeMs, batchIdHint }, auth.signature);
  if (signer !== enclaveSigner.toLowerCase()) {
    throw new Error("The L1 challenge authorization does not verify against the receipt's enclave signer");
  }
  return {
    schema: CHALLENGE_KIT_SCHEMA, orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner,
    l1Challenge: auth, createdAt: now.toISOString(),
  };
}

/// Kits for receipts whose order hash is not in `seen` yet. Each order is tried
/// once (`seen` grows); a receipt without an authorization is not marked, since
/// it gains one when the account binds a deposit address.
export function newChallengeKits(receipts: Receipt[], seen: Set<string>, now: Date = new Date()): ChallengeKit[] {
  const kits: ChallengeKit[] = [];
  for (const r of receipts) {
    if (!r || !r.l1Challenge || typeof r.orderHash !== "string") continue;
    const key = r.orderHash.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      kits.push(buildChallengeKit(r, now));
    } catch { /* unusable authorization: nothing to keep */ }
  }
  return kits;
}

export function challengeKitFileName(k: ChallengeKit): string {
  return `arcora-challenge-${k.l1Challenge.chainId}-${k.seqNo}-${k.orderHash.slice(2, 10).toLowerCase()}.json`;
}

/// One kit as an object (the tool's single-file form), several as an array.
export function serializeChallengeKits(kits: ChallengeKit[]): string {
  return JSON.stringify(kits.length === 1 ? kits[0] : kits, null, 2) + "\n";
}

interface KeyValueStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function defaultStorage(): KeyValueStorage | undefined {
  try {
    return typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    return undefined; // access itself can throw when site data is blocked
  }
}

/// A stored kit, rebuilt with only its own keys, or null. Shape checks only:
/// the signature was verified when the kit was built, and the tool verifies it
/// again before printing a call.
function normalizeKit(value: unknown): ChallengeKit | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const k = value as Record<string, unknown>;
  const auth = parseL1Challenge(k.l1Challenge);
  if (
    k.schema !== CHALLENGE_KIT_SCHEMA || !auth || typeof k.createdAt !== "string" ||
    !validReceiptFields(k as unknown as Receipt)
  ) {
    return null;
  }
  return {
    schema: CHALLENGE_KIT_SCHEMA, orderHash: k.orderHash as string, seqNo: k.seqNo as number,
    recvTimeMs: k.recvTimeMs as number, batchIdHint: k.batchIdHint as number,
    enclaveSigner: k.enclaveSigner as string, l1Challenge: auth, createdAt: k.createdAt,
  };
}

/// Saved kits; anything unreadable or malformed is ignored, never trusted.
export function loadChallengeKits(storage: KeyValueStorage | undefined = defaultStorage()): ChallengeKit[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(CHALLENGE_KIT_STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(parsed)) return [];
    return parsed.flatMap((entry) => {
      const kit = normalizeKit(entry);
      return kit ? [kit] : [];
    });
  } catch {
    return [];
  }
}

/// Add kits by order hash, keeping every earlier one and its first copy (the
/// accept response's, bound to the beneficiary at acceptance). Returns false
/// when storage is unavailable or refuses the write (never throws).
export function rememberChallengeKits(
  kits: ChallengeKit[],
  storage: KeyValueStorage | undefined = defaultStorage(),
): boolean {
  if (!storage) return false;
  try {
    storage.getItem(CHALLENGE_KIT_STORAGE_KEY); // surface a denied read before merging
    const merged = loadChallengeKits(storage);
    const known = new Set(merged.map((k) => k.orderHash.toLowerCase()));
    for (const kit of kits) {
      const k = normalizeKit(kit);
      if (k && !known.has(k.orderHash.toLowerCase())) {
        merged.push(k);
        known.add(k.orderHash.toLowerCase());
      }
    }
    storage.setItem(CHALLENGE_KIT_STORAGE_KEY, JSON.stringify(merged));
    return true;
  } catch {
    return false;
  }
}

/// Keep the kit of a just-accepted order's receipt (the raw accept response).
/// Returns whether one was kept; never throws.
export function rememberReceiptChallengeKit(
  raw: unknown,
  storage: KeyValueStorage | undefined = defaultStorage(),
  now: Date = new Date(),
): boolean {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  try {
    return rememberChallengeKits([buildChallengeKit(raw as Receipt, now)], storage);
  } catch {
    return false;
  }
}
