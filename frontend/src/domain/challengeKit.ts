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
import type { Receipt } from "./types";

export const CHALLENGE_KIT_SCHEMA = "arcora.challenge-kit.v1";
export const CHALLENGE_KIT_STORAGE_KEY = "arcora.challengeKits.v1";
/// Kits this browser stores at most, for all accounts used in it. A stored kit
/// is about 370 characters, so the store stays under 190,000 of the origin's
/// shared localStorage quota (typically 5,000,000). The bound is this
/// browser's, not the gateway's: an order that never gets a settled fill (never
/// filled, or cancelled first) stays listed as ACCEPTED, so one account can list
/// more kits than this, and other accounts' kits share the store. Past the
/// bound the account panel still offers every listed order's kit for the
/// session and warns about each kit it did not store: the user should export.
export const MAX_STORED_CHALLENGE_KITS = 500;

/// The enclave's authorization to open `DarkPerpSettlement.challengeInclusion`
/// for one order on one chain and settlement, paying any fine to `beneficiary`.
export interface L1Challenge {
  chainId: number;
  settlement: string;
  beneficiary: string;
  /// 65-byte r||s||v over `challengeAuthDigest`.
  signature: string;
}

/// A receipt as the gateway sends it: `l1Challenge` is absent from old gateways
/// and demos, and null without a bound deposit address.
export type ReceiptWithChallenge = Receipt & { l1Challenge?: L1Challenge | null };

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

/// The two fields of a tracked order this module reads (a domain TrackedOrder fits).
export interface ChallengeKitOrder {
  receipt: unknown;
  finality: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ZERO_ADDRESS = /^0x0{40}$/;
const DIGEST = /^0x[0-9a-fA-F]{64}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
/// `DarkPerpSettlement.CHALLENGE_AUTH_TAG`.
const CHALLENGE_AUTH_TAG = keccak_256(utf8ToBytes("arcora:l1-inclusion-challenge:v1"));

/// A uint64 field as a JS number: larger values cannot be held exactly.
const isU64 = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

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
  if (!isRecord(raw)) return undefined;
  const c = raw;
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

/// `receipt` plus the wire receipt's `l1Challenge`, as realClient decodes a
/// stored receipt: kept when well-formed (its four fields only), null when the
/// gateway issued none, left out when absent or malformed.
export function withL1Challenge<R extends Receipt>(receipt: R, raw: unknown): R & { l1Challenge?: L1Challenge | null } {
  const l1Challenge = parseL1Challenge(raw);
  return l1Challenge === undefined ? receipt : { ...receipt, l1Challenge };
}

/// The receipt fields a kit carries, or null when any is malformed.
function receiptFields(r: Record<string, unknown>): Omit<ChallengeKit, "schema" | "l1Challenge"> | null {
  const { orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner } = r;
  if (
    typeof orderHash !== "string" || !DIGEST.test(orderHash) ||
    !isU64(seqNo) || !isU64(recvTimeMs) || !isU64(batchIdHint) ||
    typeof enclaveSigner !== "string" || !ADDRESS.test(enclaveSigner)
  ) {
    return null;
  }
  return { orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner };
}

/// The kit for one accepted order. Throws unless the receipt carries an
/// authorization that recovers to its own enclave signer.
export function buildChallengeKit(receipt: unknown): ChallengeKit {
  const auth = isRecord(receipt) ? parseL1Challenge(receipt.l1Challenge) : undefined;
  if (!auth) throw new Error("No L1 challenge authorization in this receipt");
  const fields = receiptFields(receipt as Record<string, unknown>);
  if (!fields) throw new Error("Invalid challenge kit receipt fields");
  const signer = recoverChallengeSigner({ ...auth, ...fields }, auth.signature);
  if (signer !== fields.enclaveSigner.toLowerCase()) {
    throw new Error("The L1 challenge authorization does not verify against the receipt's enclave signer");
  }
  return { schema: CHALLENGE_KIT_SCHEMA, ...fields, l1Challenge: auth };
}

const orderHashOf = (receipt: unknown): string | null =>
  isRecord(receipt) && typeof receipt.orderHash === "string" ? receipt.orderHash.toLowerCase() : null;

/// Kits for listed orders whose hash is not in `seen` yet. Each order is tried
/// once (`seen` grows). A SETTLED order gets no kit (settled is never undone,
/// and a challenge of it is answered at once, forfeiting the stake). A receipt
/// without an authorization is not marked, since it gains one when the account
/// binds a deposit address.
export function newChallengeKits(orders: readonly ChallengeKitOrder[], seen: Set<string>): ChallengeKit[] {
  const kits: ChallengeKit[] = [];
  for (const o of orders) {
    const key = orderHashOf(o.receipt);
    if (!key || seen.has(key)) continue;
    if (o.finality === "SETTLED") {
      seen.add(key);
      continue;
    }
    if (!(o.receipt as ReceiptWithChallenge).l1Challenge) continue; // may gain one once an address is bound
    seen.add(key);
    try {
      kits.push(buildChallengeKit(o.receipt));
    } catch { /* unusable authorization: nothing to keep */ }
  }
  return kits;
}

/// Lowercase hashes of the listed orders the gateway reports SETTLED: their
/// kits are dropped, since a challenge of them is answered at once.
export function settledOrderHashes(orders: readonly ChallengeKitOrder[]): Set<string> {
  const settled = new Set<string>();
  for (const o of orders) {
    const key = o.finality === "SETTLED" ? orderHashOf(o.receipt) : null;
    if (key) settled.add(key);
  }
  return settled;
}

/// Lowercase hashes of the listed orders the gateway does not report SETTLED:
/// orders the user may still need to challenge. Their kits are stored ahead of
/// every other kit (see `rememberChallengeKits`).
export function unsettledOrderHashes(orders: readonly ChallengeKitOrder[]): Set<string> {
  const listed = new Set<string>();
  for (const o of orders) {
    const key = o.finality === "SETTLED" ? null : orderHashOf(o.receipt);
    if (key) listed.add(key);
  }
  return listed;
}

export function challengeKitFileName(k: ChallengeKit): string {
  return `arcora-challenge-${k.l1Challenge.chainId}-${k.seqNo}-${k.orderHash.slice(2, 10).toLowerCase()}.json`;
}

/// One kit as an object (the tool's single-file form), several as an array.
export function serializeChallengeKits(kits: ChallengeKit[]): string {
  return JSON.stringify(kits.length === 1 ? kits[0] : kits, null, 2) + "\n";
}

export interface ChallengeKitStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function defaultStorage(): ChallengeKitStorage | undefined {
  try {
    return typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    return undefined; // access itself can throw when site data is blocked
  }
}

/// The compact stored form of a kit: no schema, no names, no timestamps.
type StoredKit = [
  orderHash: string, seqNo: number, recvTimeMs: number, batchIdHint: number, enclaveSigner: string,
  chainId: number, settlement: string, beneficiary: string, signature: string,
];

function toStored(k: ChallengeKit): StoredKit {
  const c = k.l1Challenge;
  return [k.orderHash, k.seqNo, k.recvTimeMs, k.batchIdHint, k.enclaveSigner, c.chainId, c.settlement, c.beneficiary, c.signature];
}

/// A stored kit, or null. Shape checks only: the signature was verified when
/// the kit was built, and the tool verifies it again before printing a call.
function fromStored(value: unknown): ChallengeKit | null {
  if (!Array.isArray(value) || value.length !== 9) return null;
  const [orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner, chainId, settlement, beneficiary, signature] = value;
  const fields = receiptFields({ orderHash, seqNo, recvTimeMs, batchIdHint, enclaveSigner });
  const auth = parseL1Challenge({ chainId, settlement, beneficiary, signature });
  return fields && auth ? { schema: CHALLENGE_KIT_SCHEMA, ...fields, l1Challenge: auth } : null;
}

/// A kit as built here, rebuilt with only its own keys, or null.
function normalizeKit(value: unknown): ChallengeKit | null {
  if (!isRecord(value) || value.schema !== CHALLENGE_KIT_SCHEMA) return null;
  const fields = receiptFields(value);
  const auth = parseL1Challenge(value.l1Challenge);
  return fields && auth ? { schema: CHALLENGE_KIT_SCHEMA, ...fields, l1Challenge: auth } : null;
}

/// The stored kits; corrupt data reads as none (the next write replaces it).
function parseStored(raw: string | null): ChallengeKit[] {
  let parsed: unknown;
  try {
    parsed = raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.flatMap((entry) => {
    const kit = fromStored(entry);
    return kit ? [kit] : [];
  });
}

/// Saved kits; anything unreadable or malformed is ignored, never trusted.
export function loadChallengeKits(storage: ChallengeKitStorage | undefined = defaultStorage()): ChallengeKit[] {
  if (!storage) return [];
  try {
    return parseStored(storage.getItem(CHALLENGE_KIT_STORAGE_KEY));
  } catch {
    return [];
  }
}

const hashKey = (k: ChallengeKit) => k.orderHash.toLowerCase();

/// Newest first (by the enclave-signed receive time): the order kits are
/// offered in, and, within listed and other kits, stored in.
const newestFirst = (a: ChallengeKit, b: ChallengeKit) => b.recvTimeMs - a.recvTimeMs || b.seqNo - a.seqNo;

/// The kits to keep: `existing`, then `added`, merged by order hash (the first
/// copy wins), without the kits of orders in `settled` (lowercase hashes),
/// newest first. Not bounded: this is also the session's offer, which must hold
/// every listed order's kit. Malformed entries are skipped.
export function mergeChallengeKits(
  existing: readonly unknown[],
  added: readonly unknown[],
  settled: ReadonlySet<string> = new Set(),
): ChallengeKit[] {
  const byHash = new Map<string, ChallengeKit>();
  for (const value of [...existing, ...added]) {
    const kit = normalizeKit(value);
    if (kit && !byHash.has(hashKey(kit)) && !settled.has(hashKey(kit))) byHash.set(hashKey(kit), kit);
  }
  return [...byHash.values()].sort(newestFirst);
}

/// Keep `kits` in this browser, merged with the stored ones as
/// `mergeChallengeKits` does: the kits of orders in `settled` (orders the
/// gateway lists as SETTLED, which a settled batch includes or rejects) are
/// dropped. The store holds at most MAX_STORED_CHALLENGE_KITS, and its quota is
/// shared with claim bundles, the deposit journal and the credential record.
/// When not every kit fits (the bound, or a write the browser refuses), kits
/// are kept in this order and evicted from its end: the kits of orders in
/// `listed` (lowercase hashes of the orders the gateway lists and does not
/// report SETTLED) newest first, then every other kit (orders no longer
/// listed, or another account's) newest first. Returns true only when every
/// kit to keep is stored; false when storage is unavailable or any kit was
/// evicted, so the caller can warn. Never throws.
export function rememberChallengeKits(
  kits: readonly ChallengeKit[],
  storage: ChallengeKitStorage | undefined = defaultStorage(),
  settled: ReadonlySet<string> = new Set(),
  listed: ReadonlySet<string> = new Set(),
): boolean {
  if (!storage) return false;
  try {
    const merged = mergeChallengeKits(parseStored(storage.getItem(CHALLENGE_KIT_STORAGE_KEY)), kits, settled); // a denied read throws
    const isListed = (k: ChallengeKit) => listed.has(hashKey(k));
    const keep = [...merged.filter(isListed), ...merged.filter((k) => !isListed(k))];
    const bound = Math.min(keep.length, MAX_STORED_CHALLENGE_KITS);
    const write = (n: number): boolean => {
      try {
        storage.setItem(CHALLENGE_KIT_STORAGE_KEY, JSON.stringify(keep.slice(0, n).map(toStored)));
        return true;
      } catch {
        return false; // refused: the stored value is unchanged
      }
    };
    if (write(bound)) return bound === keep.length;
    // Refused (quota): store the longest prefix, in that order, that fits.
    let fits = 0;
    let refused = bound;
    while (refused - fits > 1) {
      const mid = Math.floor((fits + refused) / 2);
      if (write(mid)) fits = mid;
      else refused = mid;
    }
    return false;
  } catch {
    return false;
  }
}
