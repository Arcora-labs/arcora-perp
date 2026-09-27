// Real client — talks to the `gateway` crate (axum HTTP + WebSocket) which holds the
// live Rust protocol engine. It implements the SAME `DarkPerpClient` interface the
// mock does, so swapping it in (see store.tsx, gated on VITE_API_URL) changes nothing
// else in the UI.
//
// Wire format: every fixed-point amount (i128 in Rust) is carried as a DECIMAL STRING
// in JSON — JSON numbers can't hold i128 precisely — and parsed back to bigint here, so
// the UI keeps doing exact bigint money math. State arrives both as a GET /api/state
// snapshot (initial) and as live pushes over the WebSocket.
//
// SEALED ORDER INGRESS (Task 11): every order is ENCRYPTED end-to-end to the
// enclave's attested order-epoch X25519 key before it leaves the browser — the
// wire body carries ONLY `{epochId, sealed}`, never plaintext trade terms. The
// epoch key is fetched from `GET /v1/enclave/epoch` and verified against the
// enclave's secp256k1 identity (see `verifyEnclaveEpoch`) before anything is
// sealed to it. Orders POST to `/v1/orders` (the only surface that decrypts;
// the legacy demo `/api/order` route is plaintext-only and removed in prod), so
// the client self-provisions a `/v1` account at bootstrap — its `owner` pubkey
// is what the sealed-order AAD binds to.

import type { DarkPerpClient, ClientState, OrderEvent, SettlementHealth } from "./client";
import type {
  AccountState, BatchSummary, BookLevel, Market, OracleQuote, OrderBookSnapshot,
  OrderInput, Position, Receipt, Side, TimeInForce, TrackedOrder,
  WithdrawalEntry,
} from "../domain/types";
import { seal, domainAad } from "./sealedBox";
import { accountRecoveryDigest, personalSign } from "./wallet";
import { cancellationCapability } from "../domain/cancellation";
import { parseExecution } from "../domain/execution";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils";

// ── wire types (bigints as strings) ──────────────────────────────────────────
interface WireBookLevel { price: string; size: string }
interface WireOracle { marketId: number; price: string; confidence: string; publishTimeMs: number }
interface WireMarket {
  id: number; symbol: string; maxLeverage: number; maintenanceMarginRatio: number;
  initialMarginRatio: number; referencePrice: string; live: boolean;
  takerFeeBps: number; makerRebateBps: number;
}
interface WirePosition {
  marketId: number; size: string; entryPrice: string; collateral: string;
  unrealizedPnl: string; liquidationPrice: string;
}
interface WireOrderInput { marketId: number; side: "Buy" | "Sell"; size: string; limitPrice: string; tif: string; reduceOnly: boolean }
interface WireTrackedOrder {
  cancellable?: unknown;
  id: string; input: WireOrderInput; receipt: Receipt; finality: TrackedOrder["finality"];
  filledSize: string | null; avgFillPrice: string | null; createdMs: number;
  execution?: unknown;
}
interface WireState {
  markets: WireMarket[]; selectedMarketId: number; market: WireMarket; mode: ClientState["mode"];
  oracle: WireOracle; book: { marketId: number; bids: WireBookLevel[]; asks: WireBookLevel[]; unavailable?: boolean };
  marks: Record<string, string>; account: { settledBalance: string; positions: WirePosition[] };
  orders: WireTrackedOrder[]; batches: BatchSummary[]; insuranceFund: string; treasury: string; userAdlClawed: string;
  lp: { tvl: string; navPerShare: string; totalShares: string; myShares: string; myValue: string };
  mmHedge: WireHedge[];
  l1: WireL1 | null;
  attestation: { measurement: string; tcb: string; quoteVersion: number } | null;
  /// FIN-001 (absent on an old gateway) — validated field-by-field at parse time.
  depositIngestion?: unknown;
  settlementHealth?: unknown;
  settlementConsecutiveFailures?: unknown;
  settlementLastError?: unknown;
  settlementHeldSinceMs?: unknown;
}
interface WireHedge {
  marketId: number; symbol: string; inventory: string; hedgeTarget: string; notional: string;
}
interface WireL1 {
  settledRoot: string; batchCount: number; lastTx: string; bondUsdc: string; withdrawalsRoot: string;
}
interface WireWithdrawal {
  to: string; amount: string; nonce: number; leaf: string; root: string;
  claimable: boolean; proof: string[];
}
/// The gateway's WReceipt wire shape — the domain `Receipt` plus `windowId`.
interface WireV1Receipt { signature?: string; enclaveSigner?: string; orderHash: string; seqNo: number; recvTimeMs: number; batchIdHint: number; windowId: number }
/// One order in the FLAT `GET /v1/orders` shape (`v1_orders_json`) — unlike the
/// legacy /api/state entries there is no nested `input` object.
interface WireV1Order {
  cancellable?: unknown;
  orderId: string; marketId: number; side: "Buy" | "Sell"; size: string; limitPrice: string;
  tif: string; reduceOnly: boolean; orderHash: string; finality: TrackedOrder["finality"];
  filledSize: string | null; avgFillPrice: string | null; createdMs: number;
  execution?: unknown;
  /// SEC-025-E1 decision (c): the stored acceptance receipt, served by the
  /// gateway. Optional so an OLDER gateway (field absent) degrades, not crashes.
  receipt?: WireV1Receipt;
}

const B = (s: string): bigint => BigInt(s);

function pMarket(m: WireMarket): Market {
  return { ...m, referencePrice: B(m.referencePrice) };
}
function pOracle(o: WireOracle): OracleQuote {
  return { marketId: o.marketId, price: B(o.price), confidence: B(o.confidence), publishTimeMs: o.publishTimeMs };
}
function pLevel(l: WireBookLevel): BookLevel {
  return { price: B(l.price), size: B(l.size) };
}
function pBook(b: WireState["book"]): OrderBookSnapshot {
  return { marketId: b.marketId, bids: b.unavailable ? [] : b.bids.map(pLevel), asks: b.unavailable ? [] : b.asks.map(pLevel), ...(b.unavailable === true ? { unavailable: true } : {}) };
}
function pPosition(p: WirePosition): Position {
  return {
    marketId: p.marketId, size: B(p.size), entryPrice: B(p.entryPrice), collateral: B(p.collateral),
    unrealizedPnl: B(p.unrealizedPnl), liquidationPrice: B(p.liquidationPrice),
  };
}
function pOrder(o: WireTrackedOrder): TrackedOrder {
  return {
    ...cancellationCapability(o.cancellable),
    id: o.id,
    input: { ...o.input, side: o.input.side, size: B(o.input.size), limitPrice: B(o.input.limitPrice), tif: o.input.tif as OrderInput["tif"] },
    receipt: o.receipt, finality: o.finality, filledSize: B(o.filledSize ?? "0"), avgFillPrice: B(o.avgFillPrice ?? "0"), createdMs: o.createdMs,
    ...(o.execution === undefined ? {} : { execution: parseExecution(o.execution, { size: o.input.size, filledSize: o.filledSize, avgFillPrice: o.avgFillPrice }) }),
  };
}
function pAccount(a: WireState["account"]): AccountState {
  return { settledBalance: B(a.settledBalance), positions: a.positions.map(pPosition) };
}
/**
 * Map the flat `GET /v1/orders` wire shape into the UI's nested TrackedOrder.
 *
 * Receipt — SEC-025-E1 decision (c): the gateway serves the stored acceptance
 * receipt on /v1/orders (it always held it; the frontend-only alternatives could
 * only render placeholders for orders placed in other sessions). It is mapped
 * FIELD-BY-FIELD rather than passed through: the domain `Receipt` has no
 * `windowId`, and the explicit map keeps the domain type the contract instead
 * of silently carrying whatever extra keys the wire grows. An older gateway
 * that omits the field degrades to a synthesized stub (hash from the flat
 * `orderHash`, zero seq/batch) — degrade, never throw.
 *
 * Execution is separate native metadata. An upgraded gateway preserves exact
 * applied-fill quantities; a migrated legacy order can explicitly lack history.
 */
function pV1Order(o: WireV1Order): TrackedOrder {
  const r = o.receipt;
  const receipt: Receipt =
    r && typeof r.orderHash === "string" && typeof r.seqNo === "number" &&
    typeof r.recvTimeMs === "number" && typeof r.batchIdHint === "number"
      ? { orderHash: r.orderHash, seqNo: r.seqNo, recvTimeMs: r.recvTimeMs, batchIdHint: r.batchIdHint,
          ...(typeof r.signature === "string" && /^0x[0-9a-fA-F]{130}$/.test(r.signature) &&
              typeof r.enclaveSigner === "string" && /^0x[0-9a-fA-F]{40}$/.test(r.enclaveSigner)
            ? { signature: r.signature, enclaveSigner: r.enclaveSigner } : {}) }
      : { orderHash: o.orderHash, seqNo: 0, recvTimeMs: o.createdMs, batchIdHint: 0 };
  return {
    ...cancellationCapability(o.cancellable),
    id: o.orderId,
    input: {
      marketId: o.marketId, side: o.side, size: B(o.size), limitPrice: B(o.limitPrice),
      tif: o.tif as OrderInput["tif"], reduceOnly: o.reduceOnly,
    },
    receipt,
    finality: o.finality,
    filledSize: B(o.filledSize ?? "0"),
    avgFillPrice: B(o.avgFillPrice ?? "0"),
    ...(o.execution === undefined ? {} : { execution: parseExecution(o.execution, { size: o.size, filledSize: o.filledSize, avgFillPrice: o.avgFillPrice }) }),
    createdMs: o.createdMs,
  };
}
/// FIN-001, defensively: an old gateway (fields absent) or a malformed frame
/// parses to null — the UI simply hides the row, never crashes.
function pSettlement(w: WireState): SettlementHealth | null {
  const h = w.settlementHealth;
  if (h !== "HEALTHY" && h !== "DEGRADED" && h !== "HELD") return null;
  return {
    health: h,
    consecutiveFailures:
      typeof w.settlementConsecutiveFailures === "number" ? w.settlementConsecutiveFailures : 0,
    lastError: typeof w.settlementLastError === "string" ? w.settlementLastError : null,
    heldSinceMs: typeof w.settlementHeldSinceMs === "number" ? w.settlementHeldSinceMs : null,
  };
}
function parseState(w: WireState): ClientState {
  const marks: Record<number, bigint> = {};
  for (const [k, v] of Object.entries(w.marks)) marks[Number(k)] = B(v);
  return {
    markets: w.markets.map(pMarket),
    selectedMarketId: w.selectedMarketId,
    market: pMarket(w.market),
    mode: w.mode,
    oracle: pOracle(w.oracle),
    book: pBook(w.book),
    marks,
    account: pAccount(w.account),
    orders: w.orders.map(pOrder),
    batches: w.batches,
    insuranceFund: B(w.insuranceFund),
    treasury: B(w.treasury),
    lp: {
      tvl: B(w.lp.tvl),
      navPerShare: w.lp.navPerShare,
      totalShares: B(w.lp.totalShares),
      myShares: B(w.lp.myShares),
      myValue: B(w.lp.myValue),
    },
    userAdlClawed: B(w.userAdlClawed),
    mmHedge: w.mmHedge.map((h) => ({
      marketId: h.marketId,
      symbol: h.symbol,
      inventory: B(h.inventory),
      hedgeTarget: B(h.hedgeTarget),
      notional: B(h.notional),
    })),
    l1: w.l1
      ? {
          settledRoot: w.l1.settledRoot,
          batchCount: w.l1.batchCount,
          lastTx: w.l1.lastTx,
          bondUsdc: B(w.l1.bondUsdc),
          withdrawalsRoot: w.l1.withdrawalsRoot,
        }
      : null,
    attestation: w.attestation,
    settlement: pSettlement(w),
  };
}

const s = (v: bigint) => v.toString();

// ── sealed order ingress: cross-language contracts (Tasks 9/10 ↔ 11) ─────────

/// Domain-separation tags — MUST equal `perp_core::hash::Domain` discriminants.
const DOMAIN_X25519_ORDER_EPOCH = 25; // Domain::X25519OrderEpoch
const DOMAIN_ORDER_ENCRYPT_AAD = 28; // Domain::OrderEncryptAad

/// Wire length of the canonical order terms (mirrors gateway ORDER_TERMS_LEN).
const ORDER_TERMS_LEN = 51;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I128_MIN = -(1n << 127n);
const I128_MAX = (1n << 127n) - 1n;

/** u64 → 8 little-endian bytes (throws out-of-range; never truncates). */
function u64le(v: bigint): Uint8Array {
  if (v < 0n || v > U64_MAX) throw new Error(`u64 out of range: ${v}`);
  const out = new Uint8Array(8);
  let x = v;
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/** i128 → 16 little-endian bytes, two's complement (throws out-of-range). */
function i128le(v: bigint): Uint8Array {
  if (v < I128_MIN || v > I128_MAX) throw new Error(`i128 out of range: ${v}`);
  const out = new Uint8Array(16);
  let x = BigInt.asUintN(128, v);
  for (let i = 0; i < 16; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/** u64 → 8 BIG-endian bytes (throws out-of-range; never truncates). */
function u64be(v: bigint): Uint8Array {
  if (v < 0n || v > U64_MAX) throw new Error(`u64 out of range: ${v}`);
  const out = new Uint8Array(8);
  let x = v;
  for (let i = 7; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/** i128 → 16 BIG-endian bytes, two's complement (throws out-of-range). */
function i128be(v: bigint): Uint8Array {
  if (v < I128_MIN || v > I128_MAX) throw new Error(`i128 out of range: ${v}`);
  const out = new Uint8Array(16);
  let x = BigInt.asUintN(128, v);
  for (let i = 15; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

/**
 * SEC-021: the digest a withdrawal authorization signature must cover — byte-
 * identical to the gateway's `withdraw_auth_digest` (crates/gateway/src/main.rs):
 * `keccak256("dark-perp:withdraw:" ‖ chainId ‖ vault ‖ owner ‖ marketId ‖ amount ‖ to ‖ nonce)`
 *
 * Every field is fixed-width BIG-endian, no length prefixes, no separators — a
 * wrong width silently produces a different digest, so the layout is pinned
 * against the Rust known-answer vectors in realClient.test.ts:
 * ```text
 * offset  len  field
 *      0   19  "dark-perp:withdraw:"  (ASCII, no trailing space)
 *     19    8  chainId    u64 BE      (EIGHT bytes — NOT the 32-byte Solidity
 *                                      word the on-chain deposit digest uses)
 *     27   20  vault
 *     47   32  owner
 *     79    8  marketId   u64 BE
 *     87   16  amount     i128 BE (two's complement)
 *    103   20  to
 *    123    8  nonce      u64 BE      (total preimage: 131 bytes)
 * ```
 */
export function withdrawAuthDigest(
  chainId: bigint,
  vault: string,
  owner: Uint8Array,
  marketId: bigint,
  amount: bigint,
  to: string,
  nonce: bigint,
): Uint8Array {
  if (owner.length !== 32) throw new Error("owner pubkey must be 32 bytes");
  return keccak_256(concatBytes(
    utf8ToBytes("dark-perp:withdraw:"),
    u64be(chainId),
    strictHex(vault, 20),
    owner,
    u64be(marketId),
    i128be(amount),
    strictHex(to, 20),
    u64be(nonce),
  ));
}

/** Strict 0x-hex decode of EXACTLY `len` bytes (rejects odd/short/non-hex). */
function strictHex(sHex: string, len: number): Uint8Array {
  const h = sHex.startsWith("0x") || sHex.startsWith("0X") ? sHex.slice(2) : sHex;
  if (h.length !== len * 2 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error(`expected ${len}-byte 0x-hex, got ${sHex.length > 80 ? sHex.slice(0, 80) + "…" : sHex}`);
  }
  return hexToBytes(h.toLowerCase());
}

/// side/tif numeric mapping — IDENTICAL to the gateway's `mk_order` /
/// `deserialize_order_terms` encoding. Do not invent a different one.
const SIDE_BYTE: Record<Side, number> = { Buy: 1, Sell: 2 };
const TIF_BYTE: Record<TimeInForce, number> = { Gtc: 1, Ioc: 2, Fok: 3, PostOnly: 4 };

export interface OrderTermsFields {
  marketId: bigint;
  side: Side;
  size: bigint;
  limitPrice: bigint;
  tif: TimeInForce;
  reduceOnly: boolean;
  nonce: bigint;
}

/**
 * Serialize order terms to the canonical cross-language byte layout the enclave
 * decrypts (gateway `deserialize_order_terms` — Task 10/11 contract). All
 * integers little-endian; total 51 bytes:
 *
 * | offset | field       | type     | bytes | notes                                           |
 * |--------|-------------|----------|-------|-------------------------------------------------|
 * | 0      | marketId    | u64  LE  | 8     |                                                 |
 * | 8      | side        | u8       | 1     | `1 = Buy`, `2 = Sell`                           |
 * | 9      | size        | i128 LE  | 16    | size-scaled, must be > 0                        |
 * | 25     | limitPrice  | i128 LE  | 16    | price-scaled, `0` = market order                |
 * | 41     | tif         | u8       | 1     | `1 = Gtc`, `2 = Ioc`, `3 = Fok`, `4 = PostOnly` |
 * | 42     | reduceOnly  | u8       | 1     | `0 = false`, `1 = true`                         |
 * | 43     | nonce       | u64  LE  | 8     |                                                 |
 *
 * Pinned byte-for-byte against Rust `serialize_order_terms` in realClient.test.ts.
 */
export function serializeOrderTerms(t: OrderTermsFields): Uint8Array {
  const side = SIDE_BYTE[t.side];
  const tif = TIF_BYTE[t.tif];
  if (side === undefined) throw new Error(`unknown side: ${t.side}`);
  if (tif === undefined) throw new Error(`unknown tif: ${t.tif}`);
  const b = new Uint8Array(ORDER_TERMS_LEN);
  b.set(u64le(t.marketId), 0);
  b[8] = side;
  b.set(i128le(t.size), 9);
  b.set(i128le(t.limitPrice), 25);
  b[41] = tif;
  b[42] = t.reduceOnly ? 1 : 0;
  b.set(u64le(t.nonce), 43);
  return b;
}

/**
 * The signed digest of a published order-ingress epoch key (gateway
 * `enclave_epoch::epoch_signing_digest` — Task 9/11 contract):
 * `keccak256( u8(25) ‖ epochId u64 LE (8) ‖ x25519Pub (32) ‖ notAfterMs u64 LE (8) )`
 * — a 49-byte little-endian preimage. Pinned against the Rust output in tests.
 */
export function epochSigningDigest(epochId: bigint, x25519Pub: Uint8Array, notAfterMs: bigint): Uint8Array {
  if (x25519Pub.length !== 32) throw new Error("x25519Pub must be 32 bytes");
  const pre = new Uint8Array(49);
  pre[0] = DOMAIN_X25519_ORDER_EPOCH;
  pre.set(u64le(epochId), 1);
  pre.set(x25519Pub, 9);
  pre.set(u64le(notAfterMs), 41);
  return keccak_256(pre);
}

/** A verified enclave order-epoch key the client may seal orders to. */
export interface VerifiedEpoch {
  epochId: number;
  /** X25519 recipient public key (32 bytes). */
  pub: Uint8Array;
  /** Advisory expiry (ms) — refetch the epoch once passed. */
  notAfterMs: number;
}

export interface VerifyEpochOptions {
  /**
   * Pinned enclave signer 0x-address (VITE_ENCLAVE_SIGNER). UNSET in dev ⇒ warn,
   * don't gate. Present-but-empty/whitespace ⇒ hard error (a broken deployment
   * config must never silently downgrade to unpinned mode), and any set value
   * must be a 20-byte 0x-hex address.
   */
  expectedSigner?: string | null;
  /** Pinned attestation measurement 0x-hex (VITE_ENCLAVE_MEASUREMENT). Unset ⇒ skip. */
  expectedMeasurement?: string | null;
  /**
   * Production build (import.meta.env.PROD). In prod a MISSING signer pin is a
   * hard error too — unpinned epoch verification is a dev-only posture.
   */
  prod?: boolean;
}

/**
 * Verify a `GET /v1/enclave/epoch` response: the 65-byte `r‖s‖v` secp256k1
 * signature (v ∈ {27,28}) over `epochSigningDigest` must RECOVER to the pinned
 * enclave signer address (keccak256(uncompressed pubkey)[12..]). With no pinned
 * signer (dev) the recovery must still succeed, but the address gate is skipped
 * with a loud warning. Throws on ANY failure — the caller must treat a throw as
 * "do not seal to this key".
 */
export function verifyEnclaveEpoch(raw: unknown, opts: VerifyEpochOptions = {}): VerifiedEpoch {
  const r = raw as { epochId?: unknown; x25519Pub?: unknown; notAfterMs?: unknown; measurement?: unknown; sig?: unknown };
  if (
    typeof r !== "object" || r === null ||
    typeof r.epochId !== "number" || !Number.isSafeInteger(r.epochId) || r.epochId < 0 ||
    typeof r.notAfterMs !== "number" || !Number.isSafeInteger(r.notAfterMs) || r.notAfterMs < 0 ||
    typeof r.x25519Pub !== "string" || typeof r.measurement !== "string" || typeof r.sig !== "string"
  ) {
    throw new Error("enclave epoch: malformed response");
  }
  const pub = strictHex(r.x25519Pub, 32);
  const measurement = strictHex(r.measurement, 32);
  const sig = strictHex(r.sig, 65);

  const v = sig[64];
  if (v !== 27 && v !== 28) throw new Error(`enclave epoch: bad sig v byte ${v} (expected 27/28)`);

  const digest = epochSigningDigest(BigInt(r.epochId), pub, BigInt(r.notAfterMs));
  let recovered: Uint8Array;
  try {
    const signature = secp256k1.Signature.fromCompact(sig.subarray(0, 64)).addRecoveryBit(v - 27);
    recovered = signature.recoverPublicKey(digest).toRawBytes(false); // 65B uncompressed, 0x04-tagged
  } catch (e) {
    throw new Error(`enclave epoch: signature recovery failed (${e instanceof Error ? e.message : e})`);
  }
  const addr = "0x" + bytesToHex(keccak_256(recovered.subarray(1)).subarray(12));

  // Signer pin: an EMPTY/whitespace VITE_ENCLAVE_SIGNER is a config bug, not
  // "dev mode" — it must never silently downgrade to unpinned verification.
  let expectedSigner: string | null = null;
  if (typeof opts.expectedSigner === "string") {
    const pin = opts.expectedSigner.trim().toLowerCase();
    if (pin === "") {
      throw new Error(
        "enclave epoch: VITE_ENCLAVE_SIGNER is set but EMPTY — refusing the silent downgrade to unpinned mode; set the enclave signer address (or unset the var entirely in dev)",
      );
    }
    if (!/^0x[0-9a-f]{40}$/.test(pin)) {
      throw new Error("enclave epoch: VITE_ENCLAVE_SIGNER is not a 20-byte 0x-hex address");
    }
    expectedSigner = pin;
  }
  if (expectedSigner) {
    if (addr !== expectedSigner) {
      throw new Error(`enclave epoch: sig recovers to ${addr}, not the pinned enclave signer ${expectedSigner}`);
    }
  } else if (opts.prod) {
    throw new Error(
      "enclave epoch: production build without a pinned enclave signer (VITE_ENCLAVE_SIGNER) — refusing unpinned epoch verification",
    );
  } else {
    console.warn(
      "[dark-perp] VITE_ENCLAVE_SIGNER not set — enclave epoch signer UNPINNED (dev mode). Recovered signer:",
      addr,
    );
  }

  const expectedMeasurement = opts.expectedMeasurement || null;
  if (expectedMeasurement && bytesToHex(measurement) !== bytesToHex(strictHex(expectedMeasurement, 32))) {
    throw new Error("enclave epoch: measurement does not match the pinned attestation measurement");
  }

  return { epochId: r.epochId, pub, notAfterMs: r.notAfterMs };
}

/// localStorage key for the self-provisioned `/v1` trading account.
const LS_ACCOUNT_KEY = "darkperp.v1Account";

interface SealingAccount {
  apiKey: string;
  /** The account's 32-byte owner pubkey — the sealed-order AAD binds to it. */
  owner: Uint8Array;
}

/** Total recovery rounds (initial + retries) — see recoverAccount's S1 contract. */
const MAX_RECOVERY_ATTEMPTS = 3;

/**
 * Internal error of one recovery round: `retryable` decides whether
 * recoverAccount re-GETs/re-signs/re-POSTs with a FRESH nonce or gives up
 * immediately (400/401/409, wallet rejection, superseded, storage refusal).
 */
class RecoveryAttemptError extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "RecoveryAttemptError";
  }
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export class RealDarkPerpClient implements DarkPerpClient {
  private base: string;
  private wsUrl: string;
  private state: ClientState | null = null;
  private subs = new Set<(s: ClientState) => void>();
  private eventSubs = new Set<(e: OrderEvent) => void>();
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  // ── the live account stream (/v1/ws, SEC-025-E1 Task 2) ────────────────────
  // The legacy /ws is a PUBLIC broadcast: its event frames are the shared demo
  // wallet's order lifecycle, delivered to every client unfiltered — another
  // account's activity. This client's own events (fills, finality transitions,
  // ADL haircuts) arrive on the authenticated /v1/ws instead: after
  // `{"type":"auth","apiKey"}` the server forwards only events whose `owner`
  // equals the authenticated owner (and the client re-verifies — see
  // handleV1Frame). Pre-key the connection is a VALID unauthenticated state
  // that receives public market frames only: degrade, never throw.
  private wsV1Url: string;
  private wsV1: WebSocket | null = null;
  private reconnectV1Timer: ReturnType<typeof setTimeout> | null = null;
  /**
   * The authenticated stream's owner: set ONLY after the server's authOk
   * claim was verified against this client's own registration owner
   * (`sealing.owner` — review F8). Events must match it exactly.
   */
  private v1Owner: string | null = null;
  /** Auth is per-connection: reset when a new /v1/ws socket is created. */
  private v1AuthSent = false;

  // ── client-side market selection ───────────────────────────────────────────
  // The gateway's WS frame carries book/oracle/selectedMarketId for the SERVER's
  // selected market only (market 0 on the shared prod gateway) — but `marks` and
  // `markets` cover every market. Which market THIS user is looking at is a
  // per-browser concern, so it lives here (the legacy `POST /api/select-market`
  // demo route is 404 in prod AND was a global toggle shared by all users).
  /** The market this browser has selected (default 0 — the server's market). */
  private clientSelectedMarket = 0;
  /** Fetched book for the client-selected market (null until the fetch lands). */
  private selBook: OrderBookSnapshot | null = null;
  /** Fetched oracle for the client-selected market (null until the fetch lands). */
  private selOracle: OracleQuote | null = null;
  /** Freshness poll for the selected market — the WS only refreshes the server's. */
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private disposed = false;

  // ── own-account state (SEC-025-E1) ─────────────────────────────────────────
  // The public /api/state + /ws feed carries ONLY the shared demo wallet (the
  // gateway's LIQ-001 invariant keeps real /v1 tenants off it), while this
  // client's sealed orders trade as its own authenticated /v1 account. These
  // caches hold the latest authenticated /v1 reads; emit() overlays them so the
  // UI shows the CALLER's account. `null` with NO /v1 account falls through to
  // the legacy feed; `null` with an account provisioned renders the EMPTY
  // unavailable placeholder instead (review F1 — see emit()), never the demo
  // wallet. `ownAccount` is ONE AccountState
  // assembled atomically from the same refresh — balance and positions must
  // never mix accounts (a demo-wallet balance beside the caller's positions
  // invites the user to read a stranger's balance as their own collateral, and
  // feeds maxOrderSize a different account's number).
  //
  // NOTE (recorded at the fix-wave-2 review, deliberately not restructured):
  // once a read has SUCCEEDED these caches are never reset, so
  // `accountUnavailable` can only ever be true before the FIRST successful
  // read — a later read failure silently keeps showing the last-good OWN
  // data (stale, but the caller's own: the safe direction).
  private ownOrders: TrackedOrder[] | null = null;
  private ownAccount: AccountState | null = null;
  /** In-flight own-account refresh — overlapping callers join it (see refreshOwnState). */
  private ownRefresh: Promise<void> | null = null;
  /** Set when a refresh is requested while one is in flight ⇒ one trailing re-run. */
  private ownRefreshAgain = false;
  // Public progress is only a refresh hint; balances come from authenticated reads.
  private depositRefreshHint: string | null = null;

  // ── sealed order ingress state ─────────────────────────────────────────────
  /** The verified enclave order-epoch key (refetched once notAfterMs passes). */
  private epoch: VerifiedEpoch | null = null;
  private epochFetch: Promise<VerifiedEpoch> | null = null;
  /** The self-provisioned `/v1` trading account sealed orders trade as. */
  private sealing: SealingAccount | null = null;
  /**
   * Monotone provisioning latch (fix-wave-3 H3): set beside every `sealing`
   * assignment, NEVER reset. `hasAccount()`'s other two sources can each be
   * erased after the fact — the /v1/ws `error` branch nulls `sealing` (F7),
   * and the stored copy may never have been written (private mode:
   * initAccount swallows the storage-write failure) or can be cleared by
   * another tab — and with both gone emit() would repaint the shared demo
   * wallet as the caller's account: the exact defect F1 removed. An
   * in-memory bit cannot be erased. It feeds ONLY the rendering gate
   * (hasAccount → placeholder + accountUnavailable, the conservative
   * direction); it must never feed tryAuthV1/ensureAccount, which key on
   * `sealing` itself so the no-registration-loop rule (F7) stands.
   */
  private everProvisioned = false;
  private acctFetch: Promise<SealingAccount> | null = null;
  /**
   * Monotonic credential epoch (account-recovery hardening S1): bumped on EVERY
   * credential swap — a confirmed recovery, an initAccount adoption, or a
   * cross-tab storage adoption. Any async step that captured the epoch at
   * start and finds it advanced on arrival (a late recovery result, a stale
   * own-state refresh, an old socket's authOk/error frame) must discard its
   * result instead of overwriting the winner's credential/state.
   */
  private credentialEpoch = 0;
  /**
   * Generation of the stored credential record this client last wrote or
   * adopted. The stored record carries a `gen` field (records without one are
   * legacy generation 0, upgraded on the next confirmed write); a tab whose
   * in-memory `storedGen` is BEHIND the stored record must refuse to write,
   * or a stale tab would clobber a newer rotation from another tab.
   */
  private storedGen = 0;
  /** Cross-tab `storage` listener — registered in the constructor, removed in dispose(). */
  private readonly storageListener: ((ev: StorageEvent) => void) | null = null;
  /**
   * Strictly-increasing order nonce carried inside the sealed terms. The gateway
   * ENFORCES strict monotonicity per account on the decrypted terms (replay
   * protection: a captured `{epochId, sealed}` body re-POSTed is rejected), so
   * this must never repeat or decrease for the account — wall-clock ms (bumped
   * on collision) keeps it increasing across page reloads too.
   */
  private lastNonce = 0n;

  constructor(baseUrl: string, initial: ClientState) {
    this.base = baseUrl.replace(/\/$/, "");
    this.wsUrl = this.base.replace(/^http/, "ws") + "/ws";
    this.wsV1Url = this.base.replace(/^http/, "ws") + "/v1/ws";
    this.state = initial;
    // Cross-tab credential propagation (S1): another tab's write of
    // LS_ACCOUNT_KEY arrives here as a `storage` event (the writing tab itself
    // never fires one). Same-tab writes and other keys are ignored by
    // onStorageEvent.
    if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
      this.storageListener = (ev: StorageEvent) => {
        if (ev.key !== LS_ACCOUNT_KEY) return;
        this.onStorageEvent(ev.newValue);
      };
      window.addEventListener("storage", this.storageListener);
    }
    this.connect();
    this.connectV1();
  }

  /** One blocking fetch of the initial snapshot so the store has a non-null first state. */
  static async bootstrap(baseUrl: string): Promise<RealDarkPerpClient> {
    const base = baseUrl.replace(/\/$/, "");
    const res = await fetch(base + "/api/state");
    if (!res.ok) throw new Error(`gateway /api/state ${res.status}`);
    const initial = parseState((await res.json()) as WireState);
    const client = new RealDarkPerpClient(base, initial);
    // Prepare the sealed-order path (verified epoch key + /v1 trading account) up
    // front so the first order doesn't pay the round trips. A failure here is
    // non-fatal for the read-only UI — placeOrder retries and FAILS CLOSED (an
    // order is never sent in plaintext).
    try {
      await client.prepareSealing();
    } catch (e) {
      console.warn("[dark-perp] sealed-order setup failed at bootstrap (will retry on first order):", e);
    }
    // SEC-025-E1: the /api/state snapshot's account/orders are the SHARED DEMO
    // wallet — the caller's real state lives behind the authenticated /v1
    // reads. Overlay it now so the first render already shows the right
    // account; on failure (no account, gateway down) the UI degrades to the
    // legacy feed (refreshOwnState never throws).
    await client.refreshOwnState();
    return client;
  }

  /** Fetch+verify the epoch key and ensure the /v1 account exists (idempotent). */
  async prepareSealing(): Promise<void> {
    await Promise.all([this.ensureAccount(), this.ensureEpoch()]);
  }

  /**
   * The verified enclave epoch key, from cache while fresh; refetched + REVERIFIED
   * once `notAfterMs` passes. Concurrent callers share one in-flight fetch.
   */
  private ensureEpoch(): Promise<VerifiedEpoch> {
    if (this.epoch && Date.now() < this.epoch.notAfterMs) return Promise.resolve(this.epoch);
    if (!this.epochFetch) {
      this.epochFetch = this.fetchAndVerifyEpoch().finally(() => { this.epochFetch = null; });
    }
    return this.epochFetch;
  }

  private async fetchAndVerifyEpoch(): Promise<VerifiedEpoch> {
    const res = await fetch(this.base + "/v1/enclave/epoch");
    if (!res.ok) throw new Error(`/v1/enclave/epoch ${res.status}`);
    const env = import.meta.env as Record<string, string | undefined> & { PROD?: boolean };
    const ep = verifyEnclaveEpoch(await res.json(), {
      expectedSigner: env.VITE_ENCLAVE_SIGNER,
      expectedMeasurement: env.VITE_ENCLAVE_MEASUREMENT,
      prod: env.PROD === true,
    });
    if (Date.now() >= ep.notAfterMs) {
      // notAfterMs is ADVISORY (the gateway's rotation timer isn't wired yet, so a
      // long-lived gateway keeps serving its boot epoch). The key is still signed
      // by the pinned enclave identity, so sealing to it stays safe — worst case
      // the enclave dropped the secret and rejects the order server-side.
      console.warn("[dark-perp] enclave epoch is past notAfterMs (advisory); proceeding with the signed key");
    }
    this.epoch = ep;
    return ep;
  }

  /**
   * The `/v1` trading account sealed orders trade as: reuse the localStorage one
   * (revalidated against the gateway) or register a fresh account. Its `owner`
   * pubkey is bound into every sealed order's AAD.
   */
  private ensureAccount(): Promise<SealingAccount> {
    if (this.sealing) return Promise.resolve(this.sealing);
    if (!this.acctFetch) {
      this.acctFetch = this.initAccount().finally(() => { this.acctFetch = null; });
    }
    return this.acctFetch;
  }

  private async initAccount(): Promise<SealingAccount> {
    const storedRec = this.readStoredRecord();
    if (storedRec) {
      try {
        const res = await fetch(this.base + "/v1/accounts/me", { headers: { "X-Api-Key": storedRec.apiKey } });
        if (res.ok) {
          const stored = { apiKey: storedRec.apiKey, owner: strictHex(storedRec.ownerHex, 32) };
          this.storedGen = storedRec.gen; // adopt the record's generation (legacy ⇒ 0)
          this.sealing = stored;
          this.everProvisioned = true;
          // No epoch bump: first provisioning is not a swap — the /v1/ws socket
          // connected at the current epoch must keep accepting authOk/error.
          this.tryAuthV1(); // the account stream may already be open and waiting
          return stored;
        }
      } catch { /* unreachable/reset gateway — fall through and re-register */ }
    }
    const res = await fetch(this.base + "/v1/accounts", { method: "POST" });
    if (!res.ok) throw new Error(`/v1/accounts registration failed (${res.status})`);
    const j = (await res.json()) as { apiKey?: unknown; owner?: unknown };
    if (typeof j.apiKey !== "string" || typeof j.owner !== "string") {
      throw new Error("/v1/accounts: malformed registration response");
    }
    const acct: SealingAccount = { apiKey: j.apiKey, owner: strictHex(j.owner, 32) };
    try {
      // Generation-stamped, stale-overwrite-guarded — same discipline as recovery.
      this.writeStoredCredential(j.apiKey, j.owner);
    } catch { /* storage unavailable (private mode) or a newer stored credential exists — session-only */ }
    this.sealing = acct;
    this.everProvisioned = true;
    // No epoch bump — same reasoning as the stored-adoption branch above.
    this.tryAuthV1(); // the account stream may already be open and waiting
    return acct;
  }

  /**
   * The parsed stored credential record, generation included. Records written
   * before the S1 hardening carry no `gen` — they parse as generation 0 and
   * are upgraded on the next confirmed write.
   */
  private readStoredRecord(): { apiKey: string; ownerHex: string; gen: number } | null {
    try {
      const raw = localStorage.getItem(LS_ACCOUNT_KEY);
      if (!raw) return null;
      const j = JSON.parse(raw) as { apiKey?: unknown; owner?: unknown; gen?: unknown };
      if (
        typeof j !== "object" || j === null ||
        typeof j.apiKey !== "string" ||
        typeof j.owner !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(j.owner)
      ) {
        return null;
      }
      const gen =
        typeof j.gen === "number" && Number.isSafeInteger(j.gen) && j.gen >= 0 ? j.gen : 0;
      return { apiKey: j.apiKey, ownerHex: j.owner, gen };
    } catch {
      return null;
    }
  }

  /**
   * Persist a freshly confirmed credential, generation-stamped, with stale-
   * overwrite protection (S1 multi-tab): the CURRENT stored record is re-read
   * first, and if it holds a NEWER generation than this tab last saw, the
   * write is REFUSED (another tab rotated the key more recently — this stale
   * tab must not clobber it). Throws on refusal AND on storage failure; the
   * caller treats a throw as "failure to swap" and keeps its old credential.
   */
  private writeStoredCredential(apiKey: string, ownerHex: string): void {
    const current = this.readStoredRecord();
    if (
      current !== null &&
      current.ownerHex.toLowerCase() === ownerHex.toLowerCase() &&
      current.gen > this.storedGen
    ) {
      throw new Error(
        "Refusing to overwrite a newer stored credential (another tab rotated this account's key more recently).",
      );
    }
    const gen = Math.max(current?.gen ?? 0, this.storedGen) + 1;
    localStorage.setItem(
      LS_ACCOUNT_KEY,
      JSON.stringify({ apiKey, owner: ownerHex, gen, ts: Date.now() }),
    );
    this.storedGen = gen;
  }

  /**
   * Cross-tab adoption (S1): another tab wrote a new LS_ACCOUNT_KEY. Adopt it
   * ONLY when it belongs to the owner this tab currently knows (a foreign
   * owner's record is ignored — it is another user's account in a shared
   * browser profile) AND its generation is newer than what this tab last saw
   * (an older/equal generation is a stale echo — ignore). Adoption bumps the
   * credential epoch (so in-flight old-credential work is discarded), swaps
   * sealing, and forces a /v1/ws re-auth.
   */
  private onStorageEvent(newValue: string | null): void {
    if (newValue === null) return; // key removed — nothing to adopt
    let rec: { apiKey?: unknown; owner?: unknown; gen?: unknown };
    try {
      rec = JSON.parse(newValue) as { apiKey?: unknown; owner?: unknown; gen?: unknown };
    } catch {
      return; // malformed record — ignore
    }
    if (
      typeof rec !== "object" || rec === null ||
      typeof rec.apiKey !== "string" ||
      typeof rec.owner !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(rec.owner)
    ) {
      return;
    }
    const gen =
      typeof rec.gen === "number" && Number.isSafeInteger(rec.gen) && rec.gen >= 0 ? rec.gen : 0;
    // Foreign-owner records are out of this tab's owner scope — ignore.
    const known = this.sealing ?? this.readStoredAccount();
    if (known && bytesToHex(known.owner).toLowerCase() !== rec.owner.toLowerCase().slice(2)) return;
    if (!known) return; // no known owner scope — a stray record is not adopted
    if (gen <= this.storedGen) return; // stale or same-generation echo
    this.storedGen = gen;
    this.credentialEpoch++;
    this.sealing = { apiKey: rec.apiKey, owner: strictHex(rec.owner, 32) };
    this.everProvisioned = true;
    this.ownAccount = null;
    this.ownOrders = null;
    this.v1AuthSent = false;
    this.v1Owner = null;
    if (this.wsV1) { try { this.wsV1.close(); } catch { /* noop */ } } else this.connectV1();
    void this.refreshOwnState();
  }

  private readStoredAccount(): SealingAccount | null {
    const rec = this.readStoredRecord();
    if (!rec) return null;
    return { apiKey: rec.apiKey, owner: strictHex(rec.ownerHex, 32) };
  }

  /**
   * Whether a /v1 account exists for this browser — emit()'s fallback gate
   * (review F1, tightened at fix-wave-2 G1). `sealing` covers the provisioned
   * account; the STORED account covers the two states where `sealing` is null
   * yet an account exists: (a) the /v1/ws `error` branch dropped a dead key
   * (F7) before any own read had succeeded, and (b) a returning browser whose
   * stored key failed revalidation and whose re-registration also failed. In
   * both, falling through to the public feed would render the shared demo
   * wallet as the caller's account — the exact defect F1 removed, reopened by
   * its neighbour. The `everProvisioned` latch (fix-wave-3 H3) covers the
   * state where BOTH of those are gone — private mode (the storage write
   * threw, so nothing was ever stored) or a cleared storage, followed by the
   * F7 reset nulling `sealing` — because both sources are erasable and the
   * in-memory latch is not. Both the fallback AND `accountUnavailable` key on
   * this one predicate so the two can never disagree.
   */
  private hasAccount(): boolean {
    // Cheap in-memory disjuncts first (H3): emit() runs this on every WS frame
    // and every poll tick, and readStoredAccount() is a synchronous
    // localStorage read + JSON.parse — once the latch is set (any provisioned
    // session) the storage read never runs. The middle disjunct is subsumed by
    // the latch today (every `sealing` assignment sets it) and stays as a
    // guard against a future assignment site that forgets to.
    return this.everProvisioned || this.sealing !== null || this.readStoredAccount() !== null;
  }

  /**
   * Strictly-increasing order nonce (wall clock, bumped on collision). Gateway-
   * enforced: a sealed order whose decrypted nonce does not strictly increase is
   * rejected with 400 (replay protection).
   */
  private nextNonce(): bigint {
    const now = BigInt(Date.now());
    this.lastNonce = now > this.lastNonce ? now : this.lastNonce + 1n;
    return this.lastNonce;
  }

  private connect() {
    if (this.disposed) return;
    try {
      if (this.ws) { try { this.ws.close(); } catch { /* noop */ } }
      this.depositRefreshHint = null;
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string) as { type?: string; state?: WireState };
          // STATE frames only. The legacy stream also broadcasts `event`
          // frames, but those are the shared demo wallet's order lifecycle —
          // another account's activity, sent to every client unfiltered. This
          // client's own events arrive owner-filtered on /v1/ws
          // (handleV1Frame); forwarding the legacy ones would pop toasts for
          // orders that are not the caller's.
          if (msg.type === "state" && msg.state) {
            this.setState(parseState(msg.state));
            this.refreshAfterDeposit(msg.state.depositIngestion);
          }
        } catch { /* ignore malformed frame */ }
      };
      this.ws.onclose = () => { this.scheduleReconnect(); };
      this.ws.onerror = () => { try { this.ws?.close(); } catch { /* noop */ } };
    } catch {
      this.scheduleReconnect();
    }
  }

  private refreshAfterDeposit(value: unknown): void {
    if (!value || typeof value !== "object" || this.disposed || !this.hasAccount()) return;
    const d = value as Record<string, unknown>;
    if (d.state !== "ready" || typeof d.consumedCount !== "number" ||
        !Number.isSafeInteger(d.consumedCount) || d.consumedCount < 0 ||
        typeof d.consumedTip !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(d.consumedTip)) return;
    const hint = `${d.consumedCount}:${d.consumedTip}`;
    if (hint === this.depositRefreshHint) return;
    this.depositRefreshHint = hint;
    void this.refreshOwnState();
  }

  private scheduleReconnect() {
    if (this.reconnectTimer || this.disposed) return;
    this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; this.connect(); }, 1500);
  }

  // ── /v1/ws: the authenticated account stream ────────────────────────────────

  private connectV1() {
    if (this.disposed) return;
    try {
      if (this.wsV1) { try { this.wsV1.close(); } catch { /* noop */ } }
      // Per-connection state: the server forgets us on disconnect, so a new
      // socket must re-auth (and must not trust a stale authOk owner).
      this.v1AuthSent = false;
      this.v1Owner = null;
      this.wsV1 = new WebSocket(this.wsV1Url);
      // S1 epoch + identity pinning: the frame handler drops authOk/error
      // frames whose socket is no longer the current one OR whose connect
      // predates the current credential epoch — an old socket's late frame
      // after a rotation-driven reconnect must not clear/replace the new
      // credential/sealing.
      const socket = this.wsV1;
      const connectEpoch = this.credentialEpoch;
      this.wsV1.onopen = () => { this.tryAuthV1(); };
      this.wsV1.onmessage = (ev) => { this.handleV1Frame(ev.data as string, socket, connectEpoch); };
      this.wsV1.onclose = () => { this.scheduleReconnectV1(); };
      this.wsV1.onerror = () => { try { this.wsV1?.close(); } catch { /* noop */ } };
    } catch {
      this.scheduleReconnectV1();
    }
  }

  private scheduleReconnectV1() {
    if (this.reconnectV1Timer || this.disposed) return;
    this.reconnectV1Timer = setTimeout(() => { this.reconnectV1Timer = null; this.connectV1(); }, 1500);
  }

  /**
   * Send the auth handshake once BOTH preconditions hold: the socket is OPEN
   * and a /v1 account exists. Called from both edges — socket open (account may
   * already be there) and account provisioning (socket may already be open).
   * Pre-key there is simply nothing to send: the connection stays a valid
   * unauthenticated public stream (degrade, not throw).
   */
  private tryAuthV1(): void {
    const ws = this.wsV1;
    if (!ws || ws.readyState !== 1 /* OPEN */ || this.v1AuthSent) return;
    const acct = this.sealing;
    if (!acct) return;
    try {
      ws.send(JSON.stringify({ type: "auth", apiKey: acct.apiKey }));
      this.v1AuthSent = true;
    } catch { /* socket died between checks — the reconnect path re-auths */ }
  }

  /**
   * One /v1/ws frame. The wire carries four shapes (gateway `ws_v1_loop`):
   * - `{type:"markets", …}` — the public tick snapshot. Ignored: the legacy
   *   /ws state frame remains the base-state source (it alone carries mode,
   *   batches, l1, settlement health, lp, insurance, marks, attestation — the
   *   /v1 public frame has only per-market price + book).
   * - `{type:"authOk", owner}` — auth confirmed. The claimed owner is
   *   VERIFIED against the owner this client holds from registration
   *   (`sealing.owner`) before it is trusted — see the branch below — then
   *   one refresh runs so events missed while unauthenticated aren't lost.
   * - `{type:"error", message}` — auth refused: the api key is dead (this
   *   deployment wipes state.snap on every cutover, so an open tab across a
   *   redeploy lands here). The cached account is dropped so the next
   *   ensureAccount() re-registers and re-auths this socket, instead of the
   *   tab staying wedged on the dead key for its lifetime.
   * - a raw account event with an `owner` field — forwarded by the server only
   *   for the authenticated owner, and checked here against the VERIFIED
   *   owner so a confused or hostile stream still cannot cross accounts.
   */
  private handleV1Frame(raw: string, socket: WebSocket | null = null, connectEpoch = this.credentialEpoch): void {
    let v: { type?: unknown; owner?: unknown; message?: unknown };
    try {
      v = JSON.parse(raw) as { type?: unknown; owner?: unknown; message?: unknown };
    } catch {
      return; // malformed frame
    }
    if (typeof v !== "object" || v === null) return;
    // S1: an authOk/error frame from a socket that is no longer current, or
    // that connected under an older credential epoch (its auth handshake used
    // a since-rotated key), can neither establish v1Owner nor clear sealing.
    const staleSocket = socket !== null && (socket !== this.wsV1 || connectEpoch !== this.credentialEpoch);
    if (v.type === "authOk" && typeof v.owner === "string") {
      if (staleSocket) return;
      // Review F8: verify the server's claimed owner against the owner WE
      // hold from registration — storing the echo and then "re-verifying"
      // events against it would compare the server to itself and provide
      // nothing. A mismatch means the stream is confused or hostile about
      // whose account this is; refuse to treat the socket as authenticated
      // (its account events stay dropped) — this branch's whole subject is
      // not trusting a feed about whose account it is showing.
      const expected = this.sealing ? "0x" + bytesToHex(this.sealing.owner) : null;
      if (expected === null || v.owner.toLowerCase() !== expected) {
        console.warn(
          "[dark-perp] /v1/ws authOk owner mismatch — refusing the stream's account events:",
          v.owner,
        );
        return;
      }
      this.v1Owner = expected;
      // The stream is live from here, but anything that happened between the
      // last refresh and this auth was never delivered — start current.
      void this.refreshOwnState();
      return;
    }
    if (v.type === "error") {
      if (staleSocket) return;
      console.warn("[dark-perp] /v1/ws auth failed (account events unavailable):", v.message);
      // Review F7: the server refused the api key ⇒ the cached account is
      // dead (a state-wipe cutover with this tab open lands here). Leaving
      // `v1AuthSent`/`sealing` set would wedge BOTH the socket (tryAuthV1
      // never retries on it) and every /v1 read (ensureAccount returns the
      // dead account forever, 401ing into the unavailable placeholder).
      // Clear them so the NEXT ensureAccount() re-registers (initAccount
      // revalidates the stored key and replaces it) and its tryAuthV1
      // re-auths this same socket. No auto-retry here: a server answering
      // `error` to every fresh key must not drive a registration loop.
      this.v1AuthSent = false;
      this.v1Owner = null;
      this.sealing = null;
      return;
    }
    if (v.type === "markets") return; // public frame — see doc above
    // Account event: must carry OUR authenticated owner, exactly.
    if (typeof v.owner !== "string" || !this.v1Owner || v.owner !== this.v1Owner) return;
    this.handleOwnEvent(v as Record<string, unknown>);
  }

  /**
   * An own-account event landed. Whatever it is, the /v1 view moved — refresh
   * through the guarded path (the third trigger `refreshOwnState`'s in-flight
   * guard was built for). Order-finality transitions and ADL haircuts also
   * surface as OrderEvent notifications (Toaster + ActivityFeed); `fill`
   * and `execution` events refresh amounts without creating finality notifications.
   * Further maker fills can arrive even when the receipt is already SETTLED.
   */
  private handleOwnEvent(ev: Record<string, unknown>): void {
    void this.refreshOwnState();
    const orderId = typeof ev.orderId === "string" ? ev.orderId : "";
    if (ev.type === "order") {
      const f = ev.finality;
      if (f === "ACCEPTED" || f === "MATCHED" || f === "SETTLED") {
        // The wire event carries no message (the legacy stream's did) — the
        // texts mirror the gateway's legacy per-finality wording.
        const message =
          f === "MATCHED" ? "Matched (soft preconfirmation) — not yet withdrawable"
          : f === "SETTLED" ? "Settled on L1 — withdrawable"
          : "Order accepted";
        for (const cb of this.eventSubs) cb({ orderId, kind: f, message });
      }
    } else if (ev.type === "adl") {
      const clawed = typeof ev.clawed === "string" ? ev.clawed : "?";
      const message = `Auto-deleveraged: $${clawed} of your winning position was clawed to cover a counterparty's bad debt.`;
      for (const cb of this.eventSubs) cb({ orderId: orderId || "adl", kind: "ADL", message });
    }
  }

  /**
   * Single choke point between raw gateway state and the UI: every emitted state
   * gets the CLIENT-side market selection applied. The base frame's book/oracle
   * belong to the SERVER's selected market, so when a fetched per-market cache
   * exists for the client's selection it overrides them; until the fetch lands,
   * the base data falls through (exactly right when the client selection IS the
   * server's market; briefly the previous market's book otherwise — `marks` and
   * `market` metadata are already correct instantly).
   */
  private emit(base: ClientState): ClientState {
    const id = this.clientSelectedMarket;
    const hasAcct = this.hasAccount();
    return {
      ...base,
      selectedMarketId: id,
      market: base.markets.find((m) => m.id === id) ?? base.market,
      book: this.selBook ?? base.book,
      oracle: this.selOracle ?? base.oracle,
      // SEC-025-E1: the caller's own /v1 account overrides the public feed's
      // demo wallet. The base frame (the bootstrap /api/state snapshot and the
      // legacy /ws state stream — still the only live source of mode, batches,
      // l1, settlement health, lp, marks, …) carries only the shared demo
      // account — without this overlay every WS push would clobber the user's
      // own view back to demo data one frame after bootstrap fixed it.
      // `ownAccount` replaces the base account WHOLE (balance + positions from
      // the same /v1 refresh): a spread that overlaid only positions would ship
      // a mixed-account AccountState — the demo wallet's settledBalance under
      // the caller's positions.
      //
      // Fallback discipline (whole-branch review F1): the legacy feed stands
      // in ONLY while no /v1 account exists (demo build / pre-key window —
      // the public feed is all there is). Once an account exists the client
      // KNOWS whose state it should render; painting the shared demo wallet
      // there (on a transient /v1 read failure) would show a stranger's
      // balance/positions as the caller's — OrderTicket.maxOrderSize sizing
      // against a stranger's collateral — and render the demo orders as
      // ACTIONABLE rows: order ids collide across accounts
      // (`format!("o{nonce}")`, main.rs:3172), so cancelling the demo row's
      // "o42" would cancel the caller's own unseen "o42". Instead: EMPTY
      // placeholders plus the `accountUnavailable` flag, so the UI can say
      // "unreadable", never "zero" and never a stranger's numbers.
      // "An account exists" is hasAccount() — provisioned, stored (G1), OR
      // ever provisioned this session (the H3 latch): gating on `sealing`
      // alone reopened the fallback in exactly the state-wipe cutover F7's
      // error-branch reset was written for, and the first two sources are
      // both erasable (F7 nulls one; private mode never wrote the other).
      orders: this.ownOrders ?? (hasAcct ? [] : base.orders),
      account:
        this.ownAccount ??
        (hasAcct ? { settledBalance: 0n, positions: [] } : base.account),
      accountUnavailable: hasAcct && this.ownAccount === null,
    };
  }

  /** Apply the selection override and notify subscribers. */
  private setState(base: ClientState): void {
    this.state = this.emit(base);
    for (const cb of this.subs) cb(this.state);
  }

  /**
   * Fetch the selected market's PUBLIC book + oracle (`GET /v1/markets/:id/…`)
   * and re-emit. Responses that arrive late — after a further switch or after
   * dispose — are dropped so a slow fetch can never clobber the current market.
   */
  private async refreshSelected(marketId: number): Promise<void> {
    try {
      const [bRes, oRes] = await Promise.all([
        fetch(`${this.base}/v1/markets/${marketId}/orderbook`),
        fetch(`${this.base}/v1/markets/${marketId}/oracle`),
      ]);
      if (!bRes.ok || !oRes.ok) return;
      const book = pBook((await bRes.json()) as WireState["book"]);
      const oracle = pOracle((await oRes.json()) as WireOracle);
      if (this.disposed || marketId !== this.clientSelectedMarket) return; // stale response
      this.selBook = book;
      this.selOracle = oracle;
      if (this.state) this.setState(this.state);
    } catch { /* gateway hiccup — the poll retries */ }
  }

  /**
   * Keep the selected market's book/oracle fresh: the WS push only refreshes the
   * server's market, so a non-default selection would otherwise freeze. Started
   * lazily on the first market switch; cleared in dispose().
   */
  private ensurePoll(): void {
    if (this.pollTimer || this.disposed) return;
    this.pollTimer = setInterval(() => { void this.refreshSelected(this.clientSelectedMarket); }, 1500);
  }

  /** Tear down sockets + timers. The page-lifetime app never calls this; tests do. */
  dispose(): void {
    this.disposed = true;
    if (this.storageListener && typeof window !== "undefined") {
      window.removeEventListener("storage", this.storageListener);
    }
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    if (this.reconnectV1Timer) { clearTimeout(this.reconnectV1Timer); this.reconnectV1Timer = null; }
    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onmessage = null; ws.onclose = null; ws.onerror = null;
      try { ws.close(); } catch { /* noop */ }
    }
    const wsV1 = this.wsV1;
    this.wsV1 = null;
    if (wsV1) {
      wsV1.onopen = null; wsV1.onmessage = null; wsV1.onclose = null; wsV1.onerror = null;
      try { wsV1.close(); } catch { /* noop */ }
    }
  }

  private async request<T>(
    method: "POST" | "DELETE",
    path: string,
    body: unknown,
    headers?: Record<string, string>,
  ): Promise<T> {
    const res = await fetch(this.base + path, {
      method,
      headers: { "content-type": "application/json", ...(headers ?? {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body ?? {}) }),
    });
    const text = await res.text();
    // Error bodies aren't always JSON (axum extractor rejections are text/plain) —
    // never let JSON.parse mask the real failure.
    let json: { error?: string } | null = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!res.ok) throw new Error(json?.error ?? `${path} failed (${res.status}): ${text.slice(0, 200)}`);
    return json as T;
  }

  private post<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T> {
    return this.request<T>("POST", path, body, headers);
  }

  getState(): ClientState {
    if (!this.state) throw new Error("RealDarkPerpClient used before bootstrap");
    return this.state;
  }
  subscribe(cb: (s: ClientState) => void): () => void { this.subs.add(cb); return () => this.subs.delete(cb); }
  onOrderEvent(cb: (e: OrderEvent) => void): () => void { this.eventSubs.add(cb); return () => this.eventSubs.delete(cb); }

  /**
   * Seal-and-submit an order. The trade terms NEVER travel in plaintext: they are
   * serialized to the canonical 51-byte layout, sealed to the VERIFIED enclave
   * epoch key with AAD `domainAad(28, epochId u64 LE ‖ owner)` (binding the
   * ciphertext to this epoch AND this account), and POSTed as `{epochId, sealed}`
   * to `/v1/orders`. Any epoch-verification failure rejects the order (fail
   * closed) — there is no plaintext fallback.
   */
  async placeOrder(input: OrderInput): Promise<Receipt> {
    const [acct, epoch] = await Promise.all([this.ensureAccount(), this.ensureEpoch()]);
    const terms = serializeOrderTerms({
      marketId: BigInt(input.marketId),
      side: input.side,
      size: input.size,
      limitPrice: input.limitPrice,
      tif: input.tif,
      reduceOnly: input.reduceOnly,
      nonce: this.nextNonce(),
    });
    const extra = new Uint8Array(8 + 32);
    extra.set(u64le(BigInt(epoch.epochId)), 0);
    extra.set(acct.owner, 8);
    const aad = domainAad(DOMAIN_ORDER_ENCRYPT_AAD, extra);
    const sealed = seal(epoch.pub, terms, aad);
    const receipt = await this.post<Receipt>(
      "/v1/orders",
      { epochId: epoch.epochId, sealed: "0x" + bytesToHex(sealed) },
      { "X-Api-Key": acct.apiKey },
    );
    // SEC-025-E1: the accepted order lands in the account's /v1 order list —
    // refresh the own-account view now instead of waiting for the /v1/ws
    // stream (an ACCEPTED order has no finality TRANSITION yet, so no event
    // announces it). Fire and forget: the receipt must return to the caller
    // regardless.
    void this.refreshOwnState();
    return receipt;
  }

  // ── own-account reads (SEC-025-E1) ──────────────────────────────────────────

  /** The account's orders from the authenticated `GET /v1/orders` (flat wire → TrackedOrder). */
  async getOrders(): Promise<TrackedOrder[]> {
    const acct = await this.ensureAccount();
    const res = await fetch(this.base + "/v1/orders", { headers: { "X-Api-Key": acct.apiKey } });
    if (!res.ok) throw new Error(`/v1/orders ${res.status}`);
    const j = (await res.json()) as { orders?: unknown };
    if (typeof j !== "object" || j === null || !Array.isArray(j.orders)) {
      throw new Error("/v1/orders: malformed response");
    }
    return (j.orders as WireV1Order[]).map(pV1Order);
  }

  /** The account's open positions from the authenticated `GET /v1/positions`. */
  async getPositions(): Promise<Position[]> {
    const acct = await this.ensureAccount();
    const res = await fetch(this.base + "/v1/positions", { headers: { "X-Api-Key": acct.apiKey } });
    if (!res.ok) throw new Error(`/v1/positions ${res.status}`);
    const j = (await res.json()) as { positions?: unknown };
    if (typeof j !== "object" || j === null || !Array.isArray(j.positions)) {
      throw new Error("/v1/positions: malformed response");
    }
    return (j.positions as WirePosition[]).map(pPosition);
  }

  /**
   * The account's settled balance from the authenticated `GET /v1/accounts/me`.
   * The brief mandates positions come from `GET /v1/positions`, and no other
   * /v1 surface serves `settledBalance` — so the balance is a THIRD fetch here
   * rather than collapsing the positions read into /v1/accounts/me (which also
   * carries positions). Throws on absence/malformation: a refresh that cannot
   * source the balance must degrade WHOLE, never overlay positions alone.
   */
  private async getSettledBalance(): Promise<bigint> {
    const acct = await this.ensureAccount();
    const res = await fetch(this.base + "/v1/accounts/me", { headers: { "X-Api-Key": acct.apiKey } });
    if (!res.ok) throw new Error(`/v1/accounts/me ${res.status}`);
    const j = (await res.json()) as { settledBalance?: unknown };
    if (typeof j !== "object" || j === null || typeof j.settledBalance !== "string") {
      throw new Error("/v1/accounts/me: missing settledBalance");
    }
    return B(j.settledBalance); // throws on a non-decimal string ⇒ same whole-degrade
  }

  /**
   * Refresh the caller's OWN orders/positions/balance from the authenticated
   * /v1 reads and re-emit. NEVER throws: before a /v1 account exists (or when
   * the gateway is unreachable) the UI must degrade to the legacy public feed,
   * not crash — the caches simply stay as they were (`null` ⇒ fall through in
   * emit()).
   *
   * In-flight guard (the file's `ensureAccount` pattern): overlapping callers
   * join the one running refresh instead of racing it, so a slow earlier read
   * can never resolve late and overwrite a fresher list. Unlike ensureAccount
   * the result here is FRESHNESS, not identity, so a join also flags one
   * trailing re-run: the in-flight GETs may predate the change (e.g. a just-
   * accepted order) that prompted the joiner. placeOrder is the second trigger
   * today; Task 2's /v1/ws stream becomes the third.
   */
  private refreshOwnState(): Promise<void> {
    if (this.ownRefresh) {
      this.ownRefreshAgain = true;
      return this.ownRefresh;
    }
    this.ownRefresh = (async () => {
      try {
        do {
          this.ownRefreshAgain = false;
          await this.fetchOwnStateOnce();
        } while (this.ownRefreshAgain && !this.disposed);
      } finally {
        this.ownRefresh = null;
      }
    })();
    return this.ownRefresh;
  }

  /**
   * Resolves when no own-account refresh is in flight. The refresh is fire-and-
   * forget at its trigger sites, so anything needing the settled view (tests;
   * potentially UI flows) awaits this instead of guessing at microtask timing.
   */
  ownStateSettled(): Promise<void> {
    return this.ownRefresh ?? Promise.resolve();
  }

  /** One refresh pass — only refreshOwnState may call this (it holds the guard). */
  private async fetchOwnStateOnce(): Promise<void> {
    // S1 epoch tagging: a refresh whose reads were issued under an OLDER
    // credential (started before a recovery/rotation) must not overwrite the
    // post-rotation ownOrders/ownAccount when its fetches resolve late.
    const startEpoch = this.credentialEpoch;
    try {
      const [orders, positions, settledBalance] = await Promise.all([
        this.getOrders(),
        this.getPositions(),
        this.getSettledBalance(),
      ]);
      if (this.disposed || startEpoch !== this.credentialEpoch) return; // stale result — drop
      this.ownOrders = orders;
      // ONE account object, assembled atomically from this refresh: emit() swaps
      // it in whole, so the balance shown beside these positions is always the
      // same account's. All three reads degrade together (Promise.all): a
      // partial overlay would resurrect the mixed-account view.
      this.ownAccount = { settledBalance, positions };
      if (this.state) this.setState(this.state);
    } catch (e) {
      console.warn(
        "[dark-perp] /v1 own-account read failed (own view degraded until a read succeeds):",
        e,
      );
      // Re-emit even on failure (review F1): with an account provisioned the
      // emitted view must move to the empty/unavailable placeholder — the
      // bootstrap-constructed state was built BEFORE the account existed and
      // still carries the raw public feed otherwise.
      if (!this.disposed && this.state) this.setState(this.state);
    }
  }
  /**
   * SEC-025-E1 Task 3: fund the /v1 trading account the sealed orders trade
   * as — `POST /v1/accounts/deposit` ONLY. The legacy demo primary
   * (`POST /api/deposit`) is gone: it is unmounted in production, and because
   * it ran FIRST and threw, its 404 also blocked this /v1 leg — in production
   * the old deposit() could never fund anything. This route is mounted in
   * BOTH postures; the production gateway answers it with the SEC-025-C
   * unbacked-mint refusal, which must SURFACE to the caller (the wallet
   * deposit flow below is the real production funding path). On success the
   * own-account view is refreshed — the credit moves the /v1 balance and no
   * /v1/ws event announces a deposit.
   */
  async deposit(amountQuote: bigint): Promise<void> {
    const acct = await this.ensureAccount(); // no /v1 account ⇒ throw (fail closed)
    await this.post(
      "/v1/accounts/deposit",
      { marketId: this.clientSelectedMarket, amount: s(amountQuote) },
      { "X-Api-Key": acct.apiKey },
    );
    void this.refreshOwnState();
  }
  /**
   * SEC-021 fields of `GET /v1/accounts/me` — everything a withdrawal signature
   * needs: which address must sign, the next acceptable auth nonce, and the
   * deployment (chainId, vault) the digest binds. NEVER hardcode chainId/vault
   * client-side — a client built against the wrong deployment signs digests the
   * gateway silently rejects. Validated strictly: a digest built from a
   * malformed field would produce a garbage signature with no clue why.
   */
  private async fetchWithdrawAuth(acct: SealingAccount): Promise<{
    owner: Uint8Array;
    depositAddress: string | null;
    callerSigned: boolean;
    nextWithdrawNonce: number;
    chainId: bigint;
    vault: string;
  }> {
    const res = await fetch(this.base + "/v1/accounts/me", { headers: { "X-Api-Key": acct.apiKey } });
    if (!res.ok) throw new Error(`/v1/accounts/me ${res.status}`);
    const j = (await res.json()) as {
      owner?: unknown; depositAddress?: unknown; callerSigned?: unknown;
      nextWithdrawNonce?: unknown; chainId?: unknown; vault?: unknown;
    };
    if (
      typeof j !== "object" || j === null || typeof j.owner !== "string" ||
      typeof j.callerSigned !== "boolean" ||
      typeof j.nextWithdrawNonce !== "number" || !Number.isSafeInteger(j.nextWithdrawNonce) || j.nextWithdrawNonce < 0 ||
      typeof j.chainId !== "number" || !Number.isSafeInteger(j.chainId) || j.chainId < 0 ||
      typeof j.vault !== "string" ||
      (j.depositAddress != null && typeof j.depositAddress !== "string")
    ) {
      throw new Error(
        "/v1/accounts/me does not serve the SEC-021 withdrawal-authorization fields — gateway too old or malformed response",
      );
    }
    return {
      owner: strictHex(j.owner, 32),
      // normalized lowercase 0x form — it becomes both the wire `to` and the
      // `personal_sign` account parameter.
      depositAddress: j.depositAddress == null ? null : "0x" + bytesToHex(strictHex(j.depositAddress, 20)),
      callerSigned: j.callerSigned,
      // Already the next ACCEPTABLE nonce (the gateway serves last+1) — use verbatim.
      nextWithdrawNonce: j.nextWithdrawNonce,
      chainId: BigInt(j.chainId),
      vault: "0x" + bytesToHex(strictHex(j.vault, 20)),
    };
  }

  /**
   * SEC-021 UI surface: the bound withdrawal destination (null = not bound yet
   * ⇒ withdrawals are refused) and whether the account is caller-signed (the
   * advanced mode whose registered key this UI does not hold).
   */
  async withdrawAuthInfo(): Promise<{ depositAddress: string | null; callerSigned: boolean }> {
    const acct = await this.ensureAccount();
    const me = await this.fetchWithdrawAuth(acct);
    return { depositAddress: me.depositAddress, callerSigned: me.callerSigned };
  }

  /**
   * Withdraw: `POST /v1/accounts/withdraw` ONLY. It debits the per-browser
   * account the sealed orders trade as AND records the withdrawal leaf that the
   * next window-settle publishes into the vault's Merkle root — i.e. the entry
   * `listWithdrawals` shows and the on-chain `claim` pays out. A /v1 failure
   * must THROW so the form surfaces the gateway's error: reporting success
   * without a real claimable leaf is the defect class this task removes.
   * (Task 3 deleted the cosmetic legacy demo mirror that used to follow the
   * real path — its route is unmounted in production.)
   *
   * SEC-021: the gateway rejects any withdrawal without a signature over
   * `withdraw_auth_digest`, and for server-custody accounts the destination
   * MUST equal the bound deposit address — so the destination is no longer a
   * parameter: funds always return to the address the user deposited from,
   * and that address's key signs (the same `personal_sign` path the deposit
   * bind uses; the gateway accepts the EIP-191 shape it produces). Fail
   * closed: no bound address ⇒ refuse client-side rather than POST a 400.
   */
  async requestWithdrawal(amountQuote: bigint): Promise<void> {
    const acct = await this.ensureAccount(); // no /v1 account ⇒ throw (fail closed)
    const me = await this.fetchWithdrawAuth(acct);
    if (me.callerSigned) {
      // The registered signer key authorizes this account's withdrawals; this
      // UI does not hold it — signing with the wallet would produce a signature
      // the gateway rejects. Refuse loudly instead.
      throw new Error(
        "This account is caller-signed: withdrawals must be authorized by its registered signer key via the API.",
      );
    }
    if (!me.depositAddress) {
      throw new Error("Bind a deposit address before withdrawing (make one wallet deposit first).");
    }
    const to = me.depositAddress;
    const nonce = me.nextWithdrawNonce;
    const digest = withdrawAuthDigest(
      me.chainId, me.vault, me.owner,
      BigInt(this.clientSelectedMarket), amountQuote, to, BigInt(nonce),
    );
    const signature = await personalSign("0x" + bytesToHex(digest), to);
    await this.post(
      "/v1/accounts/withdraw",
      { marketId: this.clientSelectedMarket, amount: s(amountQuote), to, nonce, signature },
      { "X-Api-Key": acct.apiKey },
    );
    // Review F4: the withdrawal debits the /v1 balance server-side and NO
    // /v1/ws event announces it (events_tx carries exactly fill/order/adl,
    // main.rs:4347-4384) — without this the displayed balance stays stale
    // until an unrelated fill. Same guarded refresh path as placeOrder;
    // fire-and-forget so the caller's success resolves regardless.
    void this.refreshOwnState();
  }

  // ── SEC-025-E1 Task 3: the demo mutation surface is DELETED, not stubbed ────
  // triggerCloseOnly / resumeNormal / simulateAdl / closePosition / recover
  // are gone from this client: their legacy routes exist only in the demo
  // build (audit DP-010 — the production router does not mount them), so here
  // they could only 404 — and three of them reported that failure to the user
  // as success. The interface declares them optional and the UI presence-gates
  // (the wallet-methods idiom), so the buttons are honestly absent in live
  // mode instead of lying. closePosition in particular has NO /v1 equivalent
  // yet; re-adding it as a reduce-only /v1 order submission is a product
  // decision for a later slice, not a transport fix.

  /**
   * A07: rotate a lost browser API key using the account's existing wallet/signer authority.
   *
   * S1 retry contract: a used/stale signed authorization is NEVER replayed as
   * success. On any retryable failure — network error/timeout, 503 (the server
   * rotated but the snapshot write is unconfirmed: the old key is dead and the
   * nonce HAS advanced), durability !== "confirmed", or a malformed/missing
   * response — the retry loop re-GETs the recovery metadata (fresh nonce),
   * re-signs the CURRENT nonce, and re-POSTs, bounded to MAX_RECOVERY_ATTEMPTS.
   * On 400/401/409 or a wallet rejection there is NO automatic retry: those
   * authorizations are dead by contract, and replaying them must fail. Every
   * path preserves the previously stored credential and in-memory sealing —
   * the swap happens ONLY after a fully-validated confirmed response, in the
   * order: guarded storage write (failure ⇒ swap aborted, old credential kept)
   * → in-memory sealing swap → epoch bump → socket close → refresh.
   */
  async recoverAccount(ownerHex: string): Promise<{ owner: string; recoveryNonce: number }> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(ownerHex)) throw new Error("Owner must be a 32-byte 0x id.");
    const startEpoch = this.credentialEpoch;
    let lastError: unknown = null;
    for (let attempt = 0; attempt < MAX_RECOVERY_ATTEMPTS; attempt++) {
      if (this.credentialEpoch !== startEpoch) {
        throw new Error("Recovery superseded by a newer credential swap.");
      }
      try {
        return await this.attemptRecovery(ownerHex, startEpoch);
      } catch (e) {
        if (e instanceof RecoveryAttemptError && !e.retryable) throw e;
        if (!(e instanceof RecoveryAttemptError)) throw e; // internal bug — do not mask
        lastError = e;
      }
    }
    throw new Error(
      `Account recovery failed after ${MAX_RECOVERY_ATTEMPTS} attempts` +
        (lastError instanceof Error ? `: ${lastError.message}` : "."),
    );
  }

  /** One GET → sign → POST recovery round. See recoverAccount's S1 contract. */
  private async attemptRecovery(
    ownerHex: string,
    startEpoch: number,
  ): Promise<{ owner: string; recoveryNonce: number }> {
    // 1) Fresh recovery metadata — the nonce served here is the ONLY nonce
    //    that signature is valid for, and the server rejects a used one.
    let metaRes: Response;
    try {
      metaRes = await fetch(this.base + `/v1/accounts/recovery/${encodeURIComponent(ownerHex)}`);
    } catch (e) {
      throw new RecoveryAttemptError(`Recovery metadata fetch failed: ${errMsg(e)}`, true);
    }
    if (!metaRes.ok) {
      throw new RecoveryAttemptError(
        `Recovery metadata unavailable (${metaRes.status}).`,
        metaRes.status >= 500,
      );
    }
    let m: { owner?: unknown; authorizer?: unknown; recoveryNonce?: unknown; chainId?: unknown; vault?: unknown };
    try {
      m = (await metaRes.json()) as typeof m;
    } catch (e) {
      throw new RecoveryAttemptError(`Recovery metadata unreadable: ${errMsg(e)}`, true);
    }
    if (
      typeof m !== "object" || m === null ||
      typeof m.owner !== "string" || m.owner.toLowerCase() !== ownerHex.toLowerCase() ||
      typeof m.authorizer !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(m.authorizer) ||
      typeof m.recoveryNonce !== "number" || !Number.isSafeInteger(m.recoveryNonce) || m.recoveryNonce < 0 ||
      typeof m.chainId !== "number" || !Number.isSafeInteger(m.chainId) || m.chainId < 0 ||
      typeof m.vault !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(m.vault)
    ) {
      throw new RecoveryAttemptError("Gateway returned malformed recovery metadata.", true);
    }
    const owner = strictHex(m.owner, 32);
    // 2) Wallet signature over the CURRENT nonce. A rejection is final —
    //    retrying cannot succeed without the user.
    const digest = accountRecoveryDigest(BigInt(m.chainId), m.vault, owner, BigInt(m.recoveryNonce));
    let signature: string;
    try {
      signature = await personalSign("0x" + bytesToHex(digest), m.authorizer);
    } catch (e) {
      throw new RecoveryAttemptError(`Wallet refused the recovery signature: ${errMsg(e)}`, false);
    }
    // 3) The rotation POST — inspect the status directly: 400/401/409 are
    //    final, 503/5xx and transport failures are retryable.
    let res: Response;
    try {
      res = await fetch(this.base + "/v1/accounts/recovery", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ owner: m.owner, nonce: m.recoveryNonce, signature }),
      });
    } catch (e) {
      throw new RecoveryAttemptError(`Recovery rotation request failed: ${errMsg(e)}`, true);
    }
    if (!res.ok) {
      let msg = `Recovery rotation failed (${res.status}).`;
      try {
        const j = (await res.json()) as { error?: unknown };
        if (typeof j?.error === "string") msg = j.error;
      } catch { /* non-JSON error body — the status message stands */ }
      // 409 "superseded by a newer rotation" means the nonce we signed is
      // stale FOREVER — replaying it can only fail again. 400/401 likewise.
      const retryable = res.status === 503 || res.status >= 500;
      throw new RecoveryAttemptError(msg, retryable);
    }
    let out: { apiKey?: unknown; owner?: unknown; recoveryNonce?: unknown; durability?: unknown };
    try {
      out = (await res.json()) as typeof out;
    } catch (e) {
      throw new RecoveryAttemptError(`Recovery rotation response unreadable: ${errMsg(e)}`, true);
    }
    if (
      typeof out !== "object" || out === null ||
      typeof out.apiKey !== "string" ||
      typeof out.owner !== "string" || out.owner.toLowerCase() !== m.owner.toLowerCase() ||
      typeof out.recoveryNonce !== "number" || out.recoveryNonce !== m.recoveryNonce + 1 ||
      out.durability !== "confirmed"
    ) {
      // A response that is not fully validated confirmed success is NEVER a
      // success — a stale authorization replayed into this shape still fails.
      throw new RecoveryAttemptError("Gateway returned malformed or non-durable recovery result.", true);
    }
    // 4) Epoch guard: another recovery/swap won while we were in flight —
    //    discard this late result entirely.
    if (this.credentialEpoch !== startEpoch) {
      throw new RecoveryAttemptError("Recovery superseded by a newer credential swap.", false);
    }
    // 5) Atomic swap. The storage write goes FIRST inside try/catch: a storage
    //    failure (or a newer stored generation from another tab) aborts the
    //    swap and leaves the OLD credential untouched in memory and storage.
    try {
      this.writeStoredCredential(out.apiKey, out.owner);
    } catch (e) {
      throw new RecoveryAttemptError(
        `Recovered credential could not be stored (old credential kept): ${errMsg(e)}`,
        false,
      );
    }
    this.sealing = { apiKey: out.apiKey, owner };
    this.everProvisioned = true;
    this.ownAccount = null;
    this.ownOrders = null;
    this.credentialEpoch++; // bump AFTER sealing is the new live credential
    this.v1AuthSent = false;
    this.v1Owner = null;
    if (this.wsV1) { try { this.wsV1.close(); } catch { /* noop */ } } else this.connectV1();
    await this.refreshOwnState();
    return { owner: out.owner, recoveryNonce: out.recoveryNonce };
  }

  /**
   * Cancel an order — `DELETE /v1/orders/:id` under the account's API key,
   * so the id resolves inside the CALLER's own order list (`account_cancel`).
   *
   * This re-route closes a CROSS-ACCOUNT hazard, not just a 404: order ids
   * are `o{nonce}` in both the /v1 path and the demo wallet — per-account,
   * not globally unique — and the legacy `POST /api/cancel` resolved the id
   * against the DEMO WALLET's list. After Task 1 the UI shows the caller's
   * /v1 ids, so the old path could silently cancel a stranger's same-named
   * order and report success.
   *
   * Refusals THROW with the gateway's reason, including an unknown durable
   * outcome (503). A live remainder is cancellable even after a partial fill
   * settled. Completed fills are never undone by cancellation.
   *
   * A successful response produces the local CANCELLED notification. The private
   * execution event refreshes state without another toast; the receipt/history row
   * remains visible. A failed durability ACK produces no success notification.
   */
  async cancelOrder(orderId: string): Promise<void> {
    const acct = await this.ensureAccount();
    await this.request(
      "DELETE",
      `/v1/orders/${encodeURIComponent(orderId)}`,
      undefined,
      { "X-Api-Key": acct.apiKey },
    );
    for (const cb of this.eventSubs) {
      cb({ orderId, kind: "CANCELLED", message: "Unfilled remainder cancelled; prior fills are unchanged" });
    }
    void this.refreshOwnState();
  }
  /**
   * CLIENT-SIDE market switch. The old implementation POSTed the legacy demo
   * `/api/select-market` route — 404 in prod (silently swallowed) and, even
   * where it existed, a GLOBAL server-side selection that moved EVERY user's
   * view on the shared gateway. Instead: re-emit immediately with the selection
   * override (markets metadata + `marks[id]` already price every market), then
   * fetch the market's live book/oracle and keep them fresh on a light poll.
   * Never round-trips to /api.
   */
  selectMarket(marketId: number): void {
    const st = this.state;
    if (!st || !st.markets.some((m) => m.id === marketId)) return; // unknown id — ignore
    if (marketId === this.clientSelectedMarket) return;
    this.clientSelectedMarket = marketId;
    // The previous market's fetched data must never render under the new one.
    this.selBook = null;
    this.selOracle = null;
    this.setState(st); // instant switch (book/oracle catch up when the fetch lands)
    void this.refreshSelected(marketId);
    this.ensurePoll();
  }
  // ── injected-wallet deposit flow (see api/wallet.ts) ────────────────────────
  // These four methods make this client a `WalletDepositClient`: the wallet UI
  // is gated on their presence (the mock client lacks them ⇒ no wallet UI).

  /**
   * The self-provisioned `/v1` account's identity — the wallet flow binds the
   * connected EOA to this `owner` (it is the 32-byte pubkey inside the gateway's
   * `deposit_bind_digest`). Provisions the account on first call.
   */
  async depositAccount(): Promise<{ apiKey: string; owner: Uint8Array }> {
    const acct = await this.ensureAccount();
    return { apiKey: acct.apiKey, owner: acct.owner };
  }

  /**
   * `POST /v1/accounts/deposit/address` — bind the external EOA the account
   * funds from. `signature` must recover to `address` over the bind digest
   * (raw or EIP-191 `personal_sign` form — the gateway accepts both).
   */
  async bindDepositAddress(address: string, signature: string): Promise<void> {
    const acct = await this.ensureAccount();
    await this.post(
      "/v1/accounts/deposit/address",
      { address, signature },
      { "X-Api-Key": acct.apiKey },
    );
  }

  /**
   * `POST /v1/accounts/deposit/authorize` — SEC-019: the gateway pre-authorizes
   * this exact (from, amount) for the vault, returning the blinded `ownerCommit`
   * + the 65-byte gateway signature that `deposit(amount, ownerCommit, sig)`
   * requires on-chain. The gateway refuses unless `from` is the account's bound
   * deposit address — its error text ("Bind a deposit address first…") is
   * surfaced verbatim so the pipeline shows the real reason.
   */
  async authorizeDeposit(
    from: string,
    amount: bigint,
  ): Promise<{ ownerCommit: string; sig: string }> {
    const marketId = this.clientSelectedMarket;
    const acct = await this.ensureAccount();
    const r = await this.post<{ ownerCommit?: unknown; sig?: unknown }>(
      "/v1/accounts/deposit/authorize",
      { from, amount: s(amount), marketId, purpose: "collateral" },
      { "X-Api-Key": acct.apiKey },
    );
    if (typeof r.ownerCommit !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(r.ownerCommit)) {
      throw new Error("authorize: gateway returned a malformed ownerCommit (expected 32-byte 0x hex)");
    }
    if (typeof r.sig !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(r.sig)) {
      throw new Error("authorize: gateway returned a malformed signature (expected 65-byte 0x hex r‖s‖v)");
    }
    return { ownerCommit: r.ownerCommit, sig: r.sig };
  }

  /**
   * Request a durable receipt from the autonomous finalized ingester.
   * Cannot choose a new market or consume deposits out of order.
   * A pending result is not zero credit and never means send funds again.
   */
  async creditOnchainDeposit(txHash: string): Promise<bigint> {
    const acct = await this.ensureAccount();
    const r = await this.post<{ credited?: unknown; status?: unknown }>(
      "/v1/accounts/deposit/onchain",
      { txHash, marketId: this.clientSelectedMarket },
      { "X-Api-Key": acct.apiKey },
    );
    if (r.status === "pendingFinalizedIngestion") {
      throw new Error("Deposit is not yet confirmed by the finalized ingester. Valid authorized deposits are credited automatically; do not send another deposit.");
    }
    // Review F4: like requestWithdrawal — the credit moved the /v1 balance
    // and no /v1/ws event announces a deposit; re-read through the guarded
    // refresh or the balance stays stale until an unrelated fill.
    void this.refreshOwnState();
    return typeof r.credited === "string" ? B(r.credited) : 0n;
  }

  /**
   * The account's requested withdrawals from `GET /v1/accounts/withdrawals`, keyed
   * by the self-provisioned account's apiKey. Returns null (⇒ the UI hides the
   * surface) when no account exists yet — a browser that never provisioned one
   * cannot have withdrawals — or when the gateway doesn't serve the endpoint.
   * Parsed defensively (like the rest of this file's wire handling): a single
   * malformed entry is dropped rather than breaking the whole list.
   */
  async listWithdrawals(): Promise<{ withdrawals: WithdrawalEntry[]; vault: string } | null> {
    const acct = this.sealing ?? this.readStoredAccount();
    if (!acct) return null;
    let res: Response;
    try {
      res = await fetch(this.base + "/v1/accounts/withdrawals", { headers: { "X-Api-Key": acct.apiKey } });
    } catch {
      return null; // gateway unreachable — treat like "nothing to show", the poll retries
    }
    if (!res.ok) return null; // older gateway (404) or a reset account (401) — hide, don't error
    let j: { withdrawals?: unknown; vault?: unknown };
    try {
      j = (await res.json()) as { withdrawals?: unknown; vault?: unknown };
    } catch {
      return null;
    }
    if (typeof j !== "object" || j === null || !Array.isArray(j.withdrawals) || typeof j.vault !== "string") {
      return null;
    }
    const withdrawals: WithdrawalEntry[] = [];
    for (const raw of j.withdrawals as Partial<WireWithdrawal>[]) {
      try {
        if (
          typeof raw !== "object" || raw === null ||
          typeof raw.to !== "string" || typeof raw.amount !== "string" ||
          typeof raw.nonce !== "number" || !Number.isSafeInteger(raw.nonce) ||
          typeof raw.leaf !== "string" || typeof raw.root !== "string" ||
          typeof raw.claimable !== "boolean" || !Array.isArray(raw.proof) ||
          !raw.proof.every((p): p is string => typeof p === "string")
        ) {
          continue;
        }
        withdrawals.push({
          to: raw.to,
          amount: B(raw.amount), // throws on a non-decimal string → entry dropped
          nonce: raw.nonce,
          leaf: raw.leaf,
          root: raw.root,
          claimable: raw.claimable,
          proof: raw.proof,
        });
      } catch {
        /* drop the malformed entry, keep the rest */
      }
    }
    return { withdrawals, vault: j.vault };
  }
}

export type { WireState };
