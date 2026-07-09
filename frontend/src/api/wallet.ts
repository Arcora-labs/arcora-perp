// Injected-wallet (EIP-1193 / MetaMask-class) integration for the on-chain
// collateral flow: mint test USDC → approve → vault.deposit → bind the EOA to
// the /v1 trading account → credit the deposit — all driven from the browser
// wallet instead of the `cast` CLI. NO wallet library is used: the module talks
// raw EIP-1193 `request()` and hand-encodes the three fixed ABI shapes it needs
// (selectors are keccak-derived and pinned byte-exact in wallet.test.ts).
//
// SCOPE: the wallet signs transactions and ONE `personal_sign` bind proof. It
// never sees protocol key material, and the gateway never sees a private key —
// authorization stays exactly as strong as the gateway's `deposit_bind_digest`
// check (the signature must recover to the address being bound).

import { useSyncExternalStore } from "react";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils";

// ── chain + contract facts (Base Sepolia public testnet) ─────────────────────
// Deployed 2026-07-09 (clean pre-alpha stack). Must match TestnetNotice.tsx and
// deployments/base-sepolia.json — update BOTH on any redeploy.

/// Base Sepolia chainId 84532, as the 0x-hex EIP-695 form wallets speak.
export const BASE_SEPOLIA_CHAIN_ID = "0x14a34";

/// `wallet_addEthereumChain` params — offered when the wallet doesn't know the chain.
export const BASE_SEPOLIA_PARAMS = {
  chainId: BASE_SEPOLIA_CHAIN_ID,
  chainName: "Base Sepolia",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: ["https://sepolia.base.org"],
  blockExplorerUrls: ["https://sepolia.basescan.org"],
} as const;

/// Open-mint test collateral token (6 decimals) — anyone may call `mint`.
export const MOCK_USDC = "0x9F5365c947eCaBaf62f42EF0Fe92ab909f709bDA";
/// The collateral vault deposits enter (and withdrawal claims pay out of).
export const COLLATERAL_VAULT = "0xC3EBc0f7301D5a914b01b8d2a1B5574764330c05";

export const EXPLORER_TX = "https://sepolia.basescan.org/tx/";

// ── EIP-1193 provider ─────────────────────────────────────────────────────────

/// The minimal injected-provider surface this module uses (EIP-1193 `request`).
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
  }
}

/// Whether an injected wallet (MetaMask-class) is present at all.
export function hasInjected(): boolean {
  return typeof window !== "undefined" && !!window.ethereum;
}

function provider(): Eip1193Provider {
  if (!hasInjected()) {
    throw new Error("No browser wallet detected — install MetaMask (or use the CLI path).");
  }
  return window.ethereum!;
}

/// EIP-1193 error code for "user rejected the request" (MetaMask et al).
const USER_REJECTED = 4001;
/// MetaMask: `wallet_switchEthereumChain` to a chain the wallet doesn't have.
const UNRECOGNIZED_CHAIN = 4902;

/** Best-effort numeric code of a provider error (MetaMask nests some). */
function errCode(e: unknown): number | undefined {
  if (typeof e !== "object" || e === null) return undefined;
  const any = e as { code?: unknown; data?: { originalError?: { code?: unknown } } };
  if (typeof any.code === "number") return any.code;
  const nested = any.data?.originalError?.code;
  return typeof nested === "number" ? nested : undefined;
}

function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "object" && e !== null && typeof (e as { message?: unknown }).message === "string") {
    return (e as { message: string }).message;
  }
  return String(e);
}

/** True when the user dismissed the wallet prompt — worth a gentler message. */
export function isUserRejection(e: unknown): boolean {
  return errCode(e) === USER_REJECTED;
}

// ── connection state (module-level, shared across components) ────────────────
// One connected address for the whole app — the deposit card, the claim buttons
// and the withdraw-destination prefill all read the same source of truth.

let connected: string | null = null;
const subs = new Set<() => void>();

function notify() {
  for (const cb of subs) cb();
}

/** The connected account (lowercased 0x address) or null. */
export function connectedAddress(): string | null {
  return connected;
}

export function subscribeWallet(cb: () => void): () => void {
  subs.add(cb);
  return () => {
    subs.delete(cb);
  };
}

/** Forget the local connection (does not revoke anything wallet-side). */
export function disconnectWallet(): void {
  connected = null;
  notify();
}

/** React hook: the connected wallet address, live-updating. */
export function useWalletAddress(): string | null {
  return useSyncExternalStore(subscribeWallet, connectedAddress, () => null);
}

/**
 * Prompt the wallet to connect (`eth_requestAccounts`) and remember the first
 * account. Throws readable errors: no wallet, user-rejected, empty account list.
 */
export async function connect(): Promise<string> {
  let accounts: unknown;
  try {
    accounts = await provider().request({ method: "eth_requestAccounts" });
  } catch (e) {
    if (isUserRejection(e)) throw new Error("Connection request rejected in the wallet.");
    throw new Error(`Wallet connection failed: ${errMessage(e)}`);
  }
  if (!Array.isArray(accounts) || typeof accounts[0] !== "string" || accounts[0] === "") {
    throw new Error("Wallet returned no accounts — unlock it and try again.");
  }
  connected = accounts[0].toLowerCase();
  notify();
  return connected;
}

/**
 * Make sure the wallet is on Base Sepolia: `wallet_switchEthereumChain`, and if
 * the wallet doesn't know the chain (4902), offer to add it
 * (`wallet_addEthereumChain`) then rely on the add-flow's implicit switch.
 */
export async function ensureBaseSepolia(): Promise<void> {
  try {
    await provider().request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: BASE_SEPOLIA_CHAIN_ID }],
    });
    return;
  } catch (e) {
    if (isUserRejection(e)) throw new Error("Network switch rejected in the wallet.");
    if (errCode(e) !== UNRECOGNIZED_CHAIN) {
      throw new Error(`Could not switch the wallet to Base Sepolia: ${errMessage(e)}`);
    }
  }
  try {
    await provider().request({
      method: "wallet_addEthereumChain",
      params: [BASE_SEPOLIA_PARAMS],
    });
  } catch (e) {
    if (isUserRejection(e)) throw new Error("Adding Base Sepolia rejected in the wallet.");
    throw new Error(`Could not add Base Sepolia to the wallet: ${errMessage(e)}`);
  }
}

/**
 * Send a transaction from the connected account. Returns the tx hash; the
 * caller decides whether to await confirmation (`waitForTx`).
 */
export async function sendTx(tx: {
  from: string;
  to: string;
  data: string;
  value?: string;
}): Promise<string> {
  let hash: unknown;
  try {
    hash = await provider().request({
      method: "eth_sendTransaction",
      params: [{ from: tx.from, to: tx.to, data: tx.data, ...(tx.value ? { value: tx.value } : {}) }],
    });
  } catch (e) {
    if (isUserRejection(e)) throw new Error("Transaction rejected in the wallet.");
    throw new Error(`Transaction failed to send: ${errMessage(e)}`);
  }
  if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error("Wallet returned an invalid transaction hash.");
  }
  return hash.toLowerCase();
}

/**
 * Poll `eth_getTransactionReceipt` via the wallet's provider until the tx is
 * mined. Resolves on status 0x1; throws on revert (0x0) or after `timeoutMs`
 * (default ~90 s — Base Sepolia blocks are ~2 s, so this is generous).
 */
export async function waitForTx(
  hash: string,
  opts: { timeoutMs?: number; pollMs?: number } = {},
): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? 90_000;
  const pollMs = opts.pollMs ?? 2_000;
  const deadline = Date.now() + timeoutMs;
  // First check immediately — a same-block receipt shouldn't cost a poll interval.
  for (;;) {
    let receipt: unknown;
    try {
      receipt = await provider().request({ method: "eth_getTransactionReceipt", params: [hash] });
    } catch (e) {
      throw new Error(`Could not read the transaction receipt: ${errMessage(e)}`);
    }
    if (typeof receipt === "object" && receipt !== null) {
      const status = (receipt as { status?: unknown }).status;
      if (status === "0x1") return;
      if (status === "0x0") {
        throw new Error(`Transaction reverted on-chain — see ${EXPLORER_TX}${hash}`);
      }
      // pending/unknown status shape — keep polling
    }
    if (Date.now() + pollMs > deadline) {
      throw new Error(
        `Transaction not confirmed within ${Math.round(timeoutMs / 1000)}s — check ${EXPLORER_TX}${hash} and retry once it lands.`,
      );
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * `personal_sign` a 0x-hex digest with the connected account. MetaMask signs
 * EIP-191 over the RAW 32 bytes when handed 0x-hex data — the gateway accepts
 * raw-digest, EIP-191-over-bytes and EIP-191-over-hex-string recovery forms, so
 * whichever the wallet produces verifies.
 */
export async function personalSign(digestHex: string, address: string): Promise<string> {
  let sig: unknown;
  try {
    sig = await provider().request({ method: "personal_sign", params: [digestHex, address] });
  } catch (e) {
    if (isUserRejection(e)) throw new Error("Signature request rejected in the wallet.");
    throw new Error(`Signing failed: ${errMessage(e)}`);
  }
  if (typeof sig !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(sig)) {
    throw new Error("Wallet returned an invalid signature (expected 65-byte 0x hex).");
  }
  return sig;
}

// ── minimal ABI encoding ──────────────────────────────────────────────────────
// Only the fixed shapes this app sends. Every builder is pinned byte-exact in
// wallet.test.ts against independently computed calldata.

/// keccak256(signature)[0..4] — the 4-byte function selector.
export function selector(signature: string): Uint8Array {
  return keccak_256(utf8ToBytes(signature)).slice(0, 4);
}

/// The selector as 0x-hex (test/debug convenience).
export function selectorHex(signature: string): string {
  return "0x" + bytesToHex(selector(signature));
}

/// A 20-byte 0x address left-padded to a 32-byte ABI word.
export function encodeAddress(addr: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
    throw new Error(`not a 20-byte 0x address: ${addr}`);
  }
  const out = new Uint8Array(32);
  out.set(hexToBytes(addr.slice(2).toLowerCase()), 12);
  return out;
}

const U256_MAX = (1n << 256n) - 1n;

/// A uint256 as a 32-byte big-endian ABI word (throws out-of-range).
export function encodeUint256(v: bigint): Uint8Array {
  if (v < 0n || v > U256_MAX) throw new Error(`uint256 out of range: ${v}`);
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/// A bytes32 0x-hex value, verbatim.
export function encodeBytes32(hex: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`not a 32-byte 0x-hex value: ${hex}`);
  }
  return hexToBytes(hex.slice(2).toLowerCase());
}

function calldata(sig: string, words: Uint8Array[]): string {
  return "0x" + bytesToHex(concatBytes(selector(sig), ...words));
}

/// `mint(address,uint256)` — MockUSDC open mint (testnet faucet-in-a-tx).
export function encodeMint(to: string, amount: bigint): string {
  return calldata("mint(address,uint256)", [encodeAddress(to), encodeUint256(amount)]);
}

/// `approve(address,uint256)` — ERC-20 allowance for the vault.
export function encodeApprove(spender: string, amount: bigint): string {
  return calldata("approve(address,uint256)", [encodeAddress(spender), encodeUint256(amount)]);
}

/// `deposit(uint256)` — CollateralVault deposit (emits `Deposit(from, amount)`).
export function encodeDeposit(amount: bigint): string {
  return calldata("deposit(uint256)", [encodeUint256(amount)]);
}

/**
 * `claim(address,uint256,uint256,bytes32,bytes32[])` — the permissionless
 * withdrawal claim. `proof` is the one dynamic argument: its head word is the
 * byte offset of the tail (5 args × 32 = 0xa0), the tail is length ‖ items.
 */
export function encodeClaim(w: {
  to: string;
  amount: bigint;
  nonce: number | bigint;
  root: string;
  proof: string[];
}): string {
  const words = [
    encodeAddress(w.to),
    encodeUint256(w.amount),
    encodeUint256(BigInt(w.nonce)),
    encodeBytes32(w.root),
    encodeUint256(5n * 32n), // offset of the bytes32[] tail
    encodeUint256(BigInt(w.proof.length)),
    ...w.proof.map(encodeBytes32),
  ];
  return calldata("claim(address,uint256,uint256,bytes32,bytes32[])", words);
}

// ── gateway bind digest ───────────────────────────────────────────────────────

/**
 * The digest the deposit-address bind signature must cover — byte-identical to
 * the gateway's `deposit_bind_digest`:
 * `keccak256( ascii("dark-perp:bind-deposit:") ‖ owner (32) ‖ depositAddress (20) )`.
 * Binding the account owner into the preimage stops the proof being replayed to
 * bind the same EOA to a different account.
 */
export function bindDepositDigest(owner: Uint8Array, depositAddress: string): Uint8Array {
  if (owner.length !== 32) throw new Error("owner pubkey must be 32 bytes");
  if (!/^0x[0-9a-fA-F]{40}$/.test(depositAddress)) {
    throw new Error(`not a 20-byte 0x address: ${depositAddress}`);
  }
  const addr = hexToBytes(depositAddress.slice(2).toLowerCase());
  return keccak_256(concatBytes(utf8ToBytes("dark-perp:bind-deposit:"), owner, addr));
}

// ── wallet-deposit capability of the API client ───────────────────────────────

/**
 * The extra surface the wallet flow needs from the API client. The REAL gateway
 * client implements it (structurally); the in-browser mock does not — which is
 * exactly the live-mode gate for all wallet UI.
 */
export interface WalletDepositClient {
  /** The self-provisioned /v1 account (apiKey + 32-byte owner pubkey). */
  depositAccount(): Promise<{ apiKey: string; owner: Uint8Array }>;
  /** POST /v1/accounts/deposit/address — bind the EOA (ownership-proven). */
  bindDepositAddress(address: string, signature: string): Promise<void>;
  /** POST /v1/accounts/deposit/onchain — credit a confirmed deposit tx. Returns
   *  the credited amount in USDC base units. */
  creditOnchainDeposit(txHash: string): Promise<bigint>;
}

export function supportsWalletDeposit(c: unknown): c is WalletDepositClient {
  const x = c as Partial<Record<keyof WalletDepositClient, unknown>> | null;
  return (
    typeof x === "object" &&
    x !== null &&
    typeof x.depositAccount === "function" &&
    typeof x.bindDepositAddress === "function" &&
    typeof x.creditOnchainDeposit === "function"
  );
}
