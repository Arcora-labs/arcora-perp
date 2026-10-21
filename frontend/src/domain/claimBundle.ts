/// Self-contained claim data for one settled withdrawal — everything
/// `CollateralVault.claim` needs, so the user can claim WITHOUT the operator
/// (scripts/claim/claim_withdrawal.py verifies a saved file offline and prints
/// the `cast send` call). Bundles stay with the user: they are kept in this
/// browser's storage and offered as a download, never sent anywhere.
import type { WithdrawalEntry } from "./types";
import { validateWithdrawal } from "./withdrawal";

export const CLAIM_BUNDLE_SCHEMA = "arcora.claim-bundle.v1";
export const CLAIM_BUNDLE_STORAGE_KEY = "arcora.claimBundles.v1";

export interface ClaimBundle {
  schema: typeof CLAIM_BUNDLE_SCHEMA;
  chainId: number;
  vault: string;
  to: string;
  /// USDC base units as an exact decimal string (uint256 does not fit a JSON number).
  amount: string;
  nonce: number;
  leaf: string;
  root: string;
  proof: string[];
  createdAt: string;
}

const ZERO_ROOT = "0x" + "0".repeat(64);

export function buildClaimBundle(
  w: WithdrawalEntry,
  vault: string,
  chainId: number,
  now: Date = new Date(),
): ClaimBundle {
  validateWithdrawal(w, vault);
  if (!w.claimable || w.root.toLowerCase() === ZERO_ROOT) {
    throw new Error("Withdrawal is not claimable yet");
  }
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error("Invalid chain id");
  return {
    schema: CLAIM_BUNDLE_SCHEMA,
    chainId,
    vault,
    to: w.to,
    amount: w.amount.toString(),
    nonce: w.nonce,
    leaf: w.leaf,
    root: w.root,
    proof: [...w.proof],
    createdAt: now.toISOString(),
  };
}

export function claimBundleFileName(b: ClaimBundle): string {
  return `arcora-claim-${b.chainId}-${b.nonce}-${b.leaf.slice(2, 10).toLowerCase()}.json`;
}

/// One bundle as an object (the tool's single-file form), several as an array.
export function serializeClaimBundles(bundles: ClaimBundle[]): string {
  return JSON.stringify(bundles.length === 1 ? bundles[0] : bundles, null, 2) + "\n";
}

export interface ClaimBundleStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function defaultStorage(): ClaimBundleStorage | undefined {
  try {
    return typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    return undefined; // access itself can throw when site data is blocked
  }
}

function isBundle(value: unknown): value is ClaimBundle {
  if (!value || typeof value !== "object") return false;
  const b = value as Record<string, unknown>;
  if (b.schema !== CLAIM_BUNDLE_SCHEMA || typeof b.amount !== "string" || !/^(0|[1-9][0-9]*)$/.test(b.amount)) {
    return false;
  }
  try {
    const rebuilt = buildClaimBundle(
      {
        to: b.to as string, amount: BigInt(b.amount), nonce: b.nonce as number,
        leaf: b.leaf as string, root: b.root as string, claimable: true, proof: b.proof as string[],
      },
      b.vault as string,
      b.chainId as number,
    );
    return typeof b.createdAt === "string" && rebuilt.vault === b.vault;
  } catch {
    return false;
  }
}

/// Saved bundles; anything unreadable or malformed is ignored, never trusted.
export function loadClaimBundles(storage: ClaimBundleStorage | undefined = defaultStorage()): ClaimBundle[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(CLAIM_BUNDLE_STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter(isBundle) : [];
  } catch {
    return [];
  }
}

/// Add bundles by leaf, keeping every earlier one and its first copy. Returns
/// false when storage is unavailable or refuses the write (never throws).
export function rememberClaimBundles(
  bundles: ClaimBundle[],
  storage: ClaimBundleStorage | undefined = defaultStorage(),
): boolean {
  if (!storage) return false;
  try {
    storage.getItem(CLAIM_BUNDLE_STORAGE_KEY); // surface a denied read before merging
    const saved = loadClaimBundles(storage);
    const known = new Set(saved.map((b) => b.leaf.toLowerCase()));
    const merged = [...saved];
    for (const b of bundles) {
      if (!known.has(b.leaf.toLowerCase())) {
        merged.push(b);
        known.add(b.leaf.toLowerCase());
      }
    }
    storage.setItem(CLAIM_BUNDLE_STORAGE_KEY, JSON.stringify(merged));
    return true;
  } catch {
    return false;
  }
}
