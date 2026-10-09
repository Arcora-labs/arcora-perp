import type { WithdrawalEntry } from "./types";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DIGEST = /^0x[0-9a-fA-F]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;

export function isWithdrawalAddress(value: unknown): value is string {
  return typeof value === "string" && ADDRESS.test(value);
}

/** Shape validation only: the vault still verifies root publication and membership.
 * Fixed hex/decimal fields also prevent gateway data becoming shell syntax in
 * the offline claim command. Validate again at that output boundary.
 */
export function validateWithdrawal(w: WithdrawalEntry, vault: string): void {
  if (!isWithdrawalAddress(vault) || !isWithdrawalAddress(w.to) ||
      typeof w.amount !== "bigint" || w.amount < 0n || w.amount >= 1n << 256n ||
      !Number.isSafeInteger(w.nonce) || w.nonce < 0 ||
      typeof w.leaf !== "string" || !DIGEST.test(w.leaf) ||
      typeof w.root !== "string" || !DIGEST.test(w.root) ||
      typeof w.claimable !== "boolean" || !Array.isArray(w.proof) ||
      w.proof.length > 256 || !w.proof.every(p => typeof p === "string" && DIGEST.test(p))) {
    throw new Error("Invalid withdrawal claim data");
  }
}

export function parseWithdrawal(raw: unknown, vault: string): WithdrawalEntry | null {
  if (!raw || typeof raw !== "object") return null;
  const row = raw as Record<string, unknown>;
  if (typeof row.amount !== "string" || !DECIMAL.test(row.amount)) return null;
  try {
    const withdrawal = {
      to: row.to, amount: BigInt(row.amount), nonce: row.nonce,
      leaf: row.leaf, root: row.root, claimable: row.claimable, proof: row.proof,
    } as WithdrawalEntry;
    validateWithdrawal(withdrawal, vault);
    return withdrawal;
  } catch {
    return null;
  }
}
