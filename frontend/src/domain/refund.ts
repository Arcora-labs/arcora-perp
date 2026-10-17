import type { RefundableDeposit } from "./types";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DIGEST = /^0x[0-9a-fA-F]{64}$/;
const DECIMAL = /^[1-9][0-9]{0,77}$/;
const U64_MAX = (1n << 64n) - 1n;

/** Shape validation only: the vault re-derives the deposit leaf from these
 * fields and refuses any mismatch. Fixed hex/decimal fields also keep gateway
 * data from becoming shell syntax in the offline refund command; validate
 * again at that output boundary. */
export function validateRefund(r: RefundableDeposit, vault: string): void {
  if (typeof vault !== "string" || !ADDRESS.test(vault) ||
      !Number.isSafeInteger(r.id) || r.id < 0 || BigInt(r.id) > U64_MAX ||
      typeof r.from !== "string" || !ADDRESS.test(r.from) ||
      typeof r.ownerCommit !== "string" || !DIGEST.test(r.ownerCommit) ||
      typeof r.amount !== "bigint" || r.amount <= 0n || r.amount >= 1n << 256n) {
    throw new Error("Invalid deposit refund data");
  }
}

/** One gateway-reported refundable deposit, or null when malformed. */
export function parseRefundableDeposit(raw: unknown, vault: string): RefundableDeposit | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  if (typeof row.amount !== "string" || !DECIMAL.test(row.amount)) return null;
  if (typeof row.from !== "string" || typeof row.ownerCommit !== "string") return null;
  try {
    const refund: RefundableDeposit = {
      id: row.id as number,
      from: row.from.toLowerCase(),
      ownerCommit: row.ownerCommit.toLowerCase(),
      amount: BigInt(row.amount),
    };
    validateRefund(refund, vault);
    return refund;
  } catch {
    return null;
  }
}
