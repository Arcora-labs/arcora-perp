/** Credentials are scoped to one configured endpoint, chain and vault.
 * Cross-tab writes use a browser lock, not a non-atomic localStorage counter.
 * The server's recovery nonce is the generation; wall-clock time is not one.
 */
export interface CredentialScope { base: string; chainId: number; vault: string }
export interface StoredCredential extends CredentialScope {
  schema: 2;
  apiKey: string;
  owner: string;
  recoveryNonce: number;
}
export const LEGACY_ACCOUNT_KEY = "darkperp.v1Account";
const hex32 = /^0x[0-9a-fA-F]{64}$/;
const hex20 = /^0x[0-9a-fA-F]{40}$/;
export const validGeneration = (n: unknown): n is number =>
  typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
export function canonicalBase(base: string): string {
  const u = new URL(base);
  if (!/^https?:$/.test(u.protocol) || u.username || u.password || u.search || u.hash) {
    throw new Error("Invalid gateway URL.");
  }
  return u.toString().replace(/\/+$/, "");
}
export function parseScope(base: string, value: unknown): CredentialScope {
  const v = value as Partial<CredentialScope> | null;
  if (!v || !validGeneration(v.chainId) || typeof v.vault !== "string" || !hex20.test(v.vault)) {
    throw new Error("Gateway deployment metadata is unavailable or malformed; account access is paused.");
  }
  return { base: canonicalBase(base), chainId: v.chainId, vault: v.vault.toLowerCase() };
}
export function sameScope(a: CredentialScope, b: CredentialScope): boolean {
  return a.base === b.base && a.chainId === b.chainId && a.vault.toLowerCase() === b.vault.toLowerCase();
}
export function credentialKey(scope: CredentialScope): string {
  return `darkperp.v2Account:${JSON.stringify([scope.base, scope.chainId, scope.vault.toLowerCase()])}`;
}
export function parseCredential(raw: string | null, scope: CredentialScope): StoredCredential | null {
  if (raw === null) return null;
  let v: Partial<StoredCredential> | null;
  try { v = JSON.parse(raw) as Partial<StoredCredential> | null; }
  catch { throw new Error("Saved credential is malformed; use wallet recovery. The saved record was not erased."); }
  if (!v || v.schema !== 2 || typeof v.base !== "string" || !validGeneration(v.chainId) ||
      typeof v.vault !== "string" || !hex20.test(v.vault) ||
      typeof v.owner !== "string" || !hex32.test(v.owner) ||
      typeof v.apiKey !== "string" || !hex32.test(v.apiKey) || !validGeneration(v.recoveryNonce) ||
      !sameScope(v as CredentialScope, scope)) {
    throw new Error("Saved credential does not match this deployment; use wallet recovery. Nothing was erased.");
  }
  return { ...scope, schema: 2, apiKey: v.apiKey.toLowerCase(), owner: v.owner.toLowerCase(), recoveryNonce: v.recoveryNonce };
}
export function makeCredential(scope: CredentialScope, value: unknown): StoredCredential {
  const v = value as { apiKey?: unknown; owner?: unknown; recoveryNonce?: unknown };
  return parseCredential(JSON.stringify({ ...v, ...scope, schema: 2 }), scope)!;
}
export async function withRecoveryLock<T>(scope: CredentialScope, owner: string, operation: () => Promise<T>): Promise<T> {
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  if (!locks?.request) throw new Error("Recovery needs a secure browser tab with cross-tab locking enabled.");
  return locks.request(`${credentialKey(scope)}:recover:${owner.toLowerCase()}`, { ifAvailable: true }, async lock => {
    if (!lock) throw new Error("Recovery is already in progress in another tab. Finish it there before retrying.");
    return operation();
  });
}
/** Returns false when persistence is unavailable. A confirmed server rotation
 * must still be retained in memory; keeping the old bytes does not revive its key.
 */
export async function persistCredential(
  record: StoredCredential, isCurrent: () => boolean, allowOwnerSwitch = false,
): Promise<boolean> {
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  if (!locks?.request) return false; // do not pretend a read/setItem pair is atomic
  return locks.request(`${credentialKey(record)}:write`, async () => {
    if (!isCurrent()) throw new Error("Credential operation superseded by a newer account selection.");
    let current: StoredCredential | null;
    try { current = parseCredential(localStorage.getItem(credentialKey(record)), record); }
    catch { return false; }
    if (current && current.owner !== record.owner && !allowOwnerSwitch) {
      throw new Error("Another account was selected in this deployment; registration cannot replace it.");
    }
    if (current?.owner === record.owner && (current.recoveryNonce > record.recoveryNonce ||
        (current.recoveryNonce === record.recoveryNonce && current.apiKey !== record.apiKey))) {
      throw new Error("Refusing to overwrite a newer stored credential or an ambiguous same-generation key.");
    }
    try { localStorage.setItem(credentialKey(record), JSON.stringify(record)); }
    catch { return false; }
    return true;
  });
}

/** A deadline also covers the response body; fetch mocks and stalled bodies
 * cannot silently evade it merely by ignoring AbortSignal.
 */
export async function boundedJson(url: string, init: RequestInit = {}, timeoutMs = 15_000): Promise<{ status: number; ok: boolean; value: unknown }> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Error("Gateway request timed out; its outcome may be unknown.")); }, timeoutMs);
  });
  try {
    return await Promise.race([
      (async () => {
        const res = await fetch(url, { ...init, cache: "no-store", signal: controller.signal });
        const value: unknown = await res.json();
        return { status: res.status, ok: res.ok, value };
      })(), timeout,
    ]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

/** A legacy record is only a public recovery hint, never trusted authority.
 * Read only the validated owner; never expose or transmit its unscoped key. */
export function legacyOwnerHint(): string | null {
  try {
    const value = JSON.parse(localStorage.getItem(LEGACY_ACCOUNT_KEY) ?? "null");
    return value && typeof value.owner === "string" && hex32.test(value.owner)
      ? value.owner.toLowerCase() : null;
  } catch { return null; }
}
