import { hexToBytes, bytesToHex } from "@noble/hashes/utils";
import {
  BASE_SEPOLIA_CHAIN_ID, COLLATERAL_VAULT, MOCK_USDC, bindDepositDigest,
  depositWalletGuard, encodeApprove, encodeDeposit, encodeMint, ensureBaseSepolia,
  isUserRejection, personalSign, sendTx, waitForTx, transactionStatus, verifyFinalizedRevertedTransaction, type WalletDepositClient,
} from "./wallet";

export type DepositStep = "chain" | "mint" | "approve" | "bind" | "authorize" | "deposit" | "credit";
export type DepositStatus = "idle" | "pending" | "done" | "error";
export type DepositProgress = { step: DepositStep; status: DepositStatus; txs: Partial<Record<DepositStep, string>> };
type Journal = {
  version: 1; owner: string; marketId: number; recoveryNonce: number; amount: string;
  txs: Partial<Record<DepositStep, string>>; done: DepositStep[];
  sending: "mint" | "approve" | "deposit" | null;
  retryStep?: "mint" | "approve" | "deposit";
  failed?: { step: "mint" | "approve" | "deposit"; hash: string }[];
};
const steps: DepositStep[] = ["chain", "mint", "approve", "bind", "authorize", "deposit", "credit"];
const transactionSteps = ["mint", "approve", "deposit"] as const;
export const DEPOSIT_JOURNAL_EVENT = "darkperp:deposit-progress";
const JOURNAL_PREFIX = "darkperp.deposit.v1:";
const RESOLVED_PREFIX = "darkperp.deposit.resolved.v1:";
function notifyJournal() { window.dispatchEvent(new Event(DEPOSIT_JOURNAL_EVENT)); }
function saveJournal(key: string, journal: Journal) {
  const value = JSON.stringify(journal);
  localStorage.setItem(key, value);
  if (localStorage.getItem(key) !== value) throw new Error("Deposit progress could not be saved. Reconcile wallet activity before retrying.");
  notifyJournal();
}
function removeJournal(key: string) { localStorage.removeItem(key); notifyJournal(); }

export type PendingDeposit = {
  readonly id: string; readonly revision: string;
  readonly base: string; readonly chainId: number; readonly vault: string; readonly wallet: string;
  readonly owner: string; readonly marketId: number; readonly recoveryNonce: number; readonly amount: bigint;
  readonly step: "mint" | "approve" | "deposit";
  readonly hash: string | null; readonly unknownSend: boolean;
  readonly hasDeposit: boolean;
  readonly retryReady: boolean; readonly previousHash: string | null;
};

/** Public journal metadata only; loading this view never registers an account or
 * contacts a wallet/gateway. A stored original operation stays visible even
 * after its wallet or account is no longer selected. */
export function pendingDeposits(): PendingDeposit[] {
  const pending: PendingDeposit[] = [];
  for (let index = 0; index < localStorage.length; index++) {
    const id = localStorage.key(index);
    if (!id?.startsWith(JOURNAL_PREFIX)) continue;
    const domain = JSON.parse(id.slice(JOURNAL_PREFIX.length)) as unknown;
    if (!Array.isArray(domain) || domain.length !== 4 || typeof domain[0] !== "string" ||
        !/^https?:\/\//.test(domain[0]) || !Number.isSafeInteger(domain[1]) || domain[1] < 0 ||
        typeof domain[2] !== "string" || !/^0x[0-9a-f]{40}$/.test(domain[2]) ||
        typeof domain[3] !== "string" || !/^0x[0-9a-f]{40}$/.test(domain[3])) {
      throw new Error("Saved deposit details cannot be read. Keep the saved data and inspect your wallet activity before starting another deposit.");
    }
    const journal = readJournal(id);
    if (!journal) continue;
    const step = journal.sending ?? journal.retryStep ?? [...transactionSteps].reverse().find(step => !!journal.txs[step]);
    if (!step) continue; // a rejected prompt with no hash has no transfer to recover
    pending.push(Object.freeze({ id, revision: JSON.stringify(journal), base: domain[0], chainId: domain[1], vault: domain[2], wallet: domain[3],
      owner: journal.owner, marketId: journal.marketId, recoveryNonce: journal.recoveryNonce, amount: BigInt(journal.amount),
      step, hash: journal.sending || journal.retryStep ? null : journal.txs[step] ?? null, unknownSend: journal.sending !== null,
      hasDeposit: !!journal.txs.deposit, retryReady: !!journal.retryStep, previousHash: journal.failed?.at(-1)?.hash ?? null }));
  }
  return pending;
}

export type DepositReconciliation = { status: "pending" | "confirmed" | "reverted" | "credited" | "retry-ready"; step: PendingDeposit["step"]; hash: string };

/** Status-only recovery of a hash already returned by the original wallet.
 * No network switch, wallet signature, authorization, mint or send can occur.
 * A rotated credential may inspect the same owner/deployment/market operation;
 * its own immutable context still fences every delayed read/credit response. */
export async function reconcileDeposit(client: WalletDepositClient, pending: PendingDeposit, assertView: () => void): Promise<DepositReconciliation> {
  return reconcileOriginalDeposit(client, pending, assertView, false);
}

/** A separate explicit action archives finalized failure evidence and unlocks
 * only the failed step. It never sends, signs, switches chain or asks for credit. */
export async function prepareRevertedDepositRetry(client: WalletDepositClient, pending: PendingDeposit, assertView: () => void): Promise<DepositReconciliation> {
  return reconcileOriginalDeposit(client, pending, assertView, true);
}

async function reconcileOriginalDeposit(client: WalletDepositClient, pending: PendingDeposit, assertView: () => void, prepareRetry: boolean): Promise<DepositReconciliation> {
  if (!navigator.locks?.request) throw new Error("Status checks require browser Web Locks so another tab cannot change the original operation.");
  return navigator.locks.request(pending.id, { ifAvailable: true }, async lock => {
    if (!lock) throw new Error("This deposit is active in another tab. Wait for its wallet request to finish, then check again.");
    const current = pendingDeposits().find(item => item.id === pending.id);
    if (!current || current.revision !== pending.revision) throw new Error("Saved deposit progress changed. Review the updated original transaction and check again.");
    pending = current; // derive every hash/context fact from the stored original
    const journal = readJournal(pending.id);
    if (!journal || JSON.stringify(journal) !== pending.revision) throw new Error("Saved deposit progress changed. Review the updated original transaction and check again.");
    if (journal.retryStep) throw new Error("This finalized failure is already saved. Resume the original deposit when ready.");
    if (journal.sending || !pending.hash) throw new Error("The wallet did not return the original transaction hash. Inspect this wallet's activity; automatic transaction matching is not available. New sends remain blocked.");
    const context = await client.captureDepositContext({ existingOnly: true });
    assertView(); context.assertCurrent();
    if (context.base !== pending.base || context.chainId !== pending.chainId || context.vault.toLowerCase() !== pending.vault || context.owner !== pending.owner || context.marketId !== pending.marketId) {
      throw new Error(`Select the original account and market #${pending.marketId} on the displayed gateway before checking this deposit. Its saved transaction remains unchanged.`);
    }
    if (BigInt(pending.chainId) !== BigInt(BASE_SEPOLIA_CHAIN_ID) || pending.vault !== COLLATERAL_VAULT.toLowerCase()) {
      throw new Error("This saved deposit uses another deployment. Open its original gateway to check its transaction.");
    }
    const wallet = depositWalletGuard(pending.wallet);
    const check = async () => {
      assertView(); context.assertCurrent();
      await wallet.assertCurrent();
      assertView(); context.assertCurrent();
      if (JSON.stringify(readJournal(pending.id)) !== pending.revision) throw new Error("Saved deposit progress changed during the status check; no result was applied.");
    };
    try {
      await check();
      if (prepareRetry) {
        const failedIndex = steps.indexOf(pending.step);
        if (journal.done.includes("credit") || transactionSteps.some(step => steps.indexOf(step) > failedIndex && journal.txs[step])) {
          throw new Error("Later deposit progress exists. Keep the original transaction and reconcile its credit before retrying.");
        }
        const evidence = await verifyFinalizedRevertedTransaction(pending.hash);
        await check();
        // Archive BEFORE changing the active journal. If either write fails,
        // the old operation remains blocking; a duplicate send cannot start.
        const archiveKey = `${RESOLVED_PREFIX}${pending.id.slice(JOURNAL_PREFIX.length)}:${pending.hash}`;
        const archive = JSON.stringify({ version: 1, id: pending.id, journal, step: pending.step, evidence });
        const existing = localStorage.getItem(archiveKey);
        if (existing !== null) {
          let saved: { id?: unknown; journal?: unknown; step?: unknown; evidence?: typeof evidence };
          try { saved = JSON.parse(existing); } catch { throw new Error("Saved failure evidence is unreadable. Keep the original operation for review."); }
          if (!saved || saved.id !== pending.id || JSON.stringify(saved.journal) !== pending.revision || saved.step !== pending.step ||
              saved.evidence?.transactionHash !== evidence.transactionHash || saved.evidence?.blockHash !== evidence.blockHash || saved.evidence?.blockNumber !== evidence.blockNumber) {
            throw new Error("Saved failure evidence differs from this check. Keep the original operation for review.");
          }
        } else {
          localStorage.setItem(archiveKey, archive);
          if (localStorage.getItem(archiveKey) !== archive) throw new Error("Finalized failure could not be saved. The original transaction remains blocked.");
        }
        journal.failed = [...(journal.failed ?? []), { step: pending.step, hash: pending.hash }];
        delete journal.txs[pending.step];
        journal.done = journal.done.filter(step => steps.indexOf(step) < failedIndex);
        journal.retryStep = pending.step;
        journal.recoveryNonce = context.recoveryNonce;
        saveJournal(pending.id, journal);
        return { status: "retry-ready", step: pending.step, hash: pending.hash };
      }
      const status = await transactionStatus(pending.hash);
      await check();
      if (status !== "confirmed") return { status, step: pending.step, hash: pending.hash };
      if (pending.step === "deposit") {
        const credited = await client.creditOnchainDeposit(pending.hash, context);
        await check();
        if (credited !== pending.amount || credited <= 0n) throw new Error("The credit receipt does not match the original amount. Keep this transaction and check again; do not send funds again.");
        removeJournal(pending.id);
        return { status: "credited", step: pending.step, hash: pending.hash };
      }
      // Only a confirmed original mint/approval is marked done. Updating the
      // credential generation allows an explicit later Resume with the same
      // owner and intent; this status action itself can never send anything.
      if (!journal.done.includes(pending.step)) journal.done.push(pending.step);
      journal.recoveryNonce = context.recoveryNonce;
      saveJournal(pending.id, journal);
      return { status, step: pending.step, hash: pending.hash };
    } finally { wallet.dispose(); }
  });
}

/** No credentials or signatures enter this durable, origin-wide recovery journal. */
function readJournal(key: string): Journal | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  let j: Journal;
  try { j = JSON.parse(raw) as Journal; }
  catch { throw new Error("Saved deposit progress is malformed. Keep the saved data and inspect wallet activity before retrying."); }
  if (!j || typeof j !== "object" || Array.isArray(j) || j.version !== 1 || typeof j.owner !== "string" || !/^0x[0-9a-f]{64}$/.test(j.owner) ||
      !Number.isSafeInteger(j.marketId) || !Number.isSafeInteger(j.recoveryNonce) ||
      typeof j.amount !== "string" || !/^[1-9][0-9]*$/.test(j.amount) ||
      !j.txs || typeof j.txs !== "object" || Array.isArray(j.txs) || !Array.isArray(j.done) ||
      j.done.some(step => !steps.includes(step)) ||
      transactionSteps.some(step => j.done.includes(step) && !j.txs[step]) ||
      (j.done.includes("credit") && !j.txs.deposit) ||
      (j.sending !== null && !transactionSteps.includes(j.sending)) ||
      (j.failed !== undefined && (!Array.isArray(j.failed) || j.failed.some(item => !item || !transactionSteps.includes(item.step) || typeof item.hash !== "string" || !/^0x[0-9a-f]{64}$/.test(item.hash)))) ||
      (j.retryStep !== undefined && (!transactionSteps.includes(j.retryStep) || j.sending !== null || j.txs[j.retryStep] || j.done.includes(j.retryStep) || j.failed?.at(-1)?.step !== j.retryStep || transactionSteps.some(step => steps.indexOf(step) > steps.indexOf(j.retryStep!) && j.txs[step]))) ||
      Object.entries(j.txs).some(([step, hash]) => !transactionSteps.includes(step as typeof transactionSteps[number]) || typeof hash !== "string" || !/^0x[0-9a-f]{64}$/.test(hash))) {
    throw new Error("Saved deposit progress is malformed. Reconcile wallet activity before retrying.");
  }
  return j;
}

/**
 * One immutable deposit intent, fenced at every await. The pre-send journal is
 * durable BEFORE presenting a transaction prompt. A missing hash is unknown,
 * never evidence that the wallet did not submit. Native locks fence other tabs.
 */
export async function runWalletDeposit({ client, address, amount, assertView, progress, resume }: {
  client: WalletDepositClient; address: string; amount: bigint; resume?: PendingDeposit;
  assertView(): void; progress(value: DepositProgress): void;
}): Promise<bigint> {
  if (amount <= 0n) throw new Error("Enter a valid amount.");
  address = address.toLowerCase();
  const context = await client.captureDepositContext({ existingOnly: !!resume });
  assertView(); context.assertCurrent();
  if (BigInt(context.chainId) !== BigInt(BASE_SEPOLIA_CHAIN_ID) || context.vault.toLowerCase() !== COLLATERAL_VAULT.toLowerCase()) {
    throw new Error("Gateway deployment does not match the configured wallet chain and vault. No transaction was sent.");
  }
  const key = `darkperp.deposit.v1:${JSON.stringify([context.base, context.chainId, context.vault.toLowerCase(), address])}`;
  if (resume && resume.id !== key) throw new Error("The original deposit belongs to another gateway, wallet or deployment. Select its original context before resuming; no transaction was sent.");
  if (!navigator.locks?.request) throw new Error("Safe wallet deposits require browser Web Locks; no transaction was sent.");
  return navigator.locks.request(key, { ifAvailable: true }, async lock => {
    if (!lock) throw new Error("A deposit is already running in another tab. Wait for it to finish.");
    assertView(); context.assertCurrent();
    let journal = readJournal(key);
    if (resume && (!journal || JSON.stringify(journal) !== resume.revision || journal.amount !== amount.toString())) {
      throw new Error("The original deposit progress or amount changed. Review its saved details before resuming; no transaction was sent.");
    }
    if (journal?.sending) throw new Error(`The previous ${journal.sending} transaction outcome is unknown. Reconcile wallet activity before retrying; no duplicate transaction was sent.`);
    // No hash and no outstanding send means no transaction can be orphaned.
    // Explicit first-prompt rejection must not pin a user to the old context.
    if (journal && !journal.retryStep && Object.keys(journal.txs).length === 0) journal = null;
    // A finalized failure has no outstanding send. Explicit Resume may adopt
    // same-owner recovered access while preserving the exact saved intent.
    if (journal?.retryStep && resume && journal.owner === context.owner && journal.marketId === context.marketId) {
      journal.recoveryNonce = context.recoveryNonce;
    }
    if (journal && (journal.owner !== context.owner || journal.marketId !== context.marketId || journal.recoveryNonce !== context.recoveryNonce)) {
      throw new Error("Saved deposit belongs to another account, market or credential generation. Reconcile the original deposit before starting another.");
    }
    if (journal && journal.amount !== amount.toString()) {
      if (journal.txs.deposit || transactionSteps.some(step => journal!.txs[step] && !journal!.done.includes(step))) {
        throw new Error(`Finish the original deposit amount (${journal.amount} USDC base units) before changing the amount.`);
      }
      journal = null;
    }
    journal ??= { version: 1, owner: context.owner, marketId: context.marketId, recoveryNonce: context.recoveryNonce,
      amount: amount.toString(), txs: {}, done: [], sending: null };
    const save = () => saveJournal(key, journal);
    let wallet: ReturnType<typeof depositWalletGuard> | undefined;
    const check = async () => {
      assertView(); context.assertCurrent();
      await wallet?.assertCurrent();
      assertView(); context.assertCurrent();
    };
    const report = (step: DepositStep, status: DepositStatus) => {
      try { assertView(); context.assertCurrent(); } catch { return; }
      progress({ step, status, txs: { ...journal.txs } });
    };
    const sendAndWait = async (step: typeof transactionSteps[number], to: string, data: () => string) => {
      await check();
      let hash = journal.txs[step];
      if (!hash) {
        const calldata = data(); // validate before recording the send intent
        const retryStep = journal.retryStep;
        journal.sending = step;
        delete journal.retryStep;
        save();
        try {
          hash = await sendTx({ from: address, to, data: calldata, chainId: BASE_SEPOLIA_CHAIN_ID });
        } catch (error) {
          // Only explicit rejection proves there was no submission. RPC errors,
          // malformed hash and a closed tab leave the durable marker in place.
          if (isUserRejection(error)) { journal.sending = null; if (retryStep) journal.retryStep = retryStep; save(); }
          throw error;
        }
        journal.txs[step] = hash;
        journal.sending = null;
        save(); // preserve an old-context hash even if the wallet changed meanwhile
      }
      await check();
      report(step, "pending");
      await waitForTx(hash);
      await check();
    };
    let auth: { ownerCommit: string; sig: string } | undefined;
    let credited = 0n;
    const executors: [DepositStep, () => Promise<void>][] = [
      ["chain", async () => {
        await ensureBaseSepolia();
        assertView(); context.assertCurrent();
        wallet = depositWalletGuard(address);
        await check();
      }],
      ["mint", () => sendAndWait("mint", MOCK_USDC, () => encodeMint(address, amount))],
      ["approve", () => sendAndWait("approve", MOCK_USDC, () => encodeApprove(context.vault, amount))],
      ["bind", async () => {
        const signature = await personalSign("0x" + bytesToHex(bindDepositDigest(hexToBytes(context.owner.slice(2)), address)), address);
        await check();
        await client.bindDepositAddress(address, signature, context);
        await check();
      }],
      ["authorize", async () => {
        auth = await client.authorizeDeposit(address, amount, context);
        await check();
      }],
      ["deposit", () => sendAndWait("deposit", context.vault, () => {
        if (!auth) throw new Error("Missing deposit authorization.");
        return encodeDeposit(amount, auth.ownerCommit, auth.sig);
      })],
      ["credit", async () => {
        const hash = journal.txs.deposit;
        if (!hash) throw new Error("Missing deposit transaction hash.");
        credited = await client.creditOnchainDeposit(hash, context);
        await check();
        if (credited !== amount || credited <= 0n) {
          throw new Error("Deposit credit receipt does not match the original amount. Retain the original transaction and retry only its credit check; do not send funds again.");
        }
      }],
    ];
    try {
      for (const [step, execute] of executors) {
        await check();
        if (journal.done.includes(step) && step !== "chain" && step !== "credit" && !(step === "authorize" && !journal.txs.deposit)) {
          report(step, "done"); continue;
        }
        report(step, "pending");
        try { await execute(); }
        catch (error) { report(step, "error"); throw error; }
        await check();
        if (!journal.done.includes(step)) journal.done.push(step);
        save();
        report(step, "done");
      }
      await check();
      removeJournal(key);
      return credited;
    } finally { wallet?.dispose(); }
  });
}
