import { useEffect, useRef, useState } from "react";
import { formatUsd } from "../domain/format";
import { EXPLORER_TX, useWalletAddress, type WalletDepositClient } from "../api/wallet";
import { DEPOSIT_JOURNAL_EVENT, pendingDeposits, reconcileDeposit, type PendingDeposit } from "../api/depositFlow";

export function usePendingDeposits() {
  const read = () => {
    try { return { pending: pendingDeposits(), issue: null as string | null }; }
    catch (error) { return { pending: [] as PendingDeposit[], issue: error instanceof Error ? error.message : "Saved deposit details are unavailable." }; }
  };
  const [value, setValue] = useState(read);
  useEffect(() => {
    const refresh = () => setValue(read());
    window.addEventListener("storage", refresh);
    window.addEventListener(DEPOSIT_JOURNAL_EVENT, refresh);
    refresh(); // catch a write between first render and listener installation
    return () => {
      window.removeEventListener("storage", refresh);
      window.removeEventListener(DEPOSIT_JOURNAL_EVENT, refresh);
    };
  }, []);
  return value;
}

const stepNames = { mint: "Mint test USDC", approve: "Approve vault", deposit: "Deposit into vault" };

export function DepositRecoveryPanel({ client, pending, issue, active, onCheckStart, onCredited }: {
  client: WalletDepositClient; pending: PendingDeposit[]; issue: string | null; active: boolean;
  onCheckStart?(): void; onCredited?(): void;
}) {
  const wallet = useWalletAddress();
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ id: string; text: string; error: boolean } | null>(null);
  const checking = useRef(false);
  const view = useRef({ client, wallet, mounted: true });
  view.current = { client, wallet, mounted: true };
  useEffect(() => () => { view.current.mounted = false; }, []);

  async function check(original: PendingDeposit) {
    if (checking.current || active) return;
    checking.current = true; setBusy(original.id); setResult(null); onCheckStart?.();
    const assertView = () => {
      if (!view.current.mounted || view.current.client !== client || view.current.wallet !== wallet) {
        throw new Error("The selected wallet or gateway changed during the status check. The original transaction was retained.");
      }
    };
    try {
      const response = await reconcileDeposit(client, original, assertView);
      assertView();
      const text = response.status === "credited"
        ? `Original deposit of ${formatUsd(original.amount, 6)} is credited. No new transaction was sent.`
        : response.status === "pending"
          ? "The original transaction is still pending. Check its status again after it is mined. No new transaction was sent."
          : response.status === "reverted"
            ? "The original transaction reverted. Keep its hash and review the failure in the explorer before deciding how to proceed. No new transaction was sent."
            : `${stepNames[response.step]} is confirmed. No vault deposit is recorded yet. Resume the original deposit when ready; this check sent no transaction.`;
      setResult({ id: original.id, text, error: false });
      if (response.status === "credited") onCredited?.();
    } catch (error) {
      if (view.current.mounted) setResult({ id: original.id, text: error instanceof Error ? error.message : String(error), error: true });
    } finally {
      checking.current = false;
      if (view.current.mounted) setBusy(null);
    }
  }

  if (!pending.length && !issue && !result) return null;
  return (
    <section className="deposit-recovery" aria-label="Original deposit recovery">
      {pending.length > 0 && <h4>Original deposit in progress</h4>}
      {issue && <p className="notice notice--error">{issue}</p>}
      {pending.map(original => (
        <div key={original.id} className="deposit-recovery__item">
          <dl className="small" style={{ overflowWrap: "anywhere" }}>
            <dt>Original amount</dt><dd>{formatUsd(original.amount, 6)} USDC</dd>
            <dt>Original wallet</dt><dd><code>{original.wallet}</code></dd>
            <dt>Network</dt><dd>{original.chainId === 84532 ? "Base Sepolia" : `Chain ${original.chainId}`} · chain {original.chainId}</dd>
            <dt>Market</dt><dd>#{original.marketId}</dd>
            <dt>Trading account</dt><dd><code>{original.owner}</code></dd>
            <dt>Gateway</dt><dd>{original.base}</dd>
            <dt>Vault</dt><dd><code>{original.vault}</code></dd>
            <dt>Last transaction step</dt><dd>{stepNames[original.step]}</dd>
            <dt>Transaction hash</dt><dd>{original.hash
              ? original.chainId === 84532
                ? <a href={`${EXPLORER_TX}${original.hash}`} target="_blank" rel="noreferrer">{original.hash}</a>
                : <code>{original.hash}</code>
              : "Not returned by wallet"}</dd>
          </dl>
          {original.unknownSend ? (
            <p className="small">
              {active ? "Waiting for the wallet's transaction response. " : "The transaction outcome is unknown because the wallet did not return its hash. "}
              Open this wallet’s activity on the displayed network and locate the original {stepNames[original.step].toLowerCase()} transaction for this amount.
              Automatic transaction matching is unavailable. Keep the original transaction details; new sends remain blocked.
            </p>
          ) : (
            <>
              <p className="small">Check the original transaction and its credit status. This action cannot send another transaction.</p>
              {wallet !== original.wallet && <p className="small">Connect the original wallet shown above before checking.</p>}
              <button type="button" className="btn btn--ghost" disabled={active || busy !== null || wallet !== original.wallet} onClick={() => check(original)}>
                {busy === original.id ? "Checking original transaction…" : "Check original transaction"}
              </button>
            </>
          )}
        </div>
      ))}
      {result && <p role={result.error ? "alert" : "status"} className={`notice ${result.error ? "notice--error" : "notice--ok"}`}>{result.text}</p>}
    </section>
  );
}
