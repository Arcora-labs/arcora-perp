import { useEffect, useRef, useState, type ReactNode } from "react";
import { useStore } from "../store";
import { formatUsd, parseUsd, shortHash } from "../domain/format";
import { accountSummary } from "../domain/risk";
import type { RefundableDeposit, TrackedOrder, WithdrawalEntry } from "../domain/types";
import { validateWithdrawal } from "../domain/withdrawal";
import { depositMinimumError, marketFreeBalance, withdrawalMinimumError } from "../domain/minimums";
import { validateRefund } from "../domain/refund";
import {
  buildClaimBundle,
  claimBundleFileName,
  loadClaimBundles,
  rememberClaimBundles,
  serializeClaimBundles,
  type ClaimBundle,
  type ClaimBundleStorage,
} from "../domain/claimBundle";
import {
  MAX_STORED_CHALLENGE_KITS,
  challengeKitFileName,
  loadChallengeKits,
  mergeChallengeKits,
  newChallengeKits,
  rememberChallengeKits,
  seenChallengeKits,
  serializeChallengeKits,
  settledOrderHashes,
  unsettledOrderHashes,
  type ChallengeKit,
  type ChallengeKitStorage,
} from "../domain/challengeKit";
import type { DarkPerpClient } from "../api/client";
import {
  BASE_SEPOLIA_CHAIN_ID,
  EXPLORER_TX,
  VAULT_ERROR_TEXT,
  connect,
  dryRunCall,
  encodeClaim,
  encodeRefundDeposit,
  ensureBaseSepolia,
  hasInjected,
  sendTx,
  supportsWalletDeposit,
  useWalletAddress,
  waitForTx,
  type WalletDepositClient,
} from "../api/wallet";
import { runWalletDeposit } from "../api/depositFlow";
import { DepositRecoveryPanel, usePendingDeposits } from "./DepositRecoveryPanel";

/// Consolidated account health: equity, used vs free margin, unrealized PnL, and
/// account-wide leverage — aggregated across the open positions and free balance.
export function AccountSummary() {
  const { state } = useStore();
  const s = accountSummary(
    state.account.positions,
    state.account.settledBalance,
    (marketId) => state.marks[marketId] ?? state.oracle.price,
  );
  const equityIcon = (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><circle cx="8" cy="8" r="6" /><path d="M18.09 10.37A6 6 0 1 1 10.34 18" /><path d="M7 6h1v4" /></svg>
  );
  const levIcon = (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" /></svg>
  );
  return (
    <div className="statgrid">
      <StatCard label="Equity" value={state.accountUnavailable ? "—" : formatUsd(s.equity)} sub="Net account value" glow icon={equityIcon} />
      <StatCard label="Free · Withdrawable" value={state.accountUnavailable ? "—" : formatUsd(s.freeBalance)} sub="SETTLED · spendable now" glow tone="pos" />
      <StatCard label="Used Margin" value={state.accountUnavailable ? "—" : formatUsd(s.usedMargin)} sub="Locked by open positions" />
      <StatCard
        label="Unrealized PnL"
        value={state.accountUnavailable ? "—" : formatUsd(s.upnl)}
        sub="At current mark"
        tone={s.upnl > 0n ? "pos" : s.upnl < 0n ? "neg" : undefined}
      />
      <StatCard label="Acct Leverage" value={state.accountUnavailable ? "—" : `${s.leverage.toFixed(2)}×`} sub="Notional ÷ equity" glow accent icon={levIcon} />
    </div>
  );
}

function StatCard({
  label, value, sub, tone, glow, accent, icon,
}: {
  label: string; value: string; sub: string;
  tone?: "pos" | "neg"; glow?: boolean; accent?: boolean; icon?: ReactNode;
}) {
  const color = accent ? "var(--accent)" : tone === "pos" ? "var(--buy)" : tone === "neg" ? "var(--sell)" : "var(--text)";
  return (
    <div className="card">
      <div className="statcard__head">
        <span className="statcard__label">{label}</span>
        {icon && <span className="statcard__icon">{icon}</span>}
      </div>
      <div className={`statcard__value ${glow ? "statcard__value--glow" : ""}`} style={{ color }}>{value}</div>
      <div className="statcard__sub">{sub}</div>
    </div>
  );
}

/// SEC-021 withdrawal-authorization state as the panel sees it: `undefined` =
/// not yet loaded (or the client doesn't expose it — the mock has no binding
/// concept), otherwise the client's answer.
type WithdrawAuth = { depositAddress: string | null; callerSigned: boolean } | undefined;

export function AccountPanel() {
  const { client, state } = useStore();
  const [amount, setAmount] = useState("1000");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Live gateway ⇒ collateral enters via a REAL on-chain deposit (the demo
  // self-credit is refused by the prod gateway), so the wallet card replaces
  // the demo Deposit button. The mock client lacks the wallet surface ⇒ the
  // demo flow stays as-is.
  const walletCapable = supportsWalletDeposit(client);

  // SEC-021: withdrawals always pay the BOUND deposit address (the gateway
  // refuses anything else for server-custody accounts), so the free-text
  // destination is gone — the panel shows the bound address read-only instead.
  // Polled like WithdrawalsSection: the address appears once the deposit
  // pipeline's bind step lands, with no push channel for it.
  const [auth, setAuth] = useState<WithdrawAuth>(undefined);
  const authCapable = typeof client.withdrawAuthInfo === "function";
  useEffect(() => {
    const fetchAuth = client.withdrawAuthInfo?.bind(client);
    if (!fetchAuth) return;
    let alive = true;
    const load = () => {
      fetchAuth()
        .then((a) => { if (alive) setAuth(a); })
        .catch(() => { /* transient — keep the last answer, the poll retries */ });
    };
    load();
    const timer = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(timer); };
  }, [client]);

  // Loaded-and-unwithdrawable ⇒ the button is disabled up front; while still
  // loading it stays enabled and requestWithdrawal itself refuses cleanly.
  const withdrawBlocked = auth !== undefined && (auth.callerSigned || !auth.depositAddress);

  // In-flight guard (the WalletDepositCard `running` convention): two Withdraw
  // clicks in flight would both read the same nextWithdrawNonce off
  // /v1/accounts/me, so the second is rejected with a baffling "nonce must
  // strictly increase" — disable the buttons until the first settles instead.
  const [busy, setBusy] = useState<"deposit" | "withdraw" | null>(null);

  async function run(kind: "deposit" | "withdraw") {
    if (busy) return;
    setMsg(null);
    setErr(null);
    const v = parseUsd(amount);
    if (v === null || v <= 0n) return setErr("Enter a valid amount.");
    if (kind === "withdraw") {
      // The gateway exempts a request for the selected market's whole free
      // balance, not the account-wide one.
      const tooSmall = withdrawalMinimumError(v, marketFreeBalance(state.account, state.selectedMarketId));
      if (tooSmall) return setErr(tooSmall);
    }
    setBusy(kind);
    try {
      if (kind === "deposit") {
        await client.deposit(v);
        setMsg(`Deposited ${formatUsd(v)} — a shielded note was minted.`);
      } else {
        await client.requestWithdrawal(v);
        const dest = auth?.depositAddress;
        setMsg(
          `Withdrawal of ${formatUsd(v)}${dest ? ` to ${shortHash(dest)}` : ""} requested — it appears below as ` +
            `“Settling on-chain…” and becomes Claimable after its batch settles; timing varies.`,
        );
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="card">
      <h3 className="card__title">Account</h3>
      <div className="stat">
        <span className="stat__label">Settled balance (withdrawable)</span>
        <span className="stat__value">{formatUsd(state.account.settledBalance)}</span>
      </div>
      {/* SEC-025-E1 review F1: with a /v1 account provisioned but unreadable,
          the client emits an EMPTY placeholder instead of the public demo
          feed — say so, or a user cannot tell "no balance" from "we could
          not read your account". Fix-wave-3 H1: no automatic-recovery promise
          — after the F7 auth-error reset or a boot-time registration failure
          nothing retries on its own (see Tables.UnavailableNotice). */}
      {state.accountUnavailable && (
        <p className="small neg">
          Your account state could not be read from the gateway — the balance,
          positions and orders shown are <strong>placeholders (0), not your
          actual state</strong>. It clears as soon as a read succeeds; if this
          notice persists, reload the page.
        </p>
      )}

      {walletCapable && <WalletDepositCard client={client as DarkPerpClient & WalletDepositClient} />}

      <label className="field">
        <span className="field__label">Amount (USD)</span>
        <input className="field__input" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
      </label>
      <p className="muted small">Minimum withdrawal: 1 USDC, unless you withdraw your entire free balance in the selected market.</p>
      {authCapable && auth !== undefined && (
        auth.callerSigned ? (
          <p className="muted small">
            This account is caller-signed — withdrawals must be authorized by its
            registered signer key via the API, not from this UI.
          </p>
        ) : auth.depositAddress ? (
          <div className="field">
            <span className="field__label">Withdrawing to (bound deposit address)</span>
            <code className="mono small" style={{ overflowWrap: "anywhere" }}>{auth.depositAddress}</code>
            <p className="muted small">
              Funds always return to the address you deposited from — your wallet
              signs the withdrawal with it.
            </p>
          </div>
        ) : (
          <p className="muted small">
            Bind a deposit address before withdrawing — make one wallet deposit
            above to bind it.
          </p>
        )
      )}
      <div className="row">
        {!walletCapable && (
          <button className="btn btn--ghost" onClick={() => run("deposit")} disabled={busy !== null}>
            {busy === "deposit" ? "Working…" : "Deposit"}
          </button>
        )}
        <button
          className="btn btn--ghost"
          onClick={() => run("withdraw")}
          disabled={withdrawBlocked || busy !== null}
        >
          {busy === "withdraw" ? "Working…" : "Withdraw"}
        </button>
      </div>
      {msg && <p className="notice notice--ok">{msg}</p>}
      {err && <p className="notice notice--error">{err}</p>}
      <p className="muted small">
        Withdrawals release only from SETTLED state (§3). Open-position collateral
        cannot be withdrawn until the position is closed (§6). A requested
        withdrawal becomes claimable on-chain once its batch settles; timing varies.
      </p>

      <WithdrawalsSection client={client} />
      <RefundsSection client={client} closeOnly={state.mode === "CloseOnly"} />
      <ChallengeKitSection orders={state.orders} />
    </div>
  );
}

// ── injected-wallet deposit pipeline ─────────────────────────────────────────

type StepId = "chain" | "mint" | "approve" | "bind" | "authorize" | "deposit" | "credit";
type StepStatus = "idle" | "pending" | "done" | "error";

const WALLET_STEPS: { id: StepId; label: string }[] = [
  { id: "chain", label: "Switch wallet to Base Sepolia" },
  { id: "mint", label: "Mint test USDC to your wallet" },
  { id: "approve", label: "Approve the vault to pull USDC" },
  { id: "bind", label: "Bind wallet to trading account (signature)" },
  { id: "authorize", label: "Authorize the deposit with the gateway (SEC-019)" },
  { id: "deposit", label: "Deposit USDC into the vault" },
  { id: "credit", label: "Credit the trading account" },
];

const idleSteps = (): Record<StepId, StepStatus> => ({
  chain: "idle", mint: "idle", approve: "idle", bind: "idle", authorize: "idle", deposit: "idle", credit: "idle",
});

const STEP_GLYPH: Record<StepStatus, string> = { idle: "○", pending: "…", done: "✓", error: "✕" };
const STEP_COLOR: Record<StepStatus, string> = {
  idle: "var(--muted, inherit)", pending: "var(--accent)", done: "var(--buy)", error: "var(--sell)",
};

/** Wallet prompts retain one immutable account/deployment/market/amount intent.
 * Progress is journaled before sending; retries only resume known hashes. */
export function WalletDepositCard({ client }: { client: WalletDepositClient }) {
  const address = useWalletAddress();
  const [amount, setAmount] = useState("1000");
  const [steps, setSteps] = useState<Record<StepId, StepStatus>>(idleSteps);
  const [txs, setTxs] = useState<Partial<Record<StepId, string>>>({});
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const { pending, issue } = usePendingDeposits();
  const original = pending.find(item => item.wallet === address);
  const statusOnly = !!original && (original.unknownSend || original.hasDeposit);
  const active = useRef(false);
  const view = useRef({ client, address, amount, mounted: true });
  view.current = { client, address, amount, mounted: true };
  useEffect(() => () => { view.current.mounted = false; }, []);

  if (!hasInjected()) {
    return (
      <div className="walletflow">
        <DepositRecoveryPanel client={client} pending={pending} issue={issue} active={running}
          onCheckStart={() => { setErr(null); setOk(null); }}
          onCredited={() => { setSteps(idleSteps()); setTxs({}); }} />
        <p className="muted small">
          <strong>No browser wallet detected.</strong> Install{" "}
          <a href="https://metamask.io" target="_blank" rel="noreferrer">MetaMask</a> to
          deposit from the UI, or fund via the CLI path in the{" "}
          <a href="https://docs.arcoralabs.xyz/quickstart.html" target="_blank" rel="noreferrer">
            quickstart
          </a>{" "}
          (mint → approve → deposit with <code>cast</code>).
        </p>
      </div>
    );
  }

  async function onConnect() {
    setErr(null);
    try {
      await connect();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  function onAmountChange(v: string) {
    setAmount(v);
    // A new amount restarts the pipeline — UNLESS the deposit tx already
    // landed (then the remaining credit step doesn't depend on the amount,
    // and resetting would orphan the on-chain deposit).
    if (!running && !txs.deposit) {
      setSteps(idleSteps());
      setTxs({});
    }
  }

  async function run() {
    if (!address || active.current) return;
    const v = original?.amount ?? parseUsd(amount);
    if (v === null || v <= 0n) return setErr("Enter a valid amount.");
    // A resumed deposit already holds its permit; only a new one meets the minimum.
    if (!original) {
      const tooSmall = depositMinimumError(v);
      if (tooSmall) return setErr(tooSmall);
    }
    active.current = true;
    setErr(null); setOk(null); setRunning(true);
    const assertView = () => {
      const current = view.current;
      if (!current.mounted || current.client !== client || current.address !== address || current.amount !== amount) {
        throw new Error("Deposit form or wallet context changed; reconcile the original deposit before retrying.");
      }
    };
    try {
      const credited = await runWalletDeposit({
        client, address, amount: v, assertView, resume: original,
        progress: ({ step, status, txs: hashes }) => {
          try { assertView(); } catch { return; }
          setSteps(previous => ({ ...previous, [step]: status }));
          setTxs(hashes);
        },
      });
      assertView();
      setOk(`Deposited ${formatUsd(credited)} — credited to your trading account.`);
      setSteps(idleSteps()); setTxs({});
    } catch (error) {
      if (view.current.mounted) setErr(error instanceof Error ? error.message : String(error));
    } finally {
      active.current = false;
      if (view.current.mounted) setRunning(false);
    }
  }

  const anyProgress = WALLET_STEPS.some(({ id }) => steps[id] !== "idle");
  return (
    <div className="walletflow">
      <DepositRecoveryPanel client={client} pending={pending} issue={issue} active={running}
          onCheckStart={() => { setErr(null); setOk(null); }}
          onCredited={() => { setSteps(idleSteps()); setTxs({}); }} />
      {!address ? (
        <>
          <p className="muted small">
            Collateral enters through a <strong>real on-chain USDC deposit</strong>. Connect
            your wallet to mint test USDC, deposit into the vault and credit your
            trading account in one flow.
          </p>
          <button type="button" className="btn btn--ghost" onClick={onConnect}>
            Connect wallet
          </button>
        </>
      ) : (
        <>
          <div className="withdrawals__row muted small mono">
            <span>wallet {shortHash(address)}</span>
            <span>Base Sepolia</span>
          </div>
          <label className="field">
            <span className="field__label">Deposit amount (USDC)</span>
            <input
              className="field__input"
              value={original ? formatUsd(original.amount, 6).replace(/[$,]/g, "") : amount}
              onChange={(e) => onAmountChange(e.target.value)}
              inputMode="decimal"
              disabled={running || !!original}
            />
          </label>
          <p className="muted small">Minimum deposit: 10 USDC.</p>
          {!statusOnly && <button type="button" className="btn btn--ghost" onClick={run} disabled={running || !!issue}>
            {running ? "Working…" : original ? "Resume original deposit" : "Deposit"}
          </button>}
          {(anyProgress || running) && (
            <ol className="walletflow__steps" style={{ listStyle: "none", margin: "8px 0 0", padding: 0 }}>
              {WALLET_STEPS.map(({ id, label }, i) => {
                const s = steps[id];
                const h = txs[id];
                return (
                  <li key={id} className="mono small" style={{ color: STEP_COLOR[s] }}>
                    <span aria-hidden>{STEP_GLYPH[s]}</span> [{i + 1}] {label}
                    {h && (
                      <>
                        {" "}
                        <a href={`${EXPLORER_TX}${h}`} target="_blank" rel="noreferrer">
                          {shortHash(h)}
                        </a>
                      </>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
        </>
      )}
      {ok && <p className="notice notice--ok">{ok}</p>}
      {err && <p className="notice notice--error">{err}</p>}
    </div>
  );
}

/// The full on-chain claim call for one settled withdrawal — pure so the exact
/// command shape is unit-testable. ANYONE may send it (the vault pays `to`, not
/// the sender), so the private key stays a placeholder: the UI must NEVER ask
/// for or handle a real key.
export function buildClaimCommand(w: WithdrawalEntry, vault: string): string {
  validateWithdrawal(w, vault);
  return [
    "cast send",
    vault,
    '"claim(address,uint256,uint256,bytes32,bytes32[])"',
    w.to,
    w.amount.toString(),
    String(w.nonce),
    w.root,
    `"[${w.proof.join(",")}]"`,
    "--rpc-url https://sepolia.base.org",
    "--private-key <YOUR_KEY>",
  ].join(" ");
}

const CLAIM_CHAIN_ID = Number.parseInt(BASE_SEPOLIA_CHAIN_ID, 16);

/// Hand the user a local file; nothing leaves the browser.
function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/// One claim tx's lifecycle, keyed by the withdrawal nonce.
interface ClaimTxState {
  status: "pending" | "done" | "error";
  hash?: string;
  err?: string;
}

/// Requested withdrawals with their settle→claim lifecycle. The withdrawal flow
/// used to dead-end at "requested" — this closes it: while the window is proving
/// the entry shows pending settlement, and once `claimable` the user gets
/// the on-chain claim — sent directly from a connected wallet, with the
/// copy-pasteable `cast` command kept as the fallback. Hidden entirely when the
/// client reports null (mock mode / no provisioned account). When this browser
/// does not keep a claimable entry's claim bundle (storage blocked or full), the
/// section says so. `storage` defaults to this origin's localStorage.
/// Exported for tests (takes the client as a prop so a fake can drive it).
export function WithdrawalsSection({ client, storage }: { client: DarkPerpClient; storage?: ClaimBundleStorage }) {
  const [data, setData] = useState<{ withdrawals: WithdrawalEntry[]; vault: string } | null>(null);
  const [copiedNonce, setCopiedNonce] = useState<number | null>(null);
  const wallet = useWalletAddress();
  const [claims, setClaims] = useState<Record<number, ClaimTxState>>({});
  const [savedBundles, setSavedBundles] = useState<ClaimBundle[]>(() => loadClaimBundles(storage));
  // Listed claimable entries whose bundle this browser does not hold.
  const [unsaved, setUnsaved] = useState(0);

  // Keep every claimable entry's bundle in this browser as soon as it is
  // seen, so the claim data survives the operator going away.
  useEffect(() => {
    if (!data) return;
    const fresh = data.withdrawals.flatMap((w) => {
      try {
        return [buildClaimBundle(w, data.vault, CLAIM_CHAIN_ID)];
      } catch {
        return []; // not claimable yet, or invalid claim data
      }
    });
    if (fresh.length === 0) {
      setUnsaved(0);
    } else if (rememberClaimBundles(fresh, storage)) {
      setSavedBundles(loadClaimBundles(storage));
      setUnsaved(0);
    } else {
      // A refused write keeps none of them; one stored earlier is still kept.
      const kept = new Set(loadClaimBundles(storage).map((b) => b.leaf.toLowerCase()));
      setUnsaved(fresh.filter((b) => !kept.has(b.leaf.toLowerCase())).length);
    }
  }, [data, storage]);

  useEffect(() => {
    let alive = true;
    const load = () => {
      client
        .listWithdrawals()
        .then((d) => { if (alive) setData(d); })
        .catch(() => { /* transient fetch failure — keep the last good list, the poll retries */ });
    };
    load();
    // Poll: claimability flips server-side when the batch settles,
    // with no push channel for it — 30 s keeps the flip visible without load.
    const timer = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(timer); };
  }, [client]);

  if (!data || data.withdrawals.length === 0) return null;
  // Newest first — the per-account nonce is strictly increasing per request.
  const entries = [...data.withdrawals].sort((a, b) => b.nonce - a.nonce);

  async function copy(w: WithdrawalEntry) {
    try {
      await navigator.clipboard.writeText(buildClaimCommand(w, data!.vault));
      setCopiedNonce(w.nonce);
      setTimeout(() => setCopiedNonce((n) => (n === w.nonce ? null : n)), 2000);
    } catch { /* clipboard unavailable (permissions) — the button simply stays */ }
  }

  function downloadBundle(w: WithdrawalEntry) {
    const bundle = buildClaimBundle(w, data!.vault, CLAIM_CHAIN_ID);
    downloadText(claimBundleFileName(bundle), serializeClaimBundles([bundle]));
  }

  function exportAll() {
    downloadText(`arcora-claims-${CLAIM_CHAIN_ID}.json`, serializeClaimBundles(savedBundles));
  }

  /// Send the on-chain `claim` directly from the connected wallet. The vault
  /// pays `w.to` regardless of the sender, so ANY connected account may send it.
  async function claimWithWallet(w: WithdrawalEntry) {
    if (!wallet || !data) return;
    const set = (s: ClaimTxState) => setClaims((c) => ({ ...c, [w.nonce]: s }));
    set({ status: "pending" });
    try {
      validateWithdrawal(w, data.vault);
      await ensureBaseSepolia();
      const hash = await sendTx({ from: wallet, to: data.vault, data: encodeClaim(w) });
      set({ status: "pending", hash });
      await waitForTx(hash);
      set({ status: "done", hash });
    } catch (e) {
      setClaims((c) => ({
        ...c,
        [w.nonce]: { ...c[w.nonce], status: "error", err: e instanceof Error ? e.message : String(e) },
      }));
    }
  }

  return (
    <div className="withdrawals">
      <h3 className="card__title">Withdrawals</h3>
      {unsaved > 0 && (
        <p className="notice notice--warn" role="alert">
          This browser did not keep{" "}
          {unsaved === 1 ? "the claim file of 1 claimable withdrawal" : `the claim files of ${unsaved} claimable withdrawals`}{" "}
          (its storage is blocked or full). Use Download claim file now and keep a copy: without one, the
          claim data is offered again only while the gateway still lists the withdrawal.
        </p>
      )}
      <ul className="withdrawals__list">
        {entries.map((w) => {
          const claim = claims[w.nonce];
          return (
          <li key={w.nonce} className="withdrawals__item">
            <div className="withdrawals__row">
              <span className="stat__value">{formatUsd(w.amount)}</span>
              <span className={`badge badge--${w.claimable ? "settled" : "matched"}`}>
                {w.claimable ? "Claimable" : "Awaiting on-chain settlement…"}
              </span>
            </div>
            <div className="withdrawals__row muted small mono">
              <span>to {shortHash(w.to)}</span>
              <span>nonce {w.nonce}</span>
            </div>
            {w.claimable && (
              <div className="row">
                {wallet && hasInjected() && claim?.status !== "done" && (
                  <button
                    type="button"
                    className="btn btn--ghost"
                    onClick={() => claimWithWallet(w)}
                    disabled={claim?.status === "pending"}
                  >
                    {claim?.status === "pending" ? "Claiming…" : "Claim with wallet"}
                  </button>
                )}
                <button type="button" className="btn btn--ghost" onClick={() => copy(w)}>
                  {copiedNonce === w.nonce ? "Copied" : "Copy claim command"}
                </button>
                <button type="button" className="btn btn--ghost" onClick={() => downloadBundle(w)}>
                  Download claim file
                </button>
              </div>
            )}
            {claim?.hash && (
              <p className="muted small mono">
                {claim.status === "done" ? "Claimed ✓" : claim.status === "error" ? "Claim tx" : "Claiming…"}{" "}
                <a href={`${EXPLORER_TX}${claim.hash}`} target="_blank" rel="noreferrer">
                  {shortHash(claim.hash)}
                </a>
              </p>
            )}
            {claim?.status === "error" && claim.err && (
              <p className="notice notice--error">{claim.err}</p>
            )}
          </li>
          );
        })}
      </ul>
      <p className="muted small">
        Claimable entries are paid by the on-chain vault: send the claim from the
        connected wallet, or run the copied <code>cast send</code> command from any
        funded wallet (replace <code>&lt;YOUR_KEY&gt;</code> — anyone can send the
        claim; funds always go to the withdrawal address).
      </p>
      <p className="muted small">
        Each claimable withdrawal is also kept in this browser as a claim file. Keep a
        downloaded copy: it lets you claim without the operator, checked with{" "}
        <code>scripts/claim/claim_withdrawal.py</code>.
      </p>
      {savedBundles.length > 0 && (
        <button type="button" className="btn btn--ghost" onClick={exportAll}>
          Export all claim files ({savedBundles.length})
        </button>
      )}
    </div>
  );
}

// ── close-only deposit refunds ────────────────────────────────────────────────

/// The full on-chain refund call for one uncredited deposit — pure so the exact
/// command shape is unit-testable. Refunds pay the deposit's own address, so
/// ANY funded wallet may send it; the private key stays a placeholder.
export function buildRefundCommand(r: RefundableDeposit, vault: string): string {
  validateRefund(r, vault);
  return [
    "cast send",
    vault,
    '"refundDeposit(uint64,address,bytes32,uint256,address)"',
    String(r.id),
    r.from,
    r.ownerCommit,
    r.amount.toString(),
    r.from,
    "--rpc-url https://sepolia.base.org",
    "--private-key <YOUR_KEY>",
  ].join(" ");
}

/// One refund tx's lifecycle, keyed by the deposit id.
interface RefundTxState {
  status: "pending" | "done" | "error";
  hash?: string;
  err?: string;
}

/// Deposits that reached the vault but that settled state never credited. In
/// close-only mode the vault returns each one in full to its depositing address
/// (`refundDeposit`). Shown only in close-only mode and only when the client
/// reports entries (the mock and older gateways report none). Exported for tests.
export function RefundsSection({ client, closeOnly }: { client: DarkPerpClient; closeOnly: boolean }) {
  const [data, setData] = useState<{ deposits: RefundableDeposit[]; vault: string } | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [refunds, setRefunds] = useState<Record<number, RefundTxState>>({});
  const wallet = useWalletAddress();

  useEffect(() => {
    const list = client.listRefundableDeposits?.bind(client);
    if (!closeOnly || !list) { setData(null); return; }
    let alive = true;
    const load = () => {
      list()
        .then((d) => { if (alive) setData(d); })
        .catch(() => { /* transient — keep the last good list, the poll retries */ });
    };
    load();
    const timer = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(timer); };
  }, [client, closeOnly]);

  if (!closeOnly || !data || data.deposits.length === 0) return null;
  const entries = [...data.deposits].sort((a, b) => a.id - b.id);

  async function copy(r: RefundableDeposit) {
    try {
      await navigator.clipboard.writeText(buildRefundCommand(r, data!.vault));
      setCopiedId(r.id);
      setTimeout(() => setCopiedId((id) => (id === r.id ? null : id)), 2000);
    } catch { /* clipboard unavailable — the button simply stays */ }
  }

  /// Send `refundDeposit` from the connected wallet, paying the deposit's own
  /// address. A dry run first, so a refusal is explained without a failed tx.
  async function refundWithWallet(r: RefundableDeposit) {
    if (!wallet || !data) return;
    const set = (s: RefundTxState) => setRefunds((c) => ({ ...c, [r.id]: s }));
    set({ status: "pending" });
    try {
      validateRefund(r, data.vault);
      const calldata = encodeRefundDeposit({ ...r, to: r.from });
      await ensureBaseSepolia();
      const simulated = await dryRunCall({ from: wallet, to: data.vault, data: calldata });
      if (simulated.status === "reverted") {
        if (simulated.error === "AlreadyRefunded") return set({ status: "done" });
        throw new Error(simulated.error ? VAULT_ERROR_TEXT[simulated.error]
          : `The vault refused this refund in a dry run (revert data ${simulated.data.slice(0, 10)}).`);
      }
      const hash = await sendTx({ from: wallet, to: data.vault, data: calldata });
      set({ status: "pending", hash });
      await waitForTx(hash);
      set({ status: "done", hash });
    } catch (e) {
      setRefunds((c) => ({
        ...c,
        [r.id]: { ...c[r.id], status: "error", err: e instanceof Error ? e.message : String(e) },
      }));
    }
  }

  return (
    <div className="withdrawals" aria-label="Refundable deposits">
      <h3 className="card__title">Refundable deposits</h3>
      <p className="muted small">
        The exchange is in close-only mode. These deposits reached the vault, but
        settled state never credited them, so the vault returns each one in full to
        the address it came from.
      </p>
      <ul className="withdrawals__list">
        {entries.map((r) => {
          const refund = refunds[r.id];
          return (
            <li key={r.id} className="withdrawals__item">
              <div className="withdrawals__row">
                <span className="stat__value">{formatUsd(r.amount)}</span>
                <span className="badge badge--settled">{refund?.status === "done" ? "Refunded" : "Refundable"}</span>
              </div>
              <div className="withdrawals__row muted small mono">
                <span>to {shortHash(r.from)}</span>
                <span>deposit #{r.id}</span>
              </div>
              {refund?.status !== "done" && (
                <div className="row">
                  {wallet && hasInjected() && (
                    <button
                      type="button"
                      className="btn btn--ghost"
                      onClick={() => refundWithWallet(r)}
                      disabled={refund?.status === "pending"}
                    >
                      {refund?.status === "pending" ? "Refunding…" : "Refund with wallet"}
                    </button>
                  )}
                  <button type="button" className="btn btn--ghost" onClick={() => copy(r)}>
                    {copiedId === r.id ? "Copied" : "Copy refund command"}
                  </button>
                </div>
              )}
              {refund?.hash && (
                <p className="muted small mono">
                  {refund.status === "done" ? "Refunded ✓" : refund.status === "error" ? "Refund tx" : "Refunding…"}{" "}
                  <a href={`${EXPLORER_TX}${refund.hash}`} target="_blank" rel="noreferrer">
                    {shortHash(refund.hash)}
                  </a>
                </p>
              )}
              {refund?.status === "error" && refund.err && (
                <p className="notice notice--error">{refund.err}</p>
              )}
            </li>
          );
        })}
      </ul>
      <p className="muted small">
        Send the refund from the connected wallet, or run the copied{" "}
        <code>cast send</code> command from any funded wallet (replace{" "}
        <code>&lt;YOUR_KEY&gt;</code>). Anyone can send it; the funds always go to the
        deposit's address. Without the gateway,{" "}
        <code>scripts/claim/refund_deposit.py</code> finds your deposits on-chain and
        prints the same call.
      </p>
    </div>
  );
}

// ── L1 inclusion-challenge kits ───────────────────────────────────────────────

/// Kits listed one by one; older ones are still in the export.
const LISTED_KITS = 20;

/// Offered kits this browser did not store: how many, how many of them are not
/// for an order the account lists now, and whether the store is at its bound.
interface UnsavedKits {
  count: number;
  unlisted: number;
  atBound: boolean;
}

/// Which of the kits not kept are not for an order the account lists now: the
/// panel cannot offer them again after it closes.
function unlistedNote({ count, unlisted }: UnsavedKits): string {
  if (unlisted === 0) return "";
  const subject = unlisted === count ? (count === 1 ? "It is" : "They are") : `${unlisted} of them ${unlisted === 1 ? "is" : "are"}`;
  return ` ${subject} for ${unlisted === 1 ? "an order" : "orders"} this account does not list now` +
    " (this account's older orders, or another account's in this browser).";
}

/// The L1 challenge kits of the account's listed orders, kept in this browser
/// (bounded; see `rememberChallengeKits`). With a kit the user can open
/// `challengeInclusion` for an order no settled batch includes or rejects,
/// without the operator. A kit is dropped once the gateway lists its order as
/// SETTLED. The section offers, past the storage bound too, the kit of every
/// listed order that is not SETTLED and every kit stored or offered so far this
/// session. When the browser does not store a kit (storage blocked or full, or
/// the bound reached), the section still offers it for this session and says
/// so, counting the ones that are not for an order the account lists now
/// (older orders, or another account's in this browser). Hidden while there is
/// none. When the gateway lists an order with another authorization than the
/// kit kept for it (the account bound another deposit address, which the
/// gateway now signs for), the new kit replaces the kept one, in storage and in
/// the offer. `storage` defaults to this origin's localStorage. Exported for tests.
export function ChallengeKitSection({ orders, storage }: { orders: TrackedOrder[]; storage?: ChallengeKitStorage }) {
  const [kits, setKits] = useState<ChallengeKit[]>(() => loadChallengeKits(storage));
  const [unsaved, setUnsaved] = useState<UnsavedKits>({ count: 0, unlisted: 0, atBound: false });
  // The offered kits, for the effect (it alone changes them after the first render).
  const offered = useRef(kits);
  // Per order hash, the authorization already kept or tried, so a state push
  // re-verifies nothing and a new authorization is built.
  const seen = useRef<Map<string, string> | null>(null);
  seen.current ??= seenChallengeKits(kits);
  // Per order hash, the authorization of the kit this session built from the
  // listing: the newest copy of that order's kit this browser holds.
  const built = useRef(new Map<string, string>());

  useEffect(() => {
    const fresh = newChallengeKits(orders, seen.current!);
    const settled = settledOrderHashes(orders);
    const current = offered.current;
    if (fresh.length === 0 && !current.some((k) => settled.has(k.orderHash.toLowerCase()))) return;
    const listed = unsettledOrderHashes(orders);
    for (const [hash, signature] of seenChallengeKits(fresh)) built.current.set(hash, signature);
    // This session's other kits (stored when the panel opened, or another
    // account's) give way to a stored copy of their order: another tab may
    // have stored a newer one since (its account bound another deposit address).
    const isBuilt = (k: ChallengeKit) => built.current.get(k.orderHash.toLowerCase()) === k.l1Challenge.signature.toLowerCase();
    const own = current.filter(isBuilt);
    const others = current.filter((k) => !isBuilt(k));
    // Stored before this write, including kits another tab stored since this
    // panel opened: any of them the write evicts is offered (and counted) too.
    const before = loadChallengeKits(storage);
    const inStore = seenChallengeKits(before);
    // This session's unsaved kits go along, so they are stored once there is room.
    rememberChallengeKits(
      [...others.filter((k) => !inStore.has(k.orderHash.toLowerCase())), ...own, ...fresh], storage, settled, listed,
    );
    const stored = loadChallengeKits(storage);
    // Per order, the authorization stored: a kit is kept only when it is that one.
    const kept = seenChallengeKits(stored);
    // Not bounded: a kit the store evicted stays offered for this session. A
    // later copy wins: the listing's, then this session's built ones, then the stored ones.
    const next = mergeChallengeKits([...others, ...before, ...stored, ...own], fresh, settled);
    offered.current = next;
    setKits(next);
    const notKept = next.filter((k) => kept.get(k.orderHash.toLowerCase()) !== k.l1Challenge.signature.toLowerCase());
    setUnsaved({
      count: notKept.length,
      unlisted: notKept.filter((k) => !listed.has(k.orderHash.toLowerCase())).length,
      atBound: stored.length >= MAX_STORED_CHALLENGE_KITS,
    });
  }, [orders, storage]);

  if (kits.length === 0) return null;
  const newest = [...kits].sort((a, b) => b.recvTimeMs - a.recvTimeMs || b.seqNo - a.seqNo);
  const listed = newest.slice(0, LISTED_KITS);

  return (
    <div className="withdrawals" aria-label="Challenge kits">
      <h3 className="card__title">Challenge kits</h3>
      <p className="muted small">
        If a settled batch never includes or rejects an accepted order, its kit lets you
        open the on-chain inclusion challenge without the operator (check it with{" "}
        <code>scripts/claim/challenge_inclusion.py</code>). Keep the files private:
        opening a challenge publicly links your deposit address to the order.
      </p>
      {unsaved.count > 0 && (
        <p className="notice notice--warn" role="alert">
          This browser did not keep{" "}
          {unsaved.count < kits.length ? `${unsaved.count} of these kits` : kits.length === 1 ? "this kit" : "these kits"}{" "}
          ({unsaved.atBound ? `it keeps at most ${MAX_STORED_CHALLENGE_KITS}` : "its storage is blocked or full"}).
          {unlistedNote(unsaved)} Export now: once you leave this panel or reload the page, a kit it did not keep
          is offered again only while the gateway still lists its order.
        </p>
      )}
      <ul className="withdrawals__list">
        {listed.map((k) => (
          <li key={k.orderHash} className="withdrawals__item">
            <div className="withdrawals__row muted small mono">
              <span>order {shortHash(k.orderHash)}</span>
              <span>receipt #{k.seqNo}</span>
            </div>
            <div className="row">
              <button
                type="button"
                className="btn btn--ghost"
                aria-label={`Download challenge kit for order ${shortHash(k.orderHash)}`}
                onClick={() => downloadText(challengeKitFileName(k), serializeChallengeKits([k]))}
              >
                Download challenge kit
              </button>
            </div>
          </li>
        ))}
      </ul>
      {newest.length > listed.length && (
        <p className="muted small">{newest.length - listed.length} older kits are only in the export.</p>
      )}
      <button
        type="button"
        className="btn btn--ghost"
        onClick={() => downloadText("arcora-challenge-kits.json", serializeChallengeKits(newest))}
      >
        Export all challenge kits ({kits.length})
      </button>
    </div>
  );
}
