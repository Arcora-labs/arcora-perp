import { useEffect, useRef, useState, type ReactNode } from "react";
import { useStore } from "../store";
import { formatUsd, parseUsd, shortHash } from "../domain/format";
import { accountSummary } from "../domain/risk";
import type { WithdrawalEntry } from "../domain/types";
import type { DarkPerpClient } from "../api/client";
import {
  EXPLORER_TX,
  connect,
  encodeClaim,
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
      <StatCard label="Equity" value={formatUsd(s.equity)} sub="Net account value" glow icon={equityIcon} />
      <StatCard label="Free · Withdrawable" value={formatUsd(s.freeBalance)} sub="SETTLED · spendable now" glow tone="pos" />
      <StatCard label="Used Margin" value={formatUsd(s.usedMargin)} sub="Locked by open positions" />
      <StatCard
        label="Unrealized PnL"
        value={formatUsd(s.upnl)}
        sub="At current mark"
        tone={s.upnl > 0n ? "pos" : s.upnl < 0n ? "neg" : undefined}
      />
      <StatCard label="Acct Leverage" value={`${s.leverage.toFixed(2)}×`} sub="Notional ÷ equity" glow accent icon={levIcon} />
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
            `“Settling on-chain…” and becomes Claimable in ~10–20 min (one proof interval).`,
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
        withdrawal becomes claimable on-chain once its window settles (~10–20 min).
      </p>

      <WithdrawalsSection client={client} />
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

/// One claim tx's lifecycle, keyed by the withdrawal nonce.
interface ClaimTxState {
  status: "pending" | "done" | "error";
  hash?: string;
  err?: string;
}

/// Requested withdrawals with their settle→claim lifecycle. The withdrawal flow
/// used to dead-end at "requested" — this closes it: while the window is proving
/// the entry shows the ~10–20 min expectation, and once `claimable` the user gets
/// the on-chain claim — sent directly from a connected wallet, with the
/// copy-pasteable `cast` command kept as the fallback. Hidden entirely when the
/// client reports null (mock mode / no provisioned account).
/// Exported for tests (takes the client as a prop so a fake can drive it).
export function WithdrawalsSection({ client }: { client: DarkPerpClient }) {
  const [data, setData] = useState<{ withdrawals: WithdrawalEntry[]; vault: string } | null>(null);
  const [copiedNonce, setCopiedNonce] = useState<number | null>(null);
  const wallet = useWalletAddress();
  const [claims, setClaims] = useState<Record<number, ClaimTxState>>({});

  useEffect(() => {
    let alive = true;
    const load = () => {
      client
        .listWithdrawals()
        .then((d) => { if (alive) setData(d); })
        .catch(() => { /* transient fetch failure — keep the last good list, the poll retries */ });
    };
    load();
    // Poll: claimability flips server-side when the window settles (~10–20 min),
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

  /// Send the on-chain `claim` directly from the connected wallet. The vault
  /// pays `w.to` regardless of the sender, so ANY connected account may send it.
  async function claimWithWallet(w: WithdrawalEntry) {
    if (!wallet || !data) return;
    const set = (s: ClaimTxState) => setClaims((c) => ({ ...c, [w.nonce]: s }));
    set({ status: "pending" });
    try {
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
      <ul className="withdrawals__list">
        {entries.map((w) => {
          const claim = claims[w.nonce];
          return (
          <li key={w.nonce} className="withdrawals__item">
            <div className="withdrawals__row">
              <span className="stat__value">{formatUsd(w.amount)}</span>
              <span className={`badge badge--${w.claimable ? "settled" : "matched"}`}>
                {w.claimable ? "Claimable" : "Settling on-chain… (~10–20 min)"}
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
    </div>
  );
}
