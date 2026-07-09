import { useEffect, useState, type ReactNode } from "react";
import { useStore } from "../store";
import { formatUsd, parseUsd, shortHash } from "../domain/format";
import { accountSummary } from "../domain/risk";
import type { WithdrawalEntry } from "../domain/types";

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

/// localStorage key for the last-used withdrawal destination ADDRESS (a public
/// 0x address only — never key material; the claim's private key never enters
/// this UI).
const LS_WITHDRAW_TO_KEY = "darkperp.withdrawTo";

/// Strict 20-byte EVM address shape: `0x` + exactly 40 hex chars.
export function isEvmAddress(v: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(v);
}

export function AccountPanel() {
  const { client, state } = useStore();
  const [amount, setAmount] = useState("1000");
  const [to, setTo] = useState(() => {
    try { return localStorage.getItem(LS_WITHDRAW_TO_KEY) ?? ""; } catch { return ""; }
  });
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run(kind: "deposit" | "withdraw") {
    setMsg(null);
    setErr(null);
    const v = parseUsd(amount);
    if (v === null || v <= 0n) return setErr("Enter a valid amount.");
    try {
      if (kind === "deposit") {
        await client.deposit(v);
        setMsg(`Deposited ${formatUsd(v)} — a shielded note was minted.`);
      } else {
        const dest = to.trim();
        if (!isEvmAddress(dest)) {
          return setErr("Enter a valid destination address (0x + 40 hex) — the on-chain claim pays out there.");
        }
        await client.requestWithdrawal(v, dest);
        try { localStorage.setItem(LS_WITHDRAW_TO_KEY, dest); } catch { /* private mode — convenience only */ }
        setMsg(
          `Withdrawal of ${formatUsd(v)} to ${shortHash(dest)} requested — it appears below as ` +
            `“Settling on-chain…” and becomes Claimable in ~10–20 min (one proof interval).`,
        );
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="card">
      <h3 className="card__title">Account</h3>
      <div className="stat">
        <span className="stat__label">Settled balance (withdrawable)</span>
        <span className="stat__value">{formatUsd(state.account.settledBalance)}</span>
      </div>

      <label className="field">
        <span className="field__label">Amount (USD)</span>
        <input className="field__input" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
      </label>
      <label className="field">
        <span className="field__label">Withdrawal address (claim pays out here)</span>
        <input
          className="field__input"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="0x…"
          spellCheck={false}
          autoComplete="off"
        />
      </label>
      <div className="row">
        <button className="btn btn--ghost" onClick={() => run("deposit")}>
          Deposit
        </button>
        <button className="btn btn--ghost" onClick={() => run("withdraw")}>
          Withdraw
        </button>
      </div>
      {msg && <p className="notice notice--ok">{msg}</p>}
      {err && <p className="notice notice--error">{err}</p>}
      <p className="muted small">
        Withdrawals release only from SETTLED state (§3). Open-position collateral
        cannot be withdrawn until the position is closed (§6). A requested
        withdrawal becomes claimable on-chain once its window settles (~10–20 min).
      </p>

      <WithdrawalsSection />
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

/// Requested withdrawals with their settle→claim lifecycle. The withdrawal flow
/// used to dead-end at "requested" — this closes it: while the window is proving
/// the entry shows the ~10–20 min expectation, and once `claimable` the user gets
/// the copy-pasteable on-chain claim command. Hidden entirely when the client
/// reports null (mock mode / no provisioned account).
function WithdrawalsSection() {
  const { client } = useStore();
  const [data, setData] = useState<{ withdrawals: WithdrawalEntry[]; vault: string } | null>(null);
  const [copiedNonce, setCopiedNonce] = useState<number | null>(null);

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

  return (
    <div className="withdrawals">
      <h3 className="card__title">Withdrawals</h3>
      <ul className="withdrawals__list">
        {entries.map((w) => (
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
              <button type="button" className="btn btn--ghost" onClick={() => copy(w)}>
                {copiedNonce === w.nonce ? "Copied" : "Copy claim command"}
              </button>
            )}
          </li>
        ))}
      </ul>
      <p className="muted small">
        Claimable entries are paid by the on-chain vault: run the copied{" "}
        <code>cast send</code> command from any funded wallet (replace{" "}
        <code>&lt;YOUR_KEY&gt;</code> — anyone can send the claim; funds always go
        to the withdrawal address).
      </p>
    </div>
  );
}
