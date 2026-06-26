import { useState, type ReactNode } from "react";
import { useStore } from "../store";
import { formatUsd, parseUsd } from "../domain/format";
import { accountSummary } from "../domain/risk";

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

export function AccountPanel() {
  const { client, state } = useStore();
  const [amount, setAmount] = useState("1000");
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
        await client.requestWithdrawal(v);
        setMsg(`Withdrawal of ${formatUsd(v)} requested against SETTLED balance.`);
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
        cannot be withdrawn until the position is closed (§6).
      </p>
    </div>
  );
}
