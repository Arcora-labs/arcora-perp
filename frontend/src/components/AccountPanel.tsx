import { useState } from "react";
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
  return (
    <div className="card">
      <h3 className="card__title">Margin</h3>
      <div className="summary">
        <SummaryStat label="Equity" value={formatUsd(s.equity)} />
        <SummaryStat label="Free (withdrawable)" value={formatUsd(s.freeBalance)} />
        <SummaryStat label="Used margin" value={formatUsd(s.usedMargin)} />
        <SummaryStat
          label="Unrealized PnL"
          value={formatUsd(s.upnl)}
          tone={s.upnl > 0n ? "pos" : s.upnl < 0n ? "neg" : undefined}
        />
        <SummaryStat label="Account leverage" value={`${s.leverage.toFixed(2)}×`} />
      </div>
    </div>
  );
}

function SummaryStat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="summary__stat">
      <span className="summary__label">{label}</span>
      <span className={`summary__value mono ${tone ?? ""}`}>{value}</span>
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
