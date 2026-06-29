import { useState } from "react";
import { useStore } from "../store";
import { formatUsd } from "../domain/format";

const API = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "");

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="summary__stat">
      <span className="summary__label">{label}</span>
      <span className={`summary__value mono ${tone ?? ""}`}>{value}</span>
    </div>
  );
}

/// The LP pool (counterparty) tab: deposit USDC to take the other side of every
/// trader, earn the house edge, bear the pool's PnL. Fees go to the treasury, not
/// LPs. Stats come live from the snapshot; deposit/withdraw hit the gateway, and the
/// WS push refreshes the numbers.
export function LpVault() {
  const { state } = useStore();
  const lp = state.lp;
  const [amount, setAmount] = useState("100000");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function call(path: string, body: unknown, ok: string) {
    if (!API) {
      setErr("Connect to a live gateway (mock mode can't move the pool).");
      return;
    }
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const r = await fetch(`${API}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error((await r.json().catch(() => ({})))?.error ?? `gateway ${r.status}`);
      setMsg(ok);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function deposit() {
    const q = BigInt(Math.round(Number(amount || "0") * 1e6)); // USD → quote units
    if (q <= 0n) {
      setErr("Enter an amount > 0.");
      return;
    }
    call("/api/lp/deposit", { amount: q.toString() }, `Deposited $${amount} — LP shares minted.`);
  }

  function withdrawAll() {
    if (lp.myShares <= 0n) {
      setErr("You have no LP position.");
      return;
    }
    call("/api/lp/withdraw", { shares: lp.myShares.toString() }, "Withdrew your full LP position.");
  }

  const nav = Number(lp.navPerShare);
  const sharesDisp = (Number(lp.myShares) / 1e6).toLocaleString(undefined, { maximumFractionDigits: 2 });

  return (
    <div className="grid grid--two">
      <div className="col">
        <div className="card">
          <h3 className="card__title">Liquidity pool — the counterparty</h3>
          <p className="small muted">
            Deposit USDC to become the <strong>counterparty</strong> to every trader: the pool takes
            the other side, earns the <strong className="pos">house edge</strong> (net trader losses)
            and bears their net gains. Trading fees go to the protocol treasury, not the pool — LPs
            earn the directional edge. Seeded with a $30M operator stake.
          </p>
          <div className="summary">
            <Stat label="Pool TVL" value={formatUsd(lp.tvl)} tone="pos" />
            <Stat label="NAV / share" value={nav.toFixed(4)} tone={nav >= 1 ? "pos" : "neg"} />
          </div>
        </div>

        <div className="card">
          <h3 className="card__title">Your LP position</h3>
          <div className="summary">
            <Stat label="Your value" value={formatUsd(lp.myValue)} tone={lp.myValue > 0n ? "pos" : undefined} />
            <Stat label="Your shares" value={sharesDisp} />
          </div>
          <p className="small muted">
            Your value floats with the pool's PnL (NAV × your shares). Withdraw pays out shares ×
            current NAV from the pool's free capital.
          </p>
        </div>
      </div>

      <div className="col">
        <div className="card">
          <h3 className="card__title">Provide liquidity</h3>
          <label className="field">
            <span className="field__label">Deposit (USD)</span>
            <input
              className="field__input"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              inputMode="decimal"
            />
          </label>
          <div className="banner__actions" style={{ marginTop: 10 }}>
            <button className="btn btn--accent" onClick={deposit} disabled={busy}>
              {busy ? "…" : "Deposit"}
            </button>
            <button className="btn btn--ghost" onClick={withdrawAll} disabled={busy || lp.myShares <= 0n}>
              Withdraw all
            </button>
          </div>
          {err && <p className="small neg">{err}</p>}
          {msg && <p className="small pos">{msg}</p>}
          <p className="small muted">
            Shares minted = deposit × totalShares ÷ pool equity, so you buy in at the live NAV.
            Engine-modeled today; the on-chain ERC-4626 vault is the next step.
          </p>
        </div>
      </div>
    </div>
  );
}
