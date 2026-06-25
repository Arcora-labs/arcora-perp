import { useStore } from "../store";
import { formatPrice, formatUsd } from "../domain/format";
import { accountSummary } from "../domain/risk";

type Status = "ok" | "warn" | "down";

function StatusRow({ label, status, detail }: { label: string; status: Status; detail: string }) {
  const tone = status === "ok" ? "ok" : status === "warn" ? "warn" : "danger";
  return (
    <div className="health-row">
      <span className={`health-row__dot health-row__dot--${tone}`} aria-hidden />
      <span className="health-row__label">{label}</span>
      <span className={`health-row__detail ${tone === "ok" ? "" : tone === "warn" ? "" : "neg"}`}>{detail}</span>
    </div>
  );
}

/// System health / status dashboard: service liveness, oracle freshness per market,
/// the settlement pipeline (finality throughput), and accounting consistency. Read-only,
/// token-styled — the frontend analog of a status page. Reads the same ClientState, so
/// against a real backend it reflects real service health.
export function HealthPanel() {
  const { state } = useStore();
  const markets = state.markets;
  const liveCount = markets.filter((m) => m.live).length;
  const orders = state.orders;

  // settlement pipeline
  const accepted = orders.filter((o) => o.finality === "ACCEPTED").length;
  const matched = orders.filter((o) => o.finality === "MATCHED").length;
  const settled = orders.filter((o) => o.finality === "SETTLED").length;

  // accounting (§4 — no collateral created or destroyed). equity = free + margin +
  // uPnL is an identity inside accountSummary, so re-deriving it would be a tautology
  // that can never fail. Instead check the invariants that CAN be violated by a bad
  // state: free balance is non-negative (margin was never over-committed), no position
  // carries negative collateral, and the account is solvent (equity ≥ 0).
  const s = accountSummary(
    state.account.positions,
    state.account.settledBalance,
    (id) => state.marks[id] ?? state.oracle.price,
  );
  const noNegativeMargin = state.account.positions.every((p) => p.collateral >= 0n);
  const conserved = s.freeBalance >= 0n && s.equity >= 0n && noNegativeMargin;
  const conservationDetail = conserved
    ? "free ≥ 0 · margin ≥ 0 · solvent ✓"
    : s.freeBalance < 0n
      ? "MISMATCH — free balance negative (margin over-committed)"
      : !noNegativeMargin
        ? "MISMATCH — negative position collateral"
        : "MISMATCH — insolvent (equity < 0)";

  // selected market oracle freshness
  const ageMs = Date.now() - state.oracle.publishTimeMs;
  const stale = ageMs > 15_000;

  const oracleStatus: Status = liveCount === markets.length ? "ok" : "warn";
  const modeStatus: Status = state.mode === "CloseOnly" ? "warn" : "ok";

  return (
    <div className="grid grid--two">
      <div className="col">
        <div className="card">
          <h3 className="card__title">Services</h3>
          <StatusRow label="Web client" status="ok" detail="rendering" />
          <StatusRow
            label="Oracle feed (§8)"
            status={oracleStatus}
            detail={oracleStatus === "ok" ? "all markets live" : `${liveCount}/${markets.length} live · rest on sim walk`}
          />
          <StatusRow label="Matching / settlement (§2/§3)" status="ok" detail={`${settled} settled · ${matched + accepted} in flight`} />
          <StatusRow
            label="System mode (§6)"
            status={modeStatus}
            detail={state.mode === "CloseOnly" ? "CLOSE-ONLY — exit only" : "Normal — full trading"}
          />
          <StatusRow
            label="Collateral conservation (§4)"
            status={conserved ? "ok" : "down"}
            detail={conservationDetail}
          />
        </div>

        <div className="card">
          <h3 className="card__title">Accounting</h3>
          <div className="summary">
            <Stat label="Equity" value={formatUsd(s.equity)} />
            <Stat label="Free" value={formatUsd(s.freeBalance)} />
            <Stat label="Used margin" value={formatUsd(s.usedMargin)} />
            <Stat label="uPnL" value={formatUsd(s.upnl)} tone={s.upnl >= 0n ? "pos" : "neg"} />
          </div>
        </div>
      </div>

      <div className="col">
        <div className="card">
          <h3 className="card__title">Oracle freshness</h3>
          <p className="small muted">
            Selected market ({state.market.symbol}) index published{" "}
            <strong className={stale ? "neg" : "pos"}>{Math.max(0, Math.round(ageMs / 1000))}s</strong> ago
            {stale ? " — stale (§8 gate would reject)" : " — fresh"}.
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Market</th>
                <th>Index</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {markets.map((m) => (
                <tr key={m.id}>
                  <td>{m.symbol}</td>
                  <td className="num mono">{formatPrice(state.marks[m.id] ?? 0n)}</td>
                  <td>{m.live ? <span className="pos">live oracle</span> : <span className="muted">sim walk</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h3 className="card__title">Settlement pipeline (§3)</h3>
          <div className="summary">
            <Stat label="ACCEPTED" value={String(accepted)} />
            <Stat label="MATCHED" value={String(matched)} />
            <Stat label="SETTLED" value={String(settled)} tone="pos" />
          </div>
          <p className="small muted">
            Only SETTLED is withdrawable (§3). MATCHED is a soft preconfirmation, not financial
            certainty.
          </p>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="summary__stat">
      <span className="summary__label">{label}</span>
      <span className={`summary__value mono ${tone ?? ""}`}>{value}</span>
    </div>
  );
}
