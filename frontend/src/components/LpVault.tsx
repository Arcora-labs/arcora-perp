import { useStore } from "../store";
import { formatUsd } from "../domain/format";

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="summary__stat">
      <span className="summary__label">{label}</span>
      <span className={`summary__value mono ${tone ?? ""}`}>{value}</span>
    </div>
  );
}

/// The LP pool (counterparty) tab: pool stats come live from the snapshot.
///
/// SEC-025-E1 Task 3: the deposit/withdraw actions are GONE. They POSTed the
/// legacy `/api/lp/*` routes, which SEC-025-C removed from the production
/// router (the LP pool credited stakes through an UNBACKED mint — one such
/// credit breaks every later settle), so in production the buttons could only
/// 404; in mock mode they never worked ("mock mode can't move the pool"). A
/// route that 404s is not a fallback — the tab is now read-only and says why,
/// instead of offering a write that cannot succeed anywhere.
export function LpVault() {
  const { state } = useStore();
  const lp = state.lp;

  const nav = Number(lp.navPerShare);
  const sharesDisp = (Number(lp.myShares) / 1e6).toLocaleString(undefined, { maximumFractionDigits: 2 });

  return (
    <div className="grid grid--two">
      <div className="col">
        <div className="card">
          <h3 className="card__title">Liquidity pool — the counterparty</h3>
          <p className="small muted">
            The pool takes the <strong>other side</strong> of every trader, earns the{" "}
            <strong className="pos">house edge</strong> (net trader losses) and bears their net
            gains. Trading fees go to the protocol treasury, not the pool — LPs earn the
            directional edge.
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
            Your value floats with the pool's PnL (NAV × your shares). These figures come from
            the public pool snapshot.
          </p>
        </div>
      </div>

      <div className="col">
        <div className="card">
          <h3 className="card__title">Provide liquidity</h3>
          <p className="small muted">
            LP <strong>staking is not available</strong> in this build. The production gateway
            does not mount an LP staking route: the demo pool credited stakes through an
            unbacked mint — collateral with no on-chain backing, which would break settlement
            (SEC-025-C) — so the deposit/withdraw actions were removed rather than left to
            fail. A backed, on-chain LP vault (ERC-4626) is future work.
          </p>
        </div>
      </div>
    </div>
  );
}
