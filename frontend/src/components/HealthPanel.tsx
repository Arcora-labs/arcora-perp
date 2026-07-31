import { useStore } from "../store";
import { formatPrice, formatSize, formatUsd } from "../domain/format";
import { accountSummary } from "../domain/risk";
import type { SettlementHealth } from "../api/client";

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

/// Exported for tests: the status/detail pair the FIN-001 settle-loop row shows.
export function settlementRowModel(s: SettlementHealth): { status: Status; detail: string } {
  if (s.health === "HEALTHY") return { status: "ok", detail: "settling — breaker closed" };
  if (s.health === "DEGRADED") {
    return { status: "warn", detail: `${s.consecutiveFailures} consecutive settle failures — backing off` };
  }
  const mins =
    s.heldSinceMs === null ? null : Math.max(0, Math.round((Date.now() - s.heldSinceMs) / 60_000));
  const err = s.lastError ? ` — ${s.lastError.slice(0, 80)}` : "";
  return {
    status: "down",
    detail: `HELD${mins !== null ? ` for ${mins}m` : ""}${err} — operator resume required`,
  };
}

/// System health / status dashboard: service liveness, oracle freshness per market,
/// the settlement pipeline (finality throughput), and accounting consistency. Read-only,
/// token-styled — the frontend analog of a status page. Reads the same ClientState, so
/// against a real backend it reflects real service health.
export function HealthPanel() {
  const { client, state } = useStore();
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

  // FIN-001: the settle-loop breaker (null = old gateway / mock → row hidden)
  const settleRow = state.settlement ? settlementRowModel(state.settlement) : null;

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
          {settleRow && (
            <StatusRow label="L1 settle loop (FIN-001)" status={settleRow.status} detail={settleRow.detail} />
          )}
          <StatusRow
            label="System mode (§6)"
            status={modeStatus}
            detail={state.mode === "CloseOnly" ? "CLOSE-ONLY — exit only" : "Normal — full trading"}
          />
          {/* SEC-025-E1 fix-wave-2 G2: over the unavailable-account PLACEHOLDER
              the invariants hold vacuously (`noNegativeMargin` over [] is true)
              — "solvent ✓" would report consistency of data never read. */}
          <StatusRow
            label="Collateral conservation (§4)"
            status={state.accountUnavailable ? "warn" : conserved ? "ok" : "down"}
            detail={state.accountUnavailable ? "account state unreadable — check suspended" : conservationDetail}
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

        <div className="card">
          <h3 className="card__title">Protocol reserve &amp; treasury (§6/§9)</h3>
          <div className="summary">
            <Stat label="Protocol treasury" value={formatUsd(state.treasury)} tone="pos" />
            <Stat label="Insurance fund" value={formatUsd(state.insuranceFund)} tone="pos" />
            {/* SEC-025-E1 review F6: `userAdlClawed` comes off the PUBLIC feed
                — the shared demo wallet's counter, not the caller's. On a live
                gateway the caller's real ADL arrives as /v1/ws `adl` toasts,
                and accumulating those into a real counter is E3 scope — until
                then this stat renders only where the demo wallet IS the
                caller's account (the mock; `simulateAdl` is the established
                live/demo discriminator). */}
            {typeof client.simulateAdl === "function" && (
              <Stat
                label="Your ADL haircuts"
                value={formatUsd(state.userAdlClawed)}
                tone={state.userAdlClawed > 0n ? "neg" : undefined}
              />
            )}
          </div>
          <p className="small muted">
            Every fill on {state.market.symbol} charges a {fmtBps(state.market.takerFeeBps)} taker
            fee: the bulk accrues to the <strong className="pos">protocol treasury</strong> (operator
            revenue), and a thin slice funds the <strong>insurance fund</strong> — the bad-debt
            backstop that absorbs a liquidation shortfall before any auto-deleverage and socializes
            only once empty (audit Q3/Q7). The treasury is the final backstop after insurance + ADL.
          </p>
        </div>

        <div className="card">
          <h3 className="card__title">Market-maker hedge (§9, audit Q5)</h3>
          {state.mmHedge.length === 0 ? (
            <p className="small muted">The market-maker is flat — no inventory to hedge.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Market</th>
                  <th>MM inventory</th>
                  <th>Hedge target</th>
                  <th>Notional</th>
                </tr>
              </thead>
              <tbody>
                {state.mmHedge.map((h) => (
                  <tr key={h.marketId}>
                    <td>{h.symbol}</td>
                    <td className="num mono">{formatSize(h.inventory)}</td>
                    <td className={`num mono ${h.hedgeTarget >= 0n ? "pos" : "neg"}`}>
                      {h.hedgeTarget > 0n ? "+" : ""}
                      {formatSize(h.hedgeTarget)}
                    </td>
                    <td className="num mono">{formatUsd(h.notional)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="small muted">
            The protocol emits the maker's net inventory; a delta-neutral keeper takes the
            hedge target on an external venue (CEX/DEX) to flatten directional risk. The
            protocol never custodies or routes the hedge — venue-agnostic by design (audit Q5).
          </p>
        </div>

        {state.l1 && (
          <div className="card">
            <h3 className="card__title">L1 settlement — Base Sepolia (§3)</h3>
            <div className="summary">
              <Stat label="Batches settled on-chain" value={String(state.l1.batchCount)} tone="pos" />
              <Stat label="Sequencer bond" value={`${(Number(state.l1.bondUsdc) / 1e6).toFixed(2)} USDC`} />
            </div>
            <p className="small muted">
              Settled state root{" "}
              <span className="mono">
                {state.l1.settledRoot.slice(0, 10)}…{state.l1.settledRoot.slice(-6)}
              </span>{" "}
              advanced on-chain via <code>settleBatch</code>, gated on a USDC bond scaled to vault
              TVL (audit Q1).{" "}
              <a
                className="pos"
                href={`https://sepolia.basescan.org/tx/${state.l1.lastTx}`}
                target="_blank"
                rel="noreferrer"
              >
                latest tx ↗
              </a>
              {state.l1.withdrawalsRoot && !/^0x0+$/.test(state.l1.withdrawalsRoot) && (
                <>
                  {" "}
                  Withdrawals root{" "}
                  <span className="mono">
                    {state.l1.withdrawalsRoot.slice(0, 10)}…{state.l1.withdrawalsRoot.slice(-6)}
                  </span>{" "}
                  is published — users claim <strong className="pos">USDC</strong> from the vault on
                  Base Sepolia.
                </>
              )}
              . Phase 0 uses MockZkVerifier — the real ZK proof replaces it later (§10b).
            </p>
          </div>
        )}

        <div className="card">
          <h3 className="card__title">Enclave attestation (TEE)</h3>
          {state.attestation ? (
            <>
              <div className="summary">
                <Stat label="TCB status" value={state.attestation.tcb} tone="pos" />
                <Stat label="Quote version" value={`TD1.${state.attestation.quoteVersion === 5 ? 5 : 0}`} />
              </div>
              <p className="small muted">
                The enclave identity is bound to a <strong className="pos">verified</strong>{" "}
                Azure TDX + vTPM measurement{" "}
                <span className="mono">
                  {state.attestation.measurement.slice(0, 10)}…{state.attestation.measurement.slice(-6)}
                </span>{" "}
                (DCAP quote + measured-boot PCRs checked offline). Key release is bound to this
                measurement (#4/#5). A live confidential-VM run needs the Azure TDX quota.
              </p>
            </>
          ) : (
            <p className="small muted">
              Running with a <strong className="neg">stub</strong> enclave (no attestation
              configured). Set <code>ATTESTATION_DIR</code> to a captured/live Azure TDX quote to
              bind the enclave to a verified measurement.
            </p>
          )}
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

/// basis points → a compact percent string (10 → "0.10%").
function fmtBps(bps: number): string {
  return `${(bps / 100).toFixed(2)}%`;
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  return (
    <div className="summary__stat">
      <span className="summary__label">{label}</span>
      <span className={`summary__value mono ${tone ?? ""}`}>{value}</span>
    </div>
  );
}
