import { useStore } from "../store";

/// Surfaces the system mode. Close-only (§6) must be loud — it changes what the
/// user can do (exit only).
///
/// SEC-025-E1 Task 3: the simulate/resume controls are DEMO features — their
/// client methods are optional and the real client omits them (the legacy
/// `POST /api/mode` / `/api/simulate-adl` routes are not mounted in
/// production, and calling them 404'd silently). Presence-gating keeps the
/// buttons in mock mode and honestly absent in live mode; the mode banner
/// itself always renders (state.mode is real either way).
export function ModeBanner() {
  const { client, state } = useStore();
  if (state.clockAdmission?.paused) {
    return (
      <div className="banner banner--danger" role="status">
        <span><strong>Trading temporarily paused.</strong> A batch is awaiting settlement or recovery.
          New orders, cancellations, collateral changes and withdrawal requests are paused, including position closes.
          Existing on-chain withdrawal claims remain available. No automatic order retry is sent; review your orders before trying again.</span>
      </div>
    );
  }
  if (state.mode === "CloseOnly") {
    return (
      <div className="banner banner--danger">
        <span>
          <strong>Close-only mode.</strong> The sequencer is unavailable or a breaker
          tripped. Opening and increasing positions is blocked. Closing positions and creating
          new withdrawals still require an available gateway and settlement path. Existing
          published withdrawal claims can be claimed directly from the vault.
        </span>
        {client.resumeNormal && (
          <button
            className="btn btn--tiny"
            onClick={() => client.resumeNormal!()}
            title="Simulate the breaker clearing / sequencer recovering"
          >
            Resume normal
          </button>
        )}
      </div>
    );
  }
  return (
    <div className="banner banner--ok">
      <span>
        <strong>Normal.</strong> Trading enabled. Check Health for enclave and settlement evidence.
      </span>
      <span className="banner__actions">
        {client.simulateAdl && (
          <button
            className="btn btn--tiny"
            onClick={() => void client.simulateAdl!()}
            title="Simulate a bad-debt cascade that auto-deleverages your winning position (audit Q2)"
          >
            Simulate ADL
          </button>
        )}
        {client.triggerCloseOnly && (
          <button className="btn btn--tiny" onClick={() => client.triggerCloseOnly!()} title="Simulate liveness failure / circuit breaker">
            Simulate forced exit
          </button>
        )}
      </span>
    </div>
  );
}
