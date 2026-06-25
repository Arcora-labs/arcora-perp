import { useStore } from "../store";

/// Surfaces the system mode. Close-only (§6) must be loud — it changes what the
/// user can do (exit only).
export function ModeBanner() {
  const { client, state } = useStore();
  if (state.mode === "CloseOnly") {
    return (
      <div className="banner banner--danger">
        <span>
          <strong>Close-only mode.</strong> The sequencer is unavailable or a breaker
          tripped — you can reduce/close and withdraw against the last settled state, but
          cannot open or increase (§6).
        </span>
        <button
          className="btn btn--tiny"
          onClick={() => client.resumeNormal()}
          title="Simulate the breaker clearing / sequencer recovering"
        >
          Resume normal
        </button>
      </div>
    );
  }
  return (
    <div className="banner banner--ok">
      <span>
        <strong>Normal.</strong> Continuous dark CLOB, operator-blind matching.
      </span>
      <button className="btn btn--tiny" onClick={() => client.triggerCloseOnly()} title="Simulate liveness failure / circuit breaker">
        Simulate forced exit
      </button>
    </div>
  );
}
