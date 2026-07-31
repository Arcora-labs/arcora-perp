import { useState } from "react";
import { useStore } from "../store";
import { formatUsd } from "../domain/format";
import type { RecoveredNote } from "../domain/types";

/// Device-loss recovery (§7): enter your seed, derive a view-key, scan the
/// encrypted note archive, and reconstruct your shielded balance.
///
/// SEC-025-E1 Task 3: `client.recover` is optional — it is a DEMO surface (the
/// legacy `POST /api/recover` route is not mounted in production, so the real
/// client omits the method). Without it this panel says so honestly instead of
/// offering a scan that could only fail.
export function RecoveryPanel() {
  const { client } = useStore();
  const [seed, setSeed] = useState("");
  const [notes, setNotes] = useState<RecoveredNote[] | null>(null);
  const [scanning, setScanning] = useState(false);

  const recover = client.recover?.bind(client);

  if (!recover) {
    return (
      <div className="card">
        <h3 className="card__title">Recover from seed</h3>
        <p className="muted small">
          Seed-based note recovery is <strong>not available on the live gateway</strong>{" "}
          yet — the archive-scan route exists only in the demo build. Your balance and
          positions live in your per-browser <code>/v1</code> account; withdrawals are
          authorized by the wallet address you deposited from (SEC-021), so funds are
          recoverable through the on-chain claim path even without this panel.
        </p>
      </div>
    );
  }

  async function scan() {
    if (seed.trim() === "") return;
    setScanning(true);
    const r = await recover!(seed.trim());
    setNotes(r);
    setScanning(false);
  }

  const recoverable = (notes ?? []).filter((n) => !n.spent).reduce((a, n) => a + n.amount, 0n);

  return (
    <div className="card">
      <h3 className="card__title">Recover from seed</h3>
      <p className="muted small">
        Lost your device? Your seed derives a <strong>view-key</strong> that scans the
        encrypted note archive and rebuilds your position. The view-key can read but
        not spend (§7).
      </p>
      <label className="field">
        <span className="field__label">Recovery seed (any text in this demo)</span>
        <input className="field__input" value={seed} onChange={(e) => setSeed(e.target.value)} placeholder="seed phrase…" />
      </label>
      <button className="btn btn--ghost" onClick={scan} disabled={scanning}>
        {scanning ? "Scanning archive…" : "Scan & recover"}
      </button>

      {notes && (
        <div className="recovery__result">
          <div className="stat">
            <span className="stat__label">Recoverable balance</span>
            <span className="stat__value">{formatUsd(recoverable)}</span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Batch</th>
                <th>Amount</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {notes.map((n, i) => (
                <tr key={i}>
                  <td>#{n.batchId}</td>
                  <td>{formatUsd(n.amount)}</td>
                  <td>{n.spent ? <span className="muted">spent</span> : <span className="pos">recovered</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
