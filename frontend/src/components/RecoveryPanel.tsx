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
    // Review F5: do NOT claim funds stay recoverable after device loss. A
    // claim exists only for a withdrawal that was ALREADY REQUESTED, and
    // requesting one needs this browser's /v1 API key (requestWithdrawal
    // starts with ensureAccount) — lose the browser and no new withdrawal
    // can ever be requested.
    return (
      <div className="card">
        <h3 className="card__title">Recover from seed</h3>
        <p className="muted small">
          Seed-based note recovery is <strong>not available on the live gateway</strong>{" "}
          yet — the archive-scan route exists only in the demo build. Your balance and
          positions live in your per-browser <code>/v1</code> account, and every
          withdrawal <em>request</em> needs that account's browser-held API key:{" "}
          <strong>
            if you lose this browser (or clear its storage), the account&apos;s balance
            and positions are stranded
          </strong>{" "}
          — there is no recovery path yet. Only withdrawals you had{" "}
          <strong>already requested</strong> before the loss remain claimable on-chain
          (the claim is wallet-signed against the published withdrawals root and needs
          no API key). Do not leave more in the account than you are prepared to lose
          with the device.
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
