import { useState } from "react";
import { useStore } from "../store";
import { connect, hasInjected, useWalletAddress } from "../api/wallet";

export function RecoveryPanel() {
  const { client } = useStore();
  const wallet = useWalletAddress();
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const liveRecovery = client.recoverAccount?.bind(client);

  async function recover() {
    if (!liveRecovery || !/^0x[0-9a-fA-F]{64}$/.test(owner.trim())) return;
    setBusy(true); setError(null); setResult(null);
    try {
      if (!wallet) await connect();
      const r = await liveRecovery(owner.trim());
      setResult(r.credentialStorage === "session"
        ? `Account recovered for this tab only (generation #${r.recoveryNonce}). Browser storage is unavailable. Keep this tab open; after reloading, use wallet recovery again. The old saved key may no longer work.`
        : `Account recovered. Credential generation is now #${r.recoveryNonce}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  if (!liveRecovery) {
    return <div className="card"><h3 className="card__title">Account recovery</h3>
      <p className="muted small">Wallet-authorized account recovery is unavailable on this gateway build. Do not create a replacement account if the old account may still hold funds.</p>
    </div>;
  }

  return <div className="card">
    <h3 className="card__title">Recover account access</h3>
    <p className="muted small">
      Lost this browser&apos;s API credential? Enter the account&apos;s 32-byte owner id.
      The gateway returns the account&apos;s current recovery authorizer and nonce; your
      wallet signs a deployment-bound recovery digest. A successful durable rotation
      invalidates the old API key. The result below tells you whether the replacement was saved or is available only in this tab.
    </p>
    <label className="field"><span className="field__label">Account owner id</span>
      <input className="field__input" disabled={busy} value={owner} onChange={e=>setOwner(e.target.value)}
        placeholder="0x… (32 bytes)" autoComplete="off" spellCheck={false}/></label>
    <p className="muted small">Connected wallet: {wallet ?? "not connected"}</p>
    <button className="btn btn--ghost" onClick={recover} disabled={busy || !/^0x[0-9a-fA-F]{64}$/.test(owner.trim()) || !hasInjected()}>
      {busy ? "Authorizing recovery…" : wallet ? "Sign & recover" : "Connect wallet & recover"}
    </button>
    {error && <p className="neg small" role="alert">{error}</p>}
    {result && <p className="pos small" role="status">{result}</p>}
  </div>;
}