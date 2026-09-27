import { useState } from "react";
import { legacyOwnerHint } from "../api/credentialStore";
import { useStore } from "../store";
import { connect, hasInjected, useWalletAddress } from "../api/wallet";

export function RecoveryPanel() {
  const { client } = useStore();
  const wallet = useWalletAddress();
  const [legacyOwner] = useState(legacyOwnerHint);
  const [owner, setOwner] = useState(() => legacyOwner ?? "");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  // Persistence belongs to the current credential, not the latest attempt.
  // Keep this warning visible during a retry and after a rejected signature.
  const storageNotice = client.credentialStorage === "session"
    ? "Account access is available for this tab only. Browser storage is unavailable. Keep this tab open; after reloading, use wallet recovery again. The old saved key may no longer work."
    : null;
  const [error, setError] = useState<string | null>(null);
  const liveRecovery = client.recoverAccount?.bind(client);

  async function recover() {
    if (!liveRecovery || !/^0x[0-9a-fA-F]{64}$/.test(owner.trim())) return;
    setBusy(true); setError(null); setResult(null);
    try {
      if (!wallet) await connect();
      const r = await liveRecovery(owner.trim());
      setResult(`Account recovered. Credential generation is now #${r.recoveryNonce}.`);
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
    {legacyOwner && <p className="notice">
      Saved legacy account found. Its public owner id is filled in below; the old record is kept.
      Select the wallet previously bound to this account. Signing authorizes access for this gateway deployment only.
      Never enter a private key, seed phrase or old API key here.
    </p>}
    <p className="muted small">If the owner id is missing, find it in your previous account record or account backup.
      The owner id is public and is 32 bytes; a wallet address is only 20 bytes. The connected wallet must be the recovery authorizer.</p>
    <label className="field"><span className="field__label">Account owner id</span>
      <input className="field__input" disabled={busy} value={owner} onChange={e=>setOwner(e.target.value)}
        placeholder="0x… (32 bytes)" autoComplete="off" spellCheck={false}/></label>
    <p className="muted small">Connected wallet: {wallet ?? "not connected"}</p>
    <button className="btn btn--ghost" onClick={recover} disabled={busy || !/^0x[0-9a-fA-F]{64}$/.test(owner.trim()) || !hasInjected()}>
      {busy ? "Authorizing recovery…" : wallet ? "Sign & recover" : "Connect wallet & recover"}
    </button>
    {error && <p className="neg small" role="alert">{error}</p>}
    {(result || storageNotice) && <p className="pos small" role="status">{[result, storageNotice].filter(Boolean).join(" ")}</p>}
  </div>;
}