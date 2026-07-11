import { useState } from "react";
import { IS_LIVE } from "../api/apiBase";
import { shortHash } from "../domain/format";
import { connect, disconnectWallet, hasInjected, useWalletAddress } from "../api/wallet";

/// The header wallet control. Replaces a hard-coded placeholder address: it now
/// reflects the REAL injected-wallet connection state (shared across the app via
/// `useWalletAddress`), so connecting here also drives the deposit/claim flows in
/// AccountPanel, and vice-versa.
///
/// In mock mode (no live gateway) there is no on-chain wallet to connect, so the
/// control renders nothing — the "Testnet · Mock" label beside it already conveys
/// the mode.
export function WalletButton() {
  const address = useWalletAddress();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!IS_LIVE) return null;

  if (address) {
    return (
      <button
        className="wallet-btn"
        title="Connected — click to disconnect"
        onClick={() => disconnectWallet()}
      >
        <span className="dot dot--live" /> {shortHash(address)}
      </button>
    );
  }

  if (!hasInjected()) {
    return (
      <a
        className="wallet-btn"
        href="https://metamask.io/download/"
        target="_blank"
        rel="noreferrer"
        title="No browser wallet detected"
      >
        <span className="dot" /> No wallet
      </a>
    );
  }

  const onConnect = async () => {
    setErr(null);
    setBusy(true);
    try {
      await connect();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <button className="wallet-btn" onClick={onConnect} disabled={busy} title={err ?? undefined}>
      <span className="dot" /> {busy ? "Connecting…" : "Connect wallet"}
    </button>
  );
}
