import { useState } from "react";
import { API_BASE } from "../api/apiBase";

/// Live gateway base URL (same-origin in production). Undefined in mock mode → key
/// creation is disabled with a hint.
const API = API_BASE;

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn btn--tiny"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1200);
      }}
    >
      {done ? "copied" : "copy"}
    </button>
  );
}

/// API access tab: the place a user comes to **get credentials** for the external
/// REST + WebSocket API. There is deliberately NO in-browser order form here —
/// integrations send orders from their own code. This page mints an API key against
/// the live gateway and shows how to authenticate + call it.
export function ApiAccess() {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [owner, setOwner] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function createKey() {
    if (!API) {
      setErr("No live gateway configured (VITE_API_URL is unset — mock mode).");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(`${API}/v1/accounts`, { method: "POST" });
      if (!res.ok) throw new Error(`gateway returned ${res.status}`);
      const d = await res.json();
      setApiKey(d.apiKey);
      setOwner(d.owner);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const base = API ?? "https://<gateway>";
  const key = apiKey ?? "0x<your-api-key>";

  return (
    <div className="grid grid--two">
      <div className="col">
        <div className="card">
          <h3 className="card__title">External trading API</h3>
          <p className="small muted">
            Trade and read market data programmatically — no browser. Market-makers, bots, and
            integrations hit the <strong>same shared engine</strong>; each account is isolated by a
            secret API key. Orders are sent from <strong>your own code</strong>, never from here.
          </p>
          <button className="btn btn--accent" onClick={createKey} disabled={busy}>
            {busy ? "Creating…" : apiKey ? "Create another key" : "Create API key"}
          </button>
          {err && <p className="small neg">{err}</p>}
          {apiKey && (
            <div className="apikey">
              <div className="apikey__row">
                <span className="apikey__label">API key</span>
                <span className="mono apikey__val">{apiKey}</span>
                <Copy text={apiKey} />
              </div>
              <div className="apikey__row">
                <span className="apikey__label">Owner</span>
                <span className="mono apikey__val">{owner}</span>
              </div>
              <p className="small neg" style={{ marginTop: 8 }}>
                ⚠ Save this key now — it authenticates every request and is not stored or shown again.
              </p>
            </div>
          )}
        </div>

        <div className="card">
          <h3 className="card__title">Authenticate</h3>
          <p className="small muted">
            Send your key in the <code>X-Api-Key</code> header on every authenticated request:
          </p>
          <pre className="code">X-Api-Key: {key}</pre>
          <p className="small muted">
            Base URL <span className="mono">{base}</span>
            {API && (
              <>
                {" · "}
                <a className="pos" href={`${base}/v1/openapi.json`} target="_blank" rel="noreferrer">
                  OpenAPI 3.1 spec ↗
                </a>
              </>
            )}
          </p>
        </div>
      </div>

      <div className="col">
        <div className="card">
          <h3 className="card__title">Use it (curl)</h3>
          <pre className="code">{`# place a market order
curl -s -XPOST ${base}/v1/orders \\
  -H "X-Api-Key: ${key}" \\
  -d '{"marketId":0,"side":"Buy","size":"10000000",
       "limitPrice":"0","tif":"Ioc","reduceOnly":false}'

# your account (balance + positions)
curl -s ${base}/v1/accounts/me -H "X-Api-Key: ${key}"

# your orders + finality
curl -s ${base}/v1/orders -H "X-Api-Key: ${key}"

# public market data (no auth)
curl -s ${base}/v1/markets/0/orderbook`}</pre>
        </div>

        <div className="card">
          <h3 className="card__title">Live stream (WebSocket)</h3>
          <pre className="code">{`# public market data + (after auth) your own fills/finality
wscat -c ${base.replace(/^http/, "ws")}/v1/ws
> {"type":"auth","apiKey":"${key}"}`}</pre>
          <p className="small muted">
            Amounts are decimal strings of scaled integers (USDC ×1e6, size/price ×1e8). On-chain
            USDC deposit/withdraw and caller-signed orders are in the OpenAPI spec.
          </p>
        </div>
      </div>
    </div>
  );
}
