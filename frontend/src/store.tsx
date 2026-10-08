import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { ClientState, DarkPerpClient } from "./api/client";
import { MockDarkPerpClient } from "./api/mockClient";
import { RealDarkPerpClient } from "./api/realClient";
import { IS_LIVE, API_BASE } from "./api/apiBase";

interface Store {
  client: DarkPerpClient;
  state: ClientState;
  /// Transient UI signal: a price the order book wants the ticket to adopt as its
  /// limit price (click-to-price). The ticket consumes and clears it. `null` = none.
  prefillPrice: bigint | null;
  setPrefillPrice: (p: bigint | null) => void;
}

const Ctx = createContext<Store | null>(null);

/// Pick the backend: with VITE_API_URL set, talk to the real `gateway` (Rust engine
/// over HTTP + WebSocket); otherwise run the in-browser mock. Same interface either way.
export function StoreProvider({ children }: { children: ReactNode }) {
  if (IS_LIVE && API_BASE) return <RealStoreProvider url={API_BASE}>{children}</RealStoreProvider>;
  return <MockStoreProvider>{children}</MockStoreProvider>;
}

function MockStoreProvider({ children }: { children: ReactNode }) {
  const client = useMemo(() => new MockDarkPerpClient(), []);
  const [state, setState] = useState<ClientState>(() => client.getState());
  const [prefillPrice, setPrefillPrice] = useState<bigint | null>(null);
  useEffect(() => client.subscribe(setState), [client]);
  return <Ctx.Provider value={{ client, state, prefillPrice, setPrefillPrice }}>{children}</Ctx.Provider>;
}

/// Connects to the gateway: bootstraps the initial snapshot over HTTP, then lives on
/// the WebSocket push stream. Shows a connecting / error surface until the first state
/// arrives so the rest of the UI never sees a null state.
function RealStoreProvider({ url, children }: { url: string; children: ReactNode }) {
  const [client, setClient] = useState<DarkPerpClient | null>(null);
  const [state, setState] = useState<ClientState | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [prefillPrice, setPrefillPrice] = useState<bigint | null>(null);

  useEffect(() => {
    setErr(null);
    let unsub = () => {};
    let alive = true;
    RealDarkPerpClient.bootstrap(url)
      .then((c) => {
        if (!alive) return;
        setClient(c);
        setState(c.getState());
        unsub = c.subscribe(setState);
      })
      .catch((e) => alive && setErr(e instanceof Error ? e.message : String(e)));
    return () => { alive = false; unsub(); };
  }, [url, attempt]);

  if (err) {
    return (
      <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
        <div className="card" style={{ maxWidth: 480, textAlign: "center" }}>
          <h3 className="card__title">Gateway unreachable</h3>
          <p className="muted small" style={{ margin: 0 }}>
            We could not connect to the trading gateway. Check your connection and try again.
          </p>
          <button className="btn btn--buy" style={{ marginTop: 20 }} onClick={() => setAttempt(n => n + 1)}>Try again</button>
          <a href="/" className="navlink">Back to Arcora</a>
        </div>
      </div>
    );
  }
  if (!client || !state) {
    return (
      <div style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <span className="muted mono">Connecting to gateway…</span>
      </div>
    );
  }
  return <Ctx.Provider value={{ client, state, prefillPrice, setPrefillPrice }}>{children}</Ctx.Provider>;
}

export function useStore(): Store {
  const s = useContext(Ctx);
  if (!s) throw new Error("useStore must be used within StoreProvider");
  return s;
}
