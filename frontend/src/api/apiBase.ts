/// Resolve the gateway API base URL (HTTP + WebSocket share it).
///
/// In production the SPA and the gateway sit behind one origin — Caddy serves the
/// static build and reverse-proxies `/v1` and `/ws` to the engine — so the deployed
/// build is built with `VITE_API_URL=same-origin` and every request targets
/// `window.location.origin`. The app then works under ANY hostname (the sslip.io
/// fallback, perp.arcoralabs.xyz, a future vanity domain) with no per-domain rebuild.
///
/// Accepted values:
///   - unset / empty         → in-browser mock backend, no live gateway.
///   - "same-origin" or "/"  → the current page origin.
///   - an absolute URL       → that gateway (e.g. http://127.0.0.1:8080 for local dev).
const raw = import.meta.env.VITE_API_URL as string | undefined;

/// Whether a live gateway is configured at all (drives the live-vs-mock switch).
export const IS_LIVE: boolean = raw != null && raw !== "";

/// The gateway origin for HTTP + WS, or `undefined` in mock mode.
export const API_BASE: string | undefined = !IS_LIVE
  ? undefined
  : raw === "same-origin" || raw === "/"
    ? typeof window !== "undefined"
      ? window.location.origin
      : ""
    : (raw as string).replace(/\/$/, "");
