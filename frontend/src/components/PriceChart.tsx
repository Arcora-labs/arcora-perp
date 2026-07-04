import { useCallback, useEffect, useRef, useState } from "react";
import { useStore } from "../store";
import { formatPrice } from "../domain/format";

/// TradingView-style index-price chart (Celari design): candles/line/area on a
/// canvas with a price/time grid, last-price tag, crosshair + OHLC readout, and
/// working drawing tools (trend line, horizontal line, eraser).
///
/// Data source, two modes:
/// - **Live gateway (`VITE_API_URL` set):** the past bars are REAL —
///   `/v1/markets/:id/candles` serves the OHLC history the engine actually
///   marked against (exchange-backfilled at boot for feed markets), and live
///   ticks keep folding into the forming bar, rolling on timeframe boundaries.
/// - **Mock mode:** no engine history exists, so candles are built client-side:
///   a deterministic backfill (seeded per market+timeframe) ending at the live
///   price. This synthetic path never runs against the real gateway.

export type Candle = { o: number; h: number; l: number; c: number };
type Drawing =
  | { type: "hline"; p: number }
  | { type: "trend"; x1f: number; p1: number; x2f: number; p2: number };
type Tool = "cursor" | "trend" | "hline" | "eraser";
type Geo = {
  plotL: number; plotR: number; plotT: number; plotB: number;
  X: (xf: number) => number; Y: (p: number) => number;
  xf: (x: number) => number; py: (y: number) => number;
};

const TFS = ["1m", "5m", "15m", "1H", "4H", "1D"] as const;
const TF_MIN: Record<string, number> = { "1m": 1, "5m": 5, "15m": 15, "1H": 60, "4H": 240, "1D": 1440 };
/** The gateway's candle API uses lowercase h/d names. */
const TF_API: Record<string, string> = { "1m": "1m", "5m": "5m", "15m": "15m", "1H": "1h", "4H": "4h", "1D": "1d" };
const BARS = 80;

const API = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "");

type WireCandle = { t: number; o: string; h: string; l: string; c: string };
/** Map the gateway's 1e8-scaled string candles to chart numbers. Exported for tests. */
export function mapWireCandles(rows: WireCandle[]): Candle[] {
  return rows.map((r) => ({
    o: Number(r.o) / 1e8,
    h: Number(r.h) / 1e8,
    l: Number(r.l) / 1e8,
    c: Number(r.c) / 1e8,
  }));
}

/** mulberry32 — tiny deterministic PRNG so the backfill is stable per (market, tf). */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Backfill BARS candles via a seeded random walk that ENDS at `last`. */
function backfill(seed: number, tf: string, last: number): Candle[] {
  if (!Number.isFinite(last) || last <= 0) last = 1;
  const r = rng(seed * 2654435761 + (TF_MIN[tf] || 15) * 40503);
  const vol = last * 0.006 * (1 + (TF_MIN[tf] || 15) / 60); // bigger bars on bigger timeframes
  const closes: number[] = [last];
  for (let i = 0; i < BARS; i++) {
    const prev = closes[closes.length - 1];
    closes.push(Math.max(prev * 0.5, prev + (r() - 0.5) * 2 * vol));
  }
  closes.reverse(); // walk now ends at `last`
  closes[closes.length - 1] = last;
  const candles: Candle[] = [];
  for (let i = 0; i < closes.length - 1; i++) {
    const o = closes[i], c = closes[i + 1];
    const wick = vol * (0.4 + r() * 0.9);
    candles.push({ o, c, h: Math.max(o, c) + wick * r(), l: Math.min(o, c) - wick * r() });
  }
  return candles;
}

function distToSeg(px: number, py: number, x1: number, y1: number, x2: number, y2: number) {
  const A = px - x1, B = py - y1, C = x2 - x1, D = y2 - y1;
  const len = C * C + D * D;
  let t = len ? (A * C + B * D) / len : 0;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * C), py - (y1 + t * D));
}

export function PriceChart() {
  const { state } = useStore();
  const { oracle, selectedMarketId, market } = state;

  const [tf, setTf] = useState<string>("15m");
  const [tool, setTool] = useState<Tool>("cursor");
  const [drawings, setDrawings] = useState<Drawing[]>([]);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const candlesRef = useRef<Candle[]>([]);
  const geoRef = useRef<Geo | null>(null);
  const mouseRef = useRef({ x: 0, y: 0, in: false });
  const draggingRef = useRef(false);
  const draftRef = useRef<Drawing | null>(null);
  const tickRef = useRef(0);
  /// The forming bar's bucket start ms (live mode — mirrors the server's buckets).
  const bucketRef = useRef(0);
  /// Monotonic fetch id so a slow candles response can't clobber a newer one.
  const reqRef = useRef(0);
  const marketRef = useRef(selectedMarketId);
  // `draw` is a stable caller; drawRef.current is refreshed every render so it always
  // closes over the latest drawings/tool/timeframe without re-subscribing effects.
  const drawRef = useRef<() => void>(() => {});
  const draw = useCallback(() => drawRef.current(), []);

  const priceNum = Number(oracle.price) / 1e8;
  const pdec = priceNum >= 1000 ? 2 : priceNum >= 1 ? 3 : 5;
  const fmtN = (n: number) => n.toLocaleString("en-US", { minimumFractionDigits: pdec, maximumFractionDigits: pdec });

  // change % over the visible window (open of first candle → live close)
  const cs0 = candlesRef.current;
  const changePct = cs0.length ? ((priceNum - cs0[0].o) / cs0[0].o) * 100 : 0;
  const up = changePct >= 0;

  // --- canvas draw (ported from the Celari handoff) ----------------------------
  drawRef.current = () => {
    const c = canvasRef.current;
    if (!c || !c.parentElement) return;
    const W = c.parentElement.clientWidth, H = c.parentElement.clientHeight;
    if (W < 2 || H < 2) return;
    const dpr = window.devicePixelRatio || 1;
    if (c.width !== Math.round(W * dpr) || c.height !== Math.round(H * dpr)) { c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); }
    let ctx: CanvasRenderingContext2D | null = null;
    try { ctx = c.getContext("2d"); } catch { return; } // no 2d context (e.g. jsdom/happy-dom)
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    const candles = candlesRef.current;
    if (!candles.length) return;
    const plotL = 10, plotR = W - 64, plotT = 10, plotB = H - 22, pw = plotR - plotL, ph = plotB - plotT;
    const maxBars = Math.floor(pw / 7);
    const visN = Math.min(candles.length, Math.max(20, maxBars));
    const vis = candles.slice(candles.length - visN);
    let lo = Infinity, hi = -Infinity;
    for (const k of vis) { if (k.l < lo) lo = k.l; if (k.h > hi) hi = k.h; }
    const pad = (hi - lo) * 0.08 || hi * 0.01; lo -= pad; hi += pad;
    const span = hi - lo || 1;
    const cw = pw / visN;
    const Xi = (i: number) => plotL + i * cw + cw / 2;
    const Y = (p: number) => plotT + (1 - (p - lo) / span) * ph;
    const Xf = (f: number) => plotL + f * pw;
    const xf = (x: number) => (x - plotL) / pw;
    const py = (y: number) => lo + (1 - (y - plotT) / ph) * span;
    geoRef.current = { plotL, plotR, plotT, plotB, X: Xf, Y, xf, py };

    ctx.font = '10px "JetBrains Mono", ui-monospace, monospace';
    ctx.textBaseline = "middle";
    const steps = 5;
    for (let i = 0; i <= steps; i++) {
      const p = lo + (span * i) / steps, y = Y(p);
      ctx.strokeStyle = "rgba(255,255,255,0.045)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(plotL, y); ctx.lineTo(plotR, y); ctx.stroke();
      ctx.fillStyle = "#8E9299"; ctx.textAlign = "left"; ctx.fillText(fmtN(p), plotR + 7, y);
    }
    const tfMin = TF_MIN[tf] || 15;
    const tl = 6; ctx.textAlign = "center";
    for (let i = 0; i <= tl; i++) {
      const idx = Math.floor((visN * i) / tl), x = plotL + idx * cw;
      ctx.strokeStyle = "rgba(255,255,255,0.035)";
      ctx.beginPath(); ctx.moveTo(x, plotT); ctx.lineTo(x, plotB); ctx.stroke();
      if (i > 0 && i < tl) {
        const d = new Date(Date.now() - (visN - idx) * tfMin * 60000);
        ctx.fillStyle = "#5b5f6b";
        ctx.fillText(String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0"), x, plotB + 12);
      }
    }
    const upc = "#34d399", dnc = "#fb7185", bw = Math.max(1, Math.min(cw * 0.62, 13));
    vis.forEach((k, i) => {
      const x = Xi(i), col = k.c >= k.o ? upc : dnc;
      ctx.strokeStyle = col; ctx.fillStyle = col; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x, Y(k.h)); ctx.lineTo(x, Y(k.l)); ctx.stroke();
      const yo = Y(k.o), yc = Y(k.c), top = Math.min(yo, yc);
      ctx.fillRect(x - bw / 2, top, bw, Math.max(1, Math.abs(yc - yo)));
    });

    const last = vis[vis.length - 1].c, ly = Y(last);
    ctx.save(); ctx.strokeStyle = "#b0c4ff"; ctx.setLineDash([3, 3]); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(plotL, ly); ctx.lineTo(plotR, ly); ctx.stroke(); ctx.restore();
    ctx.fillStyle = "#b0c4ff"; ctx.fillRect(plotR, ly - 8, 62, 16);
    ctx.fillStyle = "#0a0a0b"; ctx.textAlign = "left"; ctx.fillText(fmtN(last), plotR + 5, ly);
    const lx = Xi(visN - 1), aa = 0.5 + 0.5 * Math.cos(((Date.now() % 1600) / 1600) * Math.PI * 2);
    ctx.fillStyle = "rgba(176,196,255," + 0.22 * aa + ")";
    ctx.beginPath(); ctx.arc(lx, ly, 4 + 5 * (1 - aa), 0, 7); ctx.fill();
    ctx.fillStyle = "#b0c4ff"; ctx.beginPath(); ctx.arc(lx, ly, 3, 0, 7); ctx.fill();

    const all: Drawing[] = [...drawings];
    if (draftRef.current) all.push(draftRef.current);
    all.forEach((d) => {
      if (d.type === "hline") {
        const y = Y(d.p);
        ctx.save(); ctx.strokeStyle = "rgba(176,196,255,0.65)"; ctx.setLineDash([5, 3]); ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.moveTo(plotL, y); ctx.lineTo(plotR, y); ctx.stroke(); ctx.restore();
        ctx.fillStyle = "rgba(176,196,255,0.16)"; ctx.fillRect(plotR, y - 8, 62, 16);
        ctx.fillStyle = "#b0c4ff"; ctx.fillText(fmtN(d.p), plotR + 5, y);
      } else {
        const x1 = Xf(d.x1f), y1 = Y(d.p1), x2 = Xf(d.x2f), y2 = Y(d.p2);
        ctx.strokeStyle = "#b0c4ff"; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
        ctx.fillStyle = "#b0c4ff";
        [[x1, y1], [x2, y2]].forEach((pt) => { ctx.beginPath(); ctx.arc(pt[0], pt[1], 2.6, 0, 7); ctx.fill(); });
      }
    });

    const ms = mouseRef.current;
    if (ms.in && ms.x >= plotL && ms.x <= plotR && ms.y >= plotT && ms.y <= plotB) {
      ctx.save(); ctx.strokeStyle = "rgba(255,255,255,0.22)"; ctx.setLineDash([4, 4]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(ms.x, plotT); ctx.lineTo(ms.x, plotB); ctx.moveTo(plotL, ms.y); ctx.lineTo(plotR, ms.y); ctx.stroke(); ctx.restore();
      ctx.fillStyle = "#27272a"; ctx.fillRect(plotR, ms.y - 8, 62, 16);
      ctx.fillStyle = "#fff"; ctx.textAlign = "left"; ctx.fillText(fmtN(py(ms.y)), plotR + 5, ms.y);
      const bi = Math.max(0, Math.min(visN - 1, Math.floor((ms.x - plotL) / cw))), k = vis[bi];
      if (k) {
        const tip = `O ${fmtN(k.o)}  H ${fmtN(k.h)}  L ${fmtN(k.l)}  C ${fmtN(k.c)}`;
        const twd = ctx.measureText(tip).width + 12;
        ctx.fillStyle = "rgba(17,17,19,0.92)"; ctx.fillRect(plotL, plotT, twd, 17);
        ctx.fillStyle = "#8E9299"; ctx.fillText(tip, plotL + 6, plotT + 8.5);
      }
    }
  };

  // history on market / timeframe change: REAL bars from the gateway when live,
  // the deterministic synthetic walk only in mock mode
  useEffect(() => {
    marketRef.current = selectedMarketId;
    tickRef.current = 0;
    if (!API) {
      candlesRef.current = backfill(selectedMarketId, tf, Number(oracle.price) / 1e8);
      draw();
      return;
    }
    candlesRef.current = [];
    bucketRef.current = 0;
    draw();
    const req = ++reqRef.current;
    fetch(`${API}/v1/markets/${selectedMarketId}/candles?tf=${TF_API[tf] || "15m"}&limit=${BARS + 40}`)
      .then((r) => r.json())
      .then((j: { candles?: WireCandle[] }) => {
        // ignore a stale response after the user already switched market/tf
        if (req !== reqRef.current) return;
        const rows = j.candles ?? [];
        candlesRef.current = mapWireCandles(rows);
        if (rows.length) bucketRef.current = rows[rows.length - 1].t;
        draw();
      })
      .catch(() => { /* unreachable endpoint → the chart fills from live ticks */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedMarketId, tf]);

  // live tick → fold into the forming candle; roll on the timeframe boundary
  // (live mode, matching the server's buckets) or every few ticks (mock mode)
  useEffect(() => {
    if (!Number.isFinite(priceNum) || priceNum <= 0) return;
    const cs = candlesRef.current;
    if (API) {
      const tfMs = (TF_MIN[tf] || 15) * 60000;
      const bucket = Date.now() - (Date.now() % tfMs);
      if (!cs.length || bucket > bucketRef.current) {
        bucketRef.current = bucket;
        cs.push({ o: priceNum, h: priceNum, l: priceNum, c: priceNum });
        if (cs.length > BARS + 40) cs.shift();
      } else {
        const last = cs[cs.length - 1];
        last.c = priceNum; last.h = Math.max(last.h, priceNum); last.l = Math.min(last.l, priceNum);
      }
      draw();
      return;
    }
    if (!cs.length) return;
    const last = cs[cs.length - 1];
    last.c = priceNum; last.h = Math.max(last.h, priceNum); last.l = Math.min(last.l, priceNum);
    tickRef.current++;
    if (tickRef.current % 6 === 0) { cs.push({ o: priceNum, h: priceNum, l: priceNum, c: priceNum }); if (cs.length > BARS + 20) cs.shift(); }
    draw();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [oracle.price]);

  // redraw when drawings/tool change
  useEffect(() => { draw(); }, [drawings, tool, draw]);

  // resize + a slow pulse loop (keeps the last-price beacon alive between ticks)
  useEffect(() => {
    draw();
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => draw()) : null;
    const wrap = canvasRef.current?.parentElement;
    if (ro && wrap) ro.observe(wrap);
    const id = window.setInterval(() => draw(), 140);
    return () => { if (ro) ro.disconnect(); window.clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const xy = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };
  const onMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const p = xy(e); mouseRef.current = { x: p.x, y: p.y, in: true };
    const g = geoRef.current;
    if (draggingRef.current && draftRef.current?.type === "trend" && g) {
      draftRef.current.x2f = g.xf(p.x); draftRef.current.p2 = g.py(p.y);
    }
    draw();
  };
  const onDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const p = xy(e); const g = geoRef.current; if (!g) return;
    if (tool === "trend") { draggingRef.current = true; draftRef.current = { type: "trend", x1f: g.xf(p.x), p1: g.py(p.y), x2f: g.xf(p.x), p2: g.py(p.y) }; }
    else if (tool === "hline") { setDrawings((d) => [...d, { type: "hline", p: g.py(p.y) }]); }
    else if (tool === "eraser") {
      let best = -1, bd = 9;
      drawings.forEach((d, i) => {
        const dist = d.type === "hline" ? Math.abs(g.Y(d.p) - p.y) : distToSeg(p.x, p.y, g.X(d.x1f), g.Y(d.p1), g.X(d.x2f), g.Y(d.p2));
        if (dist < bd) { bd = dist; best = i; }
      });
      if (best >= 0) setDrawings((d) => d.filter((_, i) => i !== best));
    }
  };
  const onUp = () => {
    if (draggingRef.current && draftRef.current?.type === "trend") {
      const d = draftRef.current;
      if (Math.abs(d.x2f - d.x1f) > 0.008 || Math.abs(d.p2 - d.p1) > 1e-9) setDrawings((arr) => [...arr, d]);
    }
    draggingRef.current = false; draftRef.current = null; draw();
  };
  const onLeave = () => { mouseRef.current = { x: 0, y: 0, in: false }; draw(); };

  const hint = tool === "trend" ? "Click-drag on the chart to draw a trend line"
    : tool === "hline" ? "Click on the chart to place a price line"
    : tool === "eraser" ? "Click a drawn line to remove it" : "";

  const tools: { id: Tool; title: string; path: React.ReactNode }[] = [
    { id: "cursor", title: "Cursor", path: <path d="M4 3l7 17 2.2-6.8L20 11z" /> },
    { id: "trend", title: "Trend line", path: <><line x1="4" y1="19" x2="20" y2="5" /><circle cx="4" cy="19" r="1.8" /><circle cx="20" cy="5" r="1.8" /></> },
    { id: "hline", title: "Horizontal line", path: <><line x1="3" y1="12" x2="21" y2="12" /><circle cx="8" cy="12" r="1.6" /></> },
    { id: "eraser", title: "Erase", path: <><path d="M5 14.5 12 7.5l5 5-4.5 4.5H8z" /><line x1="4" y1="20.5" x2="20" y2="20.5" /></> },
  ];

  return (
    <div className="card">
      <div className="chart__head">
        <div className="chart__id">
          <span className="chart__sym">{market.symbol}</span>
          <span className={`chart__price ${up ? "pos" : "neg"}`}>{formatPrice(oracle.price)}</span>
          <span className={`chart__delta ${up ? "pos" : "neg"}`}>{up ? "+" : ""}{changePct.toFixed(2)}%</span>
        </div>
        <div className="chart__tools">
          <div className="chart__tfs">
            {TFS.map((t) => (
              <button key={t} className={`chart__tf ${tf === t ? "is-active" : ""}`} onClick={() => setTf(t)}>{t}</button>
            ))}
          </div>
          <div className="chart__draws">
            {tools.map((t) => (
              <button key={t.id} className={`chart__draw ${tool === t.id ? "is-active" : ""}`} title={t.title} aria-label={t.title} onClick={() => setTool(t.id)}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">{t.path}</svg>
              </button>
            ))}
          </div>
          <button className="chart__tf" onClick={() => setDrawings([])}>Clear</button>
        </div>
      </div>
      <div className="chart__wrap">
        <canvas
          ref={canvasRef}
          className="chart__canvas"
          onMouseMove={onMove}
          onMouseDown={onDown}
          onMouseUp={onUp}
          onMouseLeave={onLeave}
        />
      </div>
      <div className="chart__foot">
        <span className="chart__hint">{hint}</span>
        <span>DARK BOOK · INDEX PRICE</span>
      </div>
    </div>
  );
}
