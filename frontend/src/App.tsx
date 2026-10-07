import { useEffect, useState, type ReactNode } from "react";
import { StoreProvider, useStore } from "./store";
import { IS_LIVE } from "./api/apiBase";
import { DocumentTitle } from "./components/DocumentTitle";
import { ModeBanner } from "./components/ModeBanner";
import { StatsBar } from "./components/StatsBar";
import { OrderTicket } from "./components/OrderTicket";
import { MarketPulse } from "./components/MarketPulse";
import { Markets, MarketSearch } from "./components/Markets";
import { PositionsOrders, PositionsTable } from "./components/Tables";
import { AccountPanel, AccountSummary } from "./components/AccountPanel";
import { RecoveryPanel } from "./components/RecoveryPanel";
import { FinalityLegend } from "./components/FinalityTracker";
import { Toaster } from "./components/Toaster";
import { MarketSelector } from "./components/MarketSelector";
import { PriceChart } from "./components/PriceChart";
import { ActivityFeed } from "./components/ActivityFeed";
import { ApiAccess } from "./components/ApiAccess";
import { LpVault } from "./components/LpVault";
import { WalletButton } from "./components/WalletButton";
import { Explorer } from "./components/Explorer";
import { HealthPanel } from "./components/HealthPanel";
import { TestnetNotice } from "./components/TestnetNotice";

type Tab = "trade" | "markets" | "lp" | "account" | "recover" | "explorer" | "health" | "api";
const TABS: Tab[] = ["trade", "markets", "account", "lp", "explorer", "recover", "health", "api"];
const TAB_LABEL: Record<Tab, string> = { trade: "Trade", markets: "Markets", account: "Portfolio", lp: "Vault", explorer: "Explorer", recover: "Recover", health: "Health", api: "API" };
const PAGE_COPY: Partial<Record<Tab, string>> = {
  markets: "Find your next perspective. Explore the available perpetual markets.",
  account: "Your balances, positions and transfers, in one place.",
  lp: "Follow the pool, its inventory and liquidity.",
  explorer: "Follow batch commitments and settlement evidence.",
  recover: "Restore access with the wallet bound to your account.",
  health: "See the current oracle, gateway and settlement status.",
  api: "Build with Arcora. Account access and integration details.",
};
function readTab(): Tab {
  const value = window.location.hash.replace(/^#\//, "").split("?")[0];
  return TABS.includes(value as Tab) ? value as Tab : "trade";
}
/** Lucide-style line icons (24×24, 1.75 stroke, currentColor) — the design's icon system. */
const ICON: Record<string, ReactNode> = {
  trade: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17" /><polyline points="16 7 22 7 22 13" /></svg>
  ),
  lp: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z" /></svg>
  ),
  account: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12V7H5a2 2 0 0 1 0-4h14v4" /><path d="M3 5v14a2 2 0 0 0 2 2h16v-5" /><path d="M18 12a2 2 0 0 0 0 4h4v-4Z" /></svg>
  ),
  recover: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
  ),
  explorer: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="m12 2 9 5-9 5-9-5 9-5Z" /><path d="m3 12 9 5 9-5" /><path d="m3 17 9 5 9-5" /></svg>
  ),
  health: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>
  ),
  api: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></svg>
  ),
};


export default function App() { return <StoreProvider><Workspace /></StoreProvider>; }
function Workspace() {
  const { state, client } = useStore();
  const [tab, setTab] = useState<Tab>(readTab);
  const [search, setSearch] = useState(false);
  const [menu, setMenu] = useState(false);
  const [panel, setPanel] = useState("chart");
  useEffect(() => {
    const update = () => { setTab(readTab()); setMenu(false); };
    const key = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setSearch(v => !v); } if (e.key === "Escape") setMenu(false); };
    window.addEventListener("hashchange", update); window.addEventListener("keydown", key);
    const wanted = new URLSearchParams(window.location.hash.split("?")[1] ?? window.location.search).get("market");
    const market = state.markets.find(m => m.symbol.split("/")[0] === wanted);
    if (market) client.selectMarket(market.id);
    return () => { window.removeEventListener("hashchange", update); window.removeEventListener("keydown", key); };
  }, [client]);
  function navigate(next: Tab) { setTab(next); setMenu(false); window.location.hash = `/${next}`; }
  return <>
    <DocumentTitle />
    <a className="skip-link" href="#workspace-main" onClick={e => { e.preventDefault(); document.getElementById("workspace-main")?.focus(); }}>Skip to workspace</a>
    <div className="app">
      <aside className={`sidebar ${menu ? "sidebar--open" : ""}`}>
        <a className="sidebar__brand" href="/" aria-label="Arcora home"><img src="/assets/arcora-logo.png" alt="Arcora" /><span className="sr-only">ARCORA</span></a>
        <div className="sidebar__scroll">
          <p className="sidebar__section">Your workspace</p>
          <nav className="workspace-nav" aria-label="Primary">
            {TABS.map(t => <button key={t} className={`navlink ${tab === t ? "is-active" : ""}`} aria-current={tab === t ? "page" : undefined} onClick={() => navigate(t)}>
              {ICON[t] ?? ICON.trade}{TAB_LABEL[t]}
            </button>)}
          </nav>
          <details className="sidebar-markets"><summary>Quick markets</summary><MarketSelector /></details>
        </div>
        <div className="sidebar__foot"><a href="/" className="sidebar-story"><small>A new perspective</small><strong>Less noise.<br />More possibility.</strong><span aria-hidden>↗</span></a>
          <a className="navlink" href="/docs/">Help & documentation ↗</a>
          <div className="network-note"><span className="base-dot" /><span>Base Sepolia<small>Test assets only</small></span></div>
        </div>
      </aside>
      <div className="content">
        <header className="app__header">
          <button className="menu-toggle" aria-label="Toggle navigation" aria-expanded={menu} onClick={() => setMenu(!menu)}>☰</button>
          <a className="mobile-logo" href="/" aria-label="Arcora home"><img src="/assets/arcora-logo.png" alt="Arcora" /></a>
          <button className="market-search" onClick={() => setSearch(true)}><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden><circle cx="10" cy="10" r="6" /><path d="m15 15 5 5" /></svg><span>Find your market</span><kbd>⌘ K</kbd></button>
          <div className="app__wallet"><span className="environment-pill">{IS_LIVE ? "Test gateway" : "Demo account"}</span><span className="app__net"><span className="base-dot" />Base Sepolia</span><WalletButton /></div>
        </header>
        <Toaster />
        <main className="app__main" id="workspace-main" tabIndex={-1}>
          {IS_LIVE ? <TestnetNotice /> : <div className="banner demo-notice" role="note"><strong>Browser demo · no real funds</strong><span>Balances, orders and settlement are simulated. No wallet signatures or on-chain transactions.</span></div>}
          {state.mode === "CloseOnly" && <ModeBanner />}
          {tab !== "trade" && <div className="page-heading"><h1>{TAB_LABEL[tab]}</h1><p>{PAGE_COPY[tab]}</p></div>}
          <div hidden={tab !== "trade"} className="trade-workspace">
            <StatsBar onSelect={() => setSearch(true)} />
            <div className="mobile-panels" role="group" aria-label="Trading panels">{["chart", "trade", "activity"].map(p => <button key={p} aria-pressed={panel === p} onClick={() => setPanel(p)}>{p[0].toUpperCase() + p.slice(1)}</button>)}</div>
            <section className={`grid grid--trade mobile-panel--${panel}`}>
              <div className="col--chart"><PriceChart /></div>
              <div className="col--book"><MarketPulse /></div>
              <div className="col--ticket"><OrderTicket /></div>
              <div className="col--finality"><FinalityLegend /></div>
              <div className="col--tables"><PositionsOrders /></div>
              <div className="col--activity"><ActivityFeed /></div>
            </section>
            {state.mode !== "CloseOnly" && <details className="system-controls"><summary>System status & demo controls</summary><ModeBanner /></details>}
          </div>
          {tab === "markets" && <section className="card"><Markets onSelect={() => navigate("trade")} /></section>}
          {tab === "account" && <><AccountSummary /><section className="grid grid--two"><AccountPanel /><PositionsTable /></section></>}
          {tab === "recover" && <section className="grid grid--single"><RecoveryPanel /></section>}
          {tab === "explorer" && <section className="grid grid--single"><Explorer /></section>}
          {tab === "health" && <section className="grid grid--single"><HealthPanel /></section>}
          {tab === "lp" && <section className="grid grid--single"><LpVault /></section>}
          {tab === "api" && <section className="grid grid--single"><ApiAccess /></section>}
          <footer className="app__footer"><span><span className="status-dot" />Arcora Perp · {IS_LIVE ? "Test gateway" : "Browser demo"} · test assets only.</span><a href="/design-system/">Warm Precision ↗</a></footer>
        </main>
      </div>
    </div>
    {search && <MarketSearch onClose={() => setSearch(false)} />}
  </>;
}
