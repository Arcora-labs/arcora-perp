import { useState, type ReactNode } from "react";
import { StoreProvider } from "./store";
import { DocumentTitle } from "./components/DocumentTitle";
import { ModeBanner } from "./components/ModeBanner";
import { StatsBar } from "./components/StatsBar";
import { OrderTicket } from "./components/OrderTicket";
import { OrderBook } from "./components/OrderBook";
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
import { Explorer } from "./components/Explorer";
import { HealthPanel } from "./components/HealthPanel";

type Tab = "trade" | "lp" | "account" | "recover" | "explorer" | "health" | "api";

const TAB_LABEL: Record<Tab, string> = {
  trade: "Trade",
  lp: "LP Pool",
  account: "Account",
  recover: "Recover",
  explorer: "Explorer",
  health: "Health",
  api: "API",
};

/** Lucide-style line icons (24×24, 1.75 stroke, currentColor) — the design's icon system. */
const ICON: Record<Tab, ReactNode> = {
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

const TABS: Tab[] = ["trade", "lp", "account", "recover", "explorer", "health", "api"];

export default function App() {
  const [tab, setTab] = useState<Tab>("trade");
  return (
    <StoreProvider>
      <DocumentTitle />
      <div className="app">
        <aside className="sidebar">
          <div className="sidebar__brand">
            <span className="sidebar__logo" aria-hidden>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2.4 20.3 7v10L12 21.6 3.7 17V7z" />
                <path d="M12 8.5v7" />
                <rect x="9.6" y="10.2" width="4.8" height="3.6" fill="currentColor" stroke="none" />
              </svg>
            </span>
            <span className="sidebar__wordmark">
              <span className="sidebar__name">CELARI</span>
              <span className="sidebar__sub">Perp · Dark CLOB</span>
            </span>
          </div>

          <div className="sidebar__scroll">
            <p className="sidebar__section">Markets</p>
            <MarketSelector />
          </div>

          <div className="sidebar__foot">
            <div className="card netcard">
              <div className="netcard__row">
                <span className="netcard__label">Network</span>
                <span className="netcard__live"><span className="dot dot--live" /> LIVE</span>
              </div>
              <p className="netcard__net">Base Sepolia</p>
              <p className="netcard__hint">SETTLES → ETHEREUM L1</p>
            </div>
          </div>
        </aside>

        <div className="content">
          <header className="app__header">
            <nav className="topnav" aria-label="Primary">
              {TABS.map((t) => (
                <button
                  key={t}
                  className={`navlink ${tab === t ? "is-active" : ""}`}
                  aria-current={tab === t ? "page" : undefined}
                  onClick={() => setTab(t)}
                >
                  {ICON[t]}
                  {TAB_LABEL[t]}
                </button>
              ))}
            </nav>
            <div className="app__wallet">
              <span className="app__net"><span className="dot dot--live" /> Testnet · {import.meta.env.VITE_API_URL ? "Live engine" : "Mock"}</span>
              <button className="wallet-btn"><span className="dot dot--live" /> 0x7Cf4…A29B</button>
            </div>
          </header>

          <Toaster />

          <main className="app__main">
            {tab === "trade" && (
              <>
                <StatsBar />
                <ModeBanner />
                <section className="grid grid--trade">
                  <div className="col--chart"><PriceChart /></div>
                  <div className="col--book"><OrderBook /></div>
                  <div className="col--tables">
                    <PositionsOrders />
                  </div>
                  <div className="col--ticket">
                    <OrderTicket />
                    <FinalityLegend />
                    <ActivityFeed />
                  </div>
                </section>
              </>
            )}

            {tab === "account" && (
              <>
                <AccountSummary />
                <section className="grid grid--two">
                  <AccountPanel />
                  <PositionsTable />
                </section>
              </>
            )}

            {tab === "recover" && (
              <section className="grid grid--single">
                <RecoveryPanel />
              </section>
            )}

            {tab === "explorer" && (
              <section className="grid grid--single" style={{ gridTemplateColumns: "minmax(0, 1fr)" }}>
                <Explorer />
              </section>
            )}

            {tab === "health" && (
              <section className="grid grid--single">
                <HealthPanel />
              </section>
            )}

            {tab === "lp" && (
              <section className="grid grid--single">
                <LpVault />
              </section>
            )}

            {tab === "api" && (
              <section className="grid grid--single">
                <ApiAccess />
              </section>
            )}

            <footer className="app__footer">
              dark-perp · live engine settling on Base Sepolia · trade via the browser or the
              external <code>/v1</code> API.
            </footer>
          </main>
        </div>
      </div>
    </StoreProvider>
  );
}
