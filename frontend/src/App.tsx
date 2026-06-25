import { useState } from "react";
import { StoreProvider } from "./store";
import { DocumentTitle } from "./components/DocumentTitle";
import { ModeBanner } from "./components/ModeBanner";
import { StatsBar } from "./components/StatsBar";
import { OrderTicket } from "./components/OrderTicket";
import { OrderBook } from "./components/OrderBook";
import { OrdersTable, PositionsTable } from "./components/Tables";
import { AccountPanel, AccountSummary } from "./components/AccountPanel";
import { RecoveryPanel } from "./components/RecoveryPanel";
import { FinalityLegend } from "./components/FinalityTracker";
import { Toaster } from "./components/Toaster";
import { MarketSelector } from "./components/MarketSelector";
import { PriceChart } from "./components/PriceChart";
import { ActivityFeed } from "./components/ActivityFeed";

type Tab = "trade" | "account" | "recover";

export default function App() {
  const [tab, setTab] = useState<Tab>("trade");
  return (
    <StoreProvider>
      <DocumentTitle />
      <div className="app">
        <header className="app__header">
          <div className="brand">
            <span className="brand__mark" aria-hidden />
            <span className="brand__name">dark-perp</span>
            <span className="brand__tag">fast · dark · trustless</span>
          </div>
          <nav className="app__nav">
            {(["trade", "account", "recover"] as Tab[]).map((t) => (
              <button
                key={t}
                className={`app__navlink ${tab === t ? "is-active" : ""}`}
                aria-current={tab === t ? "page" : undefined}
                onClick={() => setTab(t)}
              >
                {t[0].toUpperCase() + t.slice(1)}
              </button>
            ))}
          </nav>
          <div className="app__wallet">
            <span className="dot dot--live" /> testnet · mock
          </div>
        </header>

        <Toaster />
        <ModeBanner />
        {tab === "trade" && <MarketSelector />}
        <StatsBar />

        <main className="app__main">
          {tab === "trade" && (
            <section className="grid grid--trade">
              <div className="col col--book">
                <PriceChart />
                <OrderBook />
              </div>
              <div className="col col--ticket">
                <OrderTicket />
                <FinalityLegend />
              </div>
              <div className="col col--positions">
                <PositionsTable />
                <OrdersTable />
                <ActivityFeed />
              </div>
            </section>
          )}

          {tab === "account" && (
            <section className="grid grid--two">
              <div className="col">
                <AccountSummary />
                <AccountPanel />
              </div>
              <PositionsTable />
            </section>
          )}

          {tab === "recover" && (
            <section className="grid grid--single">
              <RecoveryPanel />
            </section>
          )}
        </main>

        <footer className="app__footer">
          <span>
            Default UI for dark-perp · backed by a mock client encoding the protocol
            semantics · swap <code>MockDarkPerpClient</code> for the real backend.
          </span>
        </footer>
      </div>
    </StoreProvider>
  );
}
