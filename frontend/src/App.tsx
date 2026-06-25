import { StoreProvider } from "./store";
import { ModeBanner } from "./components/ModeBanner";
import { OrderTicket } from "./components/OrderTicket";
import { OrderBook } from "./components/OrderBook";
import { OrdersTable, PositionsTable } from "./components/Tables";
import { AccountPanel } from "./components/AccountPanel";
import { RecoveryPanel } from "./components/RecoveryPanel";
import { FinalityLegend } from "./components/FinalityTracker";

export default function App() {
  return (
    <StoreProvider>
      <div className="app">
        <header className="app__header">
          <div className="brand">
            <span className="brand__mark" aria-hidden />
            <span className="brand__name">dark-perp</span>
            <span className="brand__tag">fast · dark · trustless</span>
          </div>
          <nav className="app__nav">
            <a className="app__navlink is-active" href="#trade">Trade</a>
            <a className="app__navlink" href="#account">Account</a>
            <a className="app__navlink" href="#recover">Recover</a>
          </nav>
        </header>

        <ModeBanner />

        <main className="app__main">
          <section id="trade" className="grid grid--trade">
            <div className="col col--book">
              <OrderBook />
            </div>
            <div className="col col--ticket">
              <OrderTicket />
              <FinalityLegend />
            </div>
            <div className="col col--positions">
              <PositionsTable />
              <OrdersTable />
            </div>
          </section>

          <section id="account" className="grid grid--two">
            <AccountPanel />
            <div id="recover">
              <RecoveryPanel />
            </div>
          </section>
        </main>

        <footer className="app__footer">
          <span>Skeleton UI — apply the design here. Backed by a mock client encoding protocol semantics.</span>
        </footer>
      </div>
    </StoreProvider>
  );
}
