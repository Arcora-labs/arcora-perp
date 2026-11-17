//! Audit 2026-11-16 GA-1 + SM-1, the tick: each tick used to update the
//! execution record of every order row the gateway keeps, and each update
//! searched the whole book for the order, so a tick cost the square of the
//! resting orders under the gateway's single lock. A tick now updates the rows
//! its batch touched (a fill, a rejection, a removal, a newly sealed order, a
//! fill still waiting for its proof) and finds each order by its hash.
use super::*;
use std::cell::Cell;

thread_local! {
    /// Order rows whose execution record a tick updated on this thread.
    static ROW_UPDATES: Cell<u64> = const { Cell::new(0) };
}

/// Count one row update of a tick.
pub(super) fn count_row_update() {
    ROW_UPDATES.with(|n| n.set(n.get() + 1));
}

/// The rows `f` updated in ticks.
fn row_updates(f: impl FnOnce()) -> u64 {
    ROW_UPDATES.with(|n| n.set(0));
    f();
    ROW_UPDATES.with(Cell::get)
}

/// A plaintext order of `size` at `limit` in market 0.
fn order(side: &str, size: i128, limit: i128, tif: &str) -> OrderReq {
    OrderReq {
        market_id: 0,
        side: side.into(),
        size: size.to_string(),
        limit_price: limit.to_string(),
        tif: tif.into(),
        ..Default::default()
    }
}

/// Register an account and credit it $50,000 in market 0.
fn account(gw: &mut Gw) -> [u8; 32] {
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
    key
}

/// Post `req` for `key`, clearing its one-second order window first.
fn post(gw: &mut Gw, key: &[u8; 32], req: &OrderReq) {
    let a = gw.accounts.get_mut(key).unwrap();
    a.last_order_ms = 0;
    a.orders_this_sec = 0;
    gw.account_place_order(key, req).unwrap();
}

/// An exchange where one account rests `wall` bids 10% under the mark, which
/// nothing trades, and another rests a sell at the mark, returned with its price.
fn walled(wall: usize) -> (Gw, [u8; 32], [u8; 32], i128) {
    let mut gw = Gw::boot();
    let px = gw.px_of(0);
    let size = SIZE_SCALE / 100;
    let bidder = account(&mut gw);
    for _ in 0..wall {
        post(&mut gw, &bidder, &order("Buy", size, px * 9 / 10, "Gtc"));
    }
    let maker = account(&mut gw);
    post(&mut gw, &maker, &order("Sell", size, px, "Gtc"));
    gw.tick();
    gw.tick();
    (gw, bidder, maker, px)
}

/// Every row of `key` reads RESTING with nothing filled.
fn all_resting(gw: &Gw, key: &[u8; 32]) -> usize {
    let rows = gw.v1_orders_json(key).unwrap()["orders"]
        .as_array()
        .unwrap()
        .clone();
    for row in &rows {
        assert_eq!(row["execution"]["status"], "RESTING", "{row}");
        assert_eq!(row["execution"]["filledSize"], "0", "{row}");
    }
    rows.len()
}

/// A tick in which nothing happens updates no row, however many orders rest.
#[test]
fn audit_1116_ga1_a_quiet_tick_updates_no_row() {
    for wall in [4, 60] {
        let (mut gw, bidder, _, _) = walled(wall);
        let updated = row_updates(|| {
            gw.tick();
        });
        assert_eq!(updated, 0, "{wall} resting bids");
        assert_eq!(all_resting(&gw, &bidder), wall);
    }
}

/// A tick in which one order crosses the resting sell updates the two rows of
/// that trade, not one row per resting order; the trade and the untouched bids
/// read as before.
#[test]
fn audit_1116_ga1_a_trade_updates_the_rows_it_touched() {
    let mut counts = Vec::new();
    for wall in [4, 60] {
        let (mut gw, bidder, maker, px) = walled(wall);
        let taker = account(&mut gw);
        post(&mut gw, &taker, &order("Buy", SIZE_SCALE / 100, px, "Gtc"));
        let mut events = Vec::new();
        let updated = row_updates(|| events = gw.tick().1);
        counts.push(updated);
        let fills = events
            .iter()
            .map(|e| serde_json::from_str::<serde_json::Value>(e).unwrap())
            .filter(|e| e["type"] == "fill")
            .count();
        assert_eq!(fills, 2, "{events:?}");
        for key in [maker, taker] {
            let row = &gw.v1_orders_json(&key).unwrap()["orders"][0];
            assert_eq!(row["execution"]["status"], "FILLED", "{row}");
        }
        assert_eq!(all_resting(&gw, &bidder), wall);
    }
    assert_eq!(
        counts[0], counts[1],
        "row updates grew with the resting bids"
    );
    assert!(counts[0] <= 2, "{} rows updated", counts[0]);
}
