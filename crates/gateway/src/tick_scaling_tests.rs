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
    /// Whether ticks on this thread check every row they skip
    /// ([`check_skipped_row`]), and how many they checked.
    static CHECK_SKIPPED: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Count one row update of a tick.
pub(super) fn count_row_update() {
    ROW_UPDATES.with(|n| n.set(n.get() + 1));
}

/// A row a tick skipped, while this thread checks them: update it as every
/// tick used to, assert that this emits no event and changes nothing a response
/// shows (only the record's last tick moves), then put the record back.
pub(super) fn check_skipped_row(o: &mut GwOrder, seq: &Sequencer, batch: &SealedBatch) {
    let Some(checked) = CHECK_SKIPPED.with(Cell::get) else {
        return;
    };
    CHECK_SKIPPED.with(|c| c.set(Some(checked + 1)));
    let record = o.execution.clone();
    let shown = |o: &GwOrder| {
        (
            execution::record_without_tick(o),
            o.filled,
            o.avg_fill,
            execution::wire(o, seq),
        )
    };
    let before = shown(o);
    let events = execution::update(o, seq, batch, false);
    assert!(
        events.is_empty(),
        "a skipped row would have emitted {events:?}"
    );
    assert_eq!(shown(o), before, "a skipped row would have changed");
    o.execution = record;
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

/// Over a pseudo-random session of four accounts and the demo user (resting,
/// crossing, IOC, FOK, post-only and market orders, the house counters,
/// cancellations, and fills settling SETTLE_TICKS later), every row a tick
/// skips would have changed nothing had the tick updated it as it used to: no
/// event, and nothing a response shows. So the events and the responses are
/// the ones a tick that updates every row gives.
#[test]
fn audit_1116_ga1_a_skipped_row_would_have_shown_no_change() {
    CHECK_SKIPPED.with(|c| c.set(Some(0)));
    let mut gw = Gw::boot();
    let keys: Vec<[u8; 32]> = (0..4).map(|_| account(&mut gw)).collect();
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    let (mut fills, mut cancels, mut updates) = (0, 0, 0);
    for _ in 0..60 {
        let px = gw.px_of(0);
        for _ in 0..next(6) {
            let key = keys[next(keys.len())];
            let side = ["Buy", "Sell"][next(2)];
            let size = SIZE_SCALE / 100 * (1 + next(3) as i128);
            let limit = match next(6) {
                0 => 0,
                n => px + px / 1_000 * (n as i128 - 3),
            };
            let tif = ["Gtc", "Gtc", "Ioc", "Fok", "PostOnly"][next(5)];
            let a = gw.accounts.get_mut(&key).unwrap();
            a.last_order_ms = 0;
            a.orders_this_sec = 0;
            let _ = gw.account_place_order(&key, &order(side, size, limit, tif));
        }
        if next(3) == 0 {
            let key = keys[next(keys.len())];
            let ids: Vec<String> = gw.accounts[&key]
                .orders
                .iter()
                .map(|o| o.id.clone())
                .collect();
            if !ids.is_empty() && gw.account_cancel(&key, &ids[next(ids.len())]).is_ok() {
                cancels += 1;
            }
        }
        if next(4) == 0 {
            let side = ["Buy", "Sell"][next(2)];
            let _ = gw.place_order(&order(side, SIZE_SCALE / 100, 0, "Ioc"));
        }
        let mut events = Vec::new();
        updates += row_updates(|| events = gw.tick().1);
        fills += events
            .iter()
            .map(|e| serde_json::from_str::<serde_json::Value>(e).unwrap())
            .filter(|e| e["type"] == "fill")
            .count();
    }
    let skipped = CHECK_SKIPPED.with(|c| c.replace(None)).unwrap();
    assert!(fills > 10, "{fills} fills");
    assert!(cancels > 2, "{cancels} cancellations");
    assert!(
        updates > 0 && skipped > updates,
        "{skipped} rows skipped, {updates} updated"
    );
}

/// A resting order as every snapshot has written it, field for field.
#[derive(serde::Serialize, serde::Deserialize)]
struct WrittenResting {
    order_hash: Digest,
    owner: PubKey,
    remaining: i128,
    price: i128,
    seq: u64,
    reduce_only: bool,
    expiry_ms: u64,
}

/// A book as every snapshot has written it, field for field.
#[derive(serde::Serialize, serde::Deserialize)]
struct WrittenBook {
    market_id: u64,
    bids: std::collections::BTreeMap<i128, std::collections::VecDeque<WrittenResting>>,
    asks: std::collections::BTreeMap<i128, std::collections::VecDeque<WrittenResting>>,
    _h: std::marker::PhantomData<()>,
}

/// The book's hash index is not persisted: a book writes the fields it always
/// wrote, and a restored book builds the index from them, so it finds every
/// order by its hash, cancels one from the middle of a queue and trades
/// against the rest.
#[test]
fn audit_1116_ga1_a_restored_book_finds_its_orders_by_hash() {
    let (gw, bidder, maker, px) = walled(8);
    let written = postcard::to_allocvec(gw.seq.book(0).unwrap()).unwrap();
    let book: WrittenBook = postcard::from_bytes(&written).unwrap();
    assert_eq!(postcard::to_allocvec(&book).unwrap(), written);
    assert_eq!(book.bids.values().map(|q| q.len()).sum::<usize>(), 8);
    assert_eq!(book.asks.values().map(|q| q.len()).sum::<usize>(), 1);

    let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    for (_, quote, _) in gw.seq.book(0).unwrap().resting_orders() {
        assert_eq!(
            restored.seq.remaining_order_size(&quote.order_hash),
            Some(quote.remaining)
        );
    }
    let middle = restored.accounts[&bidder].orders[4].id.clone();
    let middle_hash = restored.accounts[&bidder].orders[4].order_hash;
    assert_eq!(
        restored.account_cancel(&bidder, &middle),
        Ok(SIZE_SCALE / 100)
    );
    assert_eq!(restored.seq.remaining_order_size(&middle_hash), None);
    for o in &restored.accounts[&bidder].orders {
        let live = restored.seq.remaining_order_size(&o.order_hash);
        assert_eq!(live.is_some(), o.order_hash != middle_hash);
    }

    let taker = account(&mut restored);
    post(
        &mut restored,
        &taker,
        &order("Buy", SIZE_SCALE / 100, px, "Gtc"),
    );
    restored.tick();
    let row = &restored.v1_orders_json(&maker).unwrap()["orders"][0];
    assert_eq!(row["execution"]["status"], "FILLED", "{row}");
}
