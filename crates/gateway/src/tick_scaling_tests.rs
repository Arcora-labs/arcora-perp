//! Audit 2026-11-16 GA-1 + SM-1, the tick: each tick used to update the
//! execution record of every order row the gateway keeps, and each update
//! searched the whole book for the order, so a tick cost the square of the
//! resting orders under the gateway's single lock. A tick now updates the rows
//! its batch touched (a fill, a rejection, a removal, a newly sealed order) and
//! the rows holding a fill whose tick settled since (round 1 review: not every
//! row whose fills wait for their proof, on every tick), indexes the batch by
//! order hash once and finds each order by its hash.
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

/// A reduce-only version of [`order`].
fn reducing(side: &str, size: i128, limit: i128, tif: &str) -> OrderReq {
    OrderReq {
        reduce_only: true,
        ..order(side, size, limit, tif)
    }
}

/// An exchange in window-settle mode: no fill settles until a window settles
/// on L1, which a test does with [`settle_windows`].
fn windowed() -> Gw {
    let mut gw = Gw::boot();
    gw.window_settle_mode = true;
    gw.seq.set_retain_tick_snapshots(false);
    gw
}

/// Settle on L1 every window up to the open one: every tick sealed so far.
fn settle_windows(gw: &mut Gw) {
    let open = gw.seq.current_window_id();
    gw.seq.mark_window_settled(open);
}

/// Every row's record agrees with the book: an order the book holds reads
/// RESTING or PARTIALLY_FILLED with the book's remainder, and no row reads so
/// for an order the book does not hold.
fn assert_rows_match_book(gw: &Gw) {
    for o in gw
        .orders
        .iter()
        .chain(gw.accounts.values().flat_map(|a| &a.orders))
    {
        let Some(e) = o.execution.as_ref().filter(|e| e.known) else {
            continue;
        };
        let live = gw.seq.remaining_order_size(&o.order_hash);
        match e.status {
            execution::Status::Resting | execution::Status::PartiallyFilled => {
                assert_eq!(live, Some(e.remaining), "row {} reads {e:?}", o.id);
            }
            _ => assert_eq!(live, None, "row {} reads {e:?}", o.id),
        }
    }
}

/// The events of `kind` among a tick's account events.
fn events_of(events: &[String], kind: &str) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|e| serde_json::from_str::<serde_json::Value>(e).unwrap())
        .filter(|e| e["type"] == kind)
        .collect()
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
/// crossing, IOC, FOK, post-only, reduce-only and market orders, the house
/// counters, cancellations, and fills settling SETTLE_TICKS later or, in
/// window-settle mode, when a window settles), every row a tick skips would
/// have changed nothing had the tick updated it as it used to: no event, and
/// nothing a response shows. So the events and the responses are the ones a
/// tick that updates every row gives. And after every tick each row agrees with
/// the book.
fn skipped_rows_session(window: bool) {
    CHECK_SKIPPED.with(|c| c.set(Some(0)));
    let mut gw = if window { windowed() } else { Gw::boot() };
    let keys: Vec<[u8; 32]> = (0..4).map(|_| account(&mut gw)).collect();
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    let (mut fills, mut cancels, mut updates, mut settles) = (0, 0, 0, 0);
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
            let mut req = order(side, size, limit, tif);
            req.reduce_only = next(5) == 0;
            let a = gw.accounts.get_mut(&key).unwrap();
            a.last_order_ms = 0;
            a.orders_this_sec = 0;
            let _ = gw.account_place_order(&key, &req);
        }
        if next(3) == 0 {
            let key = keys[next(keys.len())];
            // Pick among the orders that still have something to cancel, so the
            // run cancels often enough whatever the random account keys did to
            // the matching (picking among every row left it flaky).
            let owner = gw.accounts[&key].wallet.owner;
            let ids: Vec<String> = gw.accounts[&key]
                .orders
                .iter()
                .filter(|o| {
                    gw.seq
                        .cancellable_size(&owner, &o.order, o.sealed)
                        .is_some()
                })
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
        if window && next(6) == 0 {
            settle_windows(&mut gw);
            settles += 1;
        }
        let mut events = Vec::new();
        updates += row_updates(|| events = gw.tick().1);
        fills += events_of(&events, "fill").len();
        assert_rows_match_book(&gw);
    }
    let skipped = CHECK_SKIPPED.with(|c| c.replace(None)).unwrap();
    assert!(fills > 10, "{fills} fills");
    assert!(cancels > 2, "{cancels} cancellations");
    assert!(!window || settles > 2, "{settles} settles");
    assert!(
        updates > 0 && skipped > updates,
        "{skipped} rows skipped, {updates} updated"
    );
}

#[test]
fn audit_1116_ga1_a_skipped_row_would_have_shown_no_change() {
    skipped_rows_session(false);
}

/// The same session in window-settle mode, where fills wait for a window to
/// settle on L1 and the rows holding them are updated only by the tick after.
#[test]
fn audit_1116_ga1_a_skipped_row_would_have_shown_no_change_in_window_mode() {
    skipped_rows_session(true);
}

/// Audit 2026-11-16 GA-1 + SM-1, round 1 review: in window-settle mode a fill
/// stays unsettled until its window settles on L1, minutes later, and IOCs the
/// house answers make such rows for free. A quiet tick updates no row however
/// many rows hold unsettled fills; the tick after a window settles updates
/// exactly those rows and reports each settled, as every tick used to. The same
/// holds for rows restored from a snapshot.
#[test]
fn audit_1116_ga1_a_quiet_tick_does_not_scale_with_unsettled_filled_rows() {
    let mut quiet = Vec::new();
    for filled in [2usize, 18] {
        let mut gw = windowed();
        let key = account(&mut gw);
        for _ in 0..filled {
            post(&mut gw, &key, &order("Buy", SIZE_SCALE / 100, 0, "Ioc"));
            gw.tick();
        }
        let rows = gw.v1_orders_json(&key).unwrap()["orders"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(rows.len(), filled);
        for row in &rows {
            assert_eq!(row["execution"]["status"], "FILLED", "{row}");
            assert_eq!(
                row["execution"]["unsettledSize"],
                (SIZE_SCALE / 100).to_string(),
                "{row}"
            );
        }
        quiet.push(row_updates(|| {
            gw.tick();
        }));

        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        restored.window_settle_mode = true;
        restored.seq.set_retain_tick_snapshots(false);
        for gw in [&mut gw, &mut restored] {
            assert_eq!(
                row_updates(|| {
                    gw.tick();
                }),
                0
            );
            settle_windows(gw);
            let mut events = Vec::new();
            let updated = row_updates(|| events = gw.tick().1);
            assert_eq!(updated as usize, filled);
            let settled = events_of(&events, "execution");
            assert_eq!(settled.len(), filled, "{events:?}");
            for event in &settled {
                assert_eq!(event["execution"]["unsettledSize"], "0", "{event}");
                assert_eq!(event["execution"]["status"], "FILLED", "{event}");
            }
            assert_eq!(
                row_updates(|| {
                    gw.tick();
                }),
                0
            );
        }
    }
    assert_eq!(quiet, [0, 0], "quiet ticks updated rows");
}

/// Audit 2026-11-16 GA-1 + SM-2, round 1 review, through the gateway's
/// admission: seven accounts each short a lot, rest a reduce-only bid and close
/// the short, leaving the bid behind; X is short with a plain bid just under
/// theirs; H asks a lot. One tick carries A's sell into the bids and, sealed
/// after it, X's reduce-only buy into H's ask. Its first seven passes each ban one
/// leftover bid, with X's buy closing X's short; in the eighth and last the sell
/// closes X's short first, so X's buy would open a position and is refused. H's
/// ask never traded: it still rests with its lot, its row says so and H can
/// cancel it. Every row the tick skipped would have shown no change, and every
/// row agrees with the book.
#[test]
fn audit_1116_ga1_the_last_pass_leaves_every_row_true() {
    CHECK_SKIPPED.with(|c| c.set(Some(0)));
    let mut gw = windowed();
    let px = gw.px_of(0);
    let lot = SIZE_SCALE / 100;
    let bid = px - px / 50;
    let ask = px + px / 100;
    let leftovers: Vec<[u8; 32]> = (0..7).map(|_| account(&mut gw)).collect();
    // A tick seals the accounts' orders in the order of their keys.
    let mut pair = [account(&mut gw), account(&mut gw)];
    pair.sort();
    let [a, x] = pair;
    let h = account(&mut gw);
    for key in leftovers.iter().chain([&x]) {
        post(&mut gw, key, &order("Sell", lot, 0, "Ioc"));
    }
    gw.tick();
    for key in &leftovers {
        post(&mut gw, key, &reducing("Buy", lot, bid, "Gtc"));
    }
    post(&mut gw, &x, &order("Buy", lot, bid - px / 1_000, "Gtc"));
    post(&mut gw, &h, &order("Sell", lot, ask, "Gtc"));
    gw.tick();
    for key in &leftovers {
        post(&mut gw, key, &order("Buy", lot, 0, "Ioc"));
    }
    gw.tick();
    assert_rows_match_book(&gw);
    let (h_id, h_hash) = {
        let row = &gw.accounts[&h].orders[0];
        (row.id.clone(), row.order_hash)
    };
    assert_eq!(gw.seq.remaining_order_size(&h_hash), Some(lot));
    for key in &leftovers {
        let rows = &gw.accounts[key].orders;
        assert_eq!(rows.len(), 3);
        assert!(gw.seq.remaining_order_size(&rows[1].order_hash).is_some());
    }

    post(&mut gw, &a, &order("Sell", lot, bid - px / 500, "Gtc"));
    post(&mut gw, &x, &reducing("Buy", lot, ask, "Gtc"));
    let events = gw.tick().1;

    assert_rows_match_book(&gw);
    assert_eq!(gw.seq.remaining_order_size(&h_hash), Some(lot));
    let row = &gw.v1_orders_json(&h).unwrap()["orders"][0];
    assert_eq!(row["execution"]["status"], "RESTING", "{row}");
    assert_eq!(row["execution"]["remainingSize"], lot.to_string(), "{row}");
    let x_buy = &gw.v1_orders_json(&x).unwrap()["orders"][0];
    assert_eq!(x_buy["execution"]["status"], "REJECTED", "{x_buy}");
    assert_eq!(
        x_buy["execution"]["reason"], "ReduceOnlyViolation",
        "{x_buy}"
    );
    for key in &leftovers {
        let row = &gw.v1_orders_json(key).unwrap()["orders"][1];
        assert_eq!(row["execution"]["status"], "REJECTED", "{row}");
    }
    assert_eq!(events_of(&events, "fill").len(), 2, "{events:?}");
    let a_sell = &gw.v1_orders_json(&a).unwrap()["orders"][0];
    assert_eq!(a_sell["execution"]["status"], "FILLED", "{a_sell}");
    assert_eq!(gw.account_cancel(&h, &h_id), Ok(lot));
    assert!(CHECK_SKIPPED.with(|c| c.replace(None)).unwrap() > 0);
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

/// Audit 2026-11-16 GA-1 + SM-1, round 1 review: an order that ended without
/// filling never reaches SETTLED, so its row used to stay in the account's
/// history forever, and an account over the history cap made every tick walk
/// every book for its resting orders. Such a row now leaves once the tick that
/// sealed it is hard; the account's resting order stays.
#[test]
fn audit_1116_ga1_rows_that_never_filled_leave_the_history_cap() {
    let mut gw = Gw::boot();
    let px = gw.px_of(0);
    let key = account(&mut gw);
    post(
        &mut gw,
        &key,
        &order("Buy", SIZE_SCALE / 100, px * 9 / 10, "Gtc"),
    );
    gw.tick();
    let resting = gw.accounts[&key].orders[0].order_hash;
    let extra = MAX_ACCOUNT_ORDER_HISTORY + 20;
    for chunk in 0..extra / 20 {
        for _ in 0..20 {
            post(
                &mut gw,
                &key,
                &order("Sell", SIZE_SCALE / 100, px + px / 50, "Ioc"),
            );
        }
        gw.tick();
        assert!(chunk > 0 || gw.accounts[&key].orders.len() == 21);
    }
    for _ in 0..=SETTLE_TICKS {
        gw.tick();
    }
    let rows = &gw.accounts[&key].orders;
    assert_eq!(rows.len(), MAX_ACCOUNT_ORDER_HISTORY);
    assert!(rows.iter().any(|o| o.order_hash == resting));
    assert!(gw.seq.remaining_order_size(&resting).is_some());
    assert_rows_match_book(&gw);
}
