//! The live void of a dead phase-0 window (`Gw::live_void_window`).
use super::*;
use crate::admission::HistorySize;
use crate::deposit_ingestion::tests::{
    app_with_blocks, chained_blocks, fresh, land_uncredited, permit, settle_open_window,
};
use crate::deposit_ingestion::{ingest_once, Purpose, Route};
use crate::deposit_rpc::{Block, Event, Page};
use crate::ops_alerts::AlertKind::DepositBlockedAtCap;
use crate::wind_down::SettledL1;
use k256::ecdsa::SigningKey;
use std::collections::BTreeMap;

type Chain = BTreeMap<u64, (Block, Vec<Event>)>;

const S: i128 = SIZE_SCALE;

/// A gateway-custody account bound to the address of its own signing key, which
/// authorizes its withdrawals and its credential recovery.
struct Keyed {
    key: [u8; 32],
    owner: PubKey,
    sk: SigningKey,
    address: [u8; 20],
}

fn keyed(gw: &mut Gw, seed: u8) -> Keyed {
    let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
    let address = eth_address(&sk);
    let (key, owner) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(address);
    Keyed {
        key,
        owner,
        sk,
        address,
    }
}

/// A collateral (market 0) or insurance permit for `a`, paid from its address.
fn routed(gw: &mut Gw, a: &Keyed, amount: u128, purpose: Purpose) -> [u8; 32] {
    gw.authorize_routed_deposit(&a.key, a.address, amount, 0, purpose, u64::MAX)
        .unwrap()
}

fn sign_withdrawal(gw: &Gw, a: &Keyed, amount: i128, auth_nonce: u64) -> [u8; 65] {
    let digest = withdraw_auth_digest(
        gw.chain_id,
        &gw.vault,
        &a.owner,
        0,
        amount,
        &a.address,
        auth_nonce,
    );
    let (sig, recid) = a.sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    wire
}

/// A signed withdrawal of `amount` from `a`'s market-0 entry to its address.
fn withdraw(gw: &mut Gw, a: &Keyed, amount: i128) -> Withdrawal {
    let auth = gw.accounts[&a.key].last_withdraw_nonce + 1;
    let sig = sign_withdrawal(gw, a, amount, auth);
    gw.account_withdraw(&a.key, 0, amount, a.address, auth, &sig)
        .unwrap()
}

fn rotate(gw: &mut Gw, a: &Keyed) -> [u8; 32] {
    let nonce = gw.accounts[&a.key].recovery_nonce;
    let digest = crate::account_recovery::digest(gw.chain_id, &gw.vault, &a.owner, nonce);
    let (sig, recid) = a.sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    gw.recover_account(a.owner, nonce, &wire).unwrap()
}

/// The deposit block of `chain` that starts at the gateway's consumed count.
fn next_page(gw: &Gw, chain: &Chain) -> Page {
    let start = gw.deposit_cursor();
    let (end, events) = chain[&start.count].clone();
    Page { start, end, events }
}

/// Credit the next deposit block, and acknowledge it as the snapshot writer does.
fn ingest(gw: &mut Gw, chain: &Chain) -> usize {
    let credited = gw.apply_deposit_page(next_page(gw, chain)).unwrap();
    gw.deposits.dirty = false;
    credited
}

fn open_trading(gw: &mut Gw) {
    gw.prod = false;
    gw.trading_gate = trading_gate::TradingGate::Open;
    gw.window_settle_mode = true;
    gw.seq.set_retain_tick_snapshots(false);
    for m in &mut gw.mkts {
        m.live = true;
    }
}

fn tick(gw: &mut Gw) {
    for (id, px) in gw.mkts.iter().map(|m| (m.id, m.px)).collect::<Vec<_>>() {
        gw.seq
            .set_oracle(id, oracle_of(px, now_ms(), id, &gw.oracle_signer));
    }
    gw.tick();
}

/// Place an order for account `key` in market 0; returns its hash.
fn submit(gw: &mut Gw, key: &[u8; 32], side: &str, size: i128, price: i128, tif: &str) -> Digest {
    gw.account_place_order(
        key,
        &OrderReq {
            market_id: 0,
            side: side.into(),
            size: size.to_string(),
            limit_price: price.to_string(),
            tif: tif.into(),
            ..Default::default()
        },
    )
    .unwrap();
    gw.accounts[key].orders[0].order_hash
}

/// Seal the open window and journal its clock intent, as the settle loop does
/// before it registers the window.
fn seal(gw: &mut Gw) -> RollbackJournal {
    gw.deposits.dirty = false;
    let window = gw.seq.state.next_batch_id;
    let (witness, ww) = gw.begin_window_settle(window).unwrap().unwrap();
    let prepared = crate::prover_client::prepare_unproved(&witness, &ww).unwrap();
    RollbackJournal {
        batch_id: witness.batch_id,
        witness,
        ww,
        prepared: Some(prepared),
    }
}

/// Prove (mock) and commit a sealed window, its manifest's ordered and
/// rejected hashes included.
fn commit(gw: &mut Gw, j: &RollbackJournal) {
    let prepared = crate::prover_client::prove_and_prepare(
        &crate::prover_client::MockProverClient,
        &j.witness,
        &j.ww,
    )
    .unwrap();
    gw.commit_window_settle(
        j.batch_id,
        j.witness.manifest.ordered.clone(),
        j.witness
            .manifest
            .rejected
            .iter()
            .map(|(h, _)| *h)
            .collect(),
        prepared,
        L1Status::default(),
        trading_gate::GateObservation::StaysClosed,
    );
}

/// Void `j`, and acknowledge the snapshot that makes it durable.
fn applied(gw: &mut Gw, j: &RollbackJournal, cause: DeadIntent) -> VoidReport {
    match gw.live_void_window(j, cause) {
        Ok(LiveVoidOutcome::Applied(report)) => {
            assert!(gw.deposits.dirty, "the void must be persisted");
            gw.deposits.dirty = false;
            report
        }
        other => panic!("the void was not applied: {other:?}"),
    }
}

/// The order hashes a void of `j` publishes as cancelled: the window's ordered
/// and rejected hashes (its ticks filled no other order here). The rejected
/// one is the house market maker's counter-order to the taker, which its
/// margin refused.
fn published(j: &RollbackJournal) -> Vec<Digest> {
    let mut hashes = j.witness.manifest.ordered.clone();
    hashes.extend(j.witness.manifest.rejected.iter().map(|(h, _)| *h));
    hashes
}

/// The notes the window's deposits minted.
fn voided_notes(j: &RollbackJournal) -> BTreeSet<Digest> {
    voided_deposits(j).iter().map(|d| d.note).collect()
}

fn rejected_as(gw: &Gw, reason: perp_core::order::RejectReason) -> Vec<Digest> {
    gw.seq
        .window_rejected()
        .iter()
        .filter(|(_, r)| *r == reason)
        .map(|(h, _)| *h)
        .collect()
}

/// A gateway with one settled window and the sealed window after it, whose
/// clock intent is journaled. The settled window credited `w`'s deposit (and,
/// with `bootstrap_before`, an insurance bootstrap that completed). The sealed
/// window credited three deposits (the maker's, the taker's and an insurance
/// deposit), the maker rested an order the taker partly filled, and `w`
/// withdrew with a signed request.
struct Voidable {
    gw: Gw,
    chain: Chain,
    journal: RollbackJournal,
    w: Keyed,
    maker: Keyed,
    taker: [u8; 32],
    operator: [u8; 32],
    /// The sealed window's deposits: the maker's, the taker's, the insurance one.
    commits: [[u8; 32]; 3],
    /// Their permit routes and blinds before they were credited.
    routes: BTreeMap<[u8; 32], Route>,
    blinds: BTreeMap<[u8; 32], [u8; 32]>,
    orders: [Digest; 2],
    withdrawal: Withdrawal,
    /// The deposit count before the sealed window (its pre-state's).
    consumed: u64,
}

fn voidable(bootstrap_before: bool) -> Voidable {
    let mut gw = fresh();
    open_trading(&mut gw);
    let floor = bootstrap::MIN_BOOTSTRAP_INSURANCE as u128;
    let w = keyed(&mut gw, 0x31);
    let mut settled = vec![routed(
        &mut gw,
        &w,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    )];
    if bootstrap_before {
        settled.push(permit(&mut gw, floor, Purpose::InsuranceBootstrap, 0).1);
    }
    let maker = keyed(&mut gw, 0x32);
    let collateral = (50_000 * QUOTE_SCALE) as u128;
    let maker_commit = routed(&mut gw, &maker, collateral, Purpose::Collateral);
    let (taker, taker_commit) = permit(&mut gw, collateral, Purpose::Collateral, 0);
    let (operator, insurance) = permit(&mut gw, floor, Purpose::InsuranceBootstrap, 0);
    let commits = [maker_commit, taker_commit, insurance];
    let chain = chained_blocks(&gw, &[&settled, &commits]);
    ingest(&mut gw, &chain);
    settle_open_window(&mut gw);
    if bootstrap_before {
        assert_eq!(gw.bootstrap, bootstrap::Bootstrap::Complete);
    }
    let consumed = gw.seq.state.consumed_deposit_count;
    let routes = gw.deposits.routes.clone();
    assert_eq!(routes.len(), 3);
    let blinds = commits
        .iter()
        .map(|c| {
            let key = routes[c].key;
            (*c, gw.accounts[&key].deposit_authorizations[c])
        })
        .collect();
    assert_eq!(ingest(&mut gw, &chain), 3);
    let px = gw.px_of(0);
    let rest = submit(&mut gw, &maker.key, "Sell", S / 10, px, "Gtc");
    tick(&mut gw);
    let take = submit(&mut gw, &taker, "Buy", S / 40, 0, "Ioc");
    tick(&mut gw);
    assert_eq!(
        gw.seq.remaining_order_size(&rest),
        Some(S / 10 - S / 40),
        "the maker's remainder rests"
    );
    let withdrawal = withdraw(&mut gw, &w, 100 * QUOTE_SCALE);
    let journal = seal(&mut gw);
    Voidable {
        gw,
        chain,
        journal,
        w,
        maker,
        taker,
        operator,
        commits,
        routes,
        blinds,
        orders: [rest, take],
        withdrawal,
        consumed,
    }
}

/// The void returns every deposit of the window to its landed permit, rewinds
/// the cursor, restores the bootstrap, drops the window's notes and withdrawal
/// leaves, and cancels its orders; re-ingestion then credits the deposits again
/// and the replacement window settles under the same batch id. A bootstrap that
/// completed before the window stays complete through a top-up in it.
#[tokio::test]
async fn live_void_restores_two_deposits_and_an_insurance_bootstrap() {
    for bootstrap_before in [false, true] {
        let Voidable {
            mut gw,
            chain,
            journal: j,
            maker,
            taker,
            operator,
            commits,
            routes,
            blinds,
            orders,
            withdrawal,
            consumed,
            ..
        } = voidable(bootstrap_before);
        let window = j.batch_id;
        let pre_root = j.witness.pre_state.state_root();
        let counter = gw.next_withdraw_nonce;
        let deposit_counters: Vec<u64> = [maker.key, taker, operator]
            .iter()
            .map(|k| gw.accounts[k].deposit_counter)
            .collect();
        let voided_tx = hex0x(&chain[&consumed].1[0].tx);
        let settled_tx = hex0x(&chain[&0].1[0].tx);
        assert!(gw.processed_deposit_txs.contains(&voided_tx));
        let archived = gw.archive.len();
        let notes = voided_notes(&j);
        assert_eq!(notes.len(), 3);
        assert!(gw
            .archive
            .notes()
            .iter()
            .any(|r| notes.contains(&r.commitment)));

        let r = applied(&mut gw, &j, DeadIntent::EmptyAfterFence);
        assert_eq!((r.batch_id, r.cause), (window, DeadIntent::EmptyAfterFence));
        assert_eq!(r.deposits, vec![consumed, consumed + 1, consumed + 2]);
        let hashes = published(&j);
        assert!(orders.iter().all(|h| hashes.contains(h)));
        assert_eq!(r.orders, hashes.len());
        assert_eq!(r.fills_reverted, 1);
        assert_eq!(r.withdrawals.len(), 1);
        assert_eq!(r.withdrawals[0].leaf(), withdrawal.leaf());
        assert_eq!(r.bootstrap_restored, !bootstrap_before);
        assert_eq!(r.archive_dropped, 3);
        assert!(!r.underivable);
        assert_eq!(r.order_events.len(), 2, "one per voided order record");
        assert!(r.summary().contains("3 deposits restored for re-ingestion"));

        // The engine is back at the window's pre-state.
        assert_eq!(gw.seq.state.state_root(), pre_root);
        assert_eq!(gw.last_settled_root, pre_root);
        assert_eq!(gw.seq.current_window_id(), window);
        // Each deposit is landed again, under its own permit.
        assert_eq!(gw.deposits.routes, routes);
        for (commit, blind) in &blinds {
            let key = routes[commit].key;
            assert_eq!(gw.accounts[&key].deposit_authorizations[commit], *blind);
        }
        assert!(gw.deposits.credits.range(consumed..).next().is_none());
        assert_eq!(
            gw.deposits.uncredited.keys().copied().collect::<Vec<_>>(),
            r.deposits
        );
        assert_eq!(
            gw.deposits.landed_commits(),
            commits.iter().copied().collect()
        );
        assert_eq!(
            gw.deposits.anchor,
            Some(gw.deposits.credits[&(consumed - 1)].event.block.clone())
        );
        assert_eq!(
            gw.bootstrap,
            if bootstrap_before {
                bootstrap::Bootstrap::Complete
            } else {
                bootstrap::Bootstrap::NotStarted
            }
        );
        assert_eq!(gw.archive.len(), archived - 3);
        assert!(!gw
            .archive
            .notes()
            .iter()
            .any(|r| notes.contains(&r.commitment)));
        assert!(!gw
            .pending_withdrawals
            .iter()
            .any(|p| p.leaf() == withdrawal.leaf()));
        assert_eq!(gw.next_withdraw_nonce, counter, "no nonce moves back");
        assert_eq!(
            [maker.key, taker, operator]
                .iter()
                .map(|k| gw.accounts[k].deposit_counter)
                .collect::<Vec<_>>(),
            deposit_counters
        );
        assert!(!gw.processed_deposit_txs.contains(&voided_tx));
        assert!(gw.processed_deposit_txs.contains(&settled_tx));
        assert_eq!(
            rejected_as(&gw, perp_core::order::RejectReason::Cancelled),
            hashes
        );
        for (key, hash) in [(maker.key, orders[0]), (taker, orders[1])] {
            let row = &gw.v1_orders_json(&key).unwrap()["orders"][0];
            assert_eq!(row["orderHash"], hex0x(&hash));
            assert_eq!(row["execution"]["status"], "CANCELLED");
            assert_eq!(row["execution"]["reason"], "WindowVoided");
            assert_eq!(row["filledSize"], "0");
            assert!(gw.seq.remaining_order_size(&hash).is_none());
        }
        gw.validate_deposit_state().unwrap();
        assert_eq!(gw.note_void_headroom(window), None);
        assert!(!gw.ops_alerts.active().contains(&DepositBlockedAtCap));

        // The same journal again finds the void and changes nothing.
        let voided = gw.snapshot_plain();
        assert_eq!(
            gw.live_void_window(&j, DeadIntent::EmptyAfterFence)
                .map(|o| matches!(o, LiveVoidOutcome::AlreadyVoided)),
            Ok(true)
        );
        assert_eq!(gw.snapshot_plain(), voided);
        let restored = Gw::boot_restored(&voided).unwrap();
        assert_eq!(restored.snapshot_plain(), voided);

        // Re-ingestion credits the deposits again, with new notes.
        let (app, _source, writer) = app_with_blocks(gw, chain.clone());
        assert_eq!(ingest_once(&app).await.unwrap(), 3);
        let mut guard = app.gw.lock().await;
        let gw = &mut *guard;
        assert!(gw.deposits.uncredited.is_empty());
        assert!(gw.deposits.routes.is_empty());
        for commit in &commits {
            assert!(!gw
                .accounts
                .values()
                .any(|a| a.deposit_authorizations.contains_key(commit)));
        }
        assert_eq!(gw.archive.len(), archived);
        assert!(!gw
            .archive
            .notes()
            .iter()
            .any(|r| notes.contains(&r.commitment)));
        assert!(gw.processed_deposit_txs.contains(&voided_tx));
        assert_eq!(
            gw.bootstrap,
            if bootstrap_before {
                bootstrap::Bootstrap::Complete
            } else {
                bootstrap::Bootstrap::InsuranceApplied { window_id: window }
            }
        );

        // The replacement window settles under the same batch id and publishes
        // the voided orders as cancelled.
        let replacement = seal(gw);
        assert_eq!(replacement.batch_id, window);
        for h in &hashes {
            assert!(replacement
                .witness
                .manifest
                .rejected
                .contains(&(*h, perp_core::order::RejectReason::Cancelled)));
        }
        let prepared = replacement.prepared.as_ref().unwrap();
        assert_eq!(prepared.outcome.new_deposit_count, consumed + 3);
        assert!(replacement.ww.is_empty());
        commit(gw, &replacement);
        for h in &hashes {
            assert_ne!(gw.seq.finality_of(h), Some(Finality::Settled));
            assert_eq!(
                gw.build_challenge_answer(h)
                    .map(|(rejected, batch, _)| (rejected, batch)),
                Some((true, window))
            );
        }
        assert_eq!(gw.bootstrap, bootstrap::Bootstrap::Complete);
        for key in [maker.key, taker] {
            let row = &gw.v1_orders_json(&key).unwrap()["orders"][0];
            assert_eq!(row["execution"]["reason"], "WindowVoided");
            assert_eq!(row["execution"]["settledSize"], "0");
        }
        drop(guard);
        writer.abort();
    }
}

/// The restored routes count toward the admission cap like any outstanding
/// permit, and in the ordinary case their page is not refused.
#[test]
fn admission_counts_restored_routes_and_reingest_is_not_refused() {
    let Voidable {
        mut gw,
        chain,
        journal: j,
        ..
    } = voidable(false);
    assert_eq!(gw.outstanding_permit_size().history, 0);
    applied(&mut gw, &j, DeadIntent::Cancelled);
    // Three deposits, each a leaf and a nullifier; the maker's and the taker's
    // open a position entry again.
    assert_eq!(
        gw.outstanding_permit_size(),
        HistorySize {
            history: 6,
            positions: 2,
            notes: 0
        }
    );
    assert_eq!(
        gw.admission_size(),
        HistorySize::of(&j.witness.pre_state).plus(gw.outstanding_permit_size())
    );
    assert_eq!(gw.note_void_headroom(j.batch_id), None);
    let page = next_page(&gw, &chain);
    assert_eq!(gw.credit_refusal(gw.page_credit_size(&page)), None);
    assert_eq!(gw.apply_deposit_page(page).unwrap(), 3);
    assert!(!gw.ops_alerts.active().contains(&DepositBlockedAtCap));
}

/// A full exit inside the voided window removed a position entry the restored
/// state holds again, and a deposit of the window opened another: with the
/// position bound at the pre-state's count, crediting the restored deposit
/// would exceed it. The void stands, warns, and ingestion holds the page.
#[test]
fn a_full_exit_inside_the_voided_window_warns_when_reingest_would_hit_the_position_cap() {
    let mut gw = fresh();
    let x = keyed(&mut gw, 0x41);
    let x_commit = routed(
        &mut gw,
        &x,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    let y = keyed(&mut gw, 0x42);
    let y_commit = routed(
        &mut gw,
        &y,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    let chain = chained_blocks(&gw, &[&[x_commit], &[y_commit]]);
    ingest(&mut gw, &chain);
    settle_open_window(&mut gw);
    let entries = HistorySize::of(&gw.seq.state).positions;
    // The full exit: the whole balance of a position with no size.
    let balance = gw.seq.state.position(&x.owner, 0).unwrap().collateral;
    withdraw(&mut gw, &x, balance);
    assert_eq!(HistorySize::of(&gw.seq.state).positions, entries - 1);
    gw.admission_cap = crate::admission::AdmissionCap {
        max_positions: entries,
        ..crate::admission::measured_cap()
    };
    assert_eq!(
        ingest(&mut gw, &chain),
        1,
        "within the bound during the window"
    );
    let j = seal(&mut gw);
    let report = applied(&mut gw, &j, DeadIntent::EmptyAfterFence);
    assert_eq!(report.deposits, vec![1]);
    assert_eq!(gw.seq.state.state_root(), j.witness.pre_state.state_root());
    assert_eq!(gw.note_void_headroom(j.batch_id), Some("position-entry"));
    assert!(gw.ops_alerts.active().contains(&DepositBlockedAtCap));
    assert_eq!(
        gw.apply_deposit_page(next_page(&gw, &chain)).unwrap_err(),
        crate::admission::HISTORY_CAP_INTAKE
    );
    assert_eq!(
        gw.deposits.uncredited.keys().copied().collect::<Vec<_>>(),
        vec![1]
    );
    gw.validate_deposit_state().unwrap();
}

/// A window that credited no deposit still rewinds the cursor to the block of
/// the last deposit the pre-state consumed; reading on from there reaches the
/// head, and no permit changes. At the legacy prefix (no credit below the
/// window) the anchor is cleared and the read starts from the chain's start.
#[tokio::test]
async fn a_deposit_free_void_rewinds_the_anchor_harmlessly() {
    let mut gw = fresh();
    let w = keyed(&mut gw, 0x51);
    let funded = routed(
        &mut gw,
        &w,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    let held = routed(
        &mut gw,
        &w,
        (2_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    let chain = chained_blocks(&gw, &[&[funded]]);
    ingest(&mut gw, &chain);
    settle_open_window(&mut gw);
    // An empty finalized page moves the anchor on inside the window.
    let later = Block {
        number: 9,
        hash: [0x99; 32],
        timestamp: None,
    };
    let start = gw.deposit_cursor();
    gw.apply_deposit_page(Page {
        start,
        end: later.clone(),
        events: vec![],
    })
    .unwrap();
    assert_eq!(gw.deposits.anchor, Some(later));
    gw.deposits.dirty = false;
    withdraw(&mut gw, &w, 10 * QUOTE_SCALE);
    let j = seal(&mut gw);
    let routes = gw.deposits.routes.clone();
    let blinds = gw.accounts[&w.key].deposit_authorizations.clone();
    let report = applied(&mut gw, &j, DeadIntent::EmptyAfterFence);
    assert!(report.deposits.is_empty());
    assert_eq!(report.archive_dropped, 0);
    assert_eq!(
        gw.deposits.anchor,
        Some(gw.deposits.credits[&0].event.block.clone())
    );
    assert_eq!(gw.deposits.routes, routes);
    assert!(routes.contains_key(&held));
    assert_eq!(gw.accounts[&w.key].deposit_authorizations, blinds);
    gw.validate_deposit_state().unwrap();
    let (app, _source, writer) = app_with_blocks(gw, chain);
    assert_eq!(ingest_once(&app).await.unwrap(), 0);
    {
        let gw = app.gw.lock().await;
        assert_eq!(gw.deposits.anchor.as_ref().map(|b| b.number), Some(50));
        assert_eq!(gw.deposits.routes, routes);
    }
    writer.abort();

    // The first window, voided: no credit is left below it.
    let mut gw = fresh();
    let a = keyed(&mut gw, 0x52);
    let commit = routed(
        &mut gw,
        &a,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    let chain = chained_blocks(&gw, &[&[commit]]);
    ingest(&mut gw, &chain);
    assert!(gw.deposits.anchor.is_some());
    let j = seal(&mut gw);
    assert_eq!(j.batch_id, 0);
    assert_eq!(
        applied(&mut gw, &j, DeadIntent::Cancelled).deposits,
        vec![0]
    );
    assert_eq!(gw.deposits.anchor, None);
    assert!(gw.deposits.credits.is_empty());
    gw.validate_deposit_state().unwrap();
    assert_eq!(
        ingest(&mut gw, &chain),
        1,
        "read again from the chain's start"
    );
}

/// Every refusal comes before any change: the snapshot is byte-equal after it.
#[test]
fn live_void_refuses_without_mutation() {
    let f = voidable(false);
    let base = f.gw.snapshot_plain();
    let fork = || Gw::boot_restored(&base).unwrap();
    let refused = |gw: &mut Gw, j: &RollbackJournal, cause: DeadIntent, why: &str| {
        let before = gw.snapshot_plain();
        match gw.live_void_window(j, cause) {
            Err(LiveVoidError::Refused(e)) => assert!(e.contains(why), "{why}: {e}"),
            other => panic!("{why}: not refused: {other:?}"),
        }
        assert_eq!(gw.snapshot_plain(), before, "{why}: the state changed");
    };
    let j = &f.journal;
    let cause = DeadIntent::EmptyAfterFence;

    // Only a cancelled or never-existing anchor is voided.
    refused(&mut fork(), j, DeadIntent::Replaced, "not voided");
    refused(&mut fork(), j, DeadIntent::CloseOnlyPhaseZero, "not voided");
    // The journal: a prepared phase-0 intent for its own window.
    let mut unprepared = j.clone();
    unprepared.prepared = None;
    refused(&mut fork(), &unprepared, cause, "no prepared");
    let mut phase_one = j.clone();
    phase_one.prepared.as_mut().unwrap().outcome.wind_down_phase = 1;
    refused(&mut fork(), &phase_one, cause, "only a phase-0 window");
    let mut other = j.clone();
    other.batch_id += 1;
    refused(&mut fork(), &other, cause, "does not open window");
    let mut gw = fork();
    gw.wind_down_started = true;
    refused(&mut gw, j, cause, "wind-down has started");
    // The shape: the open window after the seal must be empty, and a window
    // that is no longer sealed must hold the void.
    let mut gw = fork();
    open_trading(&mut gw);
    submit(&mut gw, &f.taker, "Buy", S / 40, 0, "Ioc");
    tick(&mut gw);
    refused(&mut gw, j, cause, "is not empty");
    let mut gw = fork();
    gw.seq.rollback_window(&j.witness);
    gw.rollback_window_withdrawals(j.ww.clone());
    refused(&mut gw, j, cause, "does not hold its void");
    // The settled root.
    let mut gw = fork();
    gw.last_settled_root = [0xab; 32];
    refused(&mut gw, j, cause, "last settled root");
    // A missing or an extra credit.
    let mut gw = fork();
    gw.deposits.credits.remove(&(f.consumed + 1));
    refused(&mut gw, j, cause, "has no credit");
    let mut gw = fork();
    let mut extra = gw.deposits.credits[&(f.consumed + 2)].clone();
    extra.event.id += 1;
    gw.deposits.credits.insert(extra.event.id, extra);
    refused(&mut gw, j, cause, "do not end at deposit");
    // A blind that does not open the credited commitment.
    let mut wrong_blind = j.clone();
    for op in &mut wrong_blind.witness.ops {
        if let BatchOp::Deposit { deposit_blind, .. } = op {
            deposit_blind[0] ^= 1;
            break;
        }
    }
    refused(&mut fork(), &wrong_blind, cause, "permit blind");
    // A legacy bootstrap of the window, which has no exact restore.
    let mut gw = fork();
    gw.bootstrap = bootstrap::Bootstrap::DepositApplied {
        note_commitment: [1; 32],
        spend_key: [2; 32],
        deposit_id: f.consumed,
    };
    refused(&mut gw, j, cause, "legacy insurance bootstrap");
    // A deposit ledger that does not validate before the void.
    let mut gw = fork();
    let mut stray = gw.deposits.credits[&(f.consumed + 2)].clone();
    stray.event.id = f.consumed + 10;
    stray.route.key = [0xee; 32];
    gw.deposits.uncredited.insert(stray.event.id, stray);
    refused(&mut gw, j, cause, "does not validate before the void");

    // A tick of an earlier window that no settle hardened is never voided.
    let mut gw = fresh();
    open_trading(&mut gw);
    let a = keyed(&mut gw, 0x61);
    let commit = routed(
        &mut gw,
        &a,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    let chain = chained_blocks(&gw, &[&[commit]]);
    ingest(&mut gw, &chain);
    tick(&mut gw);
    seal(&mut gw);
    // Settled on L1, but nothing here hardened the window's tick.
    gw.last_settled_root = gw.seq.state.state_root();
    withdraw(&mut gw, &a, 10 * QUOTE_SCALE);
    let j = seal(&mut gw);
    refused(&mut gw, &j, cause, "is still pending");
}

/// Once close-only is observed before re-ingestion, the restored deposits are
/// refundable to their accounts. The close-only rebase keeps their records and
/// returns the cancelled hashes, which the wind-down publishes as
/// `MarketCloseOnly`.
#[test]
fn close_only_after_a_live_void_lists_the_restored_deposits_as_refundable() {
    let f = voidable(false);
    let mut gw = f.gw;
    let j = f.journal;
    let report = applied(&mut gw, &j, DeadIntent::EmptyAfterFence);
    let ids = |gw: &Gw, key: &[u8; 32]| {
        gw.refundable_credits(key)
            .into_iter()
            .map(|c| c.event.id)
            .collect::<Vec<_>>()
    };
    assert!(ids(&gw, &f.maker.key).is_empty(), "not before close-only");
    let hashes = gw
        .rebase_to_settled(&SettledL1 {
            block: 9,
            close_only: true,
            settled: false,
            batch_count: j.batch_id,
            root: j.witness.pre_state.state_root(),
            consumed_deposit_count: f.consumed,
        })
        .unwrap();
    assert_eq!(hashes, published(&j));
    gw.seq
        .reject_in_window(&hashes, perp_core::order::RejectReason::MarketCloseOnly);
    assert_eq!(
        rejected_as(&gw, perp_core::order::RejectReason::MarketCloseOnly),
        published(&j)
    );
    assert_eq!(
        gw.deposits.uncredited.keys().copied().collect::<Vec<_>>(),
        report.deposits
    );
    assert!(gw.deposits.routes.is_empty(), "the rebase drops the routes");
    assert_eq!(ids(&gw, &f.maker.key), vec![f.consumed]);
    assert_eq!(ids(&gw, &f.taker), vec![f.consumed + 1]);
    assert_eq!(ids(&gw, &f.operator), vec![f.consumed + 2]);
    gw.validate_deposit_state().unwrap();
    Gw::boot_restored(&gw.snapshot_plain()).unwrap();
}

/// A voided withdrawal is requested again with a new signature: the old one is
/// a replay, and the new leaf takes the next counter nonce.
#[test]
fn withdrawal_after_a_void_takes_the_next_counter_nonce_and_a_new_auth_nonce() {
    let f = voidable(false);
    let mut gw = f.gw;
    let auth = gw.accounts[&f.w.key].last_withdraw_nonce;
    applied(&mut gw, &f.journal, DeadIntent::EmptyAfterFence);
    assert_eq!(gw.accounts[&f.w.key].last_withdraw_nonce, auth);
    let amount = f.withdrawal.amount as i128;
    let replay = sign_withdrawal(&gw, &f.w, amount, auth);
    assert!(gw
        .account_withdraw(&f.w.key, 0, amount, f.w.address, auth, &replay)
        .is_err());
    let again = withdraw(&mut gw, &f.w, amount);
    assert_eq!(again.nonce, f.withdrawal.nonce + 1);
    assert_ne!(again.leaf(), f.withdrawal.leaf());
    assert_eq!(gw.accounts[&f.w.key].last_withdraw_nonce, auth + 1);
}

/// The replacement window's claimable withdrawals are its own: the voided
/// leaf is in neither its withdrawal set nor its claim proofs.
#[test]
fn the_replacement_withdrawals_root_excludes_voided_leaves() {
    let f = voidable(false);
    let mut gw = f.gw;
    applied(&mut gw, &f.journal, DeadIntent::EmptyAfterFence);
    let again = withdraw(&mut gw, &f.w, f.withdrawal.amount as i128);
    let replacement = seal(&mut gw);
    assert_eq!(replacement.batch_id, f.journal.batch_id);
    assert_eq!(
        replacement
            .ww
            .iter()
            .map(Withdrawal::leaf)
            .collect::<Vec<_>>(),
        vec![again.leaf()]
    );
    let proofs = &replacement.prepared.as_ref().unwrap().withdraw_proofs;
    assert_eq!(
        proofs.keys().copied().collect::<Vec<_>>(),
        vec![again.leaf()]
    );
    assert!(!proofs.contains_key(&f.withdrawal.leaf()));
}

/// The replacement window can be voided too: its deposits are the re-ingested
/// credits with their new notes, which are dropped from the archive, and a
/// landed deposit beyond the window keeps its record.
#[test]
fn double_void_of_the_replacement_restores_reingested_deposits_once() {
    let f = voidable(false);
    let mut gw = f.gw;
    applied(&mut gw, &f.journal, DeadIntent::EmptyAfterFence);
    assert_eq!(ingest(&mut gw, &f.chain), 3);
    // Another deposit lands after them and the admission cap refuses it.
    let late = routed(
        &mut gw,
        &f.maker,
        (1_000 * QUOTE_SCALE) as u128,
        Purpose::Collateral,
    );
    land_uncredited(&mut gw, &[late], None);
    let beyond = f.consumed + 3;
    assert!(gw.deposits.uncredited.contains_key(&beyond));
    let replacement = seal(&mut gw);
    let renewed = voided_notes(&replacement);
    assert!(renewed.is_disjoint(&voided_notes(&f.journal)));
    let report = applied(&mut gw, &replacement, DeadIntent::Cancelled);
    assert_eq!(
        report.deposits,
        vec![f.consumed, f.consumed + 1, f.consumed + 2]
    );
    assert_eq!(report.archive_dropped, 3);
    assert!(!gw
        .archive
        .notes()
        .iter()
        .any(|r| renewed.contains(&r.commitment)));
    assert!(!gw
        .processed_deposit_txs
        .contains(&hex0x(&f.chain[&f.consumed].1[0].tx)));
    assert_eq!(
        gw.deposits.uncredited.keys().copied().collect::<Vec<_>>(),
        vec![f.consumed, f.consumed + 1, f.consumed + 2, beyond]
    );
    assert_eq!(gw.deposits.routes.len(), 4);
    assert_eq!(published(&replacement), published(&f.journal));
    assert_eq!(
        rejected_as(&gw, perp_core::order::RejectReason::Cancelled),
        published(&f.journal)
    );
    gw.validate_deposit_state().unwrap();
    assert_eq!(ingest(&mut gw, &f.chain), 3);
}

/// A credential rotation between the void and re-ingestion moves the restored
/// records with the account: the state validates and restores, the close-only
/// rebase keeps them refundable to the new key, and re-ingestion credits the
/// deposit to the new key.
#[test]
fn rotation_between_void_and_reingest_keeps_refund_and_boot_valid() {
    let f = voidable(false);
    let mut gw = f.gw;
    let j = f.journal;
    applied(&mut gw, &j, DeadIntent::EmptyAfterFence);
    let maker_commit = f.commits[0];
    let new = rotate(&mut gw, &f.maker);
    assert_eq!(gw.deposits.routes[&maker_commit].key, new);
    assert_eq!(gw.deposits.uncredited[&f.consumed].route.key, new);
    assert!(gw.accounts[&new]
        .deposit_authorizations
        .contains_key(&maker_commit));
    gw.validate_deposit_state().unwrap();
    let plain = gw.snapshot_plain();
    let mut closed = Gw::boot_restored(&plain).unwrap();
    closed
        .rebase_to_settled(&SettledL1 {
            block: 9,
            close_only: true,
            settled: false,
            batch_count: j.batch_id,
            root: j.witness.pre_state.state_root(),
            consumed_deposit_count: f.consumed,
        })
        .unwrap();
    let refundable = |gw: &Gw, key: &[u8; 32]| {
        gw.refundable_credits(key)
            .into_iter()
            .map(|c| c.event.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(refundable(&closed, &new), vec![f.consumed]);
    assert!(refundable(&closed, &f.maker.key).is_empty());
    assert_eq!(ingest(&mut gw, &f.chain), 3);
    assert_eq!(gw.deposits.credits[&f.consumed].route.key, new);
    assert_eq!(
        gw.seq.state.position(&f.maker.owner, 0).unwrap().collateral,
        50_000 * QUOTE_SCALE
    );
    gw.validate_deposit_state().unwrap();
}
