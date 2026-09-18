use super::*;
fn fresh() -> Gw {
    Gw::boot_with(GenesisMode::Production)
}
fn permit(gw: &mut Gw, amount: u128, purpose: Purpose, market: u64) -> ([u8; 32], [u8; 32]) {
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
    let c = gw
        .authorize_routed_deposit(&key, [0x42; 20], amount, market, purpose)
        .unwrap();
    (key, c)
}
fn page(gw: &Gw, commits: &[[u8; 32]]) -> Page {
    let start = gw.deposit_cursor();
    let mut tip = start.tip;
    let block = Block {
        number: start.anchor.as_ref().map_or(1, |b| b.number + 1),
        hash: [7; 32],
    };
    let events = commits
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let r = &gw.deposits.routes[c];
            let id = start.count + i as u64;
            tip = perp_core::merkle::deposit_chain_fold(
                &tip,
                &perp_core::merkle::deposit_leaf(&r.from, c, r.amount, id),
            );
            Event {
                id,
                from: r.from,
                commit: *c,
                amount: r.amount,
                tip,
                tx: [9; 32],
                tx_index: 0,
                log_index: i as u64,
                block: block.clone(),
            }
        })
        .collect();
    Page {
        start,
        end: block,
        events,
    }
}
#[test]
fn a01_offline_customers_and_same_transaction_credit_once_in_l1_order() {
    let mut gw = fresh();
    let (a, ca) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let (b, cb) = permit(&mut gw, 7_000_000, Purpose::Collateral, 1);
    let p = page(&gw, &[ca, cb]);
    assert_eq!(gw.apply_deposit_page(p.clone()).unwrap(), 2);
    assert!(gw.apply_deposit_page(p).is_err());
    assert_eq!(gw.seq.state.consumed_deposit_count, 2);
    assert_eq!(gw.accounts[&a].deposit_counter, 1);
    assert_eq!(gw.accounts[&b].deposit_counter, 1);
    assert_eq!(gw.deposits.credits.len(), 2);
    assert!(gw.seq.state.conservation_holds());
}
#[test]
fn a01_insurance_is_never_user_collateral() {
    let mut gw = fresh();
    let (_, c) = permit(
        &mut gw,
        bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
        Purpose::InsuranceBootstrap,
        0,
    );
    let p = page(&gw, &[c]);
    gw.apply_deposit_page(p).unwrap();
    assert_eq!(
        gw.seq.state.insurance_fund,
        bootstrap::MIN_BOOTSTRAP_INSURANCE
    );
    assert!(gw.seq.state.conservation_holds());
}
#[test]
fn a01_legacy_permits_are_preserved_without_automatic_routing() {
    let mut gw = fresh();
    let (key, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.deposits.routes.clear();
    let before = gw.seq.state.state_root();
    assert!(gw.apply_deposit_page(p).unwrap_err().contains("routing"));
    assert_eq!(gw.seq.state.state_root(), before);
    assert!(gw.accounts[&key].deposit_authorizations.contains_key(&c));
}
#[test]
fn a01_snapshot_v6_roundtrip_preserves_routing_and_consumption() {
    let mut gw = fresh();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.apply_deposit_page(p).unwrap();
    let raw = gw.snapshot_plain();
    let restored = Gw::boot_restored(&raw).unwrap();
    assert_eq!(raw, restored.snapshot_plain());
    assert_eq!(restored.deposits.credits.len(), 1);
    assert_eq!(
        gw.seq.state.consumed_deposit_tip,
        restored.seq.state.consumed_deposit_tip
    );
}

#[test]
fn a01_atomic_second_funding_failure_preserves_every_account_and_replay_op() {
    let mut gw = fresh();
    let (_, ca) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let (b, cb) = permit(&mut gw, 7_000_000, Purpose::Collateral, 1);
    let p = page(&gw, &[ca, cb]);
    gw.accounts.get_mut(&b).unwrap().wallet.spend_key = [0xee; 32];
    let before = gw.snapshot_plain();
    assert!(gw
        .apply_deposit_page(p)
        .unwrap_err()
        .contains("atomic deposit"));
    assert_eq!(
        before,
        gw.snapshot_plain(),
        "no partial Deposit, FundPosition, cursor, note, or replay log"
    );
}
#[test]
fn a01_counter_overflow_and_duplicate_commit_leave_no_partial_credit() {
    let mut gw = fresh();
    let (a, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let duplicate = page(&gw, &[c, c]);
    let before = gw.snapshot_plain();
    assert!(gw.apply_deposit_page(duplicate).is_err());
    assert_eq!(before, gw.snapshot_plain());
    gw.accounts.get_mut(&a).unwrap().deposit_counter = u64::MAX;
    let p = page(&gw, &[c]);
    let before = gw.snapshot_plain();
    assert!(gw
        .apply_deposit_page(p)
        .unwrap_err()
        .contains("counter overflow"));
    assert_eq!(before, gw.snapshot_plain());
}
#[test]
fn a01_explicit_legacy_adoption_is_owned_and_immutable() {
    let mut gw = fresh();
    let (a, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 1);
    let intended = gw.deposits.routes.remove(&c).unwrap();
    let (_, other) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    let mut wrong = gw.deposits.routes[&other].clone();
    wrong.amount = 5_000_000;
    assert!(gw.adopt_deposit_route(c, wrong).is_err());
    gw.adopt_deposit_route(c, intended.clone()).unwrap();
    gw.adopt_deposit_route(c, intended.clone()).unwrap();
    let mut wrong = intended;
    wrong.market = 0;
    assert!(gw.adopt_deposit_route(c, wrong).is_err());
    let p = page(&gw, &[c]);
    gw.apply_deposit_page(p).unwrap();
    assert_eq!(
        gw.seq.state.positions[&(gw.accounts[&a].wallet.owner, 1)].collateral,
        5_000_000
    );
    assert!(!gw
        .seq
        .state
        .positions
        .contains_key(&(gw.accounts[&a].wallet.owner, 0)));
}
#[test]
fn a01_bootstrap_then_customer_prefix_and_rollback_proof_replay_agree() {
    let mut gw = fresh();
    let (ins, ci) = permit(
        &mut gw,
        bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
        Purpose::InsuranceBootstrap,
        0,
    );
    let (a, ca) = permit(&mut gw, 5_000_000, Purpose::Collateral, 1);
    let p = page(&gw, &[ci, ca]);
    gw.apply_deposit_page(p).unwrap();
    assert!(!gw
        .seq
        .state
        .positions
        .keys()
        .any(|(owner, _)| *owner == gw.accounts[&ins].wallet.owner));
    assert_eq!(
        gw.seq.state.positions[&(gw.accounts[&a].wallet.owner, 1)].collateral,
        5_000_000
    );
    let w = gw.seq.seal_window();
    let mut replay = w.pre_state.clone();
    let roots = perp_core::commitment::derive_roots(&mut replay, &w.ops, &w.manifest).unwrap();
    assert_eq!(roots.new_state_root, gw.seq.state.state_root());
    assert_eq!(roots.deposits_root, gw.seq.state.consumed_deposit_tip);
    let (_, c) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.apply_deposit_page(p).unwrap();
    gw.seq.rollback_window(&w);
    let raw = gw.snapshot_plain();
    let mut gw = Gw::boot_restored(&raw).unwrap();
    let w = gw.seq.seal_window();
    let mut replay = w.pre_state.clone();
    let roots = perp_core::commitment::derive_roots(&mut replay, &w.ops, &w.manifest).unwrap();
    assert_eq!(roots.new_state_root, gw.seq.state.state_root());
    assert_eq!(roots.deposits_root, gw.seq.state.consumed_deposit_tip);
    assert_eq!(replay.consumed_deposit_count, 3);
    assert!(replay.conservation_holds());
    assert_eq!(
        w.ops
            .iter()
            .filter(|op| matches!(op, BatchOp::Deposit { .. }))
            .count(),
        3
    );
}
#[test]
fn a01_actual_frozen_v5_fixture_migrates_losslessly_with_pending_permit() {
    let encoded = include_str!("legacy-v5.hex").trim();
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|c| (hex_nibble(c[0]).unwrap() << 4) | hex_nibble(c[1]).unwrap())
        .collect();
    assert_eq!(&bytes[..8], b"DPSNAP5\0");
    let plain = snapshot::open(&bytes, &[42; 32]).unwrap();
    let gw = Gw::boot_restored(&plain).unwrap();
    assert_eq!(gw.accounts.len(), 1);
    let account = gw.accounts.values().next().unwrap();
    assert_eq!(
        (
            account.last_signed_nonce,
            account.last_sealed_nonce,
            account.rebind_counter
        ),
        (17, 19, 3)
    );
    assert_eq!(account.deposit_counter, 1);
    assert_eq!(account.deposit_authorizations.len(), 1);
    assert!(gw.deposits.routes.is_empty());
    assert!(gw.deposits.credits.is_empty());
    assert_eq!(gw.seq.state.consumed_deposit_count, 1);
    // Gw's old positional fields, all secrets, replay ops, notes and market prices
    // serialize byte-for-byte to the genuine old binary's plaintext.
    let prices: Vec<_> = gw
        .mkts
        .iter()
        .map(|m| (m.id, m.reference_price, m.px, m.live))
        .collect();
    assert_eq!(postcard::to_allocvec(&(&gw, prices)).unwrap(), plain);
    let new = snapshot::seal(&gw.snapshot_plain(), &[42; 32]);
    assert_eq!(&new[..8], b"DPSNAP6\0");
    let restored = Gw::boot_restored(&snapshot::open(&new, &[42; 32]).unwrap()).unwrap();
    assert_eq!(gw.snapshot_plain(), restored.snapshot_plain());
}
#[test]
fn a01_corrupt_receipt_prefix_or_snapshot_version_refuses_restore() {
    let mut gw = fresh();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.apply_deposit_page(p).unwrap();
    let good = gw.snapshot_plain();
    let mut bad = good.clone();
    bad.extend([0]);
    assert!(Gw::boot_restored(&bad).is_err());
    let mut bad = good;
    bad[4] ^= 1;
    assert!(Gw::boot_restored(&bad).is_err());
    gw.deposits.credits.get_mut(&0).unwrap().event.tip[0] ^= 1;
    assert!(Gw::boot_restored(&gw.snapshot_plain()).is_err());
}

struct Pages {
    page: Page,
    calls: std::sync::atomic::AtomicUsize,
    error: std::sync::Mutex<Option<Error>>,
}
impl crate::deposit_rpc::DepositSource for Pages {
    fn fetch(&self, cursor: Cursor) -> Result<Page, Error> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(e) = self.error.lock().unwrap().clone() {
            return Err(e);
        }
        if cursor.count == self.page.start.count {
            Ok(self.page.clone())
        } else {
            Ok(Page {
                start: cursor,
                end: self.page.end.clone(),
                events: vec![],
            })
        }
    }
}
fn app_with_page(
    gw: Gw,
    p: Page,
) -> (Shared, Arc<Pages>, tokio::sync::mpsc::Receiver<SnapshotAck>) {
    let mut app = crate::tests::test_app();
    let a = Arc::get_mut(&mut app).unwrap();
    let source = Arc::new(Pages {
        page: p,
        calls: 0.into(),
        error: std::sync::Mutex::new(None),
    });
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    a.snapshot_req = Some(tx);
    a.deposit_source = Some(source.clone());
    a.gw = Mutex::new(gw);
    a.gw.get_mut().deposits.required = true;
    (app, source, rx)
}
#[tokio::test]
async fn a01_auto_and_manual_race_wait_for_durable_ack_then_credit_once() {
    let mut gw = fresh();
    let (a, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    let (app, source, mut rx) = app_with_page(gw, p);
    let auto = tokio::spawn({
        let app = app.clone();
        async move { ingest_once(&app).await }
    });
    let ack = rx.recv().await.unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", hex0x(&a).parse().unwrap());
    let manual = tokio::spawn({
        let app = app.clone();
        async move { confirm(&app, &headers, &hex0x(&[9; 32]), 0, Purpose::Collateral).await }
    });
    tokio::task::yield_now().await;
    assert!(!auto.is_finished());
    assert!(!manual.is_finished());
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(app.gw.lock().await.deposits.check_ready().is_err());
    ack.send(true).unwrap();
    assert_eq!(auto.await.unwrap().unwrap(), 1);
    assert_eq!(manual.await.unwrap().status(), StatusCode::OK);
    let gw = app.gw.lock().await;
    assert_eq!(gw.deposits.credits.len(), 1);
    assert_eq!(gw.seq.state.consumed_deposit_count, 1);
}
#[tokio::test]
async fn a01_disk_failure_retries_persistence_before_rpc_and_restart_is_exactly_once() {
    let mut gw = fresh();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    let before = gw.snapshot_plain();
    let (app, source, mut rx) = app_with_page(gw, p.clone());
    let t = tokio::spawn({
        let app = app.clone();
        async move { ingest_once(&app).await }
    });
    rx.recv().await.unwrap().send(false).unwrap();
    assert!(t.await.unwrap().is_err());
    assert!(app.gw.lock().await.deposits.dirty);
    let t = tokio::spawn({
        let app = app.clone();
        async move { ingest_once(&app).await }
    });
    let ack = rx.recv().await.unwrap();
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    ack.send(true).unwrap();
    assert_eq!(t.await.unwrap().unwrap(), 0);
    let durable = app.gw.lock().await.snapshot_plain();
    let mut old = Gw::boot_restored(&before).unwrap();
    assert_eq!(old.apply_deposit_page(p).unwrap(), 1);
    let recovered = Gw::boot_restored(&durable).unwrap();
    assert_eq!(
        postcard::to_allocvec(&old.seq).unwrap(),
        postcard::to_allocvec(&recovered.seq).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&old.deposits).unwrap(),
        postcard::to_allocvec(&recovered.deposits).unwrap()
    );
    let restored = Gw::boot_restored(&durable).unwrap();
    assert_eq!(restored.seq.state.consumed_deposit_count, 1);
}
#[tokio::test]
async fn a01_rpc_failure_preserves_cursor_and_finalized_reorg_halt_survives_restart() {
    let mut gw = fresh();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    let (app, source, mut rx) = app_with_page(gw, p);
    *source.error.lock().unwrap() = Some(Error::Retry("injected RPC timeout".into()));
    assert!(ingest_once(&app).await.is_err());
    assert_eq!(app.gw.lock().await.seq.state.consumed_deposit_count, 0);
    assert!(app.gw.lock().await.deposits.check_ready().is_err());
    *source.error.lock().unwrap() = Some(Error::Halt("injected finalized anchor reorg".into()));
    let t = tokio::spawn({
        let app = app.clone();
        async move { ingest_once(&app).await }
    });
    rx.recv().await.unwrap().send(true).unwrap();
    assert!(t.await.unwrap().is_err());
    let raw = app.gw.lock().await.snapshot_plain();
    let restored = Gw::boot_restored(&raw).unwrap();
    assert!(restored
        .deposits
        .check_ready()
        .unwrap_err()
        .contains("reorg"));
    *source.error.lock().unwrap() = None;
    let before = source.calls.load(std::sync::atomic::Ordering::SeqCst);
    assert!(ingest_once(&app).await.is_err());
    assert_eq!(
        source.calls.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
}
