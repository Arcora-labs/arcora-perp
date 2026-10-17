use super::*;
fn fresh() -> Gw {
    Gw::boot_with(GenesisMode::Production)
}
fn permit(gw: &mut Gw, amount: u128, purpose: Purpose, market: u64) -> ([u8; 32], [u8; 32]) {
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
    let c = gw
        .authorize_routed_deposit(&key, [0x42; 20], amount, market, purpose, u64::MAX)
        .unwrap();
    (key, c)
}
fn page(gw: &Gw, commits: &[[u8; 32]]) -> Page {
    let start = gw.deposit_cursor();
    let mut tip = start.tip;
    let block = Block {
        number: start.anchor.as_ref().map_or(1, |b| b.number + 1),
        hash: [7; 32],
        timestamp: None,
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
        .as_chunks::<2>()
        .0
        .iter()
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
    assert_eq!(&new[..8], b"DPSNAP9\0");
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

#[tokio::test]
async fn a01_cancellation_at_ack_keeps_barrier_and_retry_never_recredits() {
    let mut gw = fresh();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    let (app, source, mut rx) = app_with_page(gw, p);
    let job = tokio::spawn({
        let app = app.clone();
        async move { ingest_once(&app).await }
    });
    let abandoned_ack = rx.recv().await.unwrap();
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert!(app.gw.lock().await.deposits.check_ready().is_err());
    drop(abandoned_ack);
    let job = tokio::spawn({
        let app = app.clone();
        async move { ingest_once(&app).await }
    });
    let ack = rx.recv().await.unwrap();
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let path = std::env::temp_dir().join(format!("a01-restart-{}", hex0x(&csprng_bytes32())));
    assert!(write_snapshot(&app, &path, [42; 32], Arc::new(Mutex::new(()))).await);
    ack.send(true).unwrap();
    assert_eq!(job.await.unwrap().unwrap(), 0);
    let plain = snapshot::open(&std::fs::read(&path).unwrap(), &[42; 32]).unwrap();
    std::fs::remove_file(path).unwrap();
    let restored = Gw::boot_restored(&plain).unwrap();
    assert_eq!(restored.seq.state.consumed_deposit_count, 1);
    assert_eq!(restored.deposits.credits.len(), 1);
    assert_eq!(
        restored.accounts.values().next().unwrap().deposit_counter,
        1
    );
}
#[test]
fn a01_legacy_bootstrap_half_transfer_resumes_without_minting_or_user_credit() {
    let mut gw = fresh();
    let (key, c) = permit(
        &mut gw,
        bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
        Purpose::InsuranceBootstrap,
        0,
    );
    let a = &gw.accounts[&key];
    let wallet = a.wallet;
    let blind = a.deposit_authorizations[&c];
    let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;
    let mut note_blind = [0xb0; 32];
    note_blind[..8].copy_from_slice(&0u64.to_le_bytes());
    let note = Note::new(wallet.owner, 0, amount, note_blind);
    gw.seq
        .apply(&BatchOp::Deposit {
            owner: wallet.owner,
            asset_id: 0,
            amount,
            blinding: note_blind,
            from: [0x42; 20],
            deposit_id: 0,
            deposit_blind: blind,
        })
        .unwrap();
    gw.bootstrap = bootstrap::Bootstrap::DepositApplied {
        note_commitment: note.commitment::<Keccak256>(),
        spend_key: wallet.spend_key,
        deposit_id: 0,
    };
    gw.accounts.get_mut(&key).unwrap().deposit_counter = 1;
    let prices: Vec<_> = gw
        .mkts
        .iter()
        .map(|m| (m.id, m.reference_price, m.px, m.live))
        .collect();
    let legacy = postcard::to_allocvec(&(&gw, prices)).unwrap();
    let mut gw = Gw::boot_restored(&legacy).unwrap();
    let p = Page {
        start: gw.deposit_cursor(),
        end: Block {
            number: 1,
            hash: [7; 32],
            timestamp: None,
        },
        events: vec![],
    };
    gw.apply_deposit_page(p).unwrap();
    assert_eq!(gw.seq.state.insurance_fund, amount);
    assert_eq!(gw.seq.state.consumed_deposit_count, 1);
    assert_eq!(gw.accounts[&key].deposit_counter, 1);
    assert!(!gw
        .seq
        .state
        .positions
        .keys()
        .any(|(owner, _)| *owner == wallet.owner));
    assert!(matches!(
        gw.bootstrap,
        bootstrap::Bootstrap::InsuranceApplied { .. }
    ));
    let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    let p = Page {
        start: restored.deposit_cursor(),
        end: Block {
            number: 1,
            hash: [7; 32],
            timestamp: None,
        },
        events: vec![],
    };
    restored.apply_deposit_page(p).unwrap();
    assert_eq!(restored.seq.state.insurance_fund, amount);
    let w = restored.seq.seal_window();
    let mut state = w.pre_state.clone();
    let roots = perp_core::commitment::derive_roots(&mut state, &w.ops, &w.manifest).unwrap();
    assert_eq!(roots.new_state_root, restored.seq.state.state_root());
    assert!(state.conservation_holds());
}

/// The v6 layout (no permit deadlines) is still readable when no permit is
/// outstanding: its credits, secrets and replay bytes carry over, landed credits
/// get deadline 0, and the next snapshot is written in the current layout.
#[test]
fn a05_a01_v6_migration_preserves_credits_secrets_and_replay_bytes() {
    let mut gw = fresh();
    let (_, credited) = permit(&mut gw, 5_000_000, Purpose::Collateral, 1);
    let block = page(&gw, &[credited]);
    gw.apply_deposit_page(block).unwrap();
    let prices: Vec<_> = gw
        .mkts
        .iter()
        .map(|m| (m.id, m.reference_price, m.px, m.live))
        .collect();
    let v6_of = |gw: &Gw| {
        let legacy = DepositStateV6::from_current(&gw.deposits);
        let mut v6 = SNAPSHOT_V6.to_vec();
        v6.extend_from_slice(&postcard::to_allocvec(&(gw, &prices, &legacy)).unwrap());
        v6
    };
    let root = gw.seq.state.state_root();
    let prefix = (
        gw.seq.state.consumed_deposit_count,
        gw.seq.state.consumed_deposit_tip,
    );
    let mut restored = Gw::boot_restored(&v6_of(&gw)).unwrap();
    assert_eq!(restored.seq.state.state_root(), root);
    assert_eq!(
        (
            restored.seq.state.consumed_deposit_count,
            restored.seq.state.consumed_deposit_tip
        ),
        prefix
    );
    assert_eq!(restored.deposits.credits.len(), 1);
    let mut expected = gw.deposits.credits[&0].clone();
    expected.route.valid_until = 0;
    assert_eq!(restored.deposits.credits[&0], expected);
    let current = restored.snapshot_plain();
    assert!(current.starts_with(crate::wind_down::SNAPSHOT_V9));
    assert!(current.windows(SNAPSHOT_V7.len()).any(|w| w == SNAPSHOT_V7));
    assert_eq!(
        Gw::boot_restored(&current).unwrap().snapshot_plain(),
        current
    );
    let witness = restored.seq.seal_window();
    let mut replay = witness.pre_state.clone();
    let roots =
        perp_core::commitment::derive_roots(&mut replay, &witness.ops, &witness.manifest).unwrap();
    assert_eq!(roots.new_state_root, restored.seq.state.state_root());
    assert_eq!(replay.consumed_deposit_tip, prefix.1);

    // An outstanding permit was signed for the earlier vault ABI: refused.
    let (_, _pending) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    let error = Gw::boot_restored(&v6_of(&gw)).err().unwrap();
    assert!(error.contains("outstanding deposit permits"), "{error}");
    // So is a blind-only permit without a route.
    gw.deposits.routes.clear();
    let error = Gw::boot_restored(&v6_of(&gw)).err().unwrap();
    assert!(error.contains("outstanding deposit permits"), "{error}");
}

#[test]
fn permit_reuse_needs_the_same_request_and_a_minute_left() {
    let mut gw = fresh();
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
    let until = 10_000;
    let c = gw
        .authorize_routed_deposit(&key, [0x42; 20], 5_000_000, 0, Purpose::Collateral, until)
        .unwrap();
    let request = Route {
        valid_until: 0,
        ..gw.deposits.routes[&c].clone()
    };
    assert_eq!(gw.deposits.routes[&c].valid_until, until);
    assert_eq!(gw.held_permit_deadline(&c, &request, 0), Some(until));
    let last = until - PERMIT_REUSE_MARGIN_SECS;
    assert_eq!(gw.held_permit_deadline(&c, &request, last), Some(until));
    assert_eq!(gw.held_permit_deadline(&c, &request, last + 1), None);
    for other in [
        Route {
            amount: 5_000_001,
            ..request.clone()
        },
        Route {
            market: 1,
            ..request.clone()
        },
        Route {
            from: [0x43; 20],
            ..request.clone()
        },
    ] {
        assert_eq!(gw.held_permit_deadline(&c, &other, 0), None);
    }
    gw.accounts
        .get_mut(&key)
        .unwrap()
        .deposit_authorizations
        .remove(&c);
    assert_eq!(gw.held_permit_deadline(&c, &request, 0), None);
}

#[test]
fn expired_permits_are_dropped_against_the_finalized_block_time_only() {
    let mut gw = fresh();
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
    let early = gw
        .authorize_routed_deposit(&key, [0x42; 20], 5_000_000, 0, Purpose::Collateral, 1_000)
        .unwrap();
    let exact = gw
        .authorize_routed_deposit(&key, [0x42; 20], 6_000_000, 0, Purpose::Collateral, 1_500)
        .unwrap();
    let late = gw
        .authorize_routed_deposit(&key, [0x42; 20], 7_000_000, 0, Purpose::Collateral, 2_000)
        .unwrap();
    // A restored anchor has no timestamp: nothing is collected.
    let mut idle = page(&gw, &[]);
    gw.apply_deposit_page(idle.clone()).unwrap();
    assert_eq!(gw.deposits.routes.len(), 3);
    gw.deposits.dirty = false;
    // A block at 1,500 s can still accept a permit valid until 1,500 s.
    idle.start = gw.deposit_cursor();
    idle.end = Block {
        number: 2,
        hash: [8; 32],
        timestamp: Some(1_500),
    };
    gw.apply_deposit_page(idle).unwrap();
    assert!(!gw.deposits.routes.contains_key(&early));
    assert!(gw.deposits.routes.contains_key(&exact) && gw.deposits.routes.contains_key(&late));
    let blinds = &gw.accounts[&key].deposit_authorizations;
    assert!(!blinds.contains_key(&early));
    assert!(blinds.contains_key(&exact) && blinds.contains_key(&late));
    assert!(gw.deposits.dirty, "the removal must be persisted");
    gw.validate_deposit_state().unwrap();
    // A page that credits one permit also collects the expired rest.
    let mut credit = page(&gw, &[late]);
    credit.end.timestamp = Some(1_501);
    for e in &mut credit.events {
        e.block = credit.end.clone();
    }
    assert_eq!(gw.apply_deposit_page(credit).unwrap(), 1);
    assert!(gw.deposits.routes.is_empty());
    assert!(gw.accounts[&key].deposit_authorizations.is_empty());
    assert_eq!(gw.deposits.credits.len(), 1);
}

#[test]
fn ingestion_checks_the_permit_payer_not_the_current_binding() {
    let mut gw = fresh();
    let (key, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    // The binding moved after the permit was issued.
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x43; 20]);
    assert_eq!(gw.apply_deposit_page(p).unwrap(), 1);
    assert_eq!(gw.deposits.credits[&0].event.from, [0x42; 20]);
}

#[test]
fn close_only_stops_crediting_and_reports_unsettled_credits_as_refundable() {
    let mut gw = fresh();
    let (key, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.apply_deposit_page(p).unwrap();
    let credit = gw.deposits.credits[&0].clone();
    // Unknown settled count: reported as credited, as before.
    assert_eq!(gw.credit_status(&credit), CreditStatus::Credited);
    gw.note_settled_deposit_count(0);
    assert_eq!(gw.credit_status(&credit), CreditStatus::CreditedUnsettled);
    assert!(gw.refundable_credits(&key).is_empty());
    assert!(gw
        .v1_account(&key)
        .unwrap()
        .get("refundableDeposits")
        .is_none());
    gw.deposits.l1_close_only = true;
    assert_eq!(gw.credit_status(&credit), CreditStatus::Refundable);
    assert_eq!(gw.refundable_credits(&key).len(), 1);
    assert_eq!(
        gw.v1_account(&key).unwrap()["refundableDeposits"],
        serde_json::json!([{
            "id": 0,
            "from": hex0x(&[0x42; 20]),
            "ownerCommit": hex0x(&c),
            "amount": "5000000",
        }])
    );
    // A settled count never goes back down; once it covers the credit it is settled.
    gw.note_settled_deposit_count(1);
    gw.note_settled_deposit_count(0);
    assert_eq!(gw.deposits.settled_count, Some(1));
    assert_eq!(gw.credit_status(&credit), CreditStatus::Credited);
    assert_eq!(
        gw.v1_account(&key).unwrap()["refundableDeposits"],
        serde_json::json!([])
    );
    // No later page is credited.
    let (_, next) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[next]);
    let before = gw.snapshot_plain();
    assert_eq!(gw.apply_deposit_page(p).unwrap_err(), CLOSE_ONLY_INTAKE);
    assert_eq!(before, gw.snapshot_plain());
}

#[tokio::test]
async fn close_only_intake_verifies_the_prefix_once_then_stops_polling() {
    let mut gw = fresh();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.deposits.l1_close_only = true;
    let (app, source, _rx) = app_with_page(gw, p);
    assert!(app.gw.lock().await.deposits.check_ready().is_err());
    assert_eq!(ingest_once(&app).await.unwrap(), 0);
    {
        let gw = app.gw.lock().await;
        assert!(
            gw.deposits.check_ready().is_ok(),
            "the fetch verified the prefix"
        );
        assert!(gw.deposits.credits.is_empty());
        assert_eq!(gw.deposits.last_error.as_deref(), Some(CLOSE_ONLY_INTAKE));
    }
    assert_eq!(ingest_once(&app).await.unwrap(), 0);
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The close-only rebase returns a gateway to the finalized settled state: credits
/// no settled batch consumed become refund records (kept across a restart for the
/// refund views), permits that never landed are dropped with their blinds, and
/// every precondition refuses without changing anything.
#[test]
fn close_only_rebase_keeps_only_the_settled_deposit_prefix() {
    use crate::wind_down::{Observation, SettledL1};
    let mut gw = fresh();
    let (a, ca) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    gw.apply_deposit_page(page(&gw, &[ca])).unwrap();
    gw.deposits.dirty = false;
    let (w0, ww0) = gw.begin_window_settle(0).unwrap().unwrap();
    let prepared =
        crate::prover_client::prove_and_prepare(&crate::prover_client::MockProverClient, &w0, &ww0)
            .unwrap();
    gw.commit_window_settle(
        w0.batch_id,
        w0.manifest.ordered.clone(),
        Vec::new(),
        prepared,
        L1Status::default(),
        trading_gate::GateObservation::StaysClosed,
    );
    let settled_root = gw.seq.state.state_root();
    assert_eq!(gw.last_settled_root, settled_root);
    // Unsettled after the settle: a credited deposit and a permit that never lands.
    let (b, cb) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    gw.apply_deposit_page(page(&gw, &[cb])).unwrap();
    let (c, cc) = permit(&mut gw, 1_000_000, Purpose::Collateral, 0);
    assert_eq!(gw.seq.state.consumed_deposit_count, 2);
    assert!(gw.close_only_rebase_applies(true, false));
    assert!(!gw.close_only_rebase_applies(false, false));
    assert!(!gw.close_only_rebase_applies(true, true));
    let l1 = SettledL1 {
        block: 9,
        close_only: true,
        settled: false,
        batch_count: 1,
        root: settled_root,
        consumed_deposit_count: 1,
    };
    for bad in [
        SettledL1 {
            close_only: false,
            ..l1
        },
        SettledL1 {
            settled: true,
            ..l1
        },
        SettledL1 {
            batch_count: 2,
            ..l1
        },
        SettledL1 {
            root: [1; 32],
            ..l1
        },
        SettledL1 {
            consumed_deposit_count: 2,
            ..l1
        },
    ] {
        let before = gw.snapshot_plain();
        assert!(gw.rebase_to_settled(&bad).is_err());
        assert_eq!(gw.snapshot_plain(), before, "a refusal changes nothing");
    }
    let voided = gw.rebase_to_settled(&l1).unwrap();
    assert!(voided.is_empty(), "the window held no orders");
    assert_eq!(gw.seq.state.state_root(), settled_root);
    assert_eq!(gw.seq.state.consumed_deposit_count, 1);
    assert_eq!(gw.seq.current_window_id(), 1);
    assert_eq!(
        gw.deposits.credits.keys().copied().collect::<Vec<_>>(),
        vec![0]
    );
    assert_eq!(
        gw.deposits.refunds.keys().copied().collect::<Vec<_>>(),
        vec![1]
    );
    assert!(gw.deposits.routes.is_empty());
    assert!(!gw.accounts[&c].deposit_authorizations.contains_key(&cc));
    assert!(gw.deposits.anchor.is_none());
    assert!(gw.deposits.l1_close_only);
    assert!(gw.refundable_credits(&a).is_empty());
    let rows: Vec<_> = gw
        .refundable_credits(&b)
        .into_iter()
        .map(refund_json)
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], 1);
    assert!(!gw.close_only_rebase_applies(true, false));
    Observation {
        block: 9,
        close_only: true,
        settled: false,
        batch_count: 1,
        root: settled_root,
    }
    .check_start(&gw)
    .unwrap();
    // The refund rows persist; the ledger still validates after a restart.
    let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    assert_eq!(restored.deposits.refunds, gw.deposits.refunds);
    assert_eq!(restored.seq.state.state_root(), settled_root);
    // A second rebase has nothing left to do and refuses nothing it needs.
    assert!(gw.rebase_to_settled(&l1).unwrap().is_empty());
}
