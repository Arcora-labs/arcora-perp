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
/// The genuine file an A01-era (v5) binary wrote is refused: its envelope is not
/// DPSNAP10, and its bytes under the current header fail authentication. The
/// current writer's output restores byte-for-byte.
#[test]
fn a01_actual_frozen_v5_fixture_is_refused() {
    let encoded = include_str!("legacy-v5.hex").trim();
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| (hex_nibble(c[0]).unwrap() << 4) | hex_nibble(c[1]).unwrap())
        .collect();
    assert_eq!(&bytes[..8], b"DPSNAP5\0");
    let error = snapshot::open(&bytes, &[42; 32]).unwrap_err();
    assert!(error.contains("DPSNAP10"), "{error}");
    let mut relabelled = bytes.clone();
    relabelled[..8].copy_from_slice(b"DPSNAP10");
    assert!(snapshot::open(&relabelled, &[42; 32]).is_err());
    let gw = fresh();
    let new = snapshot::seal(&gw.snapshot_plain(), &[42; 32]);
    assert_eq!(&new[..8], b"DPSNAP10");
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
fn a01_bootstrap_half_transfer_resumes_without_minting_or_user_credit() {
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
    // The half-transferred bootstrap consumed its deposit outside a receipt-
    // recording page; the ledger carries it as its inherited prefix.
    gw.deposits.legacy_prefix = Some((
        gw.seq.state.consumed_deposit_count,
        gw.seq.state.consumed_deposit_tip,
    ));
    gw.deposits.routes.clear();
    let mut gw = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
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

/// Credits, the consumed prefix and the replay op-log survive a v10 round trip;
/// the same state behind the earlier deposit-layer header is refused.
#[test]
fn credits_and_replay_survive_restore_and_the_v6_layout_is_refused() {
    let mut gw = fresh();
    let (_, credited) = permit(&mut gw, 5_000_000, Purpose::Collateral, 1);
    let block = page(&gw, &[credited]);
    gw.apply_deposit_page(block).unwrap();
    let root = gw.seq.state.state_root();
    let prefix = (
        gw.seq.state.consumed_deposit_count,
        gw.seq.state.consumed_deposit_tip,
    );
    let current = gw.snapshot_plain();
    let mut restored = Gw::boot_restored(&current).unwrap();
    assert_eq!(restored.seq.state.state_root(), root);
    assert_eq!(
        (
            restored.seq.state.consumed_deposit_count,
            restored.seq.state.consumed_deposit_tip
        ),
        prefix
    );
    assert_eq!(restored.deposits.credits.len(), 1);
    assert_eq!(restored.deposits.credits[&0], gw.deposits.credits[&0]);
    assert_eq!(restored.snapshot_plain(), current);
    let witness = restored.seq.seal_window();
    let mut replay = witness.pre_state.clone();
    let roots =
        perp_core::commitment::derive_roots(&mut replay, &witness.ops, &witness.manifest).unwrap();
    assert_eq!(roots.new_state_root, restored.seq.state.state_root());
    assert_eq!(replay.consumed_deposit_tip, prefix.1);

    let mut v6 = b"\xffDPA01-SNAPSHOT-v6\0".to_vec();
    v6.extend_from_slice(&current[snapshot::PAYLOAD_MAGIC.len() + 1..]);
    assert!(Gw::boot_restored(&v6).is_err());
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
fn a_header_that_does_not_re_hash_only_pauses_permit_gc_and_alerts_when_long() {
    use crate::ops_alerts::AlertKind::PermitGcStalled;
    let mut gw = fresh();
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
    let expired = gw
        .authorize_routed_deposit(&key, [0x42; 20], 5_000_000, 0, Purpose::Collateral, 1_000)
        .unwrap();
    let live = gw
        .authorize_routed_deposit(
            &key,
            [0x42; 20],
            6_000_000,
            0,
            Purpose::Collateral,
            u64::MAX,
        )
        .unwrap();
    let at = |gw: &Gw, number: u64, timestamp: Option<u64>, commits: &[[u8; 32]]| {
        let mut p = page(gw, commits);
        p.end = Block {
            number,
            hash: [(number % 251) as u8 + 1; 32],
            timestamp,
        };
        for e in &mut p.events {
            e.block = p.end.clone();
        }
        p
    };
    let stalled = |gw: &Gw| gw.ops_alerts.active().contains(&PermitGcStalled);
    // A page whose end header did not re-hash still credits; only GC waits.
    assert_eq!(
        gw.apply_deposit_page(at(&gw, 10, None, &[live])).unwrap(),
        1
    );
    // Once the page is durable, intake (and so settlement) is ready as usual.
    gw.deposits.dirty = false;
    assert!(gw.deposits.check_ready().is_ok());
    assert_eq!(gw.deposits.credits.len(), 1);
    assert!(gw.deposits.routes.contains_key(&expired));
    assert_eq!(gw.deposits.gc_unverified_since, Some(10));
    gw.apply_deposit_page(at(&gw, 9 + PERMIT_GC_STALL_BLOCKS, None, &[]))
        .unwrap();
    assert!(!stalled(&gw));
    gw.apply_deposit_page(at(&gw, 10 + PERMIT_GC_STALL_BLOCKS, None, &[]))
        .unwrap();
    assert!(stalled(&gw), "a long run without header time is raised");
    assert!(gw.deposits.routes.contains_key(&expired));
    // A header that re-hashes again collects what expired and recovers.
    gw.apply_deposit_page(at(&gw, 11 + PERMIT_GC_STALL_BLOCKS, Some(1_001), &[]))
        .unwrap();
    assert!(!gw.deposits.routes.contains_key(&expired));
    assert_eq!(gw.deposits.gc_unverified_since, None);
    assert!(!stalled(&gw));
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

/// After L1 close-only the first fetch verifies the consumed prefix, the deposits
/// that landed but were never credited are read to the finalized head and listed
/// as refundable, and then polling stops.
#[tokio::test]
async fn close_only_intake_verifies_the_prefix_once_then_stops_polling() {
    let mut gw = fresh();
    let (key, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.deposits.l1_close_only = true;
    let (app, source, rx) = app_with_page(gw, p);
    let writer = ack_every_snapshot(rx);
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
        assert!(gw.deposits.uncredited_scan_done);
        assert_eq!(
            gw.v1_account(&key).unwrap()["refundableDeposits"],
            serde_json::json!([{
                "id": 0,
                "from": hex0x(&[0x42; 20]),
                "ownerCommit": hex0x(&c),
                "amount": "5000000",
            }])
        );
    }
    // The page, then one read past it that found the finalized head.
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(ingest_once(&app).await.unwrap(), 0);
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    writer.abort();
}

/// Acknowledge every durability request, as a healthy snapshot writer does.
fn ack_every_snapshot(
    mut rx: tokio::sync::mpsc::Receiver<SnapshotAck>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    })
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
    let tick = gw.seq.seal_batch(&[], now_ms()).batch_id;
    assert!(gw.seq.fill_tick_pending(tick));
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
    assert!(
        !gw.seq.fill_tick_pending(tick),
        "the rebase discards the unsettled window's ticks"
    );
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

/// Deposit blocks that chain on from `gw`'s consumed prefix: block `i` (number
/// `i + 1`) holds the permitted deposits `blocks[i]`, in order. Returns each block
/// keyed by the deposit count it starts at.
fn chained_blocks(gw: &Gw, blocks: &[&[[u8; 32]]]) -> BTreeMap<u64, (Block, Vec<Event>)> {
    let start = gw.deposit_cursor();
    let (mut id, mut tip) = (start.count, start.tip);
    let mut chain = BTreeMap::new();
    for (i, commits) in blocks.iter().enumerate() {
        let block = Block {
            number: i as u64 + 1,
            hash: [0x70 + i as u8; 32],
            timestamp: None,
        };
        let first = id;
        let events = commits
            .iter()
            .enumerate()
            .map(|(log, commit)| {
                let route = &gw.deposits.routes[commit];
                tip = perp_core::merkle::deposit_chain_fold(
                    &tip,
                    &perp_core::merkle::deposit_leaf(&route.from, commit, route.amount, id),
                );
                let event = Event {
                    id,
                    from: route.from,
                    commit: *commit,
                    amount: route.amount,
                    tip,
                    tx: [0x90 + i as u8; 32],
                    tx_index: 0,
                    log_index: log as u64,
                    block: block.clone(),
                };
                id += 1;
                event
            })
            .collect();
        chain.insert(first, (block, events));
    }
    chain
}

/// A finalized chain: each deposit block is read from the cursor at its start;
/// past the last one the finalized head holds no further deposit.
struct Blocks {
    blocks: BTreeMap<u64, (Block, Vec<Event>)>,
    head: Block,
    calls: std::sync::atomic::AtomicUsize,
}
impl crate::deposit_rpc::DepositSource for Blocks {
    fn fetch(&self, cursor: Cursor) -> Result<Page, Error> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (end, events) = self
            .blocks
            .get(&cursor.count)
            .cloned()
            .unwrap_or_else(|| (self.head.clone(), Vec::new()));
        Ok(Page {
            start: cursor,
            end,
            events,
        })
    }
}

fn app_with_blocks(
    gw: Gw,
    blocks: BTreeMap<u64, (Block, Vec<Event>)>,
) -> (Shared, Arc<Blocks>, tokio::task::JoinHandle<()>) {
    let mut app = crate::tests::test_app();
    let a = Arc::get_mut(&mut app).unwrap();
    let source = Arc::new(Blocks {
        blocks,
        head: Block {
            number: 50,
            hash: [0x50; 32],
            timestamp: None,
        },
        calls: 0.into(),
    });
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    a.snapshot_req = Some(tx);
    a.deposit_source = Some(source.clone());
    a.gw = Mutex::new(gw);
    a.gw.get_mut().deposits.required = true;
    (app, source, ack_every_snapshot(rx))
}

/// While the engine is close-only no deposit is credited, and ingestion stays at
/// the oldest landed deposit. That refusal leaves intake ready (the fetch verified
/// the consumed prefix), and every permitted deposit that landed meanwhile, not
/// only the oldest, is recorded with its permit. Once the settlement is in
/// close-only each is listed with its exact `refundDeposit` arguments.
#[tokio::test]
async fn deposits_refused_in_engine_close_only_are_recorded_and_later_listed() {
    let mut gw = fresh();
    let (a, ca) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let (b, cb) = permit(&mut gw, 7_000_000, Purpose::Collateral, 1);
    let (c, cc) = permit(&mut gw, 9_000_000, Purpose::Collateral, 0);
    let blocks = chained_blocks(&gw, &[&[ca], &[cb, cc]]);
    gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
    let cursor = gw.deposit_cursor();
    let (app, source, writer) = app_with_blocks(gw, blocks);
    for pass in 1..=2 {
        assert_eq!(
            ingest_once(&app).await.unwrap_err(),
            crate::admission::ENGINE_CLOSE_ONLY_INTAKE,
            "pass {pass}"
        );
        let gw = app.gw.lock().await;
        assert!(gw.deposits.ready, "pass {pass}");
        assert!(gw.deposits.check_ready().is_ok(), "pass {pass}");
        assert_eq!(gw.deposit_cursor(), cursor, "the page is not consumed");
        assert_eq!(gw.seq.state.consumed_deposit_count, 0);
        assert!(gw.deposits.credits.is_empty());
        assert_eq!(
            gw.deposits.uncredited.keys().copied().collect::<Vec<_>>(),
            vec![0, 1, 2],
            "pass {pass}"
        );
        assert_eq!(gw.deposits.routes.len(), 3, "the permits stay held");
        let alerts = gw.ops_alerts.active();
        assert!(alerts.contains(&crate::ops_alerts::AlertKind::EngineCloseOnly));
        assert!(!alerts.contains(&crate::ops_alerts::AlertKind::DepositBlockedAtCap));
        // Not refundable before the settlement is in close-only.
        assert!(gw.refundable_credits(&b).is_empty());
        assert!(gw
            .v1_account(&b)
            .unwrap()
            .get("refundableDeposits")
            .is_none());
    }
    // First pass: the page, the block after it, and the head; second pass: the
    // page again and the head again.
    assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst), 5);
    let mut gw = app.gw.lock().await;
    let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    assert_eq!(restored.deposits.uncredited, gw.deposits.uncredited);
    gw.deposits.l1_close_only = true;
    for (key, id, commit, amount, market) in [
        (a, 0, ca, "5000000", 0),
        (b, 1, cb, "7000000", 1),
        (c, 2, cc, "9000000", 0),
    ] {
        assert_eq!(
            gw.v1_account(&key).unwrap()["refundableDeposits"],
            serde_json::json!([{
                "id": id,
                "from": hex0x(&[0x42; 20]),
                "ownerCommit": hex0x(&commit),
                "amount": amount,
            }])
        );
        assert_eq!(gw.deposits.uncredited[&id].route.market, market);
    }
    drop(gw);
    writer.abort();
}

/// For a state beyond a provable-history bound (a bound lowered under it) a
/// permitted deposit that landed is not credited: the page stays unconsumed, intake
/// stays ready, a signed full exit is still accepted (a partial withdrawal is not),
/// and the operator gets an alert of its own (the deposit now holds the deposit
/// queue). Once the state is within the bound again, the same page is credited, the
/// record goes and the alert recovers.
#[tokio::test]
async fn a_state_beyond_a_bound_holds_a_landed_deposit_with_its_own_alert_while_exits_work() {
    use crate::ops_alerts::AlertKind::{AdmissionCapReached, DepositBlockedAtCap};
    let mut gw = fresh();
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x61; 32]).unwrap();
    let address = eth_address(&sk);
    let (exiting, _) = gw.register_account(Some(address));
    gw.account_deposit(&exiting, 0, 100 * QUOTE_SCALE).unwrap();
    let (_, c) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let p = page(&gw, &[c]);
    gw.admission_cap = crate::admission::AdmissionCap {
        max_history: crate::admission::HistorySize::of(&gw.seq.state).history,
        max_positions: 1_000,
        max_notes: 1_000,
    };
    let cursor = gw.deposit_cursor();
    let consumed = gw.seq.state.consumed_deposit_count;
    let (app, _source, rx) = app_with_page(gw, p);
    let writer = ack_every_snapshot(rx);
    assert_eq!(
        ingest_once(&app).await.unwrap_err(),
        crate::admission::HISTORY_CAP_INTAKE
    );
    {
        let mut gw = app.gw.lock().await;
        assert!(gw.deposits.ready);
        assert!(gw.deposits.check_ready().is_ok());
        assert_eq!(gw.deposit_cursor(), cursor);
        assert_eq!(gw.seq.state.consumed_deposit_count, consumed);
        assert!(gw.deposits.uncredited.contains_key(&consumed));
        let alerts = gw.ops_alerts.active();
        assert!(alerts.contains(&DepositBlockedAtCap));
        assert!(alerts.contains(&AdmissionCapReached));
        // A full exit keeps working beyond the bound; a partial withdrawal does not.
        let withdraw = |gw: &mut Gw, amount: i128| {
            let (owner, auth_nonce) = {
                let a = &gw.accounts[&exiting];
                (a.wallet.owner, a.last_withdraw_nonce + 1)
            };
            let digest = withdraw_auth_digest(
                gw.chain_id,
                &gw.vault,
                &owner,
                0,
                amount,
                &address,
                auth_nonce,
            );
            let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
            let mut wire = [0u8; 65];
            wire[..64].copy_from_slice(&sig.to_bytes());
            wire[64] = 27 + recid.to_byte();
            gw.account_withdraw(&exiting, 0, amount, address, auth_nonce, &wire)
        };
        assert_eq!(
            withdraw(&mut gw, QUOTE_SCALE).unwrap_err(),
            crate::admission::HISTORY_CAP_EXIT
        );
        withdraw(&mut gw, 100 * QUOTE_SCALE).unwrap();
        gw.admission_cap = crate::admission::measured_cap();
    }
    assert_eq!(ingest_once(&app).await.unwrap(), 1);
    let gw = app.gw.lock().await;
    assert_eq!(gw.seq.state.consumed_deposit_count, consumed + 1);
    assert!(
        gw.deposits.uncredited.is_empty(),
        "the credit replaced the record"
    );
    assert!(!gw.ops_alerts.active().contains(&DepositBlockedAtCap));
    drop(gw);
    writer.abort();
}

/// The close-only rebase drops every outstanding permit, but a permitted deposit
/// that landed and was never credited keeps its record: it is listed as
/// refundable, and the record survives a restart.
#[test]
fn the_close_only_rebase_keeps_landed_uncredited_deposits() {
    use crate::wind_down::SettledL1;
    let mut gw = fresh();
    let (_, ca) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
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
    // The engine trips in the unsettled window; a permitted deposit lands and is
    // refused, and another permit never lands.
    let (b, cb) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    let (_, never) = permit(&mut gw, 1_000_000, Purpose::Collateral, 0);
    gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
    let refused = page(&gw, &[cb]);
    assert_eq!(
        gw.apply_deposit_page(refused.clone()).unwrap_err(),
        crate::admission::ENGINE_CLOSE_ONLY_INTAKE
    );
    assert_eq!(gw.record_uncredited(&refused), 1);
    assert_eq!(gw.record_uncredited(&refused), 0, "recorded once");
    let l1 = SettledL1 {
        block: 9,
        close_only: true,
        settled: false,
        batch_count: 1,
        root: settled_root,
        consumed_deposit_count: 1,
    };
    gw.rebase_to_settled(&l1).unwrap();
    assert!(gw.deposits.routes.is_empty());
    assert!(!gw.accounts[&b].deposit_authorizations.contains_key(&cb));
    assert!(!gw
        .deposits
        .uncredited
        .values()
        .any(|r| r.event.commit == never));
    assert_eq!(
        gw.refundable_credits(&b)
            .into_iter()
            .map(refund_json)
            .collect::<Vec<_>>(),
        vec![serde_json::json!({
            "id": 1,
            "from": hex0x(&[0x42; 20]),
            "ownerCommit": hex0x(&cb),
            "amount": "7000000",
        })]
    );
    let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    assert_eq!(restored.deposits.uncredited, gw.deposits.uncredited);
    assert_eq!(restored.seq.state.state_root(), settled_root);
    // A record below the consumed prefix, or one whose payer differs from its
    // permit, does not validate.
    let corruptions: [fn(&mut Credit); 2] = [|r| r.event.id = 0, |r| r.route.from = [0x43; 20]];
    for corrupt in corruptions {
        let mut bad = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        let mut row = bad.deposits.uncredited.remove(&1).unwrap();
        corrupt(&mut row);
        bad.deposits.uncredited.insert(row.event.id, row);
        assert!(bad.validate_deposit_state().is_err());
    }
}
