// Audit 2026-11-16 GF-2: an order receipt and its L1 challenge authority must not
// leave the gateway before a durable snapshot holds the order. These tests make
// no chain calls.
mod audit_1116_gf2 {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const SEED: [u8; 32] = [0x26; 32];
    const BENEFICIARY: [u8; 20] = [0x42; 20];

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("arcora-gf2-{}", hex0x(&csprng_bytes32())));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn json(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    /// An app whose durability barrier requests arrive on the returned receiver,
    /// with one funded account bound to `BENEFICIARY` under a configured
    /// settlement, so every receipt it is given carries an `l1Challenge`.
    async fn staged() -> (
        Shared,
        tokio::sync::mpsc::Receiver<SnapshotAck>,
        [u8; 32],
    ) {
        let mut app = test_app();
        let (tx, rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let key = {
            let mut gw = app.gw.lock().await;
            gw.l1_settlement = Some([0x22; 20]);
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some(BENEFICIARY);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
            key
        };
        (app, rx, key)
    }

    fn place(key: &[u8; 32]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/orders")
            .header("x-api-key", hex0x(key))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "marketId": 0, "side": "Buy", "size": "100000", "limitPrice": "1",
                    "tif": "Gtc", "reduceOnly": false,
                })
                .to_string(),
            ))
            .unwrap()
    }

    /// GF-2: with the snapshot write failing, the order response used to carry the
    /// enclave-signed receipt and its `l1Challenge` all the same. A crash then lost
    /// the order while its holder kept the authority to challenge it on L1 (and
    /// slash the bond, since no batch can ever answer it). Now the handler waits for
    /// the durable write and, when it fails, releases neither.
    #[tokio::test]
    async fn audit_1116_gf2_a_failed_snapshot_releases_no_receipt_or_l1_challenge() {
        let (app, mut rx, key) = staged().await;
        let task = tokio::spawn(build_router(app.clone(), false).oneshot(place(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the order handler did not reach the durability barrier")
            .expect("the order handler must request a durable snapshot");
        ack.send(false).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json(response).await;
        assert_eq!(body["durability"], "unknown");
        for field in ["signature", "enclaveSigner", "l1Challenge", "seqNo"] {
            assert!(body.get(field).is_none(), "{field} released: {body}");
        }
        // The order stays accepted in memory: a tick may already have matched it,
        // and the next durable snapshot holds it.
        let gw = app.gw.lock().await;
        assert_eq!(gw.accounts[&key].orders.len(), 1);
        assert_eq!(
            body["orderHash"],
            hex0x(&gw.accounts[&key].orders[0].order_hash)
        );
    }

    /// GF-2: the successful response leaves only after the write it waited for is
    /// durable, and that write holds the order.
    #[tokio::test]
    async fn audit_1116_gf2_the_receipt_follows_a_durable_write_that_holds_the_order() {
        let (app, mut rx, key) = staged().await;
        let task = tokio::spawn(build_router(app.clone(), false).oneshot(place(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the order handler did not reach the durability barrier")
            .expect("the order handler must request a durable snapshot");
        assert!(!task.is_finished(), "no receipt before the durable write");
        let dir = TestDir::new();
        let path = dir.0.join("state");
        assert!(write_snapshot(&app, &path, SEED, Arc::new(Mutex::new(()))).await);
        let plain = snapshot::open(&std::fs::read(&path).unwrap(), &SEED).unwrap();
        let restored = Gw::boot_restored(&plain).unwrap();
        assert_eq!(restored.accounts[&key].orders.len(), 1);
        ack.send(true).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = json(response).await;
        assert_eq!(
            receipt["orderHash"],
            hex0x(&restored.accounts[&key].orders[0].order_hash)
        );
        assert_eq!(receipt["l1Challenge"]["beneficiary"], hex0x(&BENEFICIARY));
    }

    fn list(key: &[u8; 32]) -> Request<Body> {
        Request::builder()
            .uri("/v1/orders")
            .header("x-api-key", hex0x(key))
            .body(Body::empty())
            .unwrap()
    }

    async fn listed_receipt(app: &Shared, key: &[u8; 32]) -> serde_json::Value {
        let listed = json(
            build_router(app.clone(), false)
                .oneshot(list(key))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed["orders"].as_array().unwrap().len(), 1);
        listed["orders"][0]["receipt"].clone()
    }

    /// GF-2: the order listing serves the stored receipt too, so it must not hand
    /// out the authority while the accept response still waits, nor after that
    /// write failed. Once a durable write holds the order, it does.
    #[tokio::test]
    async fn audit_1116_gf2_the_listing_serves_a_receipt_only_once_a_durable_write_holds_it() {
        let (app, mut rx, key) = staged().await;
        app.gw.lock().await.durable_marks = snapshot::DurableMarks::tracked();
        let task = tokio::spawn(build_router(app.clone(), false).oneshot(place(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(listed_receipt(&app, &key).await.is_null(), "listed while waiting");
        ack.send(false).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(listed_receipt(&app, &key).await.is_null(), "listed after a failed write");

        let dir = TestDir::new();
        // A write that fails confirms nothing.
        let unwritable = dir.0.join("missing").join("state");
        assert!(!write_snapshot(&app, &unwritable, SEED, Arc::new(Mutex::new(()))).await);
        assert!(listed_receipt(&app, &key).await.is_null());
        // The writer's next successful write holds the order.
        let path = dir.0.join("state");
        assert!(write_snapshot(&app, &path, SEED, Arc::new(Mutex::new(()))).await);
        let receipt = listed_receipt(&app, &key).await;
        assert_eq!(receipt["l1Challenge"]["beneficiary"], hex0x(&BENEFICIARY));
        let hash = app.gw.lock().await.accounts[&key].orders[0].order_hash;
        assert_eq!(receipt["orderHash"], hex0x(&hash));

        // An order restored from a snapshot is durable.
        let plain = snapshot::open(&std::fs::read(&path).unwrap(), &SEED).unwrap();
        let mut restored = Gw::boot_restored(&plain).unwrap();
        restored.durable_marks = snapshot::DurableMarks::tracked();
        let row = &restored.v1_orders_json(&key).unwrap()["orders"][0];
        assert_eq!(row["receipt"]["orderHash"], hex0x(&hash));
    }

    /// Marks: an order is durable once a write whose capture held its mark is.
    #[test]
    fn audit_1116_gf2_durable_marks_follow_the_captured_writes() {
        let untracked = snapshot::DurableMarks::default();
        assert_eq!(untracked.issue(), 0);
        assert!(untracked.is_durable(0));
        let marks = snapshot::DurableMarks::tracked();
        assert!(marks.is_durable(0), "restored orders");
        let first = marks.issue();
        let captured = marks.captured();
        let second = marks.issue();
        assert!(!marks.is_durable(first) && !marks.is_durable(second));
        marks.written(captured);
        assert!(marks.is_durable(first));
        assert!(!marks.is_durable(second), "accepted after the capture");
        // A slower writer of an older capture does not move the mark back.
        marks.clone().written(marks.captured());
        marks.written(captured);
        assert!(marks.is_durable(second));
    }

    /// GF-2: production without persistence cannot make any receipt durable, so it
    /// refuses the order before accepting anything, as cancellation does.
    #[tokio::test]
    async fn audit_1116_gf2_production_without_persistence_refuses_orders_before_accepting() {
        let app = test_app();
        let key = {
            let mut gw = app.gw.lock().await;
            let (key, _) = gw.register_account(None);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
            gw.prod = true;
            key
        };
        let nonce = app.gw.lock().await.accounts[&key].nonce;
        let response = build_router(app.clone(), true)
            .oneshot(place(&key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .starts_with(PERSISTENCE_UNAVAILABLE),
            "{body}"
        );
        let gw = app.gw.lock().await;
        assert!(gw.accounts[&key].orders.is_empty());
        assert_eq!(gw.accounts[&key].nonce, nonce);
    }

    // ── Second line: an open challenge for an order the gateway does not know ──

    use crate::challenge_scan::{AnswerPlan, Watcher};
    use perp_core::order::RejectReason;

    /// The settlement's `batchCount` when every batch this gateway committed has
    /// settled on L1 and nothing else has.
    fn settled_count(gw: &Gw) -> u64 {
        gw.batch_orders.keys().next_back().map_or(0, |b| b + 1)
    }

    fn open_set(open: &[Digest], batch_count: u64) -> crate::l1::OpenSetRead {
        crate::l1::OpenSetRead {
            head: 20,
            batch_count,
            hashes: open.to_vec(),
            details: vec![],
        }
    }

    /// One watcher round, with a clock admission permit, over an open set read
    /// with `open` (no stored details) at a block where the settlement holds
    /// exactly the batches this gateway committed.
    fn round(gw: &mut Gw, watcher: &mut Watcher, open: &[Digest]) -> AnswerPlan {
        watcher.observe(open_set(open, settled_count(gw)));
        gw.plan_challenge_round(watcher, true)
    }

    /// How often the open window's manifest rejects `hash`.
    fn rejections(gw: &Gw, hash: &Digest) -> usize {
        gw.seq
            .window_rejected()
            .iter()
            .filter(|(h, _)| h == hash)
            .count()
    }

    fn settling_gw() -> Gw {
        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        gw
    }

    /// Seal the open window (an empty one when `keepalive`), as the settle loop does.
    fn seal(gw: &mut Gw, keepalive: bool) -> (WindowWitness, Vec<Withdrawal>) {
        let batch_count = gw.seq.state.next_batch_id;
        gw.begin_window_settle_mode(batch_count, keepalive)
            .unwrap()
            .expect("the window has something to settle")
    }

    /// Record the sealed window as settled on L1.
    fn commit(gw: &mut Gw, witness: WindowWitness, ww: Vec<Withdrawal>) {
        let ordered = witness.manifest.ordered.clone();
        let rejected: Vec<_> = witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id = witness.batch_id;
        let prepared = prover_client::prepare_unproved(&witness, &ww).unwrap();
        let status = L1Status {
            settled_root: hex32(&prepared.outcome.new_root),
            batch_count: batch_id + 1,
            last_tx: "0xtx".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
        };
        gw.commit_window_settle(
            batch_id,
            ordered,
            rejected,
            prepared,
            status,
            trading_gate::GateObservation::OpensGate,
        );
    }

    /// GF-2 second line: an open challenge for a hash no batch holds and the
    /// gateway does not know (the order was lost) used only to raise an alert, so
    /// the bond was slashed. The gateway now declares it rejected in the open
    /// window once, and the settled batch's rejected root answers the challenge.
    #[test]
    fn audit_1116_gf2_an_unknown_challenged_hash_is_rejected_once_and_answered() {
        let mut gw = settling_gw();
        let lost = [0x51; 32];
        let mut watcher = Watcher::default();
        assert_eq!(round(&mut gw, &mut watcher, &[lost]).declared, vec![lost]);
        assert_eq!(rejections(&gw, &lost), 1, "the next batch rejects it");
        assert!(gw
            .seq
            .window_rejected()
            .contains(&(lost, RejectReason::Cancelled)));
        assert!(round(&mut gw, &mut watcher, &[lost]).declared.is_empty());
        assert_eq!(rejections(&gw, &lost), 1, "declared once");

        // While its window settles, later rounds declare nothing new.
        let batch = gw.seq.state.next_batch_id;
        let (witness, ww) = seal(&mut gw, false);
        let sealed: Vec<_> = witness.manifest.rejected.iter().filter(|(h, _)| *h == lost).collect();
        assert_eq!(sealed.len(), 1);
        round(&mut gw, &mut watcher, &[lost]);
        assert_eq!(rejections(&gw, &lost), 0, "not again while its window settles");

        // Settled: the batch's rejected root answers it, and nothing more is declared.
        commit(&mut gw, witness, ww);
        let plan = round(&mut gw, &mut watcher, &[lost]);
        assert_eq!(rejections(&gw, &lost), 0);
        assert!(plan.unanswerable.is_empty());
        assert_eq!(plan.sends.len(), 1);
        let (answer_batch, answers) = &plan.sends[0];
        assert_eq!(*answer_batch, batch);
        assert_eq!(answers.len(), 1);
        assert!(answers[0].by_rejection);
        assert_eq!(answers[0].order_hash, lost);
        let rejected = &gw.batch_orders[&batch].1;
        let root = perp_core::merkle::merkle_root(
            &rejected
                .iter()
                .map(|h| crate::withdrawals::rejection_leaf(batch, h))
                .collect::<Vec<_>>(),
        );
        assert!(perp_core::merkle::verify(
            root,
            crate::withdrawals::rejection_leaf(batch, &lost),
            &answers[0].proof
        ));
    }

    /// GF-2 second line: the declaration survives a restart, so neither the open
    /// window nor a settling one rejects the hash a second time.
    #[test]
    fn audit_1116_gf2_a_declared_rejection_survives_a_restart_without_repeating() {
        let mut gw = settling_gw();
        let lost = [0x52; 32];
        round(&mut gw, &mut Watcher::default(), &[lost]);
        assert_eq!(rejections(&gw, &lost), 1);

        // Restart with the open window holding the rejection; the watcher's own
        // state is rebuilt from nothing.
        let plain = gw.snapshot_plain();
        let mut gw = Gw::boot_restored(&plain).unwrap();
        assert_eq!(gw.snapshot_plain(), plain, "byte-exact re-encoding");
        round(&mut gw, &mut Watcher::default(), &[lost]);
        assert_eq!(rejections(&gw, &lost), 1, "not declared again after a restart");

        // Restart while its window settles.
        let (witness, _) = seal(&mut gw, false);
        assert!(witness
            .manifest
            .rejected
            .contains(&(lost, RejectReason::Cancelled)));
        let mut gw = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        round(&mut gw, &mut Watcher::default(), &[lost]);
        assert_eq!(rejections(&gw, &lost), 0, "not again while its window settles");
    }

    /// GF-2 second line: only hashes truly unknown are declared. Orders the
    /// gateway accepted (pending, resting, cancelled, or with their row gone) and
    /// orders a settled batch holds are never rejected by a challenge.
    #[test]
    fn audit_1116_gf2_a_challenge_never_rejects_an_order_the_gateway_knows() {
        let mut gw = settling_gw();
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
        let px = gw.px_of(0);
        let place = |gw: &mut Gw, side: &str, limit: i128| {
            gw.accounts.get_mut(&key).unwrap().orders_this_sec = 0;
            gw.account_place_order(
                &key,
                &OrderReq {
                    market_id: 0,
                    side: side.into(),
                    size: (SIZE_SCALE / 100).to_string(),
                    limit_price: limit.to_string(),
                    tif: "Gtc".into(),
                    reduce_only: false,
                    ..Default::default()
                },
            )
            .unwrap();
            gw.accounts[&key].orders[0].order_hash
        };
        // A resting maker sequenced in a tick, and an order cancelled after it
        // whose finished row is gone (the row budget evicts such rows).
        let resting = place(&mut gw, "Buy", px * 9 / 10);
        let cancelled = place(&mut gw, "Sell", px * 11 / 10);
        gw.tick();
        let id = gw.accounts[&key].orders[0].id.clone();
        gw.account_cancel(&key, &id).unwrap();
        gw.accounts.get_mut(&key).unwrap().orders.remove(0);
        // A pending order, accepted but not sequenced yet.
        let pending = place(&mut gw, "Buy", px * 8 / 10);
        let before = gw.seq.window_rejected().to_vec();
        let known = [resting, cancelled, pending];
        let mut watcher = Watcher::default();
        round(&mut gw, &mut watcher, &known);
        assert_eq!(gw.seq.window_rejected(), before.as_slice());

        // Settled orders are answered from their batch, never declared rejected.
        gw.tick();
        let (witness, ww) = seal(&mut gw, false);
        let batch = witness.batch_id;
        assert!(witness.manifest.ordered.contains(&resting));
        commit(&mut gw, witness, ww);
        let plan = round(&mut gw, &mut watcher, &known);
        assert!(gw.seq.window_rejected().is_empty());
        for hash in known {
            assert!(
                plan.sends
                    .iter()
                    .any(|(b, answers)| *b == batch && answers.iter().any(|a| a.order_hash == hash)),
                "answered from its batch"
            );
        }
    }

    /// GF-2 second line: a challenge that left the open set (answered, slashed or
    /// released) is resolved on L1 for good, and its record goes with it; a
    /// snapshot without records keeps the earlier layout.
    #[test]
    fn audit_1116_gf2_a_resolved_challenge_drops_its_record() {
        let mut gw = settling_gw();
        let earlier = gw.snapshot_plain();
        let lost = [0x53; 32];
        let mut watcher = Watcher::default();
        round(&mut gw, &mut watcher, &[lost]);
        let (witness, ww) = seal(&mut gw, false);
        commit(&mut gw, witness, ww);
        round(&mut gw, &mut watcher, &[]);
        let plain = gw.snapshot_plain();
        let restored = Gw::boot_restored(&plain).unwrap();
        assert_eq!(restored.snapshot_plain(), plain);
        // Only the settled batch and the counters moved: the layout is the earlier one.
        assert_eq!(&plain[..8], &earlier[..8]);
        assert!(plain.windows(8).all(|w| w != b"DPCHRJ1\0"));
    }

    /// GF-2 second line: the declaration extension is framed like the others: a
    /// snapshot with trailing bytes, an empty record set or an unknown extension
    /// after the earlier ones is refused rather than read as having no records.
    #[test]
    fn audit_1116_gf2_a_malformed_declaration_extension_is_refused() {
        let mut gw = settling_gw();
        round(&mut gw, &mut Watcher::default(), &[[0x57; 32]]);
        let plain = gw.snapshot_plain();
        assert!(Gw::boot_restored(&plain).is_ok());
        let at = plain
            .windows(8)
            .rposition(|w| w == b"DPCHRJ1\0")
            .expect("a snapshot holding a declaration carries the extension");
        let mut trailing = plain.clone();
        trailing.push(0);
        assert!(Gw::boot_restored(&trailing).is_err(), "trailing bytes");
        let mut empty = plain[..at].to_vec();
        empty.extend_from_slice(b"DPCHRJ1\0");
        empty.extend_from_slice(
            &postcard::to_allocvec(&crate::challenge_rejections::Declarations::new()).unwrap(),
        );
        assert!(Gw::boot_restored(&empty).is_err(), "an empty record set");
        let mut unknown = plain[..at].to_vec();
        unknown.extend_from_slice(b"DPXXXX1\0");
        assert!(Gw::boot_restored(&unknown).is_err(), "an unknown extension");
        assert!(Gw::boot_restored(&plain[..at]).is_ok(), "no extension at all");
    }

    /// GF-2 second line: if the batch a declaration was due in settles without the
    /// hash (its rejection was lost on the way), the next round declares it again.
    #[test]
    fn audit_1116_gf2_a_lost_declaration_is_declared_again() {
        let mut gw = settling_gw();
        let lost = [0x54; 32];
        let mut watcher = Watcher::default();
        round(&mut gw, &mut watcher, &[lost]);
        assert_eq!(rejections(&gw, &lost), 1);
        // Discard the open window without publishing its rejections again.
        let _ = gw.seq.void_open_window();
        assert_eq!(rejections(&gw, &lost), 0);
        round(&mut gw, &mut watcher, &[lost]);
        assert_eq!(rejections(&gw, &lost), 0, "its window has not settled yet");
        let (witness, ww) = seal(&mut gw, true);
        commit(&mut gw, witness, ww);
        round(&mut gw, &mut watcher, &[lost]);
        assert_eq!(rejections(&gw, &lost), 1, "declared again");
    }

    /// GF-2 second line: "in no batch" must hold against every batch the
    /// settlement has settled. While the chain holds a settled batch whose lists
    /// this gateway has not committed yet (its settle is still landing), the hash
    /// may be in it, so nothing is declared until the gateway holds that batch.
    #[test]
    fn audit_1116_gf2_nothing_is_declared_while_the_chain_is_ahead_of_the_gateway() {
        let mut gw = settling_gw();
        let lost = [0x55; 32];
        let mut watcher = Watcher::default();
        let (witness, ww) = seal(&mut gw, true);
        watcher.observe(open_set(&[lost], settled_count(&gw) + 1));
        let plan = gw.plan_challenge_round(&mut watcher, true);
        assert!(plan.declared.is_empty());
        assert_eq!(plan.unlocated, vec![lost]);
        assert_eq!(rejections(&gw, &lost), 0);
        assert!(gw.challenge_rejections.is_empty());

        // The gateway commits the batch the chain settled; it does not hold the hash.
        commit(&mut gw, witness, ww);
        watcher.observe(open_set(&[lost], settled_count(&gw)));
        let plan = gw.plan_challenge_round(&mut watcher, true);
        assert_eq!(plan.declared, vec![lost]);
        assert_eq!(rejections(&gw, &lost), 1);
    }

    /// GF-2 second line: a declaration changes the open window, so it needs a
    /// clock admission permit like every other change to it. While a sealed
    /// window holds admission closed (proving, registration, a void), the open
    /// window stays as the settle loop left it; the next round declares the hash.
    #[tokio::test]
    async fn audit_1116_gf2_a_window_holding_admission_defers_the_declaration() {
        let mut app = test_app();
        Arc::get_mut(&mut app).unwrap().clock_admission =
            clock_admission::ClockAdmission::new(true);
        let lost = [0x56; 32];
        let mut watcher = Watcher::default();
        watcher.observe(open_set(&[lost], settled_count(&*app.gw.lock().await)));
        let stop = service_shutdown::Shutdown::default();
        let mut paused = app.clock_admission.pause(&stop).await.unwrap().unwrap();
        paused.arm();
        let plan = challenge_round(&app, &mut watcher).await;
        assert!(plan.declared.is_empty());
        assert_eq!(plan.unlocated, vec![lost]);
        {
            let gw = app.gw.lock().await;
            assert_eq!(rejections(&gw, &lost), 0);
            assert!(gw.challenge_rejections.is_empty());
        }

        // The window resolved and admission reopened.
        paused.resolved();
        drop(paused);
        let plan = challenge_round(&app, &mut watcher).await;
        assert_eq!(plan.declared, vec![lost]);
        assert_eq!(rejections(&*app.gw.lock().await, &lost), 1);
    }
}
