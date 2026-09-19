// Native A05 regressions adapted to current A01 + A04 main.
// No live RPC, real funds, or production secrets. Not executed in the authoring container.
mod execution_regressions {
    use super::*;
    use perp_core::commitment::derive_roots;

    fn exchange() -> Gw {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = false; // test funding/cleartext ingress only; no funded house MM
        gw.trading_gate = trading_gate::TradingGate::Open;
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        for m in &mut gw.mkts {
            m.live = true;
        }
        refresh(&mut gw);
        gw
    }
    fn refresh(gw: &mut Gw) {
        for (id, px) in gw.mkts.iter().map(|m| (m.id, m.px)).collect::<Vec<_>>() {
            gw.seq
                .set_oracle(id, oracle_of(px, now_ms(), id, &gw.oracle_signer));
        }
    }
    fn tick(gw: &mut Gw) -> Vec<String> {
        refresh(gw);
        gw.tick().1
    }
    fn account(gw: &mut Gw) -> [u8; 32] {
        let (k, _) = gw.register_account(None);
        gw.account_deposit(&k, 0, 50_000 * QUOTE_SCALE).unwrap();
        k
    }
    fn submit(
        gw: &mut Gw,
        k: &[u8; 32],
        side: &str,
        size: i128,
        price: i128,
        tif: &str,
    ) -> WReceipt {
        gw.account_place_order(
            k,
            &OrderReq {
                market_id: 0,
                side: side.into(),
                size: size.to_string(),
                limit_price: price.to_string(),
                tif: tif.into(),
                ..Default::default()
            },
        )
        .unwrap()
    }
    fn row(gw: &Gw, k: &[u8; 32]) -> serde_json::Value {
        gw.v1_orders_json(k).unwrap()["orders"][0].clone()
    }
    fn paired() -> (Gw, [u8; 32], [u8; 32], i128) {
        let mut gw = exchange();
        let maker = account(&mut gw);
        let taker = account(&mut gw);
        gw.seq.seal_genesis_baseline();
        let px = gw.px_of(0);
        submit(&mut gw, &maker, "Sell", SIZE_SCALE / 10, px, "Gtc");
        tick(&mut gw);
        (gw, maker, taker, px)
    }
    fn assert_replay(gw: &mut Gw) -> sequencer::WindowWitness {
        let w = gw.seq.seal_window();
        let d = derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest).unwrap();
        assert_eq!(d.new_state_root, gw.seq.state.state_root());
        assert!(gw.seq.state.conservation_holds());
        w
    }

    // Reproduce the v7 writer explicitly. Calling snapshot_plain() here would
    // produce v8 and stop testing the historical execution-only format.
    fn v7_snapshot(gw: &Gw) -> Vec<u8> {
        let prices: Vec<_> = gw
            .mkts
            .iter()
            .map(|m| (m.id, m.reference_price, m.px, m.live))
            .collect();
        let mut bytes = execution::SNAPSHOT_V7.to_vec();
        bytes.extend_from_slice(deposit_ingestion::SNAPSHOT_V6);
        bytes.extend_from_slice(&postcard::to_allocvec(&(gw, prices, &gw.deposits)).unwrap());
        execution::append_snapshot(gw, &mut bytes);
        bytes
    }

    #[test]
    fn sealed_maker_cancel_removes_remainder_and_commits_manifest() {
        let (mut gw, maker, taker, _) = paired();
        let hash = gw.accounts[&maker].orders[0].order_hash;
        gw.account_cancel(&maker, "o1")
            .expect("sealed resting maker must be cancellable");
        assert_eq!(gw.seq.book(0).unwrap().resting_size(Side::Sell), 0);
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 10, 0, "Ioc");
        tick(&mut gw);
        assert_eq!(
            gw.seq
                .state
                .position(&gw.accounts[&maker].wallet.owner, 0)
                .unwrap()
                .size,
            0
        );
        assert_eq!(row(&gw, &maker)["execution"]["status"], "CANCELLED");
        let w = assert_replay(&mut gw);
        assert!(w
            .manifest
            .rejected
            .contains(&(hash, perp_core::order::RejectReason::Cancelled)));
        assert!(!gw.seq.inclusion_violations(0).contains(&hash));
    }
    #[test]
    fn partial_maker_reports_actual_size_and_emits_fill_once() {
        let (mut gw, maker, taker, px) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        let events = tick(&mut gw);
        assert_eq!(
            row(&gw, &maker)["filledSize"],
            (SIZE_SCALE / 40).to_string()
        );
        assert_eq!(row(&gw, &maker)["avgFillPrice"], px.to_string());
        assert_eq!(
            row(&gw, &maker)["execution"]["remainingSize"],
            (3 * SIZE_SCALE / 40).to_string()
        );
        assert_eq!(row(&gw, &maker)["execution"]["status"], "PARTIALLY_FILLED");
        let fills: Vec<serde_json::Value> = events
            .iter()
            .map(|s| serde_json::from_str(s).unwrap())
            .filter(|e: &serde_json::Value| e["type"] == "fill")
            .collect();
        assert_eq!(
            fills.len(),
            2,
            "one actual fill notification per counterparty"
        );
        assert!(fills
            .iter()
            .all(|e| e["size"] == (SIZE_SCALE / 40).to_string() && e["price"] == px.to_string()));
        let w = assert_replay(&mut gw);
        gw.seq.mark_window_settled(w.batch_id);
        let events = tick(&mut gw);
        assert!(
            !events
                .iter()
                .any(|s| serde_json::from_str::<serde_json::Value>(s).unwrap()["type"] == "fill"),
            "settling must not fabricate another fill"
        );
    }
    #[test]
    fn later_partial_after_settle_keeps_finality_and_tracks_new_unsettled_size() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        let w = assert_replay(&mut gw);
        gw.seq.mark_window_settled(w.batch_id);
        tick(&mut gw);
        assert_eq!(row(&gw, &maker)["finality"], "SETTLED");
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        let r = row(&gw, &maker);
        assert_eq!(
            r["finality"], "SETTLED",
            "earlier hard finality must not regress"
        );
        assert_eq!(r["filledSize"], (SIZE_SCALE / 20).to_string());
        assert_eq!(
            r["execution"]["unsettledSize"],
            (SIZE_SCALE / 40).to_string()
        );
        assert_eq!(r["execution"]["settledSize"], (SIZE_SCALE / 40).to_string());
        gw.account_cancel(&maker, "o1").unwrap();
        assert_eq!(row(&gw, &maker)["execution"]["status"], "CANCELLED");
        assert_eq!(
            row(&gw, &maker)["filledSize"],
            (SIZE_SCALE / 20).to_string()
        );
        assert_replay(&mut gw);
    }
    #[test]
    fn multi_level_taker_uses_execution_vwap_not_limit_or_zero() {
        let (mut gw, _maker, taker, px) = paired();
        let maker2 = account(&mut gw);
        submit(
            &mut gw,
            &maker2,
            "Sell",
            SIZE_SCALE / 10,
            px + 2 * PRICE_SCALE,
            "Gtc",
        );
        tick(&mut gw);
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 5, 0, "Ioc");
        tick(&mut gw);
        assert_eq!(row(&gw, &taker)["filledSize"], (SIZE_SCALE / 5).to_string());
        assert_eq!(
            row(&gw, &taker)["avgFillPrice"],
            (px + PRICE_SCALE).to_string()
        );
        assert_eq!(row(&gw, &taker)["execution"]["status"], "FILLED");
        assert_replay(&mut gw);
    }
    #[test]
    fn rejected_orders_have_zero_fills_and_specific_reason() {
        let (mut gw, _, taker, px) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE, px, "Fok");
        tick(&mut gw);
        assert_eq!(row(&gw, &taker)["filledSize"], "0");
        assert_eq!(row(&gw, &taker)["execution"]["status"], "REJECTED");
        assert_eq!(
            row(&gw, &taker)["execution"]["reason"],
            "FillOrKillUnfillable"
        );
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 20, px, "PostOnly");
        tick(&mut gw);
        assert_eq!(row(&gw, &taker)["filledSize"], "0");
        assert_eq!(row(&gw, &taker)["execution"]["reason"], "PostOnlyWouldTake");
    }
    #[test]
    fn ioc_partial_cancels_only_unfilled_remainder() {
        let (mut gw, _, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 5, 0, "Ioc");
        tick(&mut gw);
        assert_eq!(
            row(&gw, &taker)["filledSize"],
            (SIZE_SCALE / 10).to_string()
        );
        assert_eq!(row(&gw, &taker)["execution"]["remainingSize"], "0");
        assert_eq!(row(&gw, &taker)["execution"]["status"], "CANCELLED");
    }
    #[test]
    fn self_trade_removal_is_visible_without_fake_execution() {
        let (mut gw, maker, _, _) = paired();
        submit(&mut gw, &maker, "Buy", SIZE_SCALE / 20, 0, "Ioc");
        tick(&mut gw);
        let rows = gw.v1_orders_json(&maker).unwrap();
        let old = &rows["orders"][1];
        assert_eq!(old["execution"]["status"], "CANCELLED");
        assert_eq!(old["execution"]["reason"], "SelfTradePrevented");
        assert_eq!(old["filledSize"], "0");
    }
    #[test]
    fn cancel_before_seal_retains_original_receipt_and_is_idempotent() {
        let mut gw = exchange();
        let key = account(&mut gw);
        let px = gw.px_of(0);
        submit(&mut gw, &key, "Sell", SIZE_SCALE / 10, px, "Gtc");
        let receipt = row(&gw, &key)["receipt"].clone();
        gw.account_cancel(&key, "o1").unwrap();
        gw.account_cancel(&key, "o1").unwrap();
        tick(&mut gw);
        assert_eq!(row(&gw, &key)["receipt"], receipt);
        assert_eq!(row(&gw, &key)["execution"]["status"], "CANCELLED");
        assert_eq!(row(&gw, &key)["filledSize"], "0");
    }
    #[test]
    fn full_fill_cannot_be_cancelled_and_foreign_key_cannot_cancel() {
        let (mut gw, maker, taker, _) = paired();
        assert!(gw.account_cancel(&taker, "o1").is_err());
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 10, 0, "Ioc");
        tick(&mut gw);
        let err = gw.account_cancel(&maker, "o1").unwrap_err();
        assert!(err.contains("ORDER_NOT_LIVE"));
        assert_eq!(row(&gw, &maker)["execution"]["status"], "FILLED");
    }
    #[test]
    fn snapshot_roundtrip_preserves_partial_vwap_and_cancelled_remainder() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        gw.account_cancel(&maker, "o1").unwrap();
        let before = row(&gw, &maker);
        let root = gw.seq.state.state_root();
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert_eq!(restored.seq.state.state_root(), root);
        assert_eq!(row(&restored, &maker), before);
        restored.account_cancel(&maker, "o1").unwrap();
        assert_replay(&mut restored);
    }
    #[test]
    fn v5_migration_preserves_accounts_but_marks_fabricated_history_unavailable() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        // Serialize the exact legacy positional prefix, without any execution trailer.
        let markets: Vec<_> = gw
            .mkts
            .iter()
            .map(|m| (m.id, m.reference_price, m.px, m.live))
            .collect();
        let legacy = postcard::to_allocvec(&(&gw, markets)).unwrap();
        let root = gw.seq.state.state_root();
        let restored = Gw::boot_restored(&legacy).unwrap();
        assert_eq!(restored.seq.state.state_root(), root);
        assert_eq!(
            restored.accounts[&maker].wallet.owner,
            gw.accounts[&maker].wallet.owner
        );
        assert_eq!(row(&restored, &maker)["execution"]["available"], false);
        assert!(row(&restored, &maker)["filledSize"].is_null());
        assert_eq!(
            row(&restored, &maker)["execution"]["remainingSize"],
            (3 * SIZE_SCALE / 40).to_string()
        );
    }
    #[test]
    fn corrupt_execution_trailer_is_not_silently_ignored() {
        let (gw, _, _, _) = paired();
        let mut bytes = gw.snapshot_plain();
        bytes.extend_from_slice(b"bad trailing bytes");
        assert!(Gw::boot_restored(&bytes).is_err());
    }
    #[test]
    fn snapshot_envelope_has_one_way_v8_guard_and_accepts_v5() {
        let (gw, _, _, _) = paired();
        let seed = [42; 32];
        let current = snapshot::seal(&gw.snapshot_plain(), &seed);
        assert_eq!(&current[..8], b"DPSNAP8\0");
        let markets: Vec<_> = gw
            .mkts
            .iter()
            .map(|m| (m.id, m.reference_price, m.px, m.live))
            .collect();
        let old = postcard::to_allocvec(&(&gw, markets)).unwrap();
        let mut sealed = snapshot::seal(&old, &seed);
        sealed[..8].copy_from_slice(b"DPSNAP5\0");
        let nonce: [u8; 32] = sealed[8..40].try_into().unwrap();
        let mut words = vec![
            seed,
            nonce,
            perp_core::hash::word_u64((sealed.len() - 72) as u64),
        ];
        for chunk in sealed[72..].chunks(32) {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            words.push(word);
        }
        let tag =
            <Keccak256 as perp_core::hash::Hasher>::hash_words(Domain::SnapshotSealMac, &words);
        sealed[40..72].copy_from_slice(&tag);
        assert!(Gw::boot_restored(&snapshot::open(&sealed, &seed).unwrap()).is_ok());
    }
    #[test]
    fn failed_window_retains_cancel_and_rebinds_intervening_fills() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        let failed = assert_replay(&mut gw);
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        gw.account_cancel(&maker, "o1").unwrap();
        gw.seq.rollback_window(&failed);
        let retry = assert_replay(&mut gw);
        gw.seq.mark_window_settled(retry.batch_id);
        tick(&mut gw);
        assert_eq!(row(&gw, &maker)["execution"]["unsettledSize"], "0");
        assert_eq!(
            row(&gw, &maker)["filledSize"],
            (SIZE_SCALE / 20).to_string()
        );
        assert_eq!(row(&gw, &maker)["execution"]["status"], "CANCELLED");
        assert_eq!(gw.seq.book(0).unwrap().resting_size(Side::Sell), 0);
    }
    #[test]
    fn legacy_maker_finishing_remainder_is_not_actionable_or_fabricated() {
        let (mut gw, maker, taker, _) = paired();
        let markets: Vec<(u64, i128, i128, bool)> = gw
            .mkts
            .iter()
            .map(|m| (m.id, m.reference_price, m.px, m.live))
            .collect();
        let old = postcard::to_allocvec(&(&gw, markets)).unwrap();
        gw = Gw::boot_restored(&old).unwrap();
        gw.window_settle_mode = true;
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 10, 0, "Ioc");
        tick(&mut gw);
        let order = row(&gw, &maker);
        assert_eq!(order["execution"]["remainingSize"], "0");
        assert_eq!(order["execution"]["available"], false);
        assert!(order["filledSize"].is_null());
        assert!(gw
            .account_cancel(&maker, "o1")
            .unwrap_err()
            .contains("ORDER_NOT_LIVE"));
    }
    #[test]
    fn changing_v8_to_a_legacy_header_does_not_bypass_authentication() {
        let seed = [42; 32];
        for magic in [b"DPSNAP5\0", b"DPSNAP6\0", b"DPSNAP7\0"] {
            let mut sealed = snapshot::seal(b"a new-format state", &seed);
            sealed[..8].copy_from_slice(magic);
            assert!(snapshot::open(&sealed, &seed).is_err());
        }
    }
    #[test]
    fn a05_duplicate_tick_notification_is_idempotent_before_and_after_restart() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        let order = gw.accounts[&taker].orders[0].order;
        refresh(&mut gw);
        let batch = gw.seq.seal_batch(&[order], now_ms());
        let financial_root = gw.seq.state.state_root();
        for (key, newly_submitted) in [(maker, false), (taker, true)] {
            let o = &mut gw.accounts.get_mut(&key).unwrap().orders[0];
            let events = execution::update(o, &gw.seq, &batch, newly_submitted);
            assert_eq!(events.iter().filter(|e| e["type"] == "fill").count(), 1);
            o.sealed = true;
        }
        let before = gw.snapshot_plain();
        let o = &mut gw.accounts.get_mut(&maker).unwrap().orders[0];
        assert!(execution::update(o, &gw.seq, &batch, false).is_empty());
        assert_eq!(gw.snapshot_plain(), before);
        let mut restored = Gw::boot_restored(&before).unwrap();
        let o = &mut restored.accounts.get_mut(&maker).unwrap().orders[0];
        assert!(execution::update(o, &restored.seq, &batch, false).is_empty());
        assert_eq!(restored.snapshot_plain(), before);
        assert_eq!(restored.seq.state.state_root(), financial_root);
        assert_eq!(row(&restored, &maker)["filledSize"], (SIZE_SCALE / 40).to_string());
    }

    #[test]
    fn a05_reported_fills_match_successful_replay_ops_and_bad_attribution_is_unavailable() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        let order = gw.accounts[&taker].orders[0].order;
        refresh(&mut gw);
        let mut batch = gw.seq.seal_batch(&[order], now_ms());
        let actual: Vec<_> = batch.ops.iter().filter_map(|op| match op {
            BatchOp::Fill { taker, maker, market_id, taker_side, size, price, .. } =>
                Some((*taker, *maker, *market_id, *taker_side, *size, *price)),
            _ => None,
        }).collect();
        let reported: Vec<_> = batch.applied_fills.iter().map(|m|
            (m.taker, m.maker, m.market_id, m.taker_side, m.size, m.price)).collect();
        assert_eq!(actual, reported);
        assert_eq!(actual.len(), 1);
        let root = gw.seq.state.state_root();
        batch.applied_fills[0].maker = [0xff; 32];
        let o = &mut gw.accounts.get_mut(&maker).unwrap().orders[0];
        let events = execution::update(o, &gw.seq, &batch, false);
        assert!(!events.iter().any(|e| e["type"] == "fill"));
        assert_eq!(row(&gw, &maker)["execution"]["available"], false);
        assert!(row(&gw, &maker)["filledSize"].is_null());
        assert_eq!(gw.seq.state.state_root(), root);
    }

    #[test]
    fn a05_v7_cannot_silently_drop_execution_extension() {
        let (gw, _, _, _) = paired();
        let raw = v7_snapshot(&gw);
        let payload = raw.strip_prefix(execution::SNAPSHOT_V7).unwrap()
            .strip_prefix(deposit_ingestion::SNAPSHOT_V6).unwrap();
        type LegacyPart = (Gw, Vec<(u64, i128, i128, bool)>, deposit_ingestion::DepositState);
        let (_, rest): (LegacyPart, _) = postcard::take_from_bytes(payload).unwrap();
        assert!(!rest.is_empty());
        assert!(Gw::boot_restored(&raw[..raw.len() - rest.len()]).is_err());
        // Simply removing v7's prefix also leaves a forbidden v6 trailer.
        assert!(Gw::boot_restored(raw.strip_prefix(execution::SNAPSHOT_V7).unwrap()).is_err());
    }

    #[test]
    fn a07_v7_migration_preserves_partial_execution_and_replay() {
        let (mut gw, maker, taker, _) = paired();
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 40, 0, "Ioc");
        tick(&mut gw);
        gw.account_cancel(&maker, "o1").unwrap();
        let before = row(&gw, &maker);
        let old = v7_snapshot(&gw);
        let mut restored = Gw::boot_restored(&old).unwrap();
        assert_eq!(restored.seq.state.state_root(), gw.seq.state.state_root());
        assert_eq!(row(&restored, &maker), before);
        assert!(restored.accounts.values().all(|a| a.recovery_nonce == 0));
        assert_eq!(v7_snapshot(&restored), old);
        let upgraded = restored.snapshot_plain();
        assert!(upgraded.starts_with(account_recovery::SNAPSHOT_V8));
        assert_eq!(Gw::boot_restored(&upgraded).unwrap().snapshot_plain(), upgraded);
        assert_replay(&mut restored);
    }

    #[test]
    fn a07_v8_preserves_generation_and_rejects_truncation_or_downgrade() {
        let (mut gw, maker, _, _) = paired();
        gw.accounts.get_mut(&maker).unwrap().recovery_nonce = 7;
        let raw = gw.snapshot_plain();
        let restored = Gw::boot_restored(&raw).unwrap();
        assert_eq!(restored.accounts[&maker].recovery_nonce, 7);
        assert_eq!(restored.snapshot_plain(), raw);
        let payload = raw
            .strip_prefix(account_recovery::SNAPSHOT_V8)
            .unwrap()
            .strip_prefix(deposit_ingestion::SNAPSHOT_V6)
            .unwrap();
        type LegacyPart = (Gw, Vec<(u64, i128, i128, bool)>, deposit_ingestion::DepositState);
        let (_, rest): (LegacyPart, _) = postcard::take_from_bytes(payload).unwrap();
        assert!(!rest.is_empty());
        assert!(Gw::boot_restored(&raw[..raw.len() - rest.len()]).is_err());
        let legacy = v7_snapshot(&gw);
        let mut no_recovery = account_recovery::SNAPSHOT_V8.to_vec();
        no_recovery.extend_from_slice(legacy.strip_prefix(execution::SNAPSHOT_V7).unwrap());
        assert!(Gw::boot_restored(&no_recovery).is_err());
        let inner = raw.strip_prefix(account_recovery::SNAPSHOT_V8).unwrap();
        assert!(Gw::boot_restored(inner).is_err());
        let mut downgraded = execution::SNAPSHOT_V7.to_vec();
        downgraded.extend_from_slice(inner);
        assert!(Gw::boot_restored(&downgraded).is_err());
    }

    #[test]
    fn a07_authenticated_v7_envelope_remains_readable() {
        let (gw, _, _, _) = paired();
        let old = v7_snapshot(&gw);
        let seed = [42; 32];
        let mut sealed = snapshot::seal(&old, &seed);
        let nonce: [u8; 32] = sealed[8..40].try_into().unwrap();
        let mut words = vec![
            seed,
            nonce,
            perp_core::hash::word_u64((sealed.len() - 72) as u64),
        ];
        for chunk in sealed[72..].chunks(32) {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            words.push(word);
        }
        let inner =
            <Keccak256 as perp_core::hash::Hasher>::hash_words(Domain::SnapshotSealMac, &words);
        let tag = <Keccak256 as perp_core::hash::Hasher>::hash_words(
            Domain::SnapshotSealMac,
            &[perp_core::hash::word_u64(7), inner],
        );
        sealed[..8].copy_from_slice(b"DPSNAP7\0");
        sealed[40..72].copy_from_slice(&tag);
        let opened = snapshot::open(&sealed, &seed).unwrap();
        assert_eq!(opened, old);
        let restored = Gw::boot_restored(&opened).unwrap();
        assert_eq!(v7_snapshot(&restored), old);
        assert!(restored.snapshot_plain().starts_with(account_recovery::SNAPSHOT_V8));
    }

    #[test]
    fn challenge_prefers_earlier_ordered_evidence_over_later_cancellation() {
        let (mut gw, maker, _, _) = paired();
        let h = gw.accounts[&maker].orders[0].order_hash;
        gw.batch_orders.insert(4, (vec![h], vec![]));
        gw.batch_orders.insert(5, (vec![], vec![h]));
        let (rejected, batch, _) = gw.build_challenge_answer(&h).unwrap();
        assert!(!rejected);
        assert_eq!(batch, 4);
    }
}

mod cancellation_durability_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    async fn prepare(app: &Shared) -> [u8; 32] {
        let mut gw = app.gw.lock().await;
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
        let px = gw.px_of(0);
        gw.account_place_order(
            &key,
            &OrderReq {
                market_id: 0,
                side: "Sell".into(),
                size: (SIZE_SCALE / 10).to_string(),
                limit_price: (px * 101 / 100).to_string(),
                tif: "Gtc".into(),
                ..Default::default()
            },
        )
        .unwrap();
        gw.tick();
        gw.prod = true;
        key
    }
    fn request(key: &[u8; 32]) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri("/v1/orders/o1")
            .header("x-api-key", hex0x(key))
            .body(Body::empty())
            .unwrap()
    }
    #[tokio::test]
    async fn no_persistence_refuses_without_cancelling_a_live_order() {
        let app = test_app();
        let key = prepare(&app).await;
        let response = build_router(app.clone(), true)
            .oneshot(request(&key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let gw = app.gw.lock().await;
        assert!(gw.seq.book(0).unwrap().resting_size(Side::Sell) > 0);
    }
    #[tokio::test]
    async fn cancellation_waits_for_ack_retries_safely_and_uses_only_private_stream() {
        let mut app = test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let key = prepare(&app).await;
        let mut public = app.tx.subscribe();
        let mut private = app.events_tx.subscribe();
        let first = tokio::spawn(build_router(app.clone(), true).oneshot(request(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!first.is_finished());
        ack.send(false).unwrap();
        assert_eq!(
            first.await.unwrap().unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(private.try_recv().is_err());
        let retry = tokio::spawn(build_router(app.clone(), true).oneshot(request(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!retry.is_finished());
        let plain = app.gw.lock().await.snapshot_plain();
        let restored = Gw::boot_restored(&plain).unwrap();
        assert_eq!(
            restored.v1_orders_json(&key).unwrap()["orders"][0]["execution"]["status"],
            "CANCELLED"
        );
        ack.send(true).unwrap();
        assert_eq!(retry.await.unwrap().unwrap().status(), StatusCode::OK);
        let event: serde_json::Value = serde_json::from_str(&private.try_recv().unwrap()).unwrap();
        assert_eq!(event["type"], "execution");
        assert_eq!(
            event["owner"],
            app.gw.lock().await.owner_hex_for(&key).unwrap()
        );
        assert!(
            public.try_recv().is_err(),
            "private cancellation must never enter public WS"
        );
    }
}
