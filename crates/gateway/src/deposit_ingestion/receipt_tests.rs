use super::*;

fn newly_applied_credit() -> (Gw, [u8; 32], String) {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, _) = gw.register_account(None);
    let from = [0x42; 20];
    let amount = 5_000_000;
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(from);
    let commit = gw
        .authorize_routed_deposit(&key, from, amount, 1, Purpose::Collateral)
        .unwrap();
    let start = gw.deposit_cursor();
    let block = Block {
        number: 1,
        hash: [7; 32],
    };
    let tx = [9; 32];
    let event = Event {
        id: start.count,
        from,
        commit,
        amount,
        tip: perp_core::merkle::deposit_chain_fold(
            &start.tip,
            &perp_core::merkle::deposit_leaf(&from, &commit, amount, start.count),
        ),
        tx,
        tx_index: 0,
        log_index: 0,
        block: block.clone(),
    };
    gw.apply_deposit_page(Page {
        start,
        end: block,
        events: vec![event],
    })
    .unwrap();
    gw.deposits.required = true;
    (gw, key, hex0x(&tx))
}

async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn a01_receipt_read_after_a_later_poll_cannot_claim_undurable_credit() {
    // Model the gap after confirm's ingest_once releases deposit_serial: a
    // queued automatic poll has applied the requested transaction, but its ACK
    // is outstanding. The final receipt read must recheck under the Gw lock.
    let (gw, key, tx) = newly_applied_credit();
    assert!(gw.deposits.ready);
    assert!(gw.deposits.dirty);
    let before = gw.snapshot_plain();
    let response = confirmed_receipt(&gw, &key, &tx, 1, Purpose::Collateral);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response = body(response).await;
    assert_eq!(response["durability"], "unknown");
    assert!(response.get("credited").is_none());
    assert_eq!(before, gw.snapshot_plain());
}

#[tokio::test]
async fn a01_receipt_read_after_ack_returns_the_original_credit_without_reapplying() {
    let (mut gw, key, tx) = newly_applied_credit();
    gw.deposits.dirty = false; // The successful writer ACK, not a second deposit.
    let before = gw.snapshot_plain();
    for _ in 0..2 {
        let response = confirmed_receipt(&gw, &key, &tx, 1, Purpose::Collateral);
        assert_eq!(response.status(), StatusCode::OK);
        let response = body(response).await;
        assert_eq!(response["durability"], "confirmed");
        assert_eq!(response["credited"], "5000000");
        assert_eq!(response["depositIds"], serde_json::json!([0]));
        assert_eq!(response["marketId"], 1);
    }
    assert_eq!(before, gw.snapshot_plain());
    assert_eq!(gw.seq.state.consumed_deposit_count, 1);
}

#[test]
fn a01_receipt_read_rechecks_reorg_and_restart_barriers() {
    let (mut gw, key, tx) = newly_applied_credit();
    gw.deposits.dirty = false;
    gw.deposits.ready = false; // RPC error or a just-restored prefix.
    assert_eq!(
        confirmed_receipt(&gw, &key, &tx, 1, Purpose::Collateral).status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    gw.deposits.ready = true;
    gw.deposits.halt = Some("finalized anchor reorg".into());
    assert_eq!(
        confirmed_receipt(&gw, &key, &tx, 1, Purpose::Collateral).status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn a01_receipt_read_does_not_reroute_a_durable_credit() {
    let (mut gw, key, tx) = newly_applied_credit();
    gw.deposits.dirty = false;
    assert_eq!(
        confirmed_receipt(&gw, &key, &tx, 0, Purpose::Collateral).status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        confirmed_receipt(&gw, &key, &tx, 1, Purpose::InsuranceBootstrap).status(),
        StatusCode::CONFLICT
    );
    assert_eq!(gw.seq.state.insurance_fund, 0);
    assert_eq!(gw.seq.state.consumed_deposit_count, 1);
}
