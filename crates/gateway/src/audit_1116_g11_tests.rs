//! Audit 16 Nov 2026, G1-1: the global position-entry quota must not be filled with
//! 10 USDC entries, and registration must never close on it.
use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt as _;

/// What the audit filled the quota with: one 10 USDC deposit per entry.
const DUST: i128 = 10 * QUOTE_SCALE;

/// The entry minimum: the smallest deposit that opens a position entry, and the
/// balance below which a flat entry is dust.
const ENTRY_MINIMUM: i128 = 100 * QUOTE_SCALE;

/// The soft cap of the position entries (1,063 for the measured bounds).
fn positions_soft_cap(gw: &Gw) -> u64 {
    let max = gw.admission_cap.max_positions;
    max - max / 5
}

fn signer(n: u32, tag: u8) -> k256::ecdsa::SigningKey {
    let mut seed = [tag; 32];
    seed[..4].copy_from_slice(&n.to_be_bytes());
    k256::ecdsa::SigningKey::from_slice(&seed).unwrap()
}

/// A caller-signed account bound to its own address: it can hold deposit permits,
/// and its withdrawals go there.
fn bound_account(gw: &mut Gw, sk: &k256::ecdsa::SigningKey) -> ([u8; 32], [u8; 20]) {
    let address = eth_address(sk);
    let (key, _) = gw.register_account(Some(address));
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(address);
    (key, address)
}

/// The audit's attack: fresh accounts, each with one `amount` entry in every one of
/// the three markets, until the position entries reach their soft cap (with 10 USDC
/// entries, about 355 accounts). Returns the accounts.
fn fill_entries(gw: &mut Gw, amount: i128, tag: u8) -> Vec<[u8; 32]> {
    let soft = positions_soft_cap(gw);
    let mut keys = Vec::new();
    for n in 0u32.. {
        if gw.admission_size().positions >= soft {
            break;
        }
        let (key, _) = bound_account(gw, &signer(n, tag));
        for market in 0..3u64 {
            if gw.admission_size().positions < soft {
                gw.account_deposit(&key, market, amount).unwrap();
            }
        }
        keys.push(key);
    }
    keys
}

/// Store a fresh oracle report of every market's current price.
fn refresh_oracles(gw: &mut Gw) {
    let now = now_ms();
    for market in 0..3u64 {
        let oracle = oracle_of(gw.px_of(market), now, market, &gw.oracle_signer);
        gw.seq.set_oracle(market, oracle);
    }
}

fn entry(gw: &Gw, key: &[u8; 32], market: u64) -> Option<Position> {
    gw.seq
        .state
        .position(&gw.accounts[key].wallet.owner, market)
        .copied()
}

/// A signed withdrawal of `amount` from `key`'s entry in `market` to its bound address.
fn withdraw(
    gw: &mut Gw,
    key: &[u8; 32],
    sk: &k256::ecdsa::SigningKey,
    market: u64,
    amount: i128,
) -> Result<Withdrawal, String> {
    let (owner, nonce, to) = {
        let a = &gw.accounts[key];
        (
            a.wallet.owner,
            a.last_withdraw_nonce + 1,
            a.deposit_address.unwrap(),
        )
    };
    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, market, amount, &to, nonce);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    gw.account_withdraw(key, market, amount, to, nonce, &wire)
}

/// Credit the deposit of the held permit `commit` through the real ingestion path.
fn credit(gw: &mut Gw, commit: [u8; 32]) {
    let start = gw.deposit_cursor();
    let route = gw.deposits.routes[&commit].clone();
    let tip = perp_core::merkle::deposit_chain_fold(
        &start.tip,
        &perp_core::merkle::deposit_leaf(&route.from, &commit, route.amount, start.count),
    );
    let block = deposit_rpc::Block {
        number: start.anchor.as_ref().map_or(1, |b| b.number + 1),
        hash: [7; 32],
        timestamp: None,
    };
    let mut tx = [9u8; 32];
    tx[..8].copy_from_slice(&start.count.to_le_bytes());
    let page = deposit_rpc::Page {
        start: start.clone(),
        end: block.clone(),
        events: vec![deposit_rpc::Event {
            id: start.count,
            from: route.from,
            commit,
            amount: route.amount,
            tip,
            tx,
            tx_index: 0,
            log_index: 0,
            block,
        }],
    };
    gw.apply_deposit_page(page).unwrap();
    gw.deposits.dirty = false;
}

/// A router app serving `gw`, whose durability barrier always acknowledges.
async fn app_with(gw: Gw) -> (Shared, tokio::task::JoinHandle<()>) {
    let mut app = tests::test_app();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let writer = tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    *app.gw.lock().await = gw;
    (app, writer)
}

async fn json_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// `POST /v1/accounts/deposit/authorize` for a collateral permit.
async fn permit(
    app: &Shared,
    key: &[u8; 32],
    from: [u8; 20],
    market: u64,
    amount: i128,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({"from": hex0x(&from), "amount": amount.to_string(),
        "marketId": market, "purpose": "collateral"});
    let request = Request::builder()
        .method("POST")
        .uri("/v1/accounts/deposit/authorize")
        .header("content-type", "application/json")
        .header("x-api-key", hex0x(key))
        .body(Body::from(body.to_string()))
        .unwrap();
    json_of(
        build_router(app.clone(), true)
            .oneshot(request)
            .await
            .unwrap(),
    )
    .await
}

/// `POST /v1/accounts`.
async fn register(app: &Shared) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/accounts")
        .extension(axum::extract::ConnectInfo(
            "10.9.0.7:4000".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    json_of(
        build_router(app.clone(), true)
            .oneshot(request)
            .await
            .unwrap(),
    )
    .await
}

fn commit_of(body: &serde_json::Value) -> [u8; 32] {
    parse_hex32(body["ownerCommit"].as_str().unwrap()).unwrap()
}

/// The audit's state: about 352 accounts x 3 markets x 10 USDC hold the position
/// entries at their soft cap. Registration adds no entry, so it stays open.
#[test]
fn audit_1116_g11_dust_entries_at_the_position_cap_do_not_close_registration() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let dust = fill_entries(&mut gw, DUST, 0x31);
    assert!(dust.len() >= 352, "{} accounts", dust.len());
    let state = admission::HistorySize::of(&gw.seq.state);
    assert_eq!(state.positions, positions_soft_cap(&gw));
    assert!(gw.admission_cap.soft_reached(state));
    assert_eq!(gw.registration_refusal(), None);
}

/// With the entries at their soft cap, all of them 10 USDC dust, registration is
/// open, an honest deposit at the entry minimum gets its permit (one dust entry is
/// swept to its owner's bound address to make room, and the owner is told), and
/// the holders of the other dust entries keep using them.
#[tokio::test]
async fn audit_1116_g11_dust_entries_do_not_block_an_honest_new_entry() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let dust = fill_entries(&mut gw, DUST, 0x32);
    let (honest, honest_from) = bound_account(&mut gw, &signer(1, 0x42));
    refresh_oracles(&mut gw);
    let soft = positions_soft_cap(&gw);
    let before: Vec<(PubKey, u64)> = gw.seq.state.positions.keys().copied().collect();
    let (app, writer) = app_with(gw).await;
    let mut events = app.events_tx.subscribe();

    let (status, body) = register(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("apiKey").is_some());

    let (status, body) = permit(&app, &honest, honest_from, 0, ENTRY_MINIMUM).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let commit = commit_of(&body);

    let mut gw = app.gw.lock().await;
    // Exactly one dust entry left, in full, to its owner's bound address.
    let swept: Vec<_> = before
        .iter()
        .filter(|entry| !gw.seq.state.positions.contains_key(entry))
        .collect();
    assert_eq!(swept.len(), 1, "{swept:?}");
    let (owner, market) = *swept[0];
    let key = *dust
        .iter()
        .find(|key| gw.accounts[*key].wallet.owner == owner)
        .unwrap();
    let view = gw.v1_withdrawals_json(&key).unwrap();
    let rows = view["withdrawals"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{view}");
    assert_eq!(rows[0]["amount"], DUST.to_string());
    assert_eq!(
        rows[0]["to"],
        hex0x(&gw.accounts[&key].deposit_address.unwrap())
    );
    assert_eq!(rows[0]["forcedExit"], true);
    // ...and its owner is told on its own event stream.
    let owner = hex0x(&owner);
    let mut told = false;
    while let Ok(event) = events.try_recv() {
        let event: serde_json::Value = serde_json::from_str(&event).unwrap();
        if event["type"] == "forcedExit" {
            assert_eq!(event["owner"], owner);
            assert_eq!(event["marketId"], market);
            assert_eq!(event["amount"], DUST.to_string());
            told = true;
        }
    }
    assert!(told, "the swept account got no forcedExit event");
    // The honest deposit is credited and the bound is kept.
    credit(&mut gw, commit);
    assert_eq!(entry(&gw, &honest, 0).unwrap().collateral, ENTRY_MINIMUM);
    assert_eq!(gw.admission_size().positions, soft);
    assert!(!gw
        .admission_cap
        .exceeded(admission::HistorySize::of(&gw.seq.state)));

    // Another dust holder keeps its entry and can still top it up.
    let other = *dust.iter().find(|k| **k != key).unwrap();
    let other_from = gw.accounts[&other].deposit_address.unwrap();
    assert!(entry(&gw, &other, 0).is_some());
    drop(gw);
    let (status, body) = permit(&app, &other, other_from, 0, DUST).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    writer.abort();
}

/// A permit that would open a position entry (a market where the account holds
/// none, outstanding permits or not) needs the entry minimum; a top-up of an
/// existing entry keeps the 10 USDC deposit minimum.
#[tokio::test]
async fn audit_1116_g11_a_permit_that_opens_an_entry_needs_the_entry_minimum() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, from) = bound_account(&mut gw, &signer(2, 0x43));
    let (app, writer) = app_with(gw).await;

    for amount in [DUST, ENTRY_MINIMUM - 1] {
        let (status, body) = permit(&app, &key, from, 0, amount).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{amount}: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .starts_with("BELOW_ENTRY_MINIMUM"),
            "{body}"
        );
        assert_eq!(body["minimum"], ENTRY_MINIMUM.to_string());
    }
    assert!(app.gw.lock().await.deposits.routes.is_empty());
    let (status, body) = permit(&app, &key, from, 0, ENTRY_MINIMUM).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let opening = commit_of(&body);
    // An outstanding permit opens no entry yet: a smaller one would open it first.
    let (status, body) = permit(&app, &key, from, 0, DUST).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    credit(&mut *app.gw.lock().await, opening);
    // Once the entry exists, a 10 USDC top-up is accepted; a new market is not.
    let (status, body) = permit(&app, &key, from, 0, DUST).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = permit(&app, &key, from, 1, DUST).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    writer.abort();
}

/// Only a flat entry below the entry minimum is swept, and only one whose account
/// has a bound address, no outstanding permit for that market and is not the one
/// asking. An entry at the minimum, or one holding an open position, never is: at
/// the cap with no sweepable entry the permit is refused, as before.
#[tokio::test]
async fn audit_1116_g11_only_flat_dust_of_other_bound_accounts_is_swept() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    gw.admission_cap = admission::AdmissionCap {
        max_positions: 10,
        ..admission::measured_cap()
    };
    assert_eq!(positions_soft_cap(&gw), 8);
    let (asker, asker_from) = bound_account(&mut gw, &signer(3, 0x44));
    // The asker's own dust, in another market.
    gw.account_deposit(&asker, 1, DUST).unwrap();
    // Entries at the minimum.
    for n in 0..2 {
        let (key, _) = bound_account(&mut gw, &signer(n, 0x45));
        gw.account_deposit(&key, 0, ENTRY_MINIMUM).unwrap();
    }
    // Dust with no bound address.
    let (unbound, _) = gw.register_account(None);
    gw.account_deposit(&unbound, 0, DUST).unwrap();
    // Dust whose account holds an outstanding permit for the same market.
    let (topping, topping_from) = bound_account(&mut gw, &signer(4, 0x44));
    gw.account_deposit(&topping, 0, DUST).unwrap();
    gw.authorize_routed_deposit(
        &topping,
        topping_from,
        DUST as u128,
        0,
        deposit_ingestion::Purpose::Collateral,
        u64::MAX,
    )
    .unwrap();
    // Two dust entries holding an open position (each the other's counterparty).
    let (long, _) = bound_account(&mut gw, &signer(5, 0x44));
    let (short, _) = bound_account(&mut gw, &signer(6, 0x44));
    for key in [&long, &short] {
        gw.account_deposit(key, 2, DUST).unwrap();
    }
    let now = now_ms();
    let px = gw.px_of(2);
    let oracle = oracle_of(px, now, 2, &gw.oracle_signer);
    gw.seq
        .apply(&BatchOp::Fill {
            taker: gw.accounts[&long].wallet.owner,
            maker: gw.accounts[&short].wallet.owner,
            market_id: 2,
            taker_side: Side::Buy,
            size: SIZE_SCALE / 5,
            price: px,
            oracle,
            now_ms: now,
        })
        .unwrap();
    assert_ne!(entry(&gw, &long, 2).unwrap().size, 0);
    assert!(entry(&gw, &long, 2).unwrap().collateral < ENTRY_MINIMUM);
    assert_eq!(gw.admission_size().positions, 7);
    // One more entry at the minimum fills the soft cap.
    let (key, _) = bound_account(&mut gw, &signer(7, 0x45));
    gw.account_deposit(&key, 1, ENTRY_MINIMUM).unwrap();
    assert_eq!(gw.admission_size().positions, 8);
    refresh_oracles(&mut gw);
    let entries = gw.seq.state.positions.clone();
    let (app, writer) = app_with(gw).await;

    let (status, body) = permit(&app, &asker, asker_from, 0, ENTRY_MINIMUM).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body["error"].as_str().unwrap().contains("admission cap"));
    {
        let gw = app.gw.lock().await;
        assert_eq!(gw.seq.state.positions, entries, "nothing was swept");
        assert!(gw.pending_withdrawals.is_empty());
    }

    // Dust made from an entry at the minimum by a partial withdrawal is swept.
    let dusty = {
        let mut gw = app.gw.lock().await;
        let sk = signer(0, 0x45);
        let address = eth_address(&sk);
        let key = *gw
            .accounts
            .iter()
            .find(|(_, a)| a.signer == Some(address))
            .unwrap()
            .0;
        withdraw(&mut gw, &key, &sk, 0, ENTRY_MINIMUM - DUST).unwrap();
        refresh_oracles(&mut gw);
        key
    };
    let (status, body) = permit(&app, &asker, asker_from, 0, ENTRY_MINIMUM).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let gw = app.gw.lock().await;
    assert!(entry(&gw, &dusty, 0).is_none(), "the dust entry was swept");
    let swept = gw.pending_withdrawals.last().unwrap();
    assert_eq!(swept.amount, DUST as u128);
    assert_eq!(swept.to, gw.accounts[&dusty].deposit_address.unwrap());
    for (key, market) in [
        (&asker, 1),
        (&unbound, 0),
        (&topping, 0),
        (&long, 2),
        (&short, 2),
    ] {
        assert!(entry(&gw, key, market).is_some(), "swept {market}");
    }
    drop(gw);
    writer.abort();
}

/// A gateway whose position entries have a soft cap of 4, filled by four 10 USDC
/// entries credited through permits (as before the entry minimum), with an asker
/// bound to its own address and no entry yet. Returns the dust accounts too.
fn small_cap_with_dust() -> (Gw, [u8; 32], Vec<[u8; 32]>) {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    gw.admission_cap = admission::AdmissionCap {
        max_positions: 5,
        ..admission::measured_cap()
    };
    let mut dust = Vec::new();
    for n in 0..4 {
        let (key, from) = bound_account(&mut gw, &signer(n, 0x46));
        let commit = gw
            .authorize_routed_deposit(
                &key,
                from,
                DUST as u128,
                0,
                deposit_ingestion::Purpose::Collateral,
                u64::MAX,
            )
            .unwrap();
        credit(&mut gw, commit);
        dust.push(key);
    }
    let (asker, _) = bound_account(&mut gw, &signer(9, 0x46));
    assert_eq!(gw.admission_size().positions, positions_soft_cap(&gw));
    (gw, asker, dust)
}

fn sweep(gw: &mut Gw, asker: &[u8; 32]) -> Vec<(u64, Withdrawal)> {
    let request = deposit_ingestion::Route {
        key: *asker,
        from: gw.accounts[asker].deposit_address.unwrap(),
        amount: ENTRY_MINIMUM as u128,
        market: 0,
        purpose: deposit_ingestion::Purpose::Collateral,
        valid_until: 0,
    };
    gw.sweep_dust_for_permit(
        &request,
        now_ms() / 1000,
        PriceUse {
            archive: None,
            now_ms: now_ms(),
        },
    )
}

/// The sweep never signs a stale price again: without a usable oracle report for
/// the market the dust waits. With one, exactly one entry leaves, charged to its
/// account's ledger like a full exit, and its authorization nonce is untouched.
#[test]
fn audit_1116_g11_a_sweep_needs_a_fresh_oracle_and_leaves_the_account_nonce() {
    let (mut gw, asker, dust) = small_cap_with_dust();
    let now = now_ms();
    let stale = oracle_of(gw.px_of(0), now - 3_600_000, 0, &gw.oracle_signer);
    gw.seq.set_oracle(0, stale);
    assert!(sweep(&mut gw, &asker).is_empty());
    assert_eq!(gw.admission_size().positions, positions_soft_cap(&gw));
    assert!(gw.pending_withdrawals.is_empty());

    refresh_oracles(&mut gw);
    let swept = sweep(&mut gw, &asker);
    assert_eq!(swept.len(), 1);
    let (market, w) = &swept[0];
    assert_eq!(*market, 0);
    assert_eq!(w.amount, DUST as u128);
    let key = *dust
        .iter()
        .find(|k| gw.accounts[*k].wallet.owner == w.owner)
        .unwrap();
    assert!(entry(&gw, &key, 0).is_none());
    assert_eq!(gw.accounts[&key].last_withdraw_nonce, 0);
    // The credited deposit and the forced exit.
    assert_eq!(gw.withdraw_limits.units(&w.owner), 4);
    assert_eq!(
        gw.window_withdrawals.last().map(Withdrawal::leaf),
        Some(w.leaf())
    );
    // One sweep was enough: the permit is admitted now, and nothing more leaves.
    assert_eq!(
        gw.permit_cap_refusal(&asker, 0, deposit_ingestion::Purpose::Collateral),
        None
    );
    assert!(sweep(&mut gw, &asker).is_empty());
}

/// A sweep is kept across a restart: the snapshot carries its section, written
/// only once there was a sweep, so a gateway that never swept writes the bytes it
/// always did (and the snapshots written before this section load unchanged).
#[test]
fn audit_1116_g11_a_sweep_survives_a_restart() {
    let (mut gw, asker, _) = small_cap_with_dust();
    let plain = gw.snapshot_plain();
    assert!(!plain.windows(8).any(|w| w == b"DPSWEEP1"));
    assert_eq!(Gw::boot_restored(&plain).unwrap().snapshot_plain(), plain);

    refresh_oracles(&mut gw);
    let swept = sweep(&mut gw, &asker);
    let w = swept[0].1.clone();
    let key = *gw
        .accounts
        .iter()
        .find(|(_, a)| a.wallet.owner == w.owner)
        .unwrap()
        .0;
    let plain = gw.snapshot_plain();
    assert!(plain.windows(8).any(|w| w == b"DPSWEEP1"));
    let restored = Gw::boot_restored(&plain).unwrap();
    assert_eq!(restored.snapshot_plain(), plain);
    let view = restored.v1_withdrawals_json(&key).unwrap();
    assert_eq!(view["withdrawals"][0]["forcedExit"], true);
    assert_eq!(view["withdrawals"][0]["leaf"], hex0x(&w.leaf()));
    // An account's own withdrawal is no forced exit.
    let (own, sk) = (0..4)
        .map(|n| signer(n, 0x46))
        .find_map(|sk| {
            let address = eth_address(&sk);
            let (key, a) = gw
                .accounts
                .iter()
                .find(|(_, a)| a.signer == Some(address))?;
            (a.wallet.owner != w.owner).then_some((*key, sk))
        })
        .unwrap();
    withdraw(&mut gw, &own, &sk, 0, DUST).unwrap();
    let view = gw.v1_withdrawals_json(&own).unwrap();
    assert_eq!(view["withdrawals"][0]["forcedExit"], false);
    let mut bad = plain.clone();
    bad.push(0);
    assert!(Gw::boot_restored(&bad).is_err());
}

/// The close-only rebase discards the open window's withdrawals: a sweep in it is
/// undone with them, its entry is back, and it is no forced exit any more.
#[test]
fn audit_1116_g11_a_discarded_sweep_is_no_forced_exit() {
    let (mut gw, asker, _) = small_cap_with_dust();
    gw.seq.seal_genesis_baseline();
    gw.last_settled_root = gw.seq.state.state_root();
    let consumed = gw.seq.state.consumed_deposit_count;
    let entries = gw.seq.state.positions.clone();
    refresh_oracles(&mut gw);
    let swept = sweep(&mut gw, &asker);
    let leaf = swept[0].1.leaf();
    assert!(gw.dust_sweeps.contains(&leaf));
    let l1 = wind_down::SettledL1 {
        block: 100,
        close_only: true,
        settled: false,
        batch_count: gw.seq.current_window_id(),
        root: gw.last_settled_root,
        consumed_deposit_count: consumed,
    };
    gw.rebase_to_settled(&l1).unwrap();
    assert!(!gw.dust_sweeps.contains(&leaf));
    assert!(gw.pending_withdrawals.is_empty());
    assert_eq!(gw.seq.state.positions, entries);
}

/// A permit request that is refused for anything but the position entries sweeps
/// nothing: a payer other than the bound address, an amount below the entry
/// minimum, or an account that spent its history quota.
#[tokio::test]
async fn audit_1116_g11_a_refused_permit_sweeps_nothing() {
    let (mut gw, asker, _) = small_cap_with_dust();
    refresh_oracles(&mut gw);
    let from = gw.accounts[&asker].deposit_address.unwrap();
    let owner = gw.accounts[&asker].wallet.owner;
    let entries = gw.seq.state.positions.clone();
    let (app, writer) = app_with(gw).await;

    // Refused at the cap, which is checked before the payer.
    let (status, body) = permit(&app, &asker, [0x99; 20], 0, ENTRY_MINIMUM).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let (status, body) = permit(&app, &asker, from, 0, DUST).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    {
        let mut gw = app.gw.lock().await;
        for _ in 0..admission::ACCOUNT_HISTORY_QUOTA / 2 {
            gw.withdraw_limits.record_credit(&owner);
        }
    }
    let (status, body) = permit(&app, &asker, from, 0, ENTRY_MINIMUM).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let gw = app.gw.lock().await;
    assert_eq!(gw.seq.state.positions, entries, "nothing was swept");
    assert!(gw.pending_withdrawals.is_empty());
    drop(gw);
    writer.abort();
}
