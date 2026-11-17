//! Audit 16 Nov 2026, GA-2: withdrawals consume the lifetime provable-history
//! budget, so one account must not be able to spend it for everyone.
use super::*;
use crate::admission::{
    ACCOUNT_HISTORY_QUOTA, MAX_WITHDRAWALS_PER_MINUTE, MAX_WITHDRAWALS_PER_WINDOW,
    PARTIAL_WITHDRAWAL_HISTORY_CEILING, WITHDRAW_QUOTA_EXCEEDED, WITHDRAW_RATE_LIMIT_MINUTE,
    WITHDRAW_RATE_LIMIT_WINDOW, WITHDRAW_RESERVE_REACHED,
};

const MIN_UNITS: i128 = 10 * QUOTE_SCALE;

fn account(gw: &mut Gw, seed: u8, deposit: i128) -> ([u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
    account_from(gw, [seed; 32], deposit)
}

fn account_from(
    gw: &mut Gw,
    seed: [u8; 32],
    deposit: i128,
) -> ([u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
    let sk = k256::ecdsa::SigningKey::from_slice(&seed).unwrap();
    let address = eth_address(&sk);
    let (key, _) = gw.register_account(Some(address));
    gw.account_deposit(&key, 0, deposit).unwrap();
    (key, sk, address)
}

fn withdraw_at(
    gw: &mut Gw,
    key: &[u8; 32],
    sk: &k256::ecdsa::SigningKey,
    amount: i128,
    to: [u8; 20],
    now: u64,
) -> Result<Withdrawal, String> {
    let (owner, auth_nonce) = {
        let a = &gw.accounts[key];
        (a.wallet.owner, a.last_withdraw_nonce + 1)
    };
    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, auth_nonce);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    gw.account_withdraw_checked(
        key,
        0,
        amount,
        to,
        (auth_nonce, &wire),
        WithdrawalContext {
            wind_down: None,
            price: PriceUse {
                archive: None,
                now_ms: now,
            },
        },
    )
}

#[test]
fn audit_1116_ga2_thousands_of_small_withdrawals_are_stopped_early() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x71, 100_000 * QUOTE_SCALE);
    let (honest, honest_sk, honest_to) = account(&mut gw, 0x72, 100 * QUOTE_SCALE);
    let history_before = admission::HistorySize::of(&gw.seq.state).history;
    let now = now_ms();
    let mut done = 0u32;
    let mut last = String::new();
    for _ in 0..5_000 {
        match withdraw_at(&mut gw, &key, &sk, QUOTE_SCALE, to, now) {
            Ok(_) => done += 1,
            Err(e) => last = e,
        }
    }
    // A 1 USDC withdrawal is below the minimum, and nothing else gets through.
    assert_eq!(done, 0);
    assert!(last.contains("BELOW_MINIMUM"), "{last}");
    for _ in 0..5_000 {
        match withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, now) {
            Ok(_) => done += 1,
            Err(e) => last = e,
        }
    }
    assert_eq!(done, MAX_WITHDRAWALS_PER_MINUTE);
    assert!(last.starts_with("WITHDRAW_RATE_LIMIT_MINUTE"), "{last}");
    let used = admission::HistorySize::of(&gw.seq.state).history - history_before;
    assert_eq!(used, 2 * u64::from(done));
    // Registration stays open and an honest account can still withdraw.
    assert_eq!(gw.registration_refusal(), None);
    assert!(withdraw_at(&mut gw, &honest, &honest_sk, MIN_UNITS, honest_to, now).is_ok());
}

#[test]
fn audit_1116_ga2_the_minute_limit_resets_with_the_minute() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x73, 1_000 * QUOTE_SCALE);
    let t0 = 1_000_000u64;
    for _ in 0..MAX_WITHDRAWALS_PER_MINUTE {
        withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t0).unwrap();
    }
    let err = withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t0 + 59_999).unwrap_err();
    assert_eq!(err, WITHDRAW_RATE_LIMIT_MINUTE);
    withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t0 + 60_000).unwrap();
}

#[test]
fn audit_1116_ga2_the_window_limit_resets_when_the_window_is_taken() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x74, 1_000 * QUOTE_SCALE);
    let mut t = 1_000_000u64;
    for _ in 0..MAX_WITHDRAWALS_PER_WINDOW {
        withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap();
        t += 60_000;
    }
    let err = withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap_err();
    assert_eq!(err, WITHDRAW_RATE_LIMIT_WINDOW);
    // The window is sealed for settlement: its withdrawals leave the open set.
    let id = gw.seq.state.next_batch_id;
    let (_, ww) = gw.begin_window_settle(id).unwrap().unwrap();
    assert_eq!(ww.len(), MAX_WITHDRAWALS_PER_WINDOW);
    withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap();
}

#[test]
fn audit_1116_ga2_the_quota_holds_through_real_withdrawals_and_a_restart() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x75, 1_000 * QUOTE_SCALE);
    let owner = gw.accounts[&key].wallet.owner;
    let mut t = 1_000_000u64;
    for _ in 0..ACCOUNT_HISTORY_QUOTA / 2 {
        // Each minute, and the window is settled now and then.
        t += 60_000;
        gw.window_withdrawals.clear();
        withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap();
    }
    assert_eq!(gw.withdraw_limits.units(&owner), ACCOUNT_HISTORY_QUOTA);
    t += 60_000;
    gw.window_withdrawals.clear();
    let before = gw.snapshot_plain();
    let err = withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap_err();
    assert_eq!(err, WITHDRAW_QUOTA_EXCEEDED);
    assert_eq!(gw.snapshot_plain(), before);
    // A restart does not give the account a new quota.
    let mut restored = Gw::boot_restored(&before).unwrap();
    assert_eq!(
        restored.withdraw_limits.units(&owner),
        ACCOUNT_HISTORY_QUOTA
    );
    let err = withdraw_at(&mut restored, &key, &sk, MIN_UNITS, to, t).unwrap_err();
    assert_eq!(err, WITHDRAW_QUOTA_EXCEEDED);
    // The whole balance of the (flat) position still leaves, and is charged.
    let all = restored.market_free_of(&owner, 0);
    assert!(withdraw_at(&mut restored, &key, &sk, all, to, t).is_ok());
    assert_eq!(
        restored.withdraw_limits.units(&owner),
        ACCOUNT_HISTORY_QUOTA + 2
    );
}

#[test]
fn audit_1116_ga2_a_snapshot_without_usage_has_no_ledger_section() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let plain = gw.snapshot_plain();
    assert!(!plain.windows(8).any(|w| w == b"DPWLIM01"));
    assert_eq!(Gw::boot_restored(&plain).unwrap().snapshot_plain(), plain);
    let (key, sk, to) = account(&mut gw, 0x78, 100 * QUOTE_SCALE);
    withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, 1_000_000).unwrap();
    let plain = gw.snapshot_plain();
    assert!(plain.windows(8).any(|w| w == b"DPWLIM01"));
    assert_eq!(Gw::boot_restored(&plain).unwrap().snapshot_plain(), plain);
    let mut bad = plain.clone();
    bad.push(0);
    assert!(Gw::boot_restored(&bad).is_err());
}

#[test]
fn audit_1116_ga2_the_history_reserve_stops_partials_but_not_full_exits() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x79, 100_000 * QUOTE_SCALE);
    let owner = gw.accounts[&key].wallet.owner;
    // Raise the history to the reserve, outside the per-account limits.
    while admission::HistorySize::of(&gw.seq.state).history < PARTIAL_WITHDRAWAL_HISTORY_CEILING {
        gw.withdraw_limits = Default::default();
        gw.window_withdrawals.clear();
        withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, 1_000_000).unwrap();
    }
    gw.withdraw_limits = Default::default();
    gw.window_withdrawals.clear();
    let t = 1_000_000;
    let err = withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap_err();
    assert_eq!(err, WITHDRAW_RESERVE_REACHED);
    let all = gw.market_free_of(&owner, 0);
    assert!(withdraw_at(&mut gw, &key, &sk, all, to, t).is_ok());
    assert_eq!(gw.registration_refusal(), None);
}

#[test]
fn audit_1116_ga2_a_clock_that_steps_back_does_not_extend_the_minute() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x7a, 1_000 * QUOTE_SCALE);
    let t0 = 5_000_000u64;
    for _ in 0..MAX_WITHDRAWALS_PER_MINUTE {
        withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t0).unwrap();
    }
    assert_eq!(
        withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t0 + 1).unwrap_err(),
        WITHDRAW_RATE_LIMIT_MINUTE
    );
    withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t0 - 1_000).unwrap();
}

#[test]
fn audit_1116_ga2_a_voided_window_refunds_its_withdrawals_and_deposits() {
    let f = crate::live_void::tests::voidable(false);
    let mut gw = f.gw;
    let owner = gw.accounts[&f.w.key].wallet.owner;
    let maker = gw.accounts[&f.maker.key].wallet.owner;
    // The settled deposit and the window's withdrawal.
    assert_eq!(gw.withdraw_limits.units(&owner), 4);
    assert_eq!(gw.withdraw_limits.units(&maker), 2);
    match gw.live_void_window(
        &f.journal,
        crate::rollback_journal::DeadIntent::EmptyAfterFence,
    ) {
        Ok(crate::live_void::LiveVoidOutcome::Applied(_)) => {}
        other => panic!("the void was not applied: {other:?}"),
    }
    // Only the settled deposit stays charged; the window's withdrawal can be
    // signed again, and its deposits are charged when they are credited again.
    assert_eq!(gw.withdraw_limits.units(&owner), 2);
    assert_eq!(gw.withdraw_limits.units(&maker), 0);
}

#[test]
fn audit_1116_ga2_the_demo_withdraw_is_limited_like_the_production_one() {
    let mut gw = Gw::boot();
    gw.deposit(1_000 * QUOTE_SCALE).unwrap();
    let err = gw.withdraw(QUOTE_SCALE).unwrap_err();
    assert!(err.contains("BELOW_MINIMUM"), "{err}");
    for _ in 0..MAX_WITHDRAWALS_PER_MINUTE {
        gw.withdraw(MIN_UNITS).unwrap();
    }
    assert_eq!(
        gw.withdraw(MIN_UNITS).unwrap_err(),
        WITHDRAW_RATE_LIMIT_MINUTE
    );
}

#[tokio::test]
async fn audit_1116_ga2_the_withdraw_route_answers_429_and_400_with_typed_errors() {
    use axum::body::Body;
    use tower::ServiceExt as _;
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x7b, 1_000 * QUOTE_SCALE);
    let owner = gw.accounts[&key].wallet.owner;
    let app = tests::test_app();
    *app.gw.lock().await = gw;
    let (chain_id, vault) = {
        let g = app.gw.lock().await;
        (g.chain_id, g.vault)
    };
    let call = |amount: i128, nonce: u64| {
        let digest = withdraw_auth_digest(chain_id, &vault, &owner, 0, amount, &to, nonce);
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut wire = [0u8; 65];
        wire[..64].copy_from_slice(&sig.to_bytes());
        wire[64] = 27 + recid.to_byte();
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts/withdraw")
            .header("Content-Type", "application/json")
            .header("X-Api-Key", hex0x(&key))
            .body(Body::from(
                serde_json::json!({"marketId":0,"amount":amount.to_string(),"to":hex0x(&to),"nonce":nonce,"signature":hex0x(&wire)})
                    .to_string(),
            ))
            .unwrap()
    };
    let send = |req: axum::http::Request<Body>| async {
        let res = build_router(app.clone(), true).oneshot(req).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    };
    for nonce in 1..=u64::from(MAX_WITHDRAWALS_PER_MINUTE) {
        assert_eq!(send(call(MIN_UNITS, nonce)).await.0, StatusCode::OK);
    }
    let (status, body) = send(call(MIN_UNITS, 4)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("WITHDRAW_RATE_LIMIT_MINUTE"), "{body}");
    // Used up quota: a typed 400, not a rate limit.
    {
        let mut g = app.gw.lock().await;
        g.withdraw_limits = Default::default();
        for _ in 0..ACCOUNT_HISTORY_QUOTA / 2 {
            g.withdraw_limits.record_credit(&owner);
        }
    }
    let (status, body) = send(call(MIN_UNITS, 4)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("WITHDRAW_QUOTA_EXCEEDED"), "{body}");
}

#[test]
fn audit_1116_ga2_a_full_balance_below_the_minimum_may_leave() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x76, 100 * QUOTE_SCALE);
    gw.account_deposit(&key, 1, 3 * QUOTE_SCALE).unwrap();
    let now = now_ms();
    let digest_amount = MIN_UNITS - 1;
    let err = withdraw_at(&mut gw, &key, &sk, digest_amount, to, now).unwrap_err();
    assert!(err.contains("BELOW_MINIMUM"), "{err}");
    // Market 1 holds only 3 USDC: all of it leaves, though under the minimum.
    let (owner, auth_nonce) = {
        let a = &gw.accounts[&key];
        (a.wallet.owner, a.last_withdraw_nonce + 1)
    };
    let amount = 3 * QUOTE_SCALE;
    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 1, amount, &to, auth_nonce);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    let w = gw
        .account_withdraw(&key, 1, amount, to, auth_nonce, &wire)
        .unwrap();
    assert_eq!(w.amount, amount as u128);
}

/// The one-deposit page that credits the held permit `commit` (a distinct
/// transaction per deposit).
fn credit_page(gw: &Gw, commit: [u8; 32]) -> deposit_rpc::Page {
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
    deposit_rpc::Page {
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
    }
}

/// A production gateway account that signs its own withdrawals and is bound to
/// its own address, so it can hold deposit permits too.
fn permit_account(gw: &mut Gw, seed: u8) -> ([u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
    permit_account_from(gw, [seed; 32])
}

fn permit_account_from(
    gw: &mut Gw,
    seed: [u8; 32],
) -> ([u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
    let sk = k256::ecdsa::SigningKey::from_slice(&seed).unwrap();
    let address = eth_address(&sk);
    let (key, _) = gw.register_account(Some(address));
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(address);
    (key, sk, address)
}

/// Issue a collateral permit of `amount` for market 0 through the permit gate,
/// and leave it unfunded.
fn take_permit(
    gw: &mut Gw,
    key: &[u8; 32],
    from: [u8; 20],
    amount: u128,
) -> Result<[u8; 32], String> {
    if let Some(refusal) = gw.permit_cap_refusal(key, 0, deposit_ingestion::Purpose::Collateral) {
        return Err(format!("{refusal:?}"));
    }
    gw.authorize_routed_deposit(
        key,
        from,
        amount,
        0,
        deposit_ingestion::Purpose::Collateral,
        u64::MAX,
    )
}

/// Credit the deposit of the outstanding permit `commit` through the real
/// ingestion path.
fn fund_permit(gw: &mut Gw, commit: [u8; 32]) -> Result<(), String> {
    let page = credit_page(gw, commit);
    gw.apply_deposit_page(page)?;
    gw.deposits.dirty = false;
    Ok(())
}

/// Issue a minimum collateral permit for market 0 and credit its deposit through
/// the real ingestion path.
fn deposit_through_permit(gw: &mut Gw, key: &[u8; 32], from: [u8; 20]) -> Result<(), String> {
    let commit = take_permit(gw, key, from, admission::MIN_DEPOSIT_PERMIT)?;
    fund_permit(gw, commit)
}

#[test]
fn audit_1116_ga2_a_deposit_and_full_exit_loop_stops_at_the_account_quota() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, address) = permit_account(&mut gw, 0x77);
    let owner = gw.accounts[&key].wallet.owner;
    let history_before = admission::HistorySize::of(&gw.seq.state).history;
    let mut now = 1_000_000u64;
    let mut cycles = 0u32;
    for _ in 0..200 {
        // The per-minute and per-window limits are not what stops the loop.
        now += 60_000;
        gw.window_withdrawals.clear();
        if deposit_through_permit(&mut gw, &key, address).is_err() {
            break;
        }
        let all = gw.market_free_of(&owner, 0);
        withdraw_at(&mut gw, &key, &sk, all, address, now).unwrap();
        cycles += 1;
    }
    let used = admission::HistorySize::of(&gw.seq.state).history - history_before;
    assert!(cycles < 200, "the loop never stopped: {cycles} cycles");
    assert!(used <= 100, "one account used {used} history units");
}

#[test]
fn audit_1116_ga2_many_accounts_under_the_quota_cannot_close_registration() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let mut now = 1_000_000u64;
    for n in 0..130u8 {
        let mut seed = [0x5au8; 32];
        seed[0] = n;
        let (key, sk, to) = account_from(&mut gw, seed, 600 * QUOTE_SCALE);
        for _ in 0..50 {
            now += 60_000;
            gw.window_withdrawals.clear();
            if withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, now).is_err() {
                break;
            }
        }
    }
    // Sustained abuse by many accounts leaves registration and permits open.
    assert_eq!(gw.registration_refusal(), None);
    let (late, _, late_address) = permit_account(&mut gw, 0x7f);
    assert!(deposit_through_permit(&mut gw, &late, late_address).is_ok());
}

/// Review round 2: outstanding permits cost nothing (no L1 transaction), so they
/// must not count toward the exchange-wide partial-withdrawal reserve. Free
/// accounts holding unfunded permits past it leave the state's history as it was
/// and every honest partial withdrawal open.
#[test]
fn audit_1116_ga2_unfunded_permits_do_not_close_partial_withdrawals() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (honest, honest_sk, honest_to) = account(&mut gw, 0x7d, 100 * QUOTE_SCALE);
    let history = admission::HistorySize::of(&gw.seq.state).history;
    let mut accounts = 0u8;
    let mut permits = 0u64;
    while gw.admission_size().history < PARTIAL_WITHDRAWAL_HISTORY_CEILING {
        let mut seed = [0x5bu8; 32];
        seed[0] = accounts;
        accounts += 1;
        let (key, _, address) = permit_account_from(&mut gw, seed);
        while take_permit(&mut gw, &key, address, admission::MIN_DEPOSIT_PERMIT).is_ok() {
            permits += 1;
        }
    }
    assert!(accounts <= 81, "{accounts} accounts held {permits} permits");
    assert_eq!(
        admission::HistorySize::of(&gw.seq.state).history,
        history,
        "a permit adds no history until its deposit is credited"
    );
    withdraw_at(
        &mut gw, &honest, &honest_sk, MIN_UNITS, honest_to, 1_000_000,
    )
    .unwrap();
}

/// Review round 2: the withdrawal quota counts the account's outstanding permits,
/// as the permit gate does. Otherwise one account takes permits up to the quota,
/// makes partial withdrawals up to it as well, then funds the permits, whose
/// credits the quota never refuses: about twice its quota.
#[test]
fn audit_1116_ga2_outstanding_permits_count_against_the_withdrawal_quota() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, address) = permit_account(&mut gw, 0x7e);
    let owner = gw.accounts[&key].wallet.owner;
    let history = admission::HistorySize::of(&gw.seq.state).history;
    // One real deposit, then permits up to the quota, left unfunded.
    let commit = take_permit(&mut gw, &key, address, (1_000 * QUOTE_SCALE) as u128).unwrap();
    fund_permit(&mut gw, commit).unwrap();
    let mut permits = Vec::new();
    while let Ok(commit) = take_permit(&mut gw, &key, address, admission::MIN_DEPOSIT_PERMIT) {
        permits.push(commit);
    }
    assert_eq!(permits.len() as u64, ACCOUNT_HISTORY_QUOTA / 2 - 1);
    // Partial withdrawals, outside the rate limits: none fits the quota.
    let mut t = 1_000_000u64;
    let mut partial = 0usize;
    let mut last = String::new();
    for _ in 0..permits.len() {
        t += 60_000;
        gw.window_withdrawals.clear();
        match withdraw_at(&mut gw, &key, &sk, MIN_UNITS, address, t) {
            Ok(_) => partial += 1,
            Err(e) => last = e,
        }
    }
    assert_eq!(partial, 0, "partial withdrawals past the committed quota");
    assert_eq!(last, WITHDRAW_QUOTA_EXCEEDED);
    // The permits are funded: the account stays within its quota.
    for commit in permits {
        fund_permit(&mut gw, commit).unwrap();
    }
    assert_eq!(gw.withdraw_limits.units(&owner), ACCOUNT_HISTORY_QUOTA);
    let used = admission::HistorySize::of(&gw.seq.state).history - history;
    assert!(
        used <= ACCOUNT_HISTORY_QUOTA,
        "one account used {used} units"
    );
}

/// Review round 2: every visitor of the demo build shares one demo user, and the
/// demo deposit routes are not metered, so a lifetime quota on that user protects
/// nothing and closes `/api/withdraw` for everyone after 50 withdrawals in total.
/// The demo withdrawal keeps the minimum, the rate limit and the reserve.
#[test]
fn audit_1116_ga2_the_shared_demo_user_has_no_lifetime_quota() {
    let mut gw = Gw::boot();
    gw.deposit(1_000 * QUOTE_SCALE).unwrap();
    let owner = gw.user.owner;
    for _ in 0..ACCOUNT_HISTORY_QUOTA / 2 {
        gw.withdraw_limits.record_credit(&owner);
    }
    gw.withdraw(MIN_UNITS).unwrap();
    assert_eq!(
        gw.withdraw_limits.units(&owner),
        ACCOUNT_HISTORY_QUOTA,
        "the shared demo user is not charged"
    );
}

/// Review round 2: the close-only rebase discards the open window's credits and
/// withdrawals, as a live void does, so it takes back what they were charged.
#[test]
fn audit_1116_ga2_the_close_only_rebase_refunds_what_it_discards() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, address) = permit_account(&mut gw, 0x7c);
    let owner = gw.accounts[&key].wallet.owner;
    let commit = take_permit(&mut gw, &key, address, (100 * QUOTE_SCALE) as u128).unwrap();
    fund_permit(&mut gw, commit).unwrap();
    gw.seq.seal_genesis_baseline();
    gw.last_settled_root = gw.seq.state.state_root();
    let consumed = gw.seq.state.consumed_deposit_count;
    // The open window credits a deposit and makes a withdrawal; it never settles.
    deposit_through_permit(&mut gw, &key, address).unwrap();
    withdraw_at(&mut gw, &key, &sk, MIN_UNITS, address, 1_000_000).unwrap();
    assert_eq!(gw.withdraw_limits.units(&owner), 6);
    let l1 = wind_down::SettledL1 {
        block: 100,
        close_only: true,
        settled: false,
        batch_count: gw.seq.current_window_id(),
        root: gw.last_settled_root,
        consumed_deposit_count: consumed,
    };
    gw.rebase_to_settled(&l1).unwrap();
    assert!(gw.window_withdrawals.is_empty());
    assert_eq!(
        gw.withdraw_limits.units(&owner),
        2,
        "only the settled deposit stays charged"
    );
}
