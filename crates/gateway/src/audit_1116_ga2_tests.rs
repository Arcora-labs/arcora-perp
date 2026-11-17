//! Audit 16 Nov 2026, GA-2: withdrawals consume the lifetime provable-history
//! budget, so one account must not be able to spend it for everyone.
use super::*;
use crate::admission::{
    MAX_PARTIAL_WITHDRAWALS_PER_ACCOUNT, MAX_WITHDRAWALS_PER_MINUTE, MAX_WITHDRAWALS_PER_WINDOW,
    WITHDRAW_QUOTA_EXCEEDED, WITHDRAW_RATE_LIMIT_MINUTE, WITHDRAW_RATE_LIMIT_WINDOW,
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
    // The window settles: its withdrawals leave the open set.
    gw.window_withdrawals.clear();
    withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap();
}

#[test]
fn audit_1116_ga2_the_partial_quota_never_blocks_a_full_exit() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, sk, to) = account(&mut gw, 0x75, 1_000 * QUOTE_SCALE);
    let owner = gw.accounts[&key].wallet.owner;
    let mut t = 1_000_000u64;
    for _ in 0..MAX_PARTIAL_WITHDRAWALS_PER_ACCOUNT {
        gw.withdraw_limits.record(&owner, t, true);
        t += 60_000;
    }
    let before = gw.snapshot_plain();
    let err = withdraw_at(&mut gw, &key, &sk, MIN_UNITS, to, t).unwrap_err();
    assert_eq!(err, WITHDRAW_QUOTA_EXCEEDED);
    assert_eq!(gw.snapshot_plain(), before);
    // The whole balance of the (flat) position still leaves.
    let all = gw.market_free_of(&owner, 0);
    assert!(withdraw_at(&mut gw, &key, &sk, all, to, t).is_ok());
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
    let sk = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let address = eth_address(&sk);
    let (key, _) = gw.register_account(Some(address));
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(address);
    (key, sk, address)
}

/// Issue a minimum collateral permit for market 0 and credit its deposit through
/// the real ingestion path.
fn deposit_through_permit(gw: &mut Gw, key: &[u8; 32], from: [u8; 20]) -> Result<(), String> {
    if let Some(refusal) = gw.permit_cap_refusal(key, 0, deposit_ingestion::Purpose::Collateral) {
        return Err(format!("{refusal:?}"));
    }
    let commit = gw.authorize_routed_deposit(
        key,
        from,
        admission::MIN_DEPOSIT_PERMIT,
        0,
        deposit_ingestion::Purpose::Collateral,
        u64::MAX,
    )?;
    let page = credit_page(gw, commit);
    gw.apply_deposit_page(page)?;
    gw.deposits.dirty = false;
    Ok(())
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
