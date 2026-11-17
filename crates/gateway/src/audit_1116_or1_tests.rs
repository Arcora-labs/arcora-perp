//! Audit 16 Nov 2026, OR-1: a withdrawal with an open position must be measured
//! against the stored oracle report, never against the last price re-signed with a
//! fresh timestamp. While the feed is down the withdrawal is refused as
//! "oracle unavailable"; an account with no position needs no price.
use super::*;

/// How long the feed has been silent in these tests (staleness limit is 10 s).
const OUTAGE_MS: u64 = 60_000;

fn bound_account(gw: &mut Gw, seed: u8, deposit: i128) -> ([u8; 32], k256::ecdsa::SigningKey) {
    let sk = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let address = eth_address(&sk);
    let (key, _) = gw.register_account(Some(address));
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(address);
    gw.account_deposit(&key, 0, deposit).unwrap();
    (key, sk)
}

fn owner_of(gw: &Gw, key: &[u8; 32]) -> PubKey {
    gw.accounts[key].wallet.owner
}

/// Sign a fresh report of market 0's displayed price published at `at_ms`.
fn report_at(gw: &mut Gw, at_ms: u64) {
    let oracle = oracle_of(gw.px_of(0), at_ms, 0, &gw.oracle_signer);
    gw.seq.set_oracle(0, oracle);
}

/// A 0.25 unit long for `long` against `short` at the held price, filled against a
/// report published `OUTAGE_MS` ago: the feed then stopped. Returns that time.
fn open_long_then_feed_stops(gw: &mut Gw, long: PubKey, short: PubKey) -> u64 {
    let published = now_ms() - OUTAGE_MS;
    report_at(gw, published);
    let oracle = *gw.seq.oracle(0).unwrap();
    gw.seq
        .apply(&BatchOp::Fill {
            taker: long,
            maker: short,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE / 4,
            price: gw.px_of(0),
            oracle,
            now_ms: published,
        })
        .unwrap();
    assert_ne!(gw.seq.state.position(&long, 0).unwrap().size, 0);
    published
}

fn withdraw(
    gw: &mut Gw,
    key: &[u8; 32],
    sk: &k256::ecdsa::SigningKey,
    amount: i128,
    at_ms: u64,
) -> Result<Withdrawal, String> {
    let (owner, nonce, to) = {
        let a = &gw.accounts[key];
        (
            a.wallet.owner,
            a.last_withdraw_nonce + 1,
            a.deposit_address.unwrap(),
        )
    };
    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, nonce);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    gw.account_withdraw_checked(
        key,
        0,
        amount,
        to,
        (nonce, &wire),
        WithdrawalContext {
            wind_down: None,
            price: PriceUse {
                archive: None,
                now_ms: at_ms,
            },
        },
    )
}

#[test]
fn audit_1116_or1_withdraw_with_a_position_is_refused_while_the_feed_is_down() {
    let mut gw = Gw::boot();
    let (long, sk) = bound_account(&mut gw, 0x31, 3_000 * QUOTE_SCALE);
    let (short, _) = bound_account(&mut gw, 0x32, 3_000 * QUOTE_SCALE);
    let (lo, so) = (owner_of(&gw, &long), owner_of(&gw, &short));
    let published = open_long_then_feed_stops(&mut gw, lo, so);
    let root = gw.seq.state.state_root();
    let err = withdraw(
        &mut gw,
        &long,
        &sk,
        200 * QUOTE_SCALE,
        published + OUTAGE_MS,
    )
    .expect_err("a stale report must not be re-signed as fresh");
    assert!(err.contains("oracle unavailable"), "{err}");
    assert_eq!(gw.seq.state.state_root(), root, "nothing was applied");
    assert_eq!(gw.accounts[&long].last_withdraw_nonce, 0, "nonce kept");
}

#[test]
fn audit_1116_or1_withdraw_with_a_position_succeeds_on_a_fresh_feed() {
    let mut gw = Gw::boot();
    let (long, sk) = bound_account(&mut gw, 0x33, 3_000 * QUOTE_SCALE);
    let (short, _) = bound_account(&mut gw, 0x34, 3_000 * QUOTE_SCALE);
    let (lo, so) = (owner_of(&gw, &long), owner_of(&gw, &short));
    let published = open_long_then_feed_stops(&mut gw, lo, so);
    let now = published + OUTAGE_MS;
    report_at(&mut gw, now);
    withdraw(&mut gw, &long, &sk, 200 * QUOTE_SCALE, now).expect("fresh feed");
}

#[test]
fn audit_1116_or1_a_flat_account_withdraws_during_an_outage() {
    let mut gw = Gw::boot();
    let (flat, sk) = bound_account(&mut gw, 0x35, 1_000 * QUOTE_SCALE);
    report_at(&mut gw, now_ms() - OUTAGE_MS);
    withdraw(&mut gw, &flat, &sk, 200 * QUOTE_SCALE, now_ms()).expect("no oracle dependency");
}

#[test]
fn audit_1116_or1_pool_transfer_with_a_position_needs_a_fresh_report() {
    let mut gw = Gw::boot();
    let (long, _) = bound_account(&mut gw, 0x36, 3_000 * QUOTE_SCALE);
    let (short, _) = bound_account(&mut gw, 0x37, 3_000 * QUOTE_SCALE);
    let (lo, so) = (owner_of(&gw, &long), owner_of(&gw, &short));
    open_long_then_feed_stops(&mut gw, lo, so);
    let (from, to) = (gw.accounts[&long].wallet, gw.mm);
    let root = gw.seq.state.state_root();
    let err = gw
        .pool_transfer(&from, &to, 200 * QUOTE_SCALE)
        .expect_err("stale report");
    assert!(err.contains("oracle unavailable"), "{err}");
    assert_eq!(gw.seq.state.state_root(), root);
    report_at(&mut gw, now_ms());
    gw.pool_transfer(&from, &to, 200 * QUOTE_SCALE)
        .expect("fresh feed");
}

#[test]
fn audit_1116_or1_demo_withdraw_with_a_position_needs_a_fresh_report() {
    let mut gw = Gw::boot();
    let (user, mm) = (gw.user.owner, gw.mm.owner);
    open_long_then_feed_stops(&mut gw, user, mm);
    let root = gw.seq.state.state_root();
    let err = gw.withdraw(100 * QUOTE_SCALE).expect_err("stale report");
    assert!(err.contains("oracle unavailable"), "{err}");
    assert_eq!(gw.seq.state.state_root(), root);
    report_at(&mut gw, now_ms());
    gw.withdraw(100 * QUOTE_SCALE).expect("fresh feed");
}
