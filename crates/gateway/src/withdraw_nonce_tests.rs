//! The withdrawal-leaf nonce and the withdrawal minimum.
//!
//! The engine accepts a real withdrawal only with a nonce above its last committed
//! one (`State::last_withdrawal_nonce`) and at most `MAX_WITHDRAWAL_NONCE_STEP`
//! above it. The gateway counter never moves back; the engine can (a void, a
//! close-only rebase), and a restored counter can lag the engine. So the leaf nonce
//! is the larger of the counter and one past the engine's last.
use super::*;
use perp_core::engine::MAX_WITHDRAWAL_NONCE_STEP;

const KEY: [u8; 32] = [0x61; 32];

fn withdrawer() -> (Gw, [u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let sk = k256::ecdsa::SigningKey::from_slice(&KEY).unwrap();
    let address = eth_address(&sk);
    let (key, _) = gw.register_account(Some(address));
    gw.account_deposit(&key, 0, 100 * QUOTE_SCALE).unwrap();
    (gw, key, sk, address)
}

fn withdraw(
    gw: &mut Gw,
    key: &[u8; 32],
    sk: &k256::ecdsa::SigningKey,
    market: u64,
    amount: i128,
    to: [u8; 20],
) -> Result<Withdrawal, String> {
    let (owner, auth_nonce) = {
        let a = &gw.accounts[key];
        (a.wallet.owner, a.last_withdraw_nonce + 1)
    };
    let digest = withdraw_auth_digest(
        gw.chain_id,
        &gw.vault,
        &owner,
        market,
        amount,
        &to,
        auth_nonce,
    );
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    gw.account_withdraw(key, market, amount, to, auth_nonce, &wire)
}

#[test]
fn leaf_nonces_follow_the_engine_when_the_counter_lags() {
    let (mut gw, key, sk, to) = withdrawer();
    let first = withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to).unwrap();
    assert_eq!(first.nonce, 1);
    assert_eq!(gw.seq.state.last_withdrawal_nonce, 1);
    assert_eq!(gw.next_withdraw_nonce, 2);
    // A counter behind the engine never reuses a committed nonce.
    gw.next_withdraw_nonce = 1;
    let second = withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to).unwrap();
    assert_eq!(second.nonce, 2);
    assert_eq!(gw.seq.state.last_withdrawal_nonce, 2);
    assert_eq!(gw.next_withdraw_nonce, 3);
    let replay = gw.seq.seal_window();
    let roots = perp_core::commitment::derive_roots(
        &mut replay.pre_state.clone(),
        &replay.ops,
        &replay.manifest,
    )
    .unwrap();
    assert_eq!(roots.new_state_root, gw.seq.state.state_root());
}

#[test]
fn the_counter_stays_ahead_after_a_void_moves_the_engine_back() {
    let (mut gw, key, sk, to) = withdrawer();
    gw.seq.seal_genesis_baseline();
    for nonce in 1..=2 {
        assert_eq!(
            withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to)
                .unwrap()
                .nonce,
            nonce
        );
    }
    // A void returns the engine to the window baseline; the voided leaves were
    // never published, and the gateway counter does not move back.
    gw.seq.void_open_window();
    assert_eq!(gw.seq.state.last_withdrawal_nonce, 0);
    assert_eq!(gw.next_withdraw_nonce, 3);
    assert_eq!(
        withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to)
            .unwrap()
            .nonce,
        3
    );
    assert_eq!(gw.seq.state.last_withdrawal_nonce, 3);
}

#[test]
fn a_restored_lagging_counter_is_repaired_with_an_alert() {
    let (mut gw, key, sk, to) = withdrawer();
    withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to).unwrap();
    withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to).unwrap();
    assert!(!gw.repair_withdraw_nonce(), "an honest counter is ahead");
    gw.next_withdraw_nonce = 2;
    let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    assert_eq!(restored.next_withdraw_nonce, 2);
    assert!(restored.repair_withdraw_nonce());
    assert_eq!(restored.next_withdraw_nonce, 3);
    assert!(restored
        .ops_alerts
        .active()
        .contains(&ops_alerts::AlertKind::WithdrawNonceRepaired));
    assert!(!restored.repair_withdraw_nonce());
}

#[test]
fn an_engine_refusal_leaves_the_position_and_notes_untouched() {
    let (mut gw, key, sk, to) = withdrawer();
    // Spend, ahead of time, the note the next withdrawal's unbind will mint: the
    // unbind then succeeds and the burn is refused as a double spend.
    let wallet = gw.accounts[&key].wallet;
    let nonce = gw.next_withdraw_nonce;
    let mut blind = [0xD0u8; 32];
    blind[..8].copy_from_slice(&nonce.to_le_bytes());
    let note = Note::new(wallet.owner, 0, QUOTE_SCALE, blind);
    assert!(gw
        .seq
        .state
        .nullifiers
        .insert(note.nullifier::<Keccak256>(&wallet.spend_key)));
    let before = gw.snapshot_plain();
    let collateral = gw.seq.state.position(&wallet.owner, 0).unwrap().collateral;
    let error = withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to).unwrap_err();
    assert!(error.contains("withdrawal refused"), "{error}");
    assert_eq!(
        gw.seq.state.position(&wallet.owner, 0).unwrap().collateral,
        collateral
    );
    assert!(!gw
        .seq
        .state
        .notes
        .contains_key(&note.commitment::<Keccak256>()));
    assert_eq!(
        gw.snapshot_plain(),
        before,
        "nothing applied, nothing burned"
    );
}

#[test]
fn a_nonce_beyond_the_engine_step_is_refused_before_anything_is_applied() {
    let (mut gw, key, sk, to) = withdrawer();
    gw.next_withdraw_nonce = MAX_WITHDRAWAL_NONCE_STEP + 1;
    let before = gw.snapshot_plain();
    let error = withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to).unwrap_err();
    assert!(error.contains("step limit"), "{error}");
    assert_eq!(gw.snapshot_plain(), before);
    // The step limit itself is accepted.
    gw.next_withdraw_nonce = MAX_WITHDRAWAL_NONCE_STEP;
    assert_eq!(
        withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE, to)
            .unwrap()
            .nonce,
        MAX_WITHDRAWAL_NONCE_STEP
    );
}

#[test]
fn a_withdrawal_below_one_dollar_must_take_the_whole_free_balance() {
    let (mut gw, key, sk, to) = withdrawer();
    let before = gw.snapshot_plain();
    let error = withdraw(&mut gw, &key, &sk, 0, QUOTE_SCALE - 1, to).unwrap_err();
    assert!(error.contains("BELOW_MINIMUM"), "{error}");
    assert_eq!(gw.snapshot_plain(), before);
    assert!(withdraw(&mut gw, &key, &sk, 0, MIN_WITHDRAWAL, to).is_ok());
    // A small balance can always leave in full.
    gw.account_deposit(&key, 1, QUOTE_SCALE / 2).unwrap();
    assert!(withdraw(&mut gw, &key, &sk, 1, QUOTE_SCALE / 4, to)
        .unwrap_err()
        .contains("BELOW_MINIMUM"));
    let all = withdraw(&mut gw, &key, &sk, 1, QUOTE_SCALE / 2, to).unwrap();
    assert_eq!(all.amount, (QUOTE_SCALE / 2) as u128);
}

/// The minimum's exception is per market, so the account view reports each
/// market's free balance next to the account-wide one: a client can then tell
/// that the whole $0.40 of one market may leave while another market holds more,
/// and that a sub-dollar request equal to the account-wide balance may not.
#[test]
fn the_account_view_reports_the_free_balance_the_minimum_is_judged_against() {
    let (mut gw, key, sk, to) = withdrawer();
    gw.account_deposit(&key, 1, QUOTE_SCALE * 2 / 5).unwrap();
    let view = gw.v1_account(&key).unwrap();
    let expected: Vec<serde_json::Value> = gw
        .mkts
        .iter()
        .map(|m| {
            let free = match m.id {
                0 => 100 * QUOTE_SCALE,
                1 => QUOTE_SCALE * 2 / 5,
                _ => 0,
            };
            serde_json::json!({ "marketId": m.id, "free": free.to_string() })
        })
        .collect();
    assert_eq!(view["marketFree"], serde_json::json!(expected));
    let total = 100 * QUOTE_SCALE + QUOTE_SCALE * 2 / 5;
    assert_eq!(view["settledBalance"], total.to_string());
    // Under a dollar, but the account-wide balance is not this market's.
    let error = withdraw(&mut gw, &key, &sk, 1, QUOTE_SCALE / 4, to).unwrap_err();
    assert!(error.contains("BELOW_MINIMUM"), "{error}");
    // The whole of the market's free balance leaves.
    let all = withdraw(&mut gw, &key, &sk, 1, QUOTE_SCALE * 2 / 5, to).unwrap();
    assert_eq!(all.amount, (QUOTE_SCALE * 2 / 5) as u128);
    let view = gw.v1_account(&key).unwrap();
    assert_eq!(view["marketFree"][1]["free"], "0");
}
