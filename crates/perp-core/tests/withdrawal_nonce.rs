//! The withdrawal nonce is bound to state. A real L1 withdrawal (`to = Some`) must
//! carry a nonce strictly greater than `State::last_withdrawal_nonce`, by at most
//! `MAX_WITHDRAWAL_NONCE_STEP`, and becomes the new last nonce. An internal burn
//! (`to = None`) must carry nonce 0 and leaves the counter alone. The rule holds
//! across batches and across the wind-down phases, so no two withdrawal leaves
//! `(to, amount, nonce)` are ever equal. A refused withdrawal changes nothing.

use perp_core::commitment::derive_roots;
use perp_core::engine::{BatchOp, WithdrawalOut, MAX_WITHDRAWAL_NONCE_STEP};
use perp_core::fixed::QUOTE_SCALE;
use perp_core::hash::{Digest, Keccak256};
use perp_core::merkle::withdrawal_leaf;
use perp_core::note::{owner_from_spend_key, Note, PubKey};
use perp_core::order::BatchManifest;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError};
use std::collections::BTreeSet;

const SPEND: Digest = [1; 32];
const PAYOUT: [u8; 20] = [0xAB; 20];
const OTHER: [u8; 20] = [0xCD; 20];
const AMOUNT: i128 = 100 * QUOTE_SCALE;

fn owner() -> PubKey {
    owner_from_spend_key::<Keccak256>(&SPEND)
}

/// The deposit that credits a note of `amount` with blinding `blind` at the next
/// L1 deposit index of `s`, and that note's commitment.
fn deposit_op(s: &DefaultState, amount: i128, blind: Digest) -> (BatchOp, Digest) {
    let op = BatchOp::Deposit {
        owner: owner(),
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0x11; 20],
        deposit_id: s.consumed_deposit_count,
        deposit_blind: [0x22; 32],
    };
    let cm = Note::new(owner(), 0, amount, blind).commitment::<Keccak256>();
    (op, cm)
}

/// A state holding one note of `AMOUNT` per entry of `blinds`, all owned by the
/// same key: equal notes, so their withdrawals to one address differ only in
/// the nonce.
fn funded(blinds: &[u8]) -> (DefaultState, Vec<Digest>) {
    let mut s = DefaultState::new(16);
    let mut cms = Vec::new();
    for &b in blinds {
        let (op, cm) = deposit_op(&s, AMOUNT, [b; 32]);
        s.apply_batch(&[op]).expect("deposit");
        cms.push(cm);
    }
    (s, cms)
}

fn withdraw(cm: Digest, to: Option<[u8; 20]>, nonce: u64) -> BatchOp {
    BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: SPEND,
        to,
        nonce,
    }
}

fn wind_down_withdraw(cm: Digest, to: Option<[u8; 20]>, nonce: u64) -> BatchOp {
    BatchOp::WindDownWithdraw {
        note_commitment: cm,
        spend_key: SPEND,
        to,
        nonce,
    }
}

fn leaf(w: &WithdrawalOut) -> Digest {
    withdrawal_leaf(&w.to, w.amount as u128, w.nonce)
}

fn manifest_for(s: &DefaultState) -> BatchManifest {
    BatchManifest {
        previous_state_root: s.state_root(),
        batch_id: s.next_batch_id,
        batch_time_ms: 0,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0; 32],
        sequencer_pubkey_epoch: 0,
    }
}

/// Apply `op` and expect `err`, with the state exactly as it was before.
fn assert_refused_unchanged(s: &mut DefaultState, op: &BatchOp, err: EngineError) {
    let root = s.state_root();
    let notes = s.notes.len();
    let spent = s.nullifiers.len();
    let out = s.external_out;
    let last = s.last_withdrawal_nonce;
    assert_eq!(s.apply_op(op).unwrap_err(), err, "{op:?}");
    assert_eq!(s.state_root(), root, "a refused withdrawal changes nothing");
    assert_eq!(s.notes.len(), notes);
    assert_eq!(s.nullifiers.len(), spent);
    assert_eq!(s.external_out, out);
    assert_eq!(s.last_withdrawal_nonce, last);
}

#[test]
fn genesis_has_no_withdrawal_nonce() {
    assert_eq!(DefaultState::new(16).last_withdrawal_nonce, 0);
}

#[test]
fn equal_withdrawals_in_one_batch_need_distinct_nonces() {
    let (s, cms) = funded(&[1, 2]);
    // Two notes of equal value, withdrawn to one address with one nonce: both
    // leaves would be identical.
    let batch = [
        withdraw(cms[0], Some(PAYOUT), 7),
        withdraw(cms[1], Some(PAYOUT), 7),
    ];

    // The proven transition refuses the whole batch.
    assert_eq!(
        derive_roots(&mut s.clone(), &batch, &manifest_for(&s)).unwrap_err(),
        EngineError::WithdrawalNonceNotIncreasing
    );
    assert_eq!(
        s.clone().apply_batch(&batch).unwrap_err(),
        EngineError::WithdrawalNonceNotIncreasing
    );

    // Op by op: the first is accepted, the second is refused with no state change
    // and its note stays spendable.
    let mut live = s.clone();
    let first = live.apply_op(&batch[0]).unwrap().withdrawal.unwrap();
    assert_eq!(first.nonce, 7);
    assert_eq!(live.last_withdrawal_nonce, 7);
    assert_refused_unchanged(
        &mut live,
        &batch[1],
        EngineError::WithdrawalNonceNotIncreasing,
    );
    assert!(live.notes.contains_key(&cms[1]));

    let second = live
        .apply_op(&withdraw(cms[1], Some(PAYOUT), 8))
        .unwrap()
        .withdrawal
        .unwrap();
    assert_ne!(leaf(&first), leaf(&second));
    assert_eq!(live.external_out, 2 * AMOUNT);
    assert!(live.conservation_holds());

    // The same pair with increasing nonces is one valid batch.
    let ok = [
        withdraw(cms[0], Some(PAYOUT), 7),
        withdraw(cms[1], Some(PAYOUT), 8),
    ];
    let mut proven = s.clone();
    let roots = derive_roots(&mut proven, &ok, &manifest_for(&s)).unwrap();
    assert_eq!(
        roots.withdrawals_root,
        perp_core::merkle::withdrawals_root(&[
            perp_core::merkle::WithdrawalLeaf {
                to: PAYOUT,
                amount: AMOUNT as u128,
                nonce: 7,
            },
            perp_core::merkle::WithdrawalLeaf {
                to: PAYOUT,
                amount: AMOUNT as u128,
                nonce: 8,
            },
        ])
    );
    assert_eq!(proven.last_withdrawal_nonce, 8);
}

#[test]
fn nonce_at_or_below_the_last_is_refused_in_later_batches() {
    let (mut s, cms) = funded(&[1, 2]);
    s.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 5)]).unwrap();
    assert_eq!(s.last_withdrawal_nonce, 5);

    for nonce in [5, 4, 1, 0] {
        assert_eq!(
            s.clone()
                .apply_batch(&[withdraw(cms[1], Some(PAYOUT), nonce)])
                .unwrap_err(),
            EngineError::WithdrawalNonceNotIncreasing,
            "nonce {nonce}"
        );
        assert_refused_unchanged(
            &mut s,
            &withdraw(cms[1], Some(OTHER), nonce),
            EngineError::WithdrawalNonceNotIncreasing,
        );
    }

    let out = s.apply_batch(&[withdraw(cms[1], Some(PAYOUT), 6)]).unwrap();
    assert_eq!(out.withdrawals.len(), 1);
    assert_eq!(out.withdrawals[0].nonce, 6);
    assert_eq!(s.last_withdrawal_nonce, 6);
    assert!(s.conservation_holds());
}

#[test]
fn nonce_may_skip_ahead_up_to_the_step_bound() {
    let (s, cms) = funded(&[1, 2, 3]);

    // A gap is accepted: the counter jumps to the nonce used.
    let mut gap = s.clone();
    gap.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 1_000)])
        .unwrap();
    assert_eq!(gap.last_withdrawal_nonce, 1_000);

    // Exactly the bound is accepted.
    let mut at = s.clone();
    at.apply_batch(&[withdraw(cms[0], Some(PAYOUT), MAX_WITHDRAWAL_NONCE_STEP)])
        .unwrap();
    assert_eq!(at.last_withdrawal_nonce, MAX_WITHDRAWAL_NONCE_STEP);
    // ... and the bound is measured from the new last nonce.
    let mut again = at.clone();
    again
        .apply_batch(&[withdraw(
            cms[1],
            Some(PAYOUT),
            2 * MAX_WITHDRAWAL_NONCE_STEP,
        )])
        .unwrap();
    assert_eq!(again.last_withdrawal_nonce, 2 * MAX_WITHDRAWAL_NONCE_STEP);
    assert_refused_unchanged(
        &mut at,
        &withdraw(cms[1], Some(PAYOUT), 2 * MAX_WITHDRAWAL_NONCE_STEP + 1),
        EngineError::WithdrawalNonceNotIncreasing,
    );
}

#[test]
fn nonce_step_above_the_bound_is_refused() {
    let (mut s, cms) = funded(&[1]);
    for nonce in [MAX_WITHDRAWAL_NONCE_STEP + 1, u64::MAX / 2, u64::MAX] {
        assert_refused_unchanged(
            &mut s,
            &withdraw(cms[0], Some(PAYOUT), nonce),
            EngineError::WithdrawalNonceNotIncreasing,
        );
        assert_eq!(
            derive_roots(
                &mut s.clone(),
                &[withdraw(cms[0], Some(PAYOUT), nonce)],
                &manifest_for(&s)
            )
            .unwrap_err(),
            EngineError::WithdrawalNonceNotIncreasing
        );
    }
    // The note is still spendable with an in-range nonce.
    s.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 1)]).unwrap();
    assert_eq!(s.last_withdrawal_nonce, 1);
}

#[test]
fn nonce_near_the_top_of_the_range_does_not_wrap() {
    let (mut s, cms) = funded(&[1, 2]);
    // Not reachable from genesis within any realistic history; set directly to
    // check the arithmetic at the edge.
    s.last_withdrawal_nonce = u64::MAX - 1;
    s.apply_batch(&[withdraw(cms[0], Some(PAYOUT), u64::MAX)])
        .unwrap();
    assert_eq!(s.last_withdrawal_nonce, u64::MAX);
    for nonce in [u64::MAX, 0, 1] {
        assert_refused_unchanged(
            &mut s,
            &withdraw(cms[1], Some(PAYOUT), nonce),
            EngineError::WithdrawalNonceNotIncreasing,
        );
    }
    // Internal burns are unaffected by the counter.
    s.apply_batch(&[withdraw(cms[1], None, 0)]).unwrap();
    assert!(s.conservation_holds());
}

#[test]
fn internal_burn_carries_nonce_zero_and_keeps_the_counter() {
    let (mut s, cms) = funded(&[1, 2, 3]);
    s.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 3)]).unwrap();
    assert_eq!(s.last_withdrawal_nonce, 3);

    for nonce in [1, 3, 4, u64::MAX] {
        assert_refused_unchanged(
            &mut s,
            &withdraw(cms[1], None, nonce),
            EngineError::InternalBurnNonceNotZero,
        );
    }

    let out = s.apply_batch(&[withdraw(cms[1], None, 0)]).unwrap();
    assert!(out.withdrawals.is_empty(), "an internal burn emits no leaf");
    assert_eq!(
        s.last_withdrawal_nonce, 3,
        "an internal burn keeps the counter"
    );
    assert_eq!(s.external_out, 2 * AMOUNT);
    assert!(!s.notes.contains_key(&cms[1]));

    // The next real withdrawal still has to pass the counter.
    assert_refused_unchanged(
        &mut s,
        &withdraw(cms[2], Some(PAYOUT), 3),
        EngineError::WithdrawalNonceNotIncreasing,
    );
    s.apply_batch(&[withdraw(cms[2], Some(PAYOUT), 4)]).unwrap();
    assert_eq!(s.last_withdrawal_nonce, 4);
    assert!(s.conservation_holds());
}

#[test]
fn refused_withdrawal_keeps_the_note_spendable() {
    let (s, cms) = funded(&[1]);

    // A failing balance update is refused before the note is spent.
    let mut full = s.clone();
    full.external_out = i128::MAX;
    assert_refused_unchanged(
        &mut full,
        &withdraw(cms[0], Some(PAYOUT), 1),
        EngineError::Overflow,
    );
    assert_refused_unchanged(&mut full, &withdraw(cms[0], None, 0), EngineError::Overflow);
    assert!(full.notes.contains_key(&cms[0]));

    // A refused nonce leaves the note for a later valid withdrawal.
    let mut live = s.clone();
    assert_refused_unchanged(
        &mut live,
        &withdraw(cms[0], Some(PAYOUT), 0),
        EngineError::WithdrawalNonceNotIncreasing,
    );
    assert_refused_unchanged(
        &mut live,
        &withdraw(cms[0], None, 1),
        EngineError::InternalBurnNonceNotZero,
    );
    live.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 1)])
        .unwrap();
    assert!(live.notes.is_empty());
    assert!(live.conservation_holds());
}

#[test]
fn wind_down_withdrawals_continue_the_same_counter() {
    let (mut s, cms) = funded(&[1, 2, 3, 4]);

    // Phase 0: an ordinary withdrawal sets the counter.
    s.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 10)])
        .unwrap();
    assert_eq!(s.last_withdrawal_nonce, 10);

    // Phase 1: terminal settlement with nothing in reserve emits no leaf and
    // keeps the counter.
    let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    assert!(out.withdrawals.is_empty());
    assert_eq!(s.mode, Mode::CloseOnly);
    assert_eq!(s.last_withdrawal_nonce, 10);

    // Phase 2: the wind-down withdrawal follows the same rule.
    for nonce in [10, 9, 0, 10 + MAX_WITHDRAWAL_NONCE_STEP + 1] {
        assert_eq!(
            s.clone()
                .apply_batch(&[wind_down_withdraw(cms[1], Some(PAYOUT), nonce)])
                .unwrap_err(),
            EngineError::WithdrawalNonceNotIncreasing,
            "nonce {nonce}"
        );
    }
    assert_refused_unchanged(
        &mut s,
        &wind_down_withdraw(cms[1], None, 11),
        EngineError::InternalBurnNonceNotZero,
    );
    let out = s
        .apply_batch(&[
            wind_down_withdraw(cms[1], Some(PAYOUT), 11),
            wind_down_withdraw(cms[2], Some(PAYOUT), 12),
        ])
        .unwrap();
    assert_eq!(
        out.withdrawals.iter().map(|w| w.nonce).collect::<Vec<_>>(),
        [11, 12]
    );
    assert_eq!(s.last_withdrawal_nonce, 12);

    // ... including in a later phase-2 batch, and an ordinary withdrawal in
    // close-only reads the same counter.
    assert_eq!(
        s.clone()
            .apply_batch(&[wind_down_withdraw(cms[3], Some(PAYOUT), 12)])
            .unwrap_err(),
        EngineError::WithdrawalNonceNotIncreasing
    );
    assert_eq!(
        s.clone()
            .apply_batch(&[withdraw(cms[3], Some(PAYOUT), 12)])
            .unwrap_err(),
        EngineError::WithdrawalNonceNotIncreasing
    );
    s.apply_batch(&[wind_down_withdraw(cms[3], Some(PAYOUT), 13)])
        .unwrap();
    assert_eq!(s.last_withdrawal_nonce, 13);
    assert!(s.notes.is_empty());
    assert!(s.conservation_holds());
}

/// The settlement's reserve payout is a withdrawal leaf like any other: it takes
/// the nonce after the last one, and phase 2 continues above it.
#[test]
fn the_settlement_payout_takes_the_next_nonce() {
    let (mut s, cms) = funded(&[1, 2]);
    s.set_wind_down_recipient(OTHER);
    s.insurance_fund = AMOUNT;
    s.external_in += AMOUNT;
    assert!(s.conservation_holds());
    s.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 10)])
        .unwrap();

    let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    assert_eq!(
        out.withdrawals,
        [WithdrawalOut {
            to: OTHER,
            amount: AMOUNT,
            nonce: 11,
        }]
    );
    assert_eq!(s.last_withdrawal_nonce, 11);
    assert_eq!(s.insurance_fund, 0);

    for nonce in [10, 11] {
        assert_eq!(
            s.clone()
                .apply_batch(&[wind_down_withdraw(cms[1], Some(PAYOUT), nonce)])
                .unwrap_err(),
            EngineError::WithdrawalNonceNotIncreasing,
            "nonce {nonce}"
        );
    }
    s.apply_batch(&[wind_down_withdraw(cms[1], Some(PAYOUT), 12)])
        .unwrap();
    assert!(s.notes.is_empty());
    assert_eq!(s.external_in, s.external_out);
    assert!(s.conservation_holds());
}

#[test]
fn state_root_binds_the_last_withdrawal_nonce() {
    let base = DefaultState::new(16);
    let mut bumped = base.clone();
    bumped.last_withdrawal_nonce = 1;
    assert_ne!(base.state_root(), bumped.state_root());

    // The same note withdrawn to the same address under two nonces: the two
    // post-states differ only in the counter, and their roots differ.
    let (s, cms) = funded(&[1]);
    let mut a = s.clone();
    let mut b = s.clone();
    a.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 1)]).unwrap();
    b.apply_batch(&[withdraw(cms[0], Some(PAYOUT), 2)]).unwrap();
    assert_eq!(a.external_out, b.external_out);
    assert_eq!(a.nullifiers.digest(), b.nullifiers.digest());
    assert_ne!(a.state_root(), b.state_root());
    let mut aligned = a.clone();
    aligned.last_withdrawal_nonce = 2;
    assert_eq!(aligned.state_root(), b.state_root());
}

// ----- property: no repeated leaf over random histories ---------------------------

/// xorshift64*: a deterministic generator, so the property is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A nonce chosen around `last`: repeats, smaller values, small gaps, the step
/// bound on both sides, and the extremes.
fn pick_nonce(rng: &mut Rng, last: u64, used: &[u64]) -> u64 {
    match rng.below(10) {
        0 => last,
        1 => last.saturating_sub(1 + rng.below(3)),
        2 | 3 => last.saturating_add(1),
        4 | 5 => last.saturating_add(1 + rng.below(5)),
        6 => last.saturating_add(MAX_WITHDRAWAL_NONCE_STEP),
        7 => last.saturating_add(MAX_WITHDRAWAL_NONCE_STEP + 1),
        8 if !used.is_empty() => used[rng.below(used.len() as u64) as usize],
        8 => 0,
        _ => {
            if rng.below(2) == 0 {
                0
            } else {
                u64::MAX
            }
        }
    }
}

#[test]
fn random_histories_never_emit_a_repeated_withdrawal_leaf() {
    let mut rng = Rng(0x0005_EED0_FA11_BEEF);
    let mut s = DefaultState::new(16);
    let mut live: Vec<Digest> = Vec::new();
    let mut spent: Vec<Digest> = Vec::new();
    let mut leaves = BTreeSet::new();
    let mut nonces: Vec<u64> = Vec::new();
    let mut blind: u64 = 0;
    let (mut accepted, mut stale, mut burn_refused) = (0usize, 0usize, 0usize);

    for _batch in 0..120 {
        let pre = s.clone();
        let mut log = Vec::new();
        let mut emitted = Vec::new();
        for _ in 0..1 + rng.below(6) {
            let op = if live.is_empty() || rng.below(3) == 0 {
                // A note of one of two values, so equal notes are common.
                blind += 1;
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&blind.to_le_bytes());
                let amount = (1 + rng.below(2) as i128) * QUOTE_SCALE;
                let (op, cm) = deposit_op(&s, amount, b);
                live.push(cm);
                op
            } else {
                // Some withdrawals target a note that is already spent.
                let cm = if !spent.is_empty() && rng.below(6) == 0 {
                    spent[rng.below(spent.len() as u64) as usize]
                } else {
                    live[rng.below(live.len() as u64) as usize]
                };
                let to = match rng.below(4) {
                    0 => None,
                    1 => Some(OTHER),
                    _ => Some(PAYOUT),
                };
                let nonce = if to.is_none() && rng.below(2) == 0 {
                    0
                } else {
                    pick_nonce(&mut rng, s.last_withdrawal_nonce, &nonces)
                };
                withdraw(cm, to, nonce)
            };

            // The sequencer keeps an op only when the engine accepts it, and a
            // refused op must leave the state exactly as it was.
            let before = s.state_root();
            let last = s.last_withdrawal_nonce;
            match s.apply_op(&op) {
                Ok(out) => {
                    if let Some(w) = out.withdrawal {
                        assert!(w.nonce > last && w.nonce - last <= MAX_WITHDRAWAL_NONCE_STEP);
                        assert_eq!(s.last_withdrawal_nonce, w.nonce);
                        assert!(leaves.insert(leaf(&w)), "repeated leaf {w:?}");
                        nonces.push(w.nonce);
                        emitted.push(w);
                        accepted += 1;
                    } else {
                        assert_eq!(s.last_withdrawal_nonce, last);
                    }
                    if let BatchOp::Withdraw {
                        note_commitment, ..
                    } = op
                    {
                        live.retain(|c| *c != note_commitment);
                        spent.push(note_commitment);
                    }
                    log.push(op);
                }
                Err(e) => {
                    assert_eq!(s.state_root(), before, "refused {op:?} mutated state");
                    match e {
                        EngineError::WithdrawalNonceNotIncreasing => stale += 1,
                        EngineError::InternalBurnNonceNotZero => burn_refused += 1,
                        _ => {}
                    }
                }
            }
            assert!(s.conservation_holds());
        }

        // The prover replays exactly the accepted log and derives the same post-
        // state and leaves.
        let mut proven = pre.clone();
        let roots = derive_roots(&mut proven, &log, &manifest_for(&pre)).expect("accepted log");
        let expected: Vec<perp_core::merkle::WithdrawalLeaf> =
            emitted.iter().map(Into::into).collect();
        assert_eq!(
            roots.withdrawals_root,
            perp_core::merkle::withdrawals_root(&expected)
        );
        assert_eq!(proven.last_withdrawal_nonce, s.last_withdrawal_nonce);
        let mut sequenced = s.clone();
        sequenced.next_batch_id = proven.next_batch_id;
        assert_eq!(proven.state_root(), sequenced.state_root());
        s = proven;
    }

    assert!(nonces.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(s.last_withdrawal_nonce, *nonces.last().unwrap());
    // The run exercised every branch, so the property is not vacuous.
    assert!(accepted >= 40, "accepted {accepted}");
    assert!(stale >= 20, "stale {stale}");
    assert!(burn_refused >= 5, "burn {burn_refused}");
}
