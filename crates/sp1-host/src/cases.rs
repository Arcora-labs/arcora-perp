//! Case witnesses and engine refusals of the guest, beyond the normal fixture.
//! Synthetic, public test values only: every key, owner and deposit here is a
//! test value, never an observed L1 event.
//!
//! Each case is one batch over a pre-state that the engine's own operations built
//! from a deployment-shaped genesis: a depth-[`TREE_DEPTH`] tree, a wind-down
//! recipient, and markets with fees whose oracle publisher is the fixture key. The
//! clock context binds each batch the way the normal fixture's does (chain 84532,
//! verifier `0x11…11`, settlement `0x22…22`, a 10,000 ms window and 2,000 ms skew).
//! `clock-proof --no-prove` executes every case natively and in the guest, and both
//! must commit the same value.
//!
//! Each refusal is a well-framed witness the native twin refuses with its expected
//! error and the guest refuses with no public value. A refusal derived from a case
//! keeps that case's manifest and clock context; a refusal of a fresh batch carries
//! the batch's own time bounds, and the engine refuses it before the clock context
//! is compared with any root.
use crate::{witness_bytes, ClockWitness, NegativeCase, FIXTURE_ORACLE_KEY};
use perp_core::clock::{ClockContext, TimeBounds, WIRE_MAGIC};
use perp_core::commitment::{batch_time_ms, classify_wind_down_ops, derive_roots};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::funding::PRICE_REFRESH_MS;
use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use perp_core::market::{Market, MarketId};
use perp_core::merkle::MerkleTree;
use perp_core::note::{owner_from_spend_key, Note, PubKey};
use perp_core::nullifier::NullifierSet;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{BatchManifest, Side};
use perp_core::position::{RiskError, MIN_INITIAL_MARGIN};
use perp_core::state::{Mode, TREE_DEPTH};
use perp_core::{DefaultState, EngineError, FillLeg};
use prover::ProverError;

/// The wind-down recipient of every case genesis (a synthetic address).
pub const CASE_RECIPIENT: [u8; 20] = [0x5D; 20];
/// Fees of every case market, in basis points of notional: the taker fee, the
/// maker rebate and the treasury cut. The rest of the taker fee funds insurance.
const FEES_BPS: (i128, i128, i128) = (10, 2, 3);
/// The anchor time of a batch with no timed operation (its clock window is empty).
const UNTIMED_ANCHOR_MS: u64 = 101_000;
/// Domain-separation tag of the case blindings.
const BLINDING_TAG: u64 = u64::from_le_bytes(*b"dp.cases");

/// One case: its name, its wind-down phase and the exact bytes given to the guest.
pub struct CaseWitness {
    pub name: &'static str,
    pub phase: u8,
    pub witness: ClockWitness,
    pub bytes: Vec<u8>,
}

fn usd(dollars: i128) -> i128 {
    dollars * QUOTE_SCALE
}

/// The index price of `market` before any move: $1,000 for market 0, $2,000 for 1.
fn price(market: MarketId) -> i128 {
    (1_000 + 1_000 * market as i128) * PRICE_SCALE
}

fn spend_key(trader: u8) -> Digest {
    [trader; 32]
}

fn owner(trader: u8) -> PubKey {
    owner_from_spend_key::<Keccak256>(&spend_key(trader))
}

/// The L1 address a trader withdraws to (a synthetic address).
fn exit_address(trader: u8) -> [u8; 20] {
    [0xE0 | trader; 20]
}

/// A pre-state under construction. Every change goes through `apply_batch`, so
/// the state is one the engine reached, batch by batch, from its genesis.
struct Ledger {
    state: DefaultState,
    key: k256::ecdsa::SigningKey,
    blindings: u64,
}

impl Ledger {
    fn genesis(markets: &[MarketId]) -> Self {
        let key = k256::ecdsa::SigningKey::from_slice(&FIXTURE_ORACLE_KEY).expect("fixture key");
        let probe = oracle_digest(0, PRICE_SCALE, 1, 0, PRICE_SCALE);
        let publisher = OracleSig::sign(&key, &probe)
            .recover(&probe)
            .expect("fixture key recovers");
        let mut state = DefaultState::new(TREE_DEPTH);
        let (taker, maker, treasury) = FEES_BPS;
        for &id in markets {
            let mut market = Market::with_fees_treasury(id, taker, maker, treasury);
            market.oracle_pubkey = publisher;
            state.add_market(market);
        }
        state.set_wind_down_recipient(CASE_RECIPIENT);
        Self {
            state,
            key,
            blindings: 0,
        }
    }

    fn blinding(&mut self) -> Digest {
        self.blindings += 1;
        Keccak256::hash_words(
            Domain::KeyDerivation,
            &[word_u64(BLINDING_TAG), word_u64(self.blindings)],
        )
    }

    fn apply(&mut self, ops: &[BatchOp]) {
        self.state.apply_batch(ops).expect("pre-state batch");
    }

    /// A signed transcript of `market` at `index`, published at `now_ms`.
    fn oracle(&self, market: MarketId, index: i128, now_ms: u64) -> OracleTranscript {
        OracleTranscript {
            price: index,
            publish_time_ms: now_ms,
            confidence: 0,
            backup_twap: index,
            signature: OracleSig::sign(&self.key, &oracle_digest(market, index, now_ms, 0, index)),
        }
    }

    /// The next L1 deposit of `amount` to `trader`, and the commitment of its note.
    fn deposit_op(&mut self, trader: u8, amount: i128) -> (BatchOp, Digest) {
        let blinding = self.blinding();
        let deposit_blind = self.blinding();
        let owner = owner(trader);
        let op = BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding,
            from: [trader; 20],
            deposit_id: self.state.consumed_deposit_count,
            deposit_blind,
        };
        (
            op,
            Note::new(owner, 0, amount, blinding).commitment::<Keccak256>(),
        )
    }

    fn deposit(&mut self, trader: u8, amount: i128) -> Digest {
        let (op, cm) = self.deposit_op(trader, amount);
        self.apply(&[op]);
        cm
    }

    fn fund_op(trader: u8, market: MarketId, note: Digest) -> BatchOp {
        BatchOp::FundPosition {
            owner: owner(trader),
            market_id: market,
            note_commitment: note,
            spend_key: spend_key(trader),
        }
    }

    /// Deposit `amount` for `trader` and bind all of it as `market` collateral.
    fn fund(&mut self, trader: u8, market: MarketId, amount: i128) {
        let note = self.deposit(trader, amount);
        self.apply(&[Self::fund_op(trader, market, note)]);
    }

    #[allow(clippy::too_many_arguments)]
    fn fill(
        &self,
        taker: u8,
        maker: u8,
        market: MarketId,
        side: Side,
        size: i128,
        index: i128,
        now_ms: u64,
    ) -> BatchOp {
        BatchOp::Fill {
            taker: owner(taker),
            maker: owner(maker),
            market_id: market,
            taker_side: side,
            size,
            price: index,
            oracle: self.oracle(market, index, now_ms),
            now_ms,
        }
    }

    fn tick(&self, market: MarketId, mark: i128, index: i128, now_ms: u64) -> BatchOp {
        BatchOp::AccrueFunding {
            market_id: market,
            mark,
            oracle: self.oracle(market, index, now_ms),
            now_ms,
        }
    }

    fn liquidate(&self, trader: u8, market: MarketId, index: i128, now_ms: u64) -> BatchOp {
        BatchOp::Liquidate {
            owner: owner(trader),
            market_id: market,
            oracle: self.oracle(market, index, now_ms),
            now_ms,
        }
    }

    /// Unbind `amount` of `trader`'s `market` collateral into a fresh note.
    fn unbind(
        &mut self,
        trader: u8,
        market: MarketId,
        amount: i128,
        index: i128,
        now_ms: u64,
    ) -> (BatchOp, Digest) {
        let blinding = self.blinding();
        let op = BatchOp::Unbind {
            owner: owner(trader),
            market_id: market,
            amount,
            blinding,
            oracle: self.oracle(market, index, now_ms),
            now_ms,
        };
        (
            op,
            Note::new(owner(trader), 0, amount, blinding).commitment::<Keccak256>(),
        )
    }

    fn withdraw(trader: u8, note: Digest, nonce: u64) -> BatchOp {
        BatchOp::Withdraw {
            note_commitment: note,
            spend_key: spend_key(trader),
            to: Some(exit_address(trader)),
            nonce,
        }
    }

    /// `ops` as the next batch over this pre-state: the honest manifest and the
    /// clock context bound to the transition's derived roots.
    fn case(&self, name: &'static str, ops: Vec<BatchOp>) -> CaseWitness {
        let manifest = manifest_for(&self.state, &ops);
        let roots = derive_roots(&mut self.state.clone(), &ops, &manifest).expect(name);
        let clock = clock_for(
            &ops,
            &manifest,
            roots.commitment::<Keccak256>(),
            roots.wind_down_phase,
        );
        let witness = (self.state.clone(), ops, manifest, clock);
        CaseWitness {
            name,
            phase: roots.wind_down_phase,
            bytes: witness_bytes(&witness),
            witness,
        }
    }

    /// `ops` as the next batch over this pre-state, which the engine refuses:
    /// the honest manifest, and the batch's own time bounds in the clock context.
    fn refused(&self, ops: Vec<BatchOp>) -> Vec<u8> {
        let manifest = manifest_for(&self.state, &ops);
        let phase = classify_wind_down_ops(&ops).expect("well-formed batch grammar");
        let clock = clock_for(&ops, &manifest, [0u8; 32], phase);
        witness_bytes(&(self.state.clone(), ops, manifest, clock))
    }
}

fn manifest_for(state: &DefaultState, ops: &[BatchOp]) -> BatchManifest {
    BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        batch_time_ms: batch_time_ms(ops),
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    }
}

fn clock_for(ops: &[BatchOp], manifest: &BatchManifest, base: Digest, phase: u8) -> ClockContext {
    let bounds = TimeBounds::derive(ops).expect("ordered case times");
    ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: manifest.batch_id,
        previous_root: manifest.previous_state_root,
        base_commitment: base,
        phase,
        first_ms: bounds.first_ms,
        last_ms: bounds.last_ms,
        timed_ops: bounds.count,
        anchored_at_ms: if bounds.count == 0 {
            UNTIMED_ANCHOR_MS
        } else {
            bounds.last_ms + 300
        },
        max_window_ms: 10_000,
        clock_skew_ms: 2_000,
    }
}

// --- pre-states -----------------------------------------------------------------

/// Market 0 with three funded traders, an earlier L1 withdrawal (the nonce
/// counter is past zero), and an open position between traders 1 and 2. Its
/// nullifier log holds the four spent notes in insertion order.
fn history() -> Ledger {
    let mut l = Ledger::genesis(&[0]);
    l.fund(1, 0, usd(500));
    l.fund(2, 0, usd(500));
    l.fund(3, 0, usd(200));
    let note = l.deposit(4, usd(50));
    l.apply(&[Ledger::withdraw(4, note, 1)]);
    let open = l.fill(1, 2, 0, Side::Buy, SIZE_SCALE / 5, price(0), 80_000_000);
    l.apply(&[open]);
    l
}

/// Trader 1 long 1.0 in market 0 at $1,000 with $104 of collateral after the
/// taker fee, against trader 2 short with $300.20; the fees left $0.50 of
/// insurance and $0.30 of treasury.
fn thin_long(t0: u64) -> Ledger {
    let mut l = Ledger::genesis(&[0]);
    l.fund(1, 0, usd(105));
    l.fund(2, 0, usd(300));
    let open = l.fill(1, 2, 0, Side::Buy, SIZE_SCALE, price(0), t0);
    l.apply(&[open]);
    l
}

/// After a liquidation at half the entry price that the reserves and the winner
/// could not cover: trader 1's closed entry carries debt `X`, the engine is
/// close-only, and trader 1 holds a note of exactly `X`, credited before the
/// trip. Returns the ledger, the note and `X`.
fn parked_debt() -> (Ledger, Digest, i128) {
    const T0: u64 = 70_000_000;
    let mut l = thin_long(T0);
    let liquidation = l.liquidate(1, 0, price(0) / 2, T0 + 5_000);
    let debt = {
        let mut dry = l.state.clone();
        dry.apply_batch(std::slice::from_ref(&liquidation))
            .expect("the liquidation applies");
        -dry.position(&owner(1), 0)
            .expect("the closed entry keeps its debt")
            .collateral
    };
    assert!(debt > 0, "the liquidation leaves debt behind");
    let note = l.deposit(1, debt);
    l.apply(&[liquidation]);
    assert_eq!(l.state.mode, Mode::CloseOnly);
    (l, note, debt)
}

/// Two markets with open interest at prices moved since entry, and reserves (the
/// fees' insurance and treasury) for the wind-down to pay to the recipient.
fn two_market_book() -> Ledger {
    const T0: u64 = 90_000_000;
    let mut l = Ledger::genesis(&[0, 1]);
    l.fund(1, 0, usd(500));
    l.fund(2, 0, usd(500));
    l.fund(3, 1, usd(800));
    l.fund(4, 1, usd(800));
    let open = [
        l.fill(1, 2, 0, Side::Buy, SIZE_SCALE / 2, price(0), T0),
        l.fill(3, 4, 1, Side::Sell, SIZE_SCALE / 2, price(1), T0 + 10),
    ];
    l.apply(&open);
    let moved = [
        l.fill(
            1,
            2,
            0,
            Side::Buy,
            SIZE_SCALE / 10,
            price(0) * 101 / 100,
            T0 + 5_000,
        ),
        l.fill(
            3,
            4,
            1,
            Side::Sell,
            SIZE_SCALE / 10,
            price(1) * 99 / 100,
            T0 + 5_010,
        ),
    ];
    l.apply(&moved);
    l
}

// --- cases ----------------------------------------------------------------------

/// A zero-premium funding tick in the price-refresh epoch after the one of the
/// market's recorded price: it changes no funding value, and records the new
/// index price.
fn epoch_price_refresh() -> CaseWitness {
    let mut l = Ledger::genesis(&[0]);
    l.fund(1, 0, usd(500));
    l.fund(2, 0, usd(500));
    let fill = l.fill(
        1,
        2,
        0,
        Side::Buy,
        SIZE_SCALE / 10,
        price(0),
        PRICE_REFRESH_MS - 10_000,
    );
    l.apply(&[fill]);
    let index = price(0) * 101 / 100;
    let ops = vec![l.tick(0, index, index, PRICE_REFRESH_MS + 500)];
    l.case("epoch-price-refresh", ops)
}

/// A fill 30 minutes after the market's last settlement, at a non-zero stored
/// rate: it first commits that span, then a tick adopts a zero rate.
fn pause_reopen_fill() -> CaseWitness {
    const T0: u64 = 50_000_000;
    let mut l = Ledger::genesis(&[0]);
    for trader in 1..=3 {
        l.fund(trader, 0, usd(500));
    }
    let open = [
        l.fill(1, 2, 0, Side::Buy, SIZE_SCALE / 5, price(0), T0),
        l.tick(0, price(0) * 1002 / 1000, price(0), T0 + 100),
    ];
    l.apply(&open);
    let reopen = T0 + 100 + 30 * 60_000;
    let ops = vec![
        l.fill(3, 2, 0, Side::Buy, SIZE_SCALE / 10, price(0), reopen),
        l.tick(0, price(0), price(0), reopen + 200),
    ];
    l.case("pause-reopen-fill", ops)
}

/// A liquidation whose close leaves debt: the insurance fund and the treasury
/// are drawn in full, and auto-deleverage of the winner covers the rest.
fn bad_debt_treasury_adl() -> CaseWitness {
    const T0: u64 = 60_000_000;
    let l = thin_long(T0);
    let ops = vec![l.liquidate(1, 0, price(0) * 85 / 100, T0 + 5_000)];
    l.case("bad-debt-treasury-adl", ops)
}

/// A top-up of exactly the debt parked on a closed entry: the entry is left
/// with zero size and zero collateral and is removed.
fn debt_top_up_prune() -> CaseWitness {
    let (l, note, _) = parked_debt();
    l.case("debt-top-up-prune", vec![Ledger::fund_op(1, 0, note)])
}

/// The ordinary batch after that top-up: a close-only funding tick.
fn debt_top_up_next_batch() -> CaseWitness {
    let (mut l, note, _) = parked_debt();
    l.apply(&[Ledger::fund_op(1, 0, note)]);
    let ops = vec![l.tick(0, price(0) / 2, price(0) / 2, 70_000_000 + 9_000)];
    l.case("debt-top-up-next-batch", ops)
}

/// A full exit: trader 1 closes, unbinds all of its collateral (the entry is
/// removed) and withdraws it to L1 with the next nonce.
fn full_exit_prune() -> CaseWitness {
    const T: u64 = 80_000_000 + 2_000;
    let mut l = history();
    let close = l.fill(1, 2, 0, Side::Sell, SIZE_SCALE / 5, price(0), T);
    let left = {
        let mut dry = l.state.clone();
        dry.apply_op(&close).expect("the close applies");
        dry.position(&owner(1), 0)
            .expect("a closed entry with collateral")
            .collateral
    };
    let (unbind, note) = l.unbind(1, 0, left, price(0), T + 100);
    let nonce = l.state.last_withdrawal_nonce + 1;
    let ops = vec![close, unbind, Ledger::withdraw(1, note, nonce)];
    l.case("full-exit-prune", ops)
}

/// An empty batch with no timed operation over a non-empty state.
fn empty_keepalive() -> CaseWitness {
    history().case("empty-keepalive", vec![])
}

/// The one-shot wind-down over two markets: every position is closed at its
/// market's recorded price and the reserves are paid to the recipient as one
/// withdrawal leaf.
fn settle_all_two_markets() -> CaseWitness {
    two_market_book().case("settle-all-two-markets", vec![BatchOp::SettleAll])
}

/// Exits after the wind-down: one trader per market unbinds all of its flat
/// collateral and withdraws it, each with the next nonce.
fn phase_two_exit() -> CaseWitness {
    let mut l = two_market_book();
    l.apply(&[BatchOp::SettleAll]);
    let mut ops = Vec::new();
    let first_nonce = l.state.last_withdrawal_nonce + 1;
    for (nonce, (trader, market)) in (first_nonce..).zip([(1u8, 0u64), (4, 1)]) {
        let amount = l
            .state
            .position(&owner(trader), market)
            .expect("a flat entry with collateral")
            .collateral;
        let blinding = l.blinding();
        ops.push(BatchOp::WindDownUnbind {
            owner: owner(trader),
            market_id: market,
            amount,
            blinding,
        });
        ops.push(BatchOp::WindDownWithdraw {
            note_commitment: Note::new(owner(trader), 0, amount, blinding)
                .commitment::<Keccak256>(),
            spend_key: spend_key(trader),
            to: Some(exit_address(trader)),
            nonce,
        });
    }
    l.case("phase-two-exit", ops)
}

/// Every case witness, in a fixed order.
pub fn case_witnesses() -> Vec<CaseWitness> {
    vec![
        epoch_price_refresh(),
        pause_reopen_fill(),
        bad_debt_treasury_adl(),
        debt_top_up_prune(),
        debt_top_up_next_batch(),
        full_exit_prune(),
        empty_keepalive(),
        settle_all_two_markets(),
        phase_two_exit(),
    ]
}

/// The serialized leaves of `tree`, in append order (its wire is `(depth, leaves)`).
fn tree_leaves(tree: &MerkleTree<Keccak256>) -> Vec<Digest> {
    let wire = postcard::to_allocvec(tree).expect("a tree encodes");
    let (_, leaves): (u8, Vec<Digest>) = postcard::from_bytes(&wire).expect("tree wire");
    leaves
}

/// Engine refusals of well-framed witnesses:
///
/// * a pre-state whose nullifier log lost an entry, whose tree lost its leaves,
///   or whose tree holds the same leaves at depth 64, each under the manifest of
///   the honest pre-state (`ManifestMismatch`);
/// * a tree whose encoded depth holds fewer leaves than it carries (it does not
///   decode: `WitnessDecode`);
/// * a withdrawal reusing the nonce of an earlier one;
/// * an opening fill between owners with no collateral, and one whose taker
///   holds less than the initial-margin floor;
/// * a deposit while the engine is close-only.
pub fn engine_negative_cases() -> Vec<NegativeCase> {
    let exit = full_exit_prune();
    let (state, ops, manifest, clock) = &exit.witness;
    let forged = |pre: DefaultState| crate::encode_clock_witness(&pre, ops, manifest, clock);
    let log = state.nullifiers.log().to_vec();
    let leaves = tree_leaves(&state.tree);
    assert!(
        log.len() >= 2 && leaves.len() > 2,
        "the history base has spent notes"
    );

    let mut dropped = state.clone();
    dropped.nullifiers = NullifierSet::from_log(log[1..].to_vec()).expect("a shorter log");
    let mut erased = state.clone();
    erased.tree = MerkleTree::from_leaves(state.tree.depth(), Vec::new()).expect("empty tree");
    let mut deep = state.clone();
    deep.tree = MerkleTree::from_leaves(64, leaves).expect("depth 64 holds the leaves");
    // The tree is the first field of the encoded state: its depth is the byte
    // after the framing magic. Depth 1 holds two leaves; this tree carries more.
    let mut overfull = exit.bytes.clone();
    assert_eq!(overfull[WIRE_MAGIC.len()], TREE_DEPTH);
    overfull[WIRE_MAGIC.len()] = 1;

    let mut reused = ops.clone();
    match reused.last_mut() {
        Some(BatchOp::Withdraw { nonce, .. }) => *nonce = state.last_withdrawal_nonce,
        _ => unreachable!("the exit ends with its withdrawal"),
    }

    let dust = {
        let l = Ledger::genesis(&[0]);
        let fill = l.fill(7, 8, 0, Side::Buy, 1, price(0), 1_000_000);
        l.refused(vec![fill])
    };
    let under_floor = {
        let mut l = Ledger::genesis(&[0]);
        l.fund(5, 0, MIN_INITIAL_MARGIN - 1);
        l.fund(6, 0, usd(5));
        // $5 of notional: 10% initial margin is $0.50, below the $1 floor.
        let fill = l.fill(5, 6, 0, Side::Buy, SIZE_SCALE / 200, price(0), 1_000_000);
        l.refused(vec![fill])
    };
    let close_only_deposit = {
        let (mut l, _, _) = parked_debt();
        let (deposit, _) = l.deposit_op(5, usd(10));
        l.refused(vec![deposit])
    };

    let insufficient_taker = ProverError::Transition(EngineError::Risk {
        source: RiskError::InsufficientMargin,
        leg: Some(FillLeg::Taker),
    });
    let manifest_mismatch = ProverError::Transition(EngineError::ManifestMismatch);
    vec![
        NegativeCase {
            name: "forged-nullifier-log",
            bytes: forged(dropped),
            expected_error: manifest_mismatch,
        },
        NegativeCase {
            name: "erased-tree-history",
            bytes: forged(erased),
            expected_error: manifest_mismatch,
        },
        NegativeCase {
            name: "depth-64-tree",
            bytes: forged(deep),
            expected_error: manifest_mismatch,
        },
        NegativeCase {
            name: "overfull-tree",
            bytes: overfull,
            expected_error: ProverError::WitnessDecode,
        },
        NegativeCase {
            name: "duplicate-withdrawal-nonce",
            bytes: crate::encode_clock_witness(state, &reused, manifest, clock),
            expected_error: ProverError::Transition(EngineError::WithdrawalNonceNotIncreasing),
        },
        NegativeCase {
            name: "unfunded-dust-fill",
            bytes: dust,
            expected_error: insufficient_taker,
        },
        NegativeCase {
            name: "under-floor-fill",
            bytes: under_floor,
            expected_error: insufficient_taker,
        },
        NegativeCase {
            name: "deposit-in-close-only",
            bytes: close_only_deposit,
            expected_error: ProverError::Transition(EngineError::CloseOnly),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_clock_witness, native_case_from_bytes};

    fn by_name(name: &str) -> CaseWitness {
        case_witnesses()
            .into_iter()
            .find(|case| case.name == name)
            .expect("case exists")
    }

    /// The post-state of a case, natively.
    fn post(case: &CaseWitness) -> DefaultState {
        native_case_from_bytes(&case.bytes).expect(case.name).1
    }

    #[test]
    fn every_case_is_accepted_and_bound_to_its_clock() {
        let cases = case_witnesses();
        let mut names: Vec<_> = cases.iter().map(|case| case.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), cases.len(), "case names are unique");
        for case in &cases {
            assert!(case.bytes.starts_with(WIRE_MAGIC), "{}", case.name);
            assert_eq!(
                witness_bytes(&decode_clock_witness(&case.bytes).unwrap()),
                case.bytes,
                "{}: canonical encoding",
                case.name
            );
            let (bound, state) = native_case_from_bytes(&case.bytes).expect(case.name);
            assert_eq!(bound.roots.wind_down_phase, case.phase, "{}", case.name);
            assert_eq!(
                bound.commitment,
                case.witness.3.commitment(),
                "{}",
                case.name
            );
            let public = prover::public_from_witness(&case.bytes).expect(case.name);
            assert_eq!(
                public.commitment::<Keccak256>(),
                bound.commitment,
                "{}",
                case.name
            );
            assert!(state.conservation_holds(), "{}", case.name);
            assert!(
                state.positions.values().all(|p| !p.is_empty()),
                "{}: no empty entry is stored",
                case.name
            );
        }
        let phases: Vec<u8> = cases.iter().map(|case| case.phase).collect();
        assert_eq!(phases, [0, 0, 0, 0, 0, 0, 0, 1, 2]);
    }

    #[test]
    fn the_epoch_refresh_records_the_new_index_without_changing_funding() {
        let case = by_name("epoch-price-refresh");
        let before = case.witness.0.funding[&0];
        let after = post(&case).funding[&0];
        assert!(before.last_price_ms < PRICE_REFRESH_MS);
        assert_eq!(after.last_price_ms, PRICE_REFRESH_MS + 500);
        assert_eq!(after.last_price, price(0) * 101 / 100);
        assert_eq!(
            (after.cumulative_index, after.rate, after.last_update_ms),
            (before.cumulative_index, before.rate, before.last_update_ms)
        );
    }

    #[test]
    fn the_reopen_fill_commits_the_paused_span_at_the_stored_rate() {
        let case = by_name("pause-reopen-fill");
        let before = case.witness.0.funding[&0];
        let after = post(&case).funding[&0];
        assert_ne!(before.rate, 0, "a non-zero stored rate prices the pause");
        let reopen = before.last_update_ms + 30 * 60_000;
        let mut paused = before;
        paused.settle_to(price(0), reopen);
        assert!(paused.cumulative_index > before.cumulative_index);
        // the fill commits the pause, then the tick commits its 200 ms at the
        // same stored rate before it adopts the zero rate
        let mut expected = paused;
        expected.settle_to(price(0), reopen + 200);
        assert_eq!(after.cumulative_index, expected.cumulative_index);
        assert_eq!((after.rate, after.last_update_ms), (0, reopen + 200));
    }

    #[test]
    fn the_bad_debt_draws_insurance_and_treasury_then_the_winner() {
        let case = by_name("bad-debt-treasury-adl");
        let pre = &case.witness.0;
        let after = post(&case);
        assert!(pre.insurance_fund > 0 && pre.treasury > 0);
        assert_eq!((after.insurance_fund, after.treasury), (0, 0));
        let winner_before = pre.position(&owner(2), 0).unwrap().collateral;
        let winner_after = after.position(&owner(2), 0).unwrap().collateral;
        assert!(winner_after < winner_before, "the winner is clawed");
        assert!(after.position(&owner(1), 0).is_none(), "covered in full");
        assert_eq!(after.mode, Mode::Normal);
    }

    #[test]
    fn the_top_up_prunes_the_parked_debt_and_the_next_batch_derives() {
        let (l, _, debt) = parked_debt();
        let parked = l.state.position(&owner(1), 0).unwrap();
        assert_eq!((parked.size, parked.collateral), (0, -debt));
        let top_up = by_name("debt-top-up-prune");
        let after = post(&top_up);
        assert!(
            after.position(&owner(1), 0).is_none(),
            "the repaid entry is removed"
        );
        let next = by_name("debt-top-up-next-batch");
        assert_eq!(next.witness.0.state_root(), after.state_root());
        assert_eq!(post(&next).mode, Mode::CloseOnly);
    }

    #[test]
    fn the_full_exit_removes_the_entry_and_withdraws_with_the_next_nonce() {
        let case = by_name("full-exit-prune");
        let pre = &case.witness.0;
        let after = post(&case);
        assert!(after.position(&owner(1), 0).is_none());
        assert_eq!(after.last_withdrawal_nonce, pre.last_withdrawal_nonce + 1);
        assert!(
            pre.last_withdrawal_nonce >= 1,
            "an earlier withdrawal exists"
        );
        let mut log = pre.nullifiers.log().to_vec();
        assert!(log.len() >= 2);
        let insertion = log.clone();
        log.sort_unstable();
        assert_ne!(log, insertion, "the log is not in sorted order");
    }

    #[test]
    fn the_keepalive_is_untimed_and_advances_only_the_batch() {
        let case = by_name("empty-keepalive");
        assert!(case.witness.1.is_empty());
        assert_eq!(case.witness.3.timed_ops, 0);
        let after = post(&case);
        assert_eq!(after.next_batch_id, case.witness.0.next_batch_id + 1);
    }

    #[test]
    fn the_wind_down_pays_the_reserves_to_the_recipient_and_phase_two_exits() {
        let case = by_name("settle-all-two-markets");
        let pre = &case.witness.0;
        assert_eq!(pre.markets.len(), 2);
        assert!(pre.positions.values().filter(|p| p.size != 0).count() >= 4);
        let mut state = pre.clone();
        let out = state.apply_batch(&case.witness.1).unwrap();
        assert_eq!(out.withdrawals.len(), 1, "one sink leaf");
        let sink = out.withdrawals[0];
        assert_eq!(sink.to, CASE_RECIPIENT);
        assert_eq!(sink.nonce, pre.last_withdrawal_nonce + 1);
        assert!(sink.amount > 0);
        assert_eq!(
            (state.insurance_fund, state.treasury, state.vault_pool),
            (0, 0, 0)
        );
        assert!(state
            .positions
            .values()
            .all(|p| p.size == 0 && p.collateral > 0));

        let exit = by_name("phase-two-exit");
        assert_eq!(exit.witness.0.state_root(), state.state_root());
        let mut after = state.clone();
        let out = after.apply_batch(&exit.witness.1).unwrap();
        let nonces: Vec<u64> = out.withdrawals.iter().map(|w| w.nonce).collect();
        assert_eq!(nonces, [sink.nonce + 1, sink.nonce + 2]);
        assert!(after.position(&owner(1), 0).is_none());
        assert!(after.position(&owner(4), 1).is_none());
    }

    #[test]
    fn engine_refusals_reject_for_the_intended_reasons() {
        let cases = engine_negative_cases();
        assert_eq!(cases.len(), 8);
        for case in &cases {
            assert_eq!(
                prover::public_from_witness(&case.bytes).unwrap_err(),
                case.expected_error,
                "{}",
                case.name
            );
            assert_eq!(
                native_case_from_bytes(&case.bytes).err(),
                Some(case.expected_error),
                "{}",
                case.name
            );
            if case.expected_error == ProverError::WitnessDecode {
                continue;
            }
            // Each pre-state is a valid one: under its own manifest, an empty
            // batch over it derives. So each refusal comes from the forged
            // pre-state or from the batch's op, never from framing or the clock.
            let (pre, _, _, _) = decode_clock_witness(&case.bytes).unwrap();
            let ops = Vec::new();
            derive_roots(&mut pre.clone(), &ops, &manifest_for(&pre, &ops)).expect(case.name);
        }
        let (_, ops, _, _) = decode_clock_witness(&cases[4].bytes).unwrap();
        assert!(matches!(
            ops.last(),
            Some(BatchOp::Withdraw { nonce: 1, .. })
        ));
        // The forged pre-states differ from the honest one only where named.
        let exit = full_exit_prune();
        for case in &cases[..3] {
            let (pre, ops, manifest, clock) = decode_clock_witness(&case.bytes).unwrap();
            assert_ne!(
                pre.state_root(),
                exit.witness.0.state_root(),
                "{}",
                case.name
            );
            assert_eq!(
                (ops.len(), manifest.previous_state_root, clock),
                (
                    exit.witness.1.len(),
                    exit.witness.2.previous_state_root,
                    exit.witness.3
                ),
                "{}",
                case.name
            );
        }
    }
}
