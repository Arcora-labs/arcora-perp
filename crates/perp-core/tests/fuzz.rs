//! Deterministic property fuzzer. It applies long, randomized sequences of valid
//! and invalid operations to the engine and asserts the core invariants survive
//! EVERY step — most importantly collateral conservation. Because `apply_op` is
//! atomic, conservation must hold whether an op succeeds or is rejected; the
//! fuzzer hammers exactly that. Every session runs on a market with a real
//! oracle key, so fills, funding ticks, liquidations and unbinds pass the
//! signature gate, and it ends with the wind-down settlement and every phase-2
//! exit. No external crates: a small xorshift PRNG keeps the run deterministic
//! and reproducible from the seed printed on failure.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::Side;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, Note};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// Owner id derived from the spend key `[i as u8; 32]` this owner funds/withdraws with
// (audit DP-003): the note owner must equal `owner_from_spend_key(spend_key)`, so the
// generator binds the two instead of picking them as independent literals.
fn owner(i: u64) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[i as u8; 32])
}

/// ZK-001: fixture publisher key. Markets set their `oracle_pubkey` to its address
/// (via [`signed_market`]) so transcripts run through the REAL signature gate.
fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

/// The publisher's eth address, recovered via the public API.
fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

fn signed_market(m: Market) -> Market {
    let mut m = m;
    m.oracle_pubkey = oracle_addr();
    m
}

/// A transcript signed by the fixture publisher over `oracle_digest(market_id, ..)`.
fn signed_oracle(
    market_id: u64,
    price: i128,
    publish_time_ms: u64,
    confidence: i128,
    backup_twap: i128,
) -> OracleTranscript {
    let d = oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap);
    OracleTranscript {
        price,
        publish_time_ms,
        confidence,
        backup_twap,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    signed_oracle(
        0,
        price_usd * PRICE_SCALE,
        now,
        5 * PRICE_SCALE,
        price_usd * PRICE_SCALE,
    )
}

/// The wind-down recipient every session binds at setup.
const RECIPIENT: [u8; 20] = [0x5E; 20];
const N_OWNERS: u64 = 4;
const MINUTE: u64 = 60_000;

fn spend_key(i: u64) -> [u8; 32] {
    [i as u8; 32]
}

/// How often each kind of op succeeded (or, for the deposits in close-only, was
/// refused as required) over all sessions. The fuzzer asserts a minimum for
/// most of them, so it cannot pass while exercising nothing.
#[derive(Debug, Default)]
struct Counts {
    fill: u64,
    accrue: u64,
    liquidate: u64,
    adl_haircut: u64,
    parked_debt: u64,
    deposit: u64,
    deposit_refused_in_close_only: u64,
    fund: u64,
    debt_top_up: u64,
    unbind: u64,
    withdraw: u64,
    pruned: u64,
    close_only_sessions: u64,
    settle_all: u64,
    settle_all_refused: u64,
    payout: u64,
    exits: u64,
}

/// One randomized session: a signed market, a wind-down recipient, four
/// funded owners, then random ops with pauses and price gaps, and finally the
/// wind-down settlement and every phase-2 exit.
struct Session {
    s: DefaultState,
    rng: Rng,
    now: u64,
    /// Whole dollars.
    price: i128,
    /// The signed transcript at `price`, re-signed when the price moves or the
    /// transcript gets old.
    orc: OracleTranscript,
    /// Counter that keeps every minted note's blinding unique.
    blind: u64,
    /// The highest withdrawal-leaf nonce emitted so far.
    last_leaf_nonce: u64,
    ctx: String,
}

impl Session {
    fn new(seed: u64, market: Market) -> Self {
        let mut s = DefaultState::new(20);
        s.add_market(signed_market(market));
        s.set_wind_down_recipient(RECIPIENT);
        let now = 1_700_000_000_000u64;
        let mut session = Session {
            s,
            rng: Rng(seed | 1),
            now,
            price: 100_000,
            orc: oracle(100_000, now),
            blind: 0,
            last_leaf_nonce: 0,
            ctx: format!("seed={seed}"),
        };
        // pre-fund every owner so fills have collateral to work with
        for i in 0..N_OWNERS {
            let amount = 50_000 * QUOTE_SCALE;
            let (deposit, cm) = session.deposit(i, amount);
            session
                .s
                .apply_batch(&[
                    deposit,
                    BatchOp::FundPosition {
                        owner: owner(i),
                        market_id: 0,
                        note_commitment: cm,
                        spend_key: spend_key(i),
                    },
                ])
                .unwrap();
        }
        assert!(session.s.conservation_holds());
        session
    }

    fn blinding(&mut self) -> [u8; 32] {
        self.blind += 1;
        let mut b = word_u64(self.blind);
        b[31] = 0xB1;
        b
    }

    /// A deposit for owner `i` at the next L1 index, and its note's commitment.
    fn deposit(&mut self, i: u64, amount: i128) -> (BatchOp, [u8; 32]) {
        let blinding = self.blinding();
        let cm = Note::new(owner(i), 0, amount, blinding).commitment::<Keccak256>();
        let op = BatchOp::Deposit {
            owner: owner(i),
            asset_id: 0,
            amount,
            blinding,
            from: [i as u8; 20],
            deposit_id: self.s.consumed_deposit_count,
            deposit_blind: [0xDB; 32],
        };
        (op, cm)
    }

    fn transcript(&mut self) -> OracleTranscript {
        if self.orc.price != self.price * PRICE_SCALE || self.now - self.orc.publish_time_ms > 5_000
        {
            self.orc = oracle(self.price, self.now);
        }
        self.orc
    }

    /// An unspent note of an owner whose flat position carries debt, and the
    /// index of that owner.
    fn debt_note(&self) -> Option<([u8; 32], u64)> {
        (0..N_OWNERS)
            .filter(|&i| {
                self.s
                    .position(&owner(i), 0)
                    .is_some_and(|p| p.size == 0 && p.collateral < 0)
            })
            .find_map(|i| {
                self.s
                    .notes
                    .iter()
                    .find(|(_, n)| n.owner == owner(i))
                    .map(|(cm, _)| (*cm, i))
            })
    }

    /// A random unspent note and the index of its owner.
    fn some_note(&mut self) -> Option<([u8; 32], u64)> {
        let notes: Vec<_> = self.s.notes.iter().map(|(cm, n)| (*cm, n.owner)).collect();
        if notes.is_empty() {
            return None;
        }
        let (cm, o) = notes[self.rng.below(notes.len() as u64) as usize];
        (0..N_OWNERS).find(|&i| owner(i) == o).map(|i| (cm, i))
    }

    fn next_op(&mut self) -> BatchOp {
        // time: up to 700 ms, sometimes a 30-minute or a 2-hour pause
        self.now += match self.rng.below(150) {
            0 => 30 * MINUTE,
            1 => 120 * MINUTE,
            _ => 1 + self.rng.below(700),
        };
        // price: a small walk on some steps, sometimes a 5-25% gap
        match self.rng.below(40) {
            0 => {
                let gap = self.price * (5 + self.rng.below(21) as i128) / 100;
                self.price += if self.rng.below(2) == 0 { gap } else { -gap };
            }
            1..=10 => self.price += self.rng.below(1001) as i128 - 500,
            _ => {}
        }
        self.price = self.price.clamp(40_000, 200_000);
        let orc = self.transcript();
        let (now, px) = (self.now, orc.price);
        let tick = |rng: &mut Rng| BatchOp::AccrueFunding {
            market_id: 0,
            mark: if rng.below(3) == 0 {
                px
            } else {
                px + px * (rng.below(21) as i128 - 10) / 10_000
            },
            oracle: orc,
            now_ms: now,
        };
        let a = self.rng.below(N_OWNERS);
        let b = (a + 1 + self.rng.below(N_OWNERS - 1)) % N_OWNERS;
        match self.rng.below(100) {
            0..=24 => BatchOp::Fill {
                taker: owner(a),
                maker: owner(b),
                market_id: 0,
                taker_side: if self.rng.below(2) == 0 {
                    Side::Buy
                } else {
                    Side::Sell
                },
                size: (1 + self.rng.below(30)) as i128 * (SIZE_SCALE / 10),
                price: px + px * (self.rng.below(101) as i128 - 50) / 10_000,
                oracle: orc,
                now_ms: now,
            },
            // a full close of `a`'s position against `b`
            25..=29 => match self.s.position(&owner(a), 0).filter(|p| p.is_open()) {
                Some(p) => BatchOp::Fill {
                    taker: owner(a),
                    maker: owner(b),
                    market_id: 0,
                    taker_side: if p.size > 0 { Side::Sell } else { Side::Buy },
                    size: p.size.abs(),
                    price: px,
                    oracle: orc,
                    now_ms: now,
                },
                None => tick(&mut self.rng),
            },
            30..=44 => tick(&mut self.rng),
            45..=54 => BatchOp::Liquidate {
                owner: owner(a),
                market_id: 0,
                oracle: orc,
                now_ms: now,
            },
            55..=62 => {
                let amount = (1 + self.rng.below(5_000)) as i128 * QUOTE_SCALE;
                self.deposit(a, amount).0
            }
            // re-funds, and top-ups of a flat position's debt
            63..=72 => match self
                .debt_note()
                .filter(|_| self.rng.below(2) == 0)
                .or_else(|| self.some_note())
            {
                Some((cm, i)) => BatchOp::FundPosition {
                    owner: owner(i),
                    market_id: 0,
                    note_commitment: cm,
                    spend_key: spend_key(i),
                },
                None => tick(&mut self.rng),
            },
            73..=84 => {
                let idx = self.s.funding[&0].index_at(px, now);
                let m = self.s.markets[&0];
                let pos = self.s.position(&owner(a), 0).copied();
                let amount = match pos {
                    // a full exit of a flat position's collateral
                    Some(p) if !p.is_open() && self.rng.below(2) == 0 => p.collateral,
                    // everything above initial margin, at the settled index or
                    // at the index stored before the open span (which the
                    // engine must refuse when the span charges this position)
                    Some(p) if p.is_open() && self.rng.below(2) == 0 => {
                        let at = if self.rng.below(2) == 0 {
                            idx
                        } else {
                            self.s.funding[&0].cumulative_index
                        };
                        p.equity(px, at)
                            .zip(p.initial_required(&m, px))
                            .map_or(0, |(e, im)| e - im)
                    }
                    _ => (1 + self.rng.below(2_000)) as i128 * QUOTE_SCALE,
                };
                BatchOp::Unbind {
                    owner: owner(a),
                    market_id: 0,
                    amount,
                    blinding: self.blinding(),
                    oracle: orc,
                    now_ms: now,
                }
            }
            85..=96 => match self.some_note() {
                Some((cm, i)) => {
                    let last = self.s.last_withdrawal_nonce;
                    let (to, nonce) = match self.rng.below(10) {
                        0 => (None, 0),
                        1 => (Some([i as u8; 20]), last),
                        2 => (Some([i as u8; 20]), last + 1 + self.rng.below(1_000)),
                        _ => (Some([i as u8; 20]), last + 1),
                    };
                    BatchOp::Withdraw {
                        note_commitment: cm,
                        spend_key: spend_key(i),
                        to,
                        nonce,
                    }
                }
                None => tick(&mut self.rng),
            },
            97 if self.rng.below(8) == 0 => BatchOp::EnterCloseOnly,
            _ => tick(&mut self.rng),
        }
    }

    /// Apply `op` and check every per-op invariant.
    fn apply_and_check(&mut self, op: &BatchOp, counts: &mut Counts) {
        let ctx = format!("{} op={op:?}", self.ctx);
        let root = self.s.state_root();
        let mode = self.s.mode;
        let m = self.s.markets[&0];
        let positions = self.s.positions.clone();
        // the index every op that carries an oracle must read and store
        let index = match op {
            BatchOp::Fill { oracle, now_ms, .. }
            | BatchOp::AccrueFunding { oracle, now_ms, .. }
            | BatchOp::Liquidate { oracle, now_ms, .. }
            | BatchOp::Unbind { oracle, now_ms, .. } => Some((
                oracle.price,
                self.s.funding[&0].index_at(oracle.price, *now_ms),
            )),
            _ => None,
        };
        let result = match op {
            // half of the liquidations go through the sequencer's entry point
            BatchOp::Liquidate {
                owner,
                market_id,
                oracle,
                now_ms,
            } if self.rng.below(2) == 0 => self
                .s
                .liquidate(owner, *market_id, oracle, *now_ms)
                .map(|_| perp_core::engine::OpOutput::default()),
            _ => self.s.apply_op(op),
        };

        match &result {
            Err(e) => {
                assert_eq!(
                    self.s.state_root(),
                    root,
                    "a refused op changes nothing: {ctx}"
                );
                if matches!(op, BatchOp::Deposit { .. }) && mode == Mode::CloseOnly {
                    assert_eq!(*e, EngineError::CloseOnly, "{ctx}");
                    counts.deposit_refused_in_close_only += 1;
                }
            }
            Ok(out) => {
                if let Some((_, idx)) = index {
                    assert_eq!(
                        self.s.funding[&0].cumulative_index, idx,
                        "the stored index is the one settled to the op's time: {ctx}"
                    );
                }
                match op {
                    BatchOp::Fill { .. } => counts.fill += 1,
                    BatchOp::AccrueFunding { .. } => counts.accrue += 1,
                    BatchOp::Deposit { .. } => {
                        assert_eq!(
                            mode,
                            Mode::Normal,
                            "no deposit is credited in close-only: {ctx}"
                        );
                        counts.deposit += 1;
                    }
                    BatchOp::FundPosition { owner, .. } => {
                        counts.fund += 1;
                        if positions
                            .get(&(*owner, 0))
                            .is_some_and(|p| p.size == 0 && p.collateral < 0)
                        {
                            counts.debt_top_up += 1;
                        }
                    }
                    BatchOp::Unbind { owner, .. } => {
                        counts.unbind += 1;
                        let (px, idx) = index.unwrap();
                        if let Some(p) = self.s.position(owner, 0).filter(|p| p.is_open()) {
                            assert_eq!(
                                p.check_initial_margin(&m, px, idx),
                                Ok(()),
                                "an unbind keeps initial margin at the settled index: {ctx}"
                            );
                        }
                    }
                    BatchOp::Liquidate { owner, .. } => {
                        counts.liquidate += 1;
                        if self.s.position(owner, 0).is_some_and(|p| p.collateral < 0) {
                            counts.parked_debt += 1;
                        }
                        let (px, idx) = index.unwrap();
                        for (key, before) in &positions {
                            if key.0 == *owner || !before.is_open() {
                                continue;
                            }
                            let after = self.s.positions[key];
                            assert_eq!(
                                (after.size, after.entry_price, after.funding_entry),
                                (before.size, before.entry_price, before.funding_entry),
                                "{ctx}"
                            );
                            let clawed = before.collateral - after.collateral;
                            let clawable = before.adl_clawable(&m, px, idx).unwrap_or(0);
                            assert!(
                                (0..=clawable).contains(&clawed),
                                "a haircut of {clawed} exceeds the clawable {clawable}: {ctx}"
                            );
                            if clawed > 0 {
                                counts.adl_haircut += 1;
                            }
                            if !before.is_liquidatable(&m, px, idx) {
                                assert!(
                                    !after.is_liquidatable(&m, px, idx),
                                    "auto-deleverage made a position liquidatable: {ctx}"
                                );
                            }
                        }
                    }
                    BatchOp::Withdraw { .. } => counts.withdraw += 1,
                    _ => {}
                }
                if let Some(w) = out.withdrawal {
                    assert!(
                        w.nonce > self.last_leaf_nonce,
                        "every withdrawal leaf has a new nonce: {ctx}"
                    );
                    self.last_leaf_nonce = w.nonce;
                }
                counts.pruned += positions
                    .keys()
                    .filter(|k| !self.s.positions.contains_key(k))
                    .count() as u64;
            }
        }
        assert!(self.s.conservation_holds(), "conservation broken: {ctx}");
        // every funding state stays in range, so the post-state passes the
        // pre-state shape check
        assert_eq!(self.s.validate_witness_shape(), Ok(()), "{ctx}");
        assert!(
            self.s.positions.values().all(|p| !p.is_empty()),
            "no entry with zero size and zero collateral is stored: {ctx}"
        );
        if mode == Mode::CloseOnly {
            assert_eq!(self.s.mode, Mode::CloseOnly, "close-only is final: {ctx}");
        }
    }

    /// The wind-down settlement, then every phase-2 exit. Returns the final
    /// state root.
    fn finish(mut self, counts: &mut Counts) -> [u8; 32] {
        let ctx = self.ctx.clone();
        if self.s.mode == Mode::CloseOnly {
            counts.close_only_sessions += 1;
        }
        let inside = self.s.internal_value().unwrap();
        let last = self.s.last_withdrawal_nonce;
        // The settlement succeeds whenever the value inside is not negative;
        // otherwise its claims cannot cover its deficit, and it is refused and
        // changes nothing.
        if inside < 0 {
            let root = self.s.state_root();
            assert_eq!(
                self.s.apply_batch(&[BatchOp::SettleAll]),
                Err(EngineError::WindDownInsolvent),
                "{ctx}"
            );
            assert_eq!(self.s.state_root(), root, "{ctx}");
            counts.settle_all_refused += 1;
            return root;
        }
        let out = self
            .s
            .apply_batch(&[BatchOp::SettleAll])
            .unwrap_or_else(|e| panic!("settlement refused with {e:?}: {ctx}"));
        counts.settle_all += 1;
        assert!(out.withdrawals.len() <= 1, "{ctx}");
        let payout: i128 = out.withdrawals.iter().map(|w| w.amount).sum();
        if let Some(w) = out.withdrawals.first() {
            assert_eq!((w.to, w.nonce), (RECIPIENT, last + 1), "{ctx}");
            assert!(w.nonce > self.last_leaf_nonce, "{ctx}");
            self.last_leaf_nonce = w.nonce;
            counts.payout += 1;
        }
        let s = &mut self.s;
        assert_eq!(
            (s.vault_pool, s.insurance_fund, s.treasury),
            (0, 0, 0),
            "with a recipient set no reserve is left: {ctx}"
        );
        assert_eq!(
            s.internal_value().unwrap() + payout,
            inside,
            "the settlement creates no value: {ctx}"
        );
        assert!(
            s.positions
                .values()
                .all(|p| p.size == 0 && p.collateral > 0),
            "{ctx}"
        );
        assert_eq!(s.mode, Mode::CloseOnly, "{ctx}");
        assert!(s.conservation_holds(), "{ctx}");
        // no deposit is credited after the settlement either
        let (deposit, _) = self.deposit(0, 10 * QUOTE_SCALE);
        let root = self.s.state_root();
        assert_eq!(
            self.s.apply_op(&deposit),
            Err(EngineError::CloseOnly),
            "{ctx}"
        );
        assert_eq!(self.s.state_root(), root, "{ctx}");

        // phase 2: every claim leaves, one owner per batch
        for i in 0..N_OWNERS {
            let o = owner(i);
            let mut nonce = self.s.last_withdrawal_nonce;
            let mut ops = Vec::new();
            if let Some(amount) = self.s.position(&o, 0).map(|p| p.collateral) {
                let blinding = self.blinding();
                ops.push(BatchOp::WindDownUnbind {
                    owner: o,
                    market_id: 0,
                    amount,
                    blinding,
                });
                nonce += 1;
                ops.push(BatchOp::WindDownWithdraw {
                    note_commitment: Note::new(o, 0, amount, blinding).commitment::<Keccak256>(),
                    spend_key: spend_key(i),
                    to: Some([i as u8; 20]),
                    nonce,
                });
            }
            for (cm, _) in self.s.notes.iter().filter(|(_, n)| n.owner == o) {
                nonce += 1;
                ops.push(BatchOp::WindDownWithdraw {
                    note_commitment: *cm,
                    spend_key: spend_key(i),
                    to: Some([i as u8; 20]),
                    nonce,
                });
            }
            if ops.is_empty() {
                continue;
            }
            let out = self
                .s
                .apply_batch(&ops)
                .unwrap_or_else(|e| panic!("phase-2 exit refused with {e:?}: {ctx}"));
            for w in out.withdrawals {
                assert!(w.nonce > self.last_leaf_nonce, "{ctx}");
                self.last_leaf_nonce = w.nonce;
            }
            counts.exits += 1;
            assert!(self.s.conservation_holds(), "{ctx}");
        }
        let s = &self.s;
        assert!(s.positions.is_empty() && s.notes.is_empty(), "{ctx}");
        assert_eq!(s.internal_value(), Some(0), "{ctx}");
        assert_eq!(
            s.external_in, s.external_out,
            "the exits drain the vault: {ctx}"
        );
        s.state_root()
    }
}

/// Run one randomized session from `seed` on `market`, checking the invariants
/// after every op, and return its final state root.
fn run_session(seed: u64, steps: usize, market: Market, counts: &mut Counts) -> [u8; 32] {
    let mut session = Session::new(seed, market);
    for step in 0..steps {
        session.ctx = format!("seed={seed} step={step}");
        let op = session.next_op();
        session.apply_and_check(&op, counts);
    }
    session.finish(counts)
}

/// Random sessions on a fee-free market and on a market with fees and a
/// treasury cut. After every op: a refused op changes nothing; conservation;
/// the shape check; no empty position entry; no deposit credited in
/// close-only; every op that carries an oracle stores the index settled to its
/// own time, and an unbind keeps initial margin at that index; a liquidation's
/// haircuts stay within each winner's clawable amount and make no position
/// liquidatable; withdrawal leaves carry strictly increasing nonces. At the end
/// of each session the settlement leaves no reserve and creates no value (or,
/// when the value inside is negative, is refused and changes nothing), and the
/// phase-2 exits drain the vault exactly.
#[test]
fn fuzz_conservation_holds_over_random_sessions() {
    let mut counts = Counts::default();
    for seed in 1..=48u64 {
        let market = if seed % 2 == 0 {
            Market::conservative(0)
        } else {
            Market::with_fees_treasury(0, 10, 2, 6)
        };
        run_session(
            seed.wrapping_mul(0x9E3779B97F4A7C15),
            250,
            market,
            &mut counts,
        );
    }
    println!("{counts:?}");
    let floors = [
        ("fill", counts.fill, 300),
        ("accrue", counts.accrue, 1_000),
        ("liquidate", counts.liquidate, 20),
        ("adl_haircut", counts.adl_haircut, 20),
        ("parked_debt", counts.parked_debt, 5),
        ("deposit", counts.deposit, 250),
        (
            "deposit_refused_in_close_only",
            counts.deposit_refused_in_close_only,
            50,
        ),
        ("fund", counts.fund, 200),
        ("debt_top_up", counts.debt_top_up, 1),
        ("unbind", counts.unbind, 250),
        ("withdraw", counts.withdraw, 250),
        ("pruned", counts.pruned, 50),
        ("close_only_sessions", counts.close_only_sessions, 5),
        ("settle_all", counts.settle_all, 40),
        ("payout", counts.payout, 5),
        ("exits", counts.exits, 40),
    ];
    for (name, got, floor) in floors {
        assert!(got >= floor, "{name}: {got} < {floor} ({counts:?})");
    }
}

/// The same seed gives the same session, op for op.
#[test]
fn fuzz_session_is_deterministic() {
    let run = || {
        run_session(
            7,
            120,
            Market::with_fees_treasury(0, 10, 2, 6),
            &mut Counts::default(),
        )
    };
    assert_eq!(run(), run());
}

#[test]
fn fuzz_state_root_is_deterministic() {
    // same seed ⇒ identical final state root (determinism is load-bearing for ZK)
    let root = |seed: u64| {
        let mut s = DefaultState::new(20);
        s.add_market(signed_market(Market::conservative(0)));
        // mirror run_session setup deterministically, then a few ops
        let mut rng = Rng(seed | 1);
        for i in 0..4u64 {
            let o = owner(i);
            let blind = [(i as u8) | 0x80; 32];
            let amount = 50_000 * QUOTE_SCALE;
            let cm = Note::new(o, 0, amount, blind).commitment::<Keccak256>();
            s.apply_op(&BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount,
                blinding: blind,
                from: [i as u8; 20],
                deposit_id: i,
                deposit_blind: [0xDBu8; 32],
            })
            .unwrap();
            s.apply_op(&BatchOp::FundPosition {
                owner: o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [i as u8; 32],
            })
            .unwrap();
        }
        for _ in 0..20 {
            let a = rng.below(4);
            let b = (a + 1) % 4;
            let _ = s.apply_op(&BatchOp::Fill {
                taker: owner(a),
                maker: owner(b),
                market_id: 0,
                taker_side: Side::Buy,
                size: SIZE_SCALE / 5,
                price: 100_000 * PRICE_SCALE,
                oracle: oracle(100_000, 2_000),
                now_ms: 2_000,
            });
        }
        s.state_root()
    };
    assert_eq!(root(42), root(42), "same seed ⇒ same state root");
}

/// Oracle gate property fuzzer (validates the P4 checked-math fix at scale).
///
/// Feeds wild prices/confidence/twaps — including i128 extremes — at random clocks
/// and asserts the gate (1) NEVER panics (no overflow/wrap, since it must also run
/// in the zkVM guest), and (2) only returns `Ok(p)` when p == price and EVERY bound
/// genuinely holds. A single overflowing multiply slipping a bad price through, or
/// panicking the circuit, would show up here.
#[test]
fn fuzz_oracle_validate_is_total_and_sound() {
    use perp_core::fixed::{abs, RATE_SCALE};
    // Signed market: each transcript below is signed over its own random fields, so it
    // clears the (first) fail-closed signature gate and the random inputs genuinely
    // reach the price/freshness/confidence/deviation math this fuzzer targets.
    let m = signed_market(Market::conservative(0));
    let mut rng = Rng(0xACE1);
    // a spread of magnitudes incl. extremes that exercise the checked multiplies
    let pool: [i128; 9] = [
        0,
        1,
        -1,
        100_000 * PRICE_SCALE,
        i128::MAX,
        i128::MIN,
        i128::MAX / 2,
        RATE_SCALE,
        1_000_000_000_000,
    ];
    let pick = |rng: &mut Rng| pool[(rng.below(pool.len() as u64)) as usize];

    // The pool has 9 values across each of price/confidence/backup_twap (9^3 = 729
    // combos); 20k signed iterations at random clocks cover them densely. (Lower than
    // the pre-ZK-001 100k because every iteration now also signs+recovers a real
    // secp256k1 signature to clear the fail-closed gate; the downstream-gate coverage
    // is unchanged.)
    for _ in 0..20_000 {
        let price = pick(&mut rng);
        let confidence = pick(&mut rng);
        let backup_twap = pick(&mut rng);
        let publish_time_ms = rng.next();
        let now_ms = rng.next();
        let t = signed_oracle(m.id, price, publish_time_ms, confidence, backup_twap);
        // (1) totality: must return a value, never panic/wrap.
        let res = t.validate(&m, now_ms);
        // (2) soundness: Ok ⇒ price returned verbatim AND every gate truly holds.
        if let Ok(p) = res {
            assert_eq!(p, price, "Ok must echo the price");
            assert!(price > 0, "Ok price must be positive");
            assert!(publish_time_ms <= now_ms, "Ok price not from the future");
            assert!(
                now_ms - publish_time_ms <= m.max_oracle_staleness_ms,
                "Ok price within staleness"
            );
            // confidence and deviation bounds recomputed with i128 headroom (i256-ish
            // via checked ops is overkill here; the pool values keep products in range
            // EXCEPT the extremes, which the gate rejects — so Ok ⇒ products fit).
            let conf_ok = abs(confidence)
                .checked_mul(RATE_SCALE)
                .zip(m.max_oracle_confidence_ratio.checked_mul(price))
                .map(|(l, r)| l <= r)
                .unwrap_or(false);
            assert!(conf_ok, "Ok ⇒ confidence bound holds");
            if backup_twap > 0 {
                let dev_ok = abs(price - backup_twap)
                    .checked_mul(RATE_SCALE)
                    .zip(m.max_oracle_deviation_ratio.checked_mul(price))
                    .map(|(l, r)| l <= r)
                    .unwrap_or(false);
                assert!(dev_ok, "Ok ⇒ deviation bound holds");
            }
        }
    }
}

/// Merkle tree property fuzzer (validates the P5 leaf-domain fix at scale).
///
/// Appends random leaves to random-depth trees and asserts: (1) every appended
/// leaf proves+verifies against the live root; (2) a wrong leaf, a tampered
/// sibling, or a re-pointed index all FAIL; (3) the inner-node value of any pair
/// is rejected when offered as a leaf (the second-preimage property the leaf
/// domain enforces). Determinism is also checked: same leaves ⇒ same root.
#[test]
fn fuzz_merkle_proofs_sound_and_second_preimage_safe() {
    use perp_core::hash::{Domain, Hasher};
    use perp_core::merkle::{MerkleProof, MerkleTree};

    let mut rng = Rng(0x5EED);
    for _ in 0..400 {
        let depth = (rng.below(6) + 2) as u8; // depth 2..=7 (cap 4..=128)
        let cap = 1u64 << depth;
        let n = 1 + rng.below(cap.min(40)); // at least one leaf
        let mut t: MerkleTree<Keccak256> = MerkleTree::new(depth);
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for _ in 0..n {
            let leaf = word_u64(rng.next());
            if t.append(leaf).is_ok() {
                leaves.push(leaf);
            }
        }
        let root = t.root();
        // determinism: rebuilding the same leaves gives the same root
        let mut t2: MerkleTree<Keccak256> = MerkleTree::new(depth);
        for l in &leaves {
            let _ = t2.append(*l);
        }
        assert_eq!(root, t2.root(), "same leaves ⇒ same root");

        for (i, leaf) in leaves.iter().enumerate() {
            let p = t.prove(i as u64).unwrap();
            assert!(
                MerkleTree::<Keccak256>::verify(&root, leaf, &p),
                "leaf verifies"
            );
            // wrong leaf rejected
            assert!(!MerkleTree::<Keccak256>::verify(
                &root,
                &word_u64(0xDEAD_0000 + i as u64),
                &p
            ));
            // tampered sibling rejected (if any siblings)
            if !p.siblings.is_empty() {
                let mut bad = p.clone();
                bad.siblings[0] = word_u64(0xBAD);
                assert!(
                    !MerkleTree::<Keccak256>::verify(&root, leaf, &bad),
                    "tampered rejected"
                );
            }
            // re-pointed index rejected (unless it happens to collide, vanishingly rare)
            if leaves.len() > 1 {
                let mut moved = p.clone();
                moved.leaf_index ^= 1;
                assert!(
                    !MerkleTree::<Keccak256>::verify(&root, leaf, &moved),
                    "index-bound"
                );
            }
        }
        // second-preimage: the inner node over leaves 0,1 must not pass as a leaf
        if leaves.len() >= 2 {
            let l0 = Keccak256::hash_words(Domain::MerkleLeaf, &[leaves[0]]);
            let l1 = Keccak256::hash_words(Domain::MerkleLeaf, &[leaves[1]]);
            let inner = Keccak256::compress(Domain::MerkleNode, &l0, &l1);
            let p0 = t.prove(0).unwrap();
            if p0.siblings.len() >= 2 {
                let forged = MerkleProof {
                    leaf_index: 0,
                    siblings: p0.siblings[1..].to_vec(),
                };
                assert!(
                    !MerkleTree::<Keccak256>::verify(&root, &inner, &forged),
                    "inner node rejected as leaf"
                );
            }
        }
    }
}
