//! Global shielded state and the state root (§1, §3).
//!
//! The state root is the single value anchored on L1 by every settled batch. It
//! binds every consensus-critical field: the note-commitment tree root, the
//! nullifier-set contents, the unspent-note set, the positions and funding digests,
//! the market parameters, the balance counters (insurance / vault pool / treasury /
//! external in/out), the operating mode, the batch counter, the last withdrawal
//! nonce and the wind-down recipient. Binding the nullifier-set contents (not just
//! its count) and the unspent-note set is what makes a forged pre-state unable to
//! double-spend under an unchanged root (audit DP-002). The conservation identity —
//! `Σ notes + Σ position collateral + insurance + vault pool + treasury ==
//! external_in − external_out` — is an invariant maintained by *every* operation
//! (Proof-v1: collateral conservation). Its sums are checked: a sum that overflows
//! makes the identity fail rather than wrap.

use crate::funding::FundingState;
use crate::hash::{word_i128, word_u64, Digest, Domain, Hasher};
use crate::market::{Market, MarketId};
use crate::merkle::MerkleTree;
use crate::note::{Note, PubKey};
use crate::nullifier::NullifierSet;
use crate::position::Position;
use alloc::collections::BTreeMap;

/// Depth of the note-commitment tree of every deployed state (capacity `2^24`
/// notes). Genesis is `State::new(TREE_DEPTH)`.
pub const TREE_DEPTH: u8 = 24;

/// Role tag of [`State::state_root`]. The state root and the notes, positions,
/// funding and markets digests all hash under `Domain::StateRoot`, and a domain
/// carries no length or role, so each of their preimages starts with its own tag
/// word (`word_u64(TAG_*)`): two of them never share a preimage format, whatever
/// their word counts, and none shares one with another `Domain::StateRoot` hash
/// (the batch commitment, a nullifier-chain link). The tag values are distinct
/// ASCII strings, read little-endian.
pub const TAG_STATE: u64 = u64::from_le_bytes(*b"dp.state");
/// Role tag of [`State::notes_digest`].
pub const TAG_NOTES: u64 = u64::from_le_bytes(*b"dp.notes");
/// Role tag of [`State::positions_digest`].
pub const TAG_POSITIONS: u64 = u64::from_le_bytes(*b"dp.posns");
/// Role tag of [`State::funding_digest`].
pub const TAG_FUNDING: u64 = u64::from_le_bytes(*b"dp.fundg");
/// Role tag of [`State::markets_digest`].
pub const TAG_MARKETS: u64 = u64::from_le_bytes(*b"dp.mrkts");

/// The sum of `values`, or `None` when it overflows `i128`.
pub(crate) fn checked_sum(values: impl IntoIterator<Item = i128>) -> Option<i128> {
    values
        .into_iter()
        .try_fold(0i128, |acc, v| acc.checked_add(v))
}

/// A 20-byte L1 address packed into a 32-byte word: its bytes in the low
/// positions, the rest zero (the layout of the little-endian `word_*` encoders).
fn word_address(a: &[u8; 20]) -> Digest {
    let mut w = [0u8; 32];
    w[..20].copy_from_slice(a);
    w
}

/// Operating mode. Close-only is the forced-exit emergency state (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Mode {
    Normal,
    /// Opening/increasing blocked; only reduce/close/liquidate/withdraw (§6).
    CloseOnly,
}

/// The full protocol state the engine transitions.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct State<H: Hasher> {
    pub tree: MerkleTree<H>,
    pub nullifiers: NullifierSet<H>,
    /// Unspent notes known to the engine, keyed by commitment.
    pub notes: BTreeMap<Digest, Note>,
    pub markets: BTreeMap<MarketId, Market>,
    pub funding: BTreeMap<MarketId, FundingState>,
    /// Position entries by `(owner, market_id)`. The engine never stores an entry
    /// with zero size and zero collateral: an op that would leave one removes it.
    /// A decoded pre-state may still hold one; it is accepted, and behaves exactly
    /// like a missing entry.
    pub positions: BTreeMap<(PubKey, MarketId), Position>,
    pub insurance_fund: i128,
    /// Net clearing-house balance. Realized PnL and funding are routed through
    /// this pool so that `Σ collateral + vault_pool` is conserved across fills
    /// (a closing position's realized gain is drawn from the pool, funded by the
    /// open counterparties' yet-unrealized losses). With matched long/short fills
    /// at one price, the pool stays bounded and nets to zero when all positions
    /// close. This is what makes collateral conservation an exact integer
    /// identity in Phase 0 rather than an oracle-dependent approximation.
    pub vault_pool: i128,
    /// Protocol-treasury balance: the operator's accrued trading-fee revenue (§9).
    /// Grows by each fill's `treasury_fee`. It backs bad debt: a liquidation's
    /// shortfall is covered by the insurance fund, then by the treasury, and only
    /// then by auto-deleverage of the winners before the system trips to
    /// close-only; `SettleAll` likewise draws on it before any haircut. There is no
    /// payout op and no operator-directed transfer: only `SettleAll` pays out what
    /// is left of it, together with the insurance fund and the clearing pool, to
    /// [`State::wind_down_recipient`].
    pub treasury: i128,
    pub external_in: i128,
    pub external_out: i128,
    pub mode: Mode,
    pub next_batch_id: u64,
    /// The nonce of the most recent real L1 withdrawal (`Withdraw` or
    /// `WindDownWithdraw` with `to = Some`); 0 before the first. Every later real
    /// withdrawal must carry a strictly greater nonce (see
    /// [`crate::engine::MAX_WITHDRAWAL_NONCE_STEP`]), so no two withdrawal leaves
    /// ever share one. Internal burns leave it unchanged. Bound into the root.
    pub last_withdrawal_nonce: u64,
    /// SEC-019: running tip of the in-circuit deposit hash-chain accumulator — the
    /// fold over every L1 deposit leaf the engine has consumed. Bound into the root
    /// (alongside `consumed_deposit_count`) so the in-circuit fold is incremental and
    /// a prover cannot advance it off-chain without changing the committed state.
    pub consumed_deposit_tip: Digest,
    /// SEC-019: number of L1 deposit leaves folded into `consumed_deposit_tip`.
    pub consumed_deposit_count: u64,
    /// The L1 address the wind-down pays the protocol's remaining reserves to. It
    /// is fixed at setup ([`State::set_wind_down_recipient`]); no op changes it.
    /// Bound into the root, so a deployment's genesis root pins it. All zero when
    /// unset, which only tests and demos use.
    pub wind_down_recipient: [u8; 20],
}

impl<H: Hasher> State<H> {
    /// Create empty state with a commitment tree of the given depth.
    pub fn new(tree_depth: u8) -> Self {
        Self {
            tree: MerkleTree::new(tree_depth),
            nullifiers: NullifierSet::new(),
            notes: BTreeMap::new(),
            markets: BTreeMap::new(),
            funding: BTreeMap::new(),
            positions: BTreeMap::new(),
            insurance_fund: 0,
            vault_pool: 0,
            treasury: 0,
            external_in: 0,
            external_out: 0,
            mode: Mode::Normal,
            next_batch_id: 0,
            last_withdrawal_nonce: 0,
            consumed_deposit_tip: [0u8; 32],
            consumed_deposit_count: 0,
            wind_down_recipient: [0u8; 20],
        }
    }

    /// Set the wind-down recipient (a setup action, like [`State::add_market`]; it
    /// is not part of the proven transition). Call it before the genesis root is
    /// taken: the recipient is a root word, so it cannot change afterwards without
    /// changing the anchored root.
    pub fn set_wind_down_recipient(&mut self, recipient: [u8; 20]) {
        self.wind_down_recipient = recipient;
    }

    /// Register a market (governance action). Markets must be internally coherent
    /// (`maintenance < initial`, `fee < maintenance`, positive oracle bounds) — an
    /// incoherent market would corrupt the margin/liquidation math, so we assert it
    /// here rather than let a misconfiguration through. This is a setup-time check,
    /// not part of the proven `apply_batch` transition.
    pub fn add_market(&mut self, market: Market) {
        // HARD assert (not debug_assert): an incoherent market silently corrupts the
        // fee/margin/liquidation math (e.g. a treasury cut > net fee drives the insurance
        // fund negative), so it must fail-fast at setup even in a release build, not be
        // compiled out. Setup-time config, not the proven transition.
        assert!(
            market.is_coherent(),
            "refusing to register an incoherent market"
        );
        self.funding.insert(market.id, FundingState::default());
        self.markets.insert(market.id, market);
    }

    /// 2026-10-08 review: the state root hashes the `markets` map KEY, never
    /// `Market.id`, so a witness could carry `Market { id: X }` under key `Y ≠ X`
    /// with an unchanged state root. `add_market` keys by `id`, but a decoded
    /// witness state is not so constrained — re-check at root-derivation time
    /// (fail-closed) before trusting any digest over this map.
    pub fn validate_market_keys(&self) -> Result<(), crate::EngineError> {
        for (key, market) in &self.markets {
            if *key != market.id {
                return Err(crate::EngineError::MarketIdMismatch);
            }
        }
        Ok(())
    }

    /// The shape check run on a decoded pre-state before any digest over it is
    /// trusted. Every serialized field is either hashed into `state_root`, derived
    /// on decode, or checked here; this checks exactly the fields the root does
    /// not hash, against what every state built by `new`, `add_market` and the
    /// engine's ops satisfies by construction:
    ///
    /// * each market is stored under its own `id` (the root hashes the key);
    /// * the funding map covers exactly the registered markets, and every funding
    ///   state is in the range the engine maintains
    ///   ([`FundingState::is_well_formed`]);
    /// * each position is stored under `(owner, market_id)` of its own fields
    ///   (the root hashes the key; payouts always use the key).
    ///
    /// It checks binding only. In particular it never refuses a position entry
    /// for its values (an entry with zero size and zero collateral included):
    /// those are root-bound, and refusing an anchored root would make it
    /// unprovable.
    pub fn validate_witness_shape(&self) -> Result<(), crate::EngineError> {
        self.validate_market_keys()?;
        if !self.funding.keys().eq(self.markets.keys())
            || !self.funding.values().all(FundingState::is_well_formed)
        {
            return Err(crate::EngineError::FundingStateInvalid);
        }
        for ((owner, market_id), p) in &self.positions {
            if p.owner != *owner || p.market_id != *market_id {
                return Err(crate::EngineError::PositionKeyMismatch);
            }
        }
        Ok(())
    }

    /// Sum of all unspent note amounts; `None` if the sum overflows.
    pub fn notes_value(&self) -> Option<i128> {
        checked_sum(self.notes.values().map(|n| n.amount))
    }

    /// Sum of all position collateral; `None` if the sum overflows.
    pub fn positions_collateral(&self) -> Option<i128> {
        checked_sum(self.positions.values().map(|p| p.collateral))
    }

    /// Total value tracked inside the protocol: the notes, the position
    /// collateral, the insurance fund, the clearing pool and the treasury. `None`
    /// if the sum overflows.
    pub fn internal_value(&self) -> Option<i128> {
        checked_sum([
            self.notes_value()?,
            self.positions_collateral()?,
            self.insurance_fund,
            self.vault_pool,
            self.treasury,
        ])
    }

    /// The conservation identity `internal_value == external_in − external_out`.
    /// MUST hold after every operation (Proof-v1). Every sum and the difference
    /// are checked, and an overflow on either side makes it fail, identically in
    /// native and guest builds.
    pub fn conservation_holds(&self) -> bool {
        match (
            self.internal_value(),
            self.external_in.checked_sub(self.external_out),
        ) {
            (Some(inside), Some(outside)) => inside == outside,
            _ => false,
        }
    }

    /// A deterministic digest over positions (owner, market, size, entry,
    /// collateral, funding_entry), order-independent via the BTreeMap ordering.
    /// Preimage: `TAG_POSITIONS`, then six words per entry.
    pub fn positions_digest(&self) -> Digest {
        let mut words = alloc::vec![word_u64(TAG_POSITIONS)];
        for ((owner, market), p) in &self.positions {
            words.push(*owner);
            words.push(word_u64(*market));
            words.push(word_i128(p.size));
            words.push(word_i128(p.entry_price));
            words.push(word_i128(p.collateral));
            words.push(word_i128(p.funding_entry));
        }
        H::hash_words(Domain::StateRoot, &words)
    }

    /// A deterministic digest over per-market funding state. The cumulative
    /// funding index is applied to positions at settlement, and the stored rate,
    /// carry and recorded price decide every later span and settlement, so all of
    /// it MUST be part of the committed root — otherwise a prover could misreport
    /// funding without changing the state root. Preimage: `TAG_FUNDING`, then per
    /// market `id, cumulative_index, last_update_ms, rate, remainder, last_price,
    /// last_price_ms`.
    pub fn funding_digest(&self) -> Digest {
        let mut words = alloc::vec![word_u64(TAG_FUNDING)];
        for (id, f) in &self.funding {
            words.push(word_u64(*id));
            words.push(word_i128(f.cumulative_index));
            words.push(word_u64(f.last_update_ms));
            words.push(word_i128(f.rate));
            words.push(word_i128(f.remainder));
            words.push(word_i128(f.last_price));
            words.push(word_u64(f.last_price_ms));
        }
        H::hash_words(Domain::StateRoot, &words)
    }

    /// A deterministic digest over the UNSPENT-note set (keyed by commitment). The
    /// tree root commits every note ever appended, but not which remain spendable;
    /// binding this set stops a forged pre-state from replaying a spent note as
    /// unspent (audit DP-002). Order-independent via the `BTreeMap` ordering.
    /// Preimage: `TAG_NOTES`, then five words per note.
    pub fn notes_digest(&self) -> Digest {
        let mut words = alloc::vec![word_u64(TAG_NOTES)];
        for (cm, n) in &self.notes {
            words.push(*cm);
            words.push(n.owner);
            words.push(word_u64(n.asset_id));
            words.push(word_i128(n.amount));
            words.push(n.blinding);
        }
        H::hash_words(Domain::StateRoot, &words)
    }

    /// A deterministic digest over per-market risk/fee parameters. Bound into the
    /// root so a prover cannot silently alter margins, oracle bounds, or fees under
    /// an unchanged state root (audit DP-002). Order-independent via the `BTreeMap`.
    /// Preimage: `TAG_MARKETS`, then thirteen words per market.
    pub fn markets_digest(&self) -> Digest {
        let mut words = alloc::vec![word_u64(TAG_MARKETS)];
        for (id, m) in &self.markets {
            words.push(word_u64(*id));
            words.push(word_i128(m.initial_margin_ratio));
            words.push(word_i128(m.maintenance_margin_ratio));
            words.push(word_i128(m.liquidation_fee_ratio));
            words.push(word_u64(m.max_oracle_staleness_ms));
            words.push(word_i128(m.max_oracle_confidence_ratio));
            words.push(word_i128(m.max_oracle_deviation_ratio));
            words.push(word_i128(m.taker_fee_ratio));
            words.push(word_i128(m.maker_rebate_ratio));
            words.push(word_i128(m.treasury_fee_ratio));
            // ZK-001: the per-market oracle trust anchor + mark band. `oracle_pubkey` is
            // packed into a 32-byte word (its 20 address bytes in the low positions, like
            // the little-endian `word_u64`/`word_i128` encoders above); the mark-deviation
            // ratio folds via `word_i128`, exactly like the sibling `*_ratio` bounds.
            words.push(word_address(&m.oracle_pubkey));
            words.push(word_i128(m.max_mark_deviation_ratio));
            // SEC-022: the fill band, bound like every other risk parameter so a prover
            // cannot widen the price constraint under an unchanged state root.
            words.push(word_i128(m.max_fill_deviation_ratio));
        }
        H::hash_words(Domain::StateRoot, &words)
    }

    /// The L1-anchored state root (§1, §3). Binds every consensus-critical field:
    /// the note-commitment tree, the nullifier-set contents, the unspent-note set,
    /// positions, funding, market parameters, all balance counters, the operating
    /// mode, the batch counter, the last withdrawal nonce and the wind-down
    /// recipient (audit DP-002). The preimage is [`State::state_root_words`].
    pub fn state_root(&self) -> Digest {
        H::hash_words(Domain::StateRoot, &self.state_root_words())
    }

    /// The eighteen-word preimage of [`State::state_root`]: `TAG_STATE`, then
    ///
    /// | # | word |
    /// |---|---|
    /// | 1 | `tree.root()` |
    /// | 2 | `nullifiers.digest()` |
    /// | 3 | [`State::notes_digest`] |
    /// | 4 | [`State::positions_digest`] |
    /// | 5 | [`State::funding_digest`] |
    /// | 6 | [`State::markets_digest`] |
    /// | 7-11 | `insurance_fund`, `vault_pool`, `treasury`, `external_in`, `external_out` |
    /// | 12-13 | `consumed_deposit_tip`, `consumed_deposit_count` |
    /// | 14 | `mode` (0 = normal, 1 = close-only) |
    /// | 15 | `next_batch_id` |
    /// | 16 | `last_withdrawal_nonce` |
    /// | 17 | `wind_down_recipient` |
    pub fn state_root_words(&self) -> [Digest; 18] {
        let mode_word: u64 = match self.mode {
            Mode::Normal => 0,
            Mode::CloseOnly => 1,
        };
        [
            word_u64(TAG_STATE),
            self.tree.root(),
            self.nullifiers.digest(),
            self.notes_digest(),
            self.positions_digest(),
            self.funding_digest(),
            self.markets_digest(),
            word_i128(self.insurance_fund),
            word_i128(self.vault_pool),
            word_i128(self.treasury),
            word_i128(self.external_in),
            word_i128(self.external_out),
            // SEC-019: deposit-accumulator words (raw tip digest + u64 count),
            // encoded like the other u64 counters below via `word_u64`.
            self.consumed_deposit_tip,
            word_u64(self.consumed_deposit_count),
            word_u64(mode_word),
            word_u64(self.next_batch_id),
            word_u64(self.last_withdrawal_nonce),
            word_address(&self.wind_down_recipient),
        ]
    }

    /// Convenience accessor.
    pub fn position(&self, owner: &PubKey, market: MarketId) -> Option<&Position> {
        self.positions.get(&(*owner, market))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Keccak256;

    #[test]
    fn empty_state_conserves() {
        let s: State<Keccak256> = State::new(16);
        assert!(s.conservation_holds());
        assert_eq!(s.internal_value(), Some(0));
    }

    /// The conservation sums are checked: an overflowing sum, on either side,
    /// fails the identity instead of wrapping (or panicking in a debug build).
    #[test]
    fn an_overflowing_conservation_sum_fails_the_identity() {
        use crate::note::Note;
        let mut s: State<Keccak256> = State::new(16);
        for i in 0..2u8 {
            let n = Note::new([i; 32], 0, i128::MAX / 2 + 1, [i; 32]);
            s.notes.insert(n.commitment::<Keccak256>(), n);
        }
        assert_eq!(s.notes_value(), None);
        assert_eq!(s.internal_value(), None);
        // the wrapped value would be i128::MIN; no external figure matches it
        s.external_in = i128::MIN;
        assert!(!s.conservation_holds());

        let mut t: State<Keccak256> = State::new(16);
        t.vault_pool = i128::MAX;
        t.treasury = 1;
        assert_eq!(t.internal_value(), None);
        assert!(!t.conservation_holds());

        let mut u: State<Keccak256> = State::new(16);
        u.external_in = i128::MIN;
        u.external_out = 1;
        assert!(!u.conservation_holds(), "the external difference overflows");
    }

    #[test]
    fn state_root_changes_with_external_flow() {
        let mut s: State<Keccak256> = State::new(16);
        let r0 = s.state_root();
        s.external_in += 1;
        assert_ne!(r0, s.state_root());
    }

    // audit DP-002: the root must bind the nullifier-set CONTENTS, not just its size —
    // otherwise a prover can swap which notes were spent while keeping the same count.
    #[test]
    fn state_root_binds_nullifier_contents_not_just_count() {
        let mut a: State<Keccak256> = State::new(16);
        let mut b: State<Keccak256> = State::new(16);
        assert!(a.nullifiers.insert([1u8; 32]));
        assert!(b.nullifiers.insert([2u8; 32])); // equal count (1), different contents
        assert_eq!(a.nullifiers.len(), b.nullifiers.len());
        assert_ne!(
            a.state_root(),
            b.state_root(),
            "nullifier sets of equal size but different contents must not share a root",
        );
    }

    // audit DP-002: the emergency close-only mode is consensus-critical and must be bound.
    #[test]
    fn state_root_binds_mode() {
        let mut a: State<Keccak256> = State::new(16);
        let b: State<Keccak256> = State::new(16);
        a.mode = Mode::CloseOnly;
        assert_ne!(
            a.state_root(),
            b.state_root(),
            "the close-only mode must be part of the committed root",
        );
    }

    // audit DP-002: the set of unspent notes must be bound, else a spent note can be
    // replayed as still-spendable in a forged witness pre-state.
    #[test]
    fn state_root_binds_unspent_notes() {
        let mut a: State<Keccak256> = State::new(16);
        let b: State<Keccak256> = State::new(16);
        let n = Note::new([9u8; 32], 0, 1_000_000, [3u8; 32]);
        a.notes.insert(n.commitment::<Keccak256>(), n);
        assert_ne!(
            a.state_root(),
            b.state_root(),
            "the unspent-note set must be bound into the root",
        );
    }

    // audit DP-002: the batch counter and the last withdrawal nonce order settlement
    // and must be bound.
    #[test]
    fn state_root_binds_withdrawal_nonce_and_batch() {
        let base: State<Keccak256> = State::new(16);
        let mut with_nonce = base.clone();
        with_nonce.last_withdrawal_nonce += 1;
        assert_ne!(
            base.state_root(),
            with_nonce.state_root(),
            "last_withdrawal_nonce must be bound"
        );
        let mut with_batch = base.clone();
        with_batch.next_batch_id += 1;
        assert_ne!(
            base.state_root(),
            with_batch.state_root(),
            "next_batch_id must be bound"
        );
    }

    // SEC-019: the in-circuit deposit-accumulator words (consumed tip + count) must be
    // bound into the root so a prover cannot advance the deposit fold off-chain without
    // changing the committed state. Genesis has an empty accumulator (tip=0, count=0).
    #[test]
    fn state_root_binds_deposit_accumulator() {
        let mut a: State<Keccak256> = State::new(16);
        let r0 = a.state_root();
        a.consumed_deposit_count = 1;
        assert_ne!(a.state_root(), r0, "count must be in the root");
        let mut b: State<Keccak256> = State::new(16);
        b.consumed_deposit_tip = [7u8; 32];
        assert_ne!(b.state_root(), r0, "tip must be in the root");
        assert_eq!(State::<Keccak256>::new(16).consumed_deposit_count, 0);
        assert_eq!(State::<Keccak256>::new(16).consumed_deposit_tip, [0u8; 32]);
    }

    // audit DP-002: per-market risk/fee parameters must be bound so a prover cannot
    // silently alter margins or fees under an unchanged root.
    #[test]
    fn state_root_binds_market_config() {
        let mut a: State<Keccak256> = State::new(16);
        let mut b: State<Keccak256> = State::new(16);
        a.markets.insert(0, Market::conservative(0));
        b.markets.insert(0, Market::with_fees(0, 10, 4)); // same id, different fee schedule
        assert_ne!(
            a.state_root(),
            b.state_root(),
            "market risk/fee parameters must be bound into the root",
        );
    }

    // ZK-001: the per-market oracle publisher key is the trust anchor `validate()` will
    // require a signature under. It MUST be bound into markets_digest — otherwise a prover
    // could swap which key a market trusts under an unchanged state root, defeating the
    // in-circuit signature check. Two states differing ONLY in `oracle_pubkey` must not
    // share a markets_digest.
    #[test]
    fn market_binds_oracle_pubkey_in_digest() {
        let mut a: State<Keccak256> = State::new(16);
        let mut b: State<Keccak256> = State::new(16);
        let mut ma = Market::conservative(1);
        ma.oracle_pubkey = [0xAB; 20];
        a.add_market(ma);
        let mut mb = Market::conservative(1);
        mb.oracle_pubkey = [0xCD; 20]; // same market, different publisher key
        b.add_market(mb);
        assert_ne!(
            a.markets_digest(),
            b.markets_digest(),
            "oracle_pubkey must be bound into markets_digest",
        );
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for b in bytes {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// One market whose funding state has every field non-zero.
    fn funded_market_state() -> State<Keccak256> {
        let mut s: State<Keccak256> = State::new(16);
        s.add_market(Market::conservative(3));
        *s.funding.get_mut(&3).unwrap() = FundingState {
            cumulative_index: -1_234_567,
            last_update_ms: 1_700_000_000_123,
            rate: -317,
            remainder: 2_999_999_999_999,
            last_price: 64_250 * crate::fixed::PRICE_SCALE,
            last_price_ms: 1_700_000_000_100,
        };
        s
    }

    // The serialized layout is pinned: the tree encodes `(depth, leaves)`, the
    // nullifier set its insertion-order log, and nothing derived (SEC-026: the leaf
    // index contributes zero bytes); a funding state encodes its six fields in
    // declaration order, and the wind-down recipient is the state's last field.
    // The roots are those of the tagged eighteen-word preimage.
    #[cfg(feature = "serde")]
    #[test]
    fn postcard_encoding_and_state_roots_are_pinned() {
        use crate::engine::BatchOp;
        use crate::note::owner_from_spend_key;
        use tiny_keccak::{Hasher as _, Keccak};

        fn hex_keccak(bytes: &[u8]) -> alloc::string::String {
            let mut k = Keccak::v256();
            k.update(bytes);
            let mut out = [0u8; 32];
            k.finalize(&mut out);
            hex(&out)
        }

        // (a) an empty state — the genesis shape
        let empty: State<Keccak256> = State::new(16);
        let b = postcard::to_allocvec(&empty).expect("serialize empty state");
        assert_eq!(b.len(), 68, "empty-state postcard length pinned");
        assert_eq!(
            hex_keccak(&b),
            "2b2e4c40194330c4a28810ee47640656c0a7da0b210eed5a22e077f62b945202",
            "empty-state postcard bytes pinned"
        );
        assert_eq!(
            hex(&empty.state_root()),
            "b3eda58db4298c0784a9e561b994385f7dc3ccce669328d11ff875afc0e87551",
            "empty-state root pinned"
        );

        // (b) a state with history: one deposit consumed, then spent (tree leaf +
        // retained nullifier + external flow), so every encoded field is live
        let spend_key = [1u8; 32];
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
        let mut s: State<Keccak256> = State::new(16);
        let note = Note::new(owner, 0, 1_000_000, [7u8; 32]);
        let cm = note.commitment::<Keccak256>();
        s.apply_op(&BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount: 1_000_000,
            blinding: [7u8; 32],
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        })
        .expect("deposit");
        s.apply_op(&BatchOp::Withdraw {
            note_commitment: cm,
            spend_key,
            to: None,
            nonce: 0,
        })
        .expect("withdraw");
        s.set_wind_down_recipient([0xC5; 20]);
        let b = postcard::to_allocvec(&s).expect("serialize state");
        assert_eq!(b.len(), 136, "historied-state postcard length pinned");
        assert_eq!(
            hex_keccak(&b),
            "0a360552bdde515cea191b82072b47f04ce61472a9289164602df7d469d4bf00",
            "historied-state postcard bytes pinned"
        );
        assert_eq!(
            &b[b.len() - 20..],
            &[0xC5; 20],
            "the recipient is encoded last"
        );
        assert_eq!(
            hex(&s.state_root()),
            "6715640a8eadffb87a9c4eb2d56ef8a186d0ceece3eb2ef93f43f8a24caff8e1",
            "historied-state root pinned"
        );
        let back: State<Keccak256> = postcard::from_bytes(&b).expect("decode");
        assert_eq!(back.state_root(), s.state_root());
        assert_eq!(postcard::to_allocvec(&back).unwrap(), b);

        // (c) one market with every funding field non-zero
        let m = funded_market_state();
        let b = postcard::to_allocvec(&m).expect("serialize funded state");
        assert_eq!(b.len(), 149, "funded-state postcard length pinned");
        assert_eq!(
            hex_keccak(&b),
            "44b7745505af556e0216d942f69fe9bf46c0b2067d0063af8a07751a484ca4ba",
            "funded-state postcard bytes pinned"
        );
        let back: State<Keccak256> = postcard::from_bytes(&b).expect("decode");
        assert_eq!(back.funding, m.funding);
        assert_eq!(back.state_root(), m.state_root());
    }

    /// The state root is `H(StateRoot, preimage)` over the eighteen words of the
    /// table on [`State::state_root_words`], and each map digest is
    /// `H(StateRoot, [its tag, its entries' words...])`. Rebuilt here from the
    /// fields, independently of the implementation, and pinned.
    #[test]
    fn state_root_preimage_is_the_tagged_eighteen_words() {
        use crate::hash::word_i128;
        let h = |words: &[Digest]| Keccak256::hash_words(Domain::StateRoot, words);
        let addr = |a: &[u8; 20]| {
            let mut w = [0u8; 32];
            w[..20].copy_from_slice(a);
            w
        };

        let mut s = funded_market_state();
        let owner = [0x31u8; 32];
        let mut p = Position::empty(owner, 3);
        p.size = -7;
        p.entry_price = 11;
        p.collateral = 13;
        p.funding_entry = -17;
        s.positions.insert((owner, 3), p);
        let note = Note::new(owner, 0, 19, [0x23u8; 32]);
        let cm = note.commitment::<Keccak256>();
        s.tree.append(cm).unwrap();
        s.notes.insert(cm, note);
        assert!(s.nullifiers.insert([0x29u8; 32]));
        s.insurance_fund = -1;
        s.vault_pool = 2;
        s.treasury = -3;
        s.external_in = 4;
        s.external_out = -5;
        s.consumed_deposit_tip = [0x37u8; 32];
        s.consumed_deposit_count = 6;
        s.mode = Mode::CloseOnly;
        s.next_batch_id = 8;
        s.last_withdrawal_nonce = 9;
        s.set_wind_down_recipient([0x41u8; 20]);

        let f = s.funding[&3];
        let funding = h(&[
            word_u64(TAG_FUNDING),
            word_u64(3),
            word_i128(f.cumulative_index),
            word_u64(f.last_update_ms),
            word_i128(f.rate),
            word_i128(f.remainder),
            word_i128(f.last_price),
            word_u64(f.last_price_ms),
        ]);
        assert_eq!(s.funding_digest(), funding);
        let positions = h(&[
            word_u64(TAG_POSITIONS),
            owner,
            word_u64(3),
            word_i128(-7),
            word_i128(11),
            word_i128(13),
            word_i128(-17),
        ]);
        assert_eq!(s.positions_digest(), positions);
        let notes = h(&[
            word_u64(TAG_NOTES),
            cm,
            owner,
            word_u64(0),
            word_i128(19),
            [0x23u8; 32],
        ]);
        assert_eq!(s.notes_digest(), notes);
        let m = s.markets[&3];
        let markets = h(&[
            word_u64(TAG_MARKETS),
            word_u64(3),
            word_i128(m.initial_margin_ratio),
            word_i128(m.maintenance_margin_ratio),
            word_i128(m.liquidation_fee_ratio),
            word_u64(m.max_oracle_staleness_ms),
            word_i128(m.max_oracle_confidence_ratio),
            word_i128(m.max_oracle_deviation_ratio),
            word_i128(m.taker_fee_ratio),
            word_i128(m.maker_rebate_ratio),
            word_i128(m.treasury_fee_ratio),
            addr(&m.oracle_pubkey),
            word_i128(m.max_mark_deviation_ratio),
            word_i128(m.max_fill_deviation_ratio),
        ]);
        assert_eq!(s.markets_digest(), markets);

        let preimage = [
            word_u64(TAG_STATE),
            s.tree.root(),
            s.nullifiers.digest(),
            notes,
            positions,
            funding,
            markets,
            word_i128(-1),
            word_i128(2),
            word_i128(-3),
            word_i128(4),
            word_i128(-5),
            [0x37u8; 32],
            word_u64(6),
            word_u64(1),
            word_u64(8),
            word_u64(9),
            addr(&[0x41u8; 20]),
        ];
        assert_eq!(s.state_root_words(), preimage);
        assert_eq!(s.state_root(), h(&preimage));
        assert_eq!(
            hex(&s.state_root()),
            "e1326f5e74b186f01a1774648f10708ccbd95ab3152ca257373ded12b930509a"
        );
    }

    /// The canonical genesis: a depth-`TREE_DEPTH` tree, `Market::conservative(0)`
    /// and the wind-down recipient `0x00…01`.
    #[test]
    fn canonical_genesis_state_root_is_pinned() {
        assert_eq!(TREE_DEPTH, 24);
        let mut g: State<Keccak256> = State::new(TREE_DEPTH);
        g.add_market(Market::conservative(0));
        let mut recipient = [0u8; 20];
        recipient[19] = 1;
        g.set_wind_down_recipient(recipient);
        assert_eq!(
            hex(&g.state_root()),
            "3ef9389bad36be69e819a0f3c27b35e30bdc148c9c50e3e7bef5b87832d3d1fe"
        );
    }

    #[test]
    fn role_tags_are_distinct_and_lead_each_preimage() {
        let tags = [
            TAG_STATE,
            TAG_NOTES,
            TAG_POSITIONS,
            TAG_FUNDING,
            TAG_MARKETS,
        ];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // an empty map's digest is the hash of its tag alone, so no two coincide
        let s: State<Keccak256> = State::new(16);
        let h = |t: u64| Keccak256::hash_words(Domain::StateRoot, &[word_u64(t)]);
        assert_eq!(s.notes_digest(), h(TAG_NOTES));
        assert_eq!(s.positions_digest(), h(TAG_POSITIONS));
        assert_eq!(s.funding_digest(), h(TAG_FUNDING));
        assert_eq!(s.markets_digest(), h(TAG_MARKETS));
    }

    #[test]
    fn state_root_binds_wind_down_recipient() {
        let a: State<Keccak256> = State::new(16);
        let mut b = a.clone();
        b.set_wind_down_recipient([0x01; 20]);
        let mut c = a.clone();
        c.wind_down_recipient[19] = 1;
        assert_ne!(a.state_root(), b.state_root());
        assert_ne!(a.state_root(), c.state_root());
        assert_ne!(b.state_root(), c.state_root());
    }

    /// Every funding field is bound: changing any one of them moves the funding
    /// digest and the root.
    #[test]
    fn state_root_binds_every_funding_field() {
        let base = funded_market_state();
        let edits: [fn(&mut FundingState); 6] = [
            |f| f.cumulative_index += 1,
            |f| f.last_update_ms += 1,
            |f| f.rate += 1,
            |f| f.remainder -= 1,
            |f| f.last_price += 1,
            |f| f.last_price_ms += 1,
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut s = base.clone();
            edit(s.funding.get_mut(&3).unwrap());
            assert_ne!(s.funding_digest(), base.funding_digest(), "field {i}");
            assert_ne!(s.state_root(), base.state_root(), "field {i}");
        }
    }

    /// The shape check refuses a funding state outside the range the engine
    /// maintains, and accepts every value inside it.
    #[test]
    fn witness_shape_refuses_out_of_range_funding_state() {
        use crate::funding::{FUNDING_DIVISOR, MAX_FUNDING_RATE_PER_INTERVAL};
        let base = funded_market_state();
        assert_eq!(base.validate_witness_shape(), Ok(()));
        let bad: [fn(&mut FundingState); 6] = [
            |f| f.rate = MAX_FUNDING_RATE_PER_INTERVAL + 1,
            |f| f.rate = -MAX_FUNDING_RATE_PER_INTERVAL - 1,
            |f| f.remainder = FUNDING_DIVISOR,
            |f| f.remainder = -FUNDING_DIVISOR,
            |f| f.last_price = -1,
            |f| {
                f.last_price = 0;
                f.last_price_ms = 1;
            },
        ];
        for (i, edit) in bad.iter().enumerate() {
            let mut s = base.clone();
            edit(s.funding.get_mut(&3).unwrap());
            assert_eq!(
                s.validate_witness_shape(),
                Err(crate::EngineError::FundingStateInvalid),
                "case {i}"
            );
        }
        let mut edge = base.clone();
        let f = edge.funding.get_mut(&3).unwrap();
        f.rate = -MAX_FUNDING_RATE_PER_INTERVAL;
        f.remainder = -(FUNDING_DIVISOR - 1);
        f.last_price = 0;
        f.last_price_ms = 0;
        assert_eq!(edge.validate_witness_shape(), Ok(()));
    }

    // ZK-001 (Task 4, carry-forward M1): the per-market mark band is consumed by the
    // funding path to bound `AccrueFunding.mark` against the signed index. Task 2 folded
    // `max_mark_deviation_ratio` into `markets_digest`, but never asserted it — so a
    // prover could swap the band under an unchanged state root, loosening (or nulling)
    // the funding-mark constraint. Two states differing ONLY in the mark band must not
    // share a markets_digest.
    #[test]
    fn market_binds_max_mark_deviation_ratio_in_digest() {
        let mut a: State<Keccak256> = State::new(16);
        let mut b: State<Keccak256> = State::new(16);
        let ma = Market::conservative(1); // max_mark_deviation_ratio = 5%
        a.add_market(ma);
        let mut mb = Market::conservative(1);
        mb.max_mark_deviation_ratio = 80_000; // same market, wider (8%) mark band
        b.add_market(mb);
        assert_ne!(
            a.markets_digest(),
            b.markets_digest(),
            "max_mark_deviation_ratio must be bound into markets_digest",
        );
    }

    // SEC-022: the per-market fill band bounds the price a fill may execute at relative
    // to the attested oracle mark. It MUST be bound into `markets_digest` — otherwise a
    // prover could widen (or null) the band under an unchanged state root, which is the
    // whole constraint. Two states differing ONLY in the fill band must not share a digest.
    #[test]
    fn market_binds_max_fill_deviation_ratio_in_digest() {
        let mut a: State<Keccak256> = State::new(16);
        let mut b: State<Keccak256> = State::new(16);
        a.add_market(Market::conservative(1)); // max_fill_deviation_ratio = 2%
        let mut mb = Market::conservative(1);
        mb.max_fill_deviation_ratio = 40_000; // same market, wider (4%) fill band
        b.add_market(mb);
        assert_ne!(
            a.markets_digest(),
            b.markets_digest(),
            "max_fill_deviation_ratio must be bound into markets_digest",
        );
    }
}
