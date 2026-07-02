//! Global shielded state and the state root (§1, §3).
//!
//! The state root is the single value anchored on L1 by every settled batch. It
//! binds every consensus-critical field: the note-commitment tree root, the
//! nullifier-set contents, the unspent-note set, the positions and funding digests,
//! the market parameters, the balance counters (insurance / vault pool / treasury /
//! external in/out), the operating mode, and the batch/sequence counters. Binding
//! the nullifier-set contents (not just its count) and the unspent-note set is what
//! makes a forged pre-state unable to double-spend under an unchanged root (audit
//! DP-002). The conservation identity — `Σ notes + Σ position collateral + insurance
//! == external_in − external_out` — is an invariant maintained by *every* operation
//! (Proof-v1: collateral conservation).

use crate::funding::FundingState;
use crate::hash::{word_i128, word_u64, Digest, Domain, Hasher};
use crate::market::{Market, MarketId};
use crate::merkle::MerkleTree;
use crate::note::{Note, PubKey};
use crate::nullifier::NullifierSet;
use crate::position::Position;
use alloc::collections::BTreeMap;

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
    pub nullifiers: NullifierSet,
    /// Unspent notes known to the engine, keyed by commitment.
    pub notes: BTreeMap<Digest, Note>,
    pub markets: BTreeMap<MarketId, Market>,
    pub funding: BTreeMap<MarketId, FundingState>,
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
    /// Grows by each fill's `treasury_fee`; can be paid out or injected into the
    /// insurance fund as a final backstop (`TreasuryToInsurance`).
    pub treasury: i128,
    pub external_in: i128,
    pub external_out: i128,
    pub mode: Mode,
    pub next_batch_id: u64,
    pub next_seq: u64,
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
            next_seq: 0,
        }
    }

    /// Register a market (governance action). Markets must be internally coherent
    /// (`maintenance < initial`, `fee < maintenance`, positive oracle bounds) — an
    /// incoherent market would corrupt the margin/liquidation math, so we assert it
    /// here rather than let a misconfiguration through. This is a setup-time check,
    /// not part of the proven `apply_batch` transition.
    pub fn add_market(&mut self, market: Market) {
        debug_assert!(
            market.is_coherent(),
            "refusing to register an incoherent market"
        );
        self.funding.insert(market.id, FundingState::default());
        self.markets.insert(market.id, market);
    }

    /// Sum of all unspent note amounts.
    pub fn notes_value(&self) -> i128 {
        self.notes.values().map(|n| n.amount).sum()
    }

    /// Sum of all position collateral.
    pub fn positions_collateral(&self) -> i128 {
        self.positions.values().map(|p| p.collateral).sum()
    }

    /// Total value tracked inside the protocol.
    pub fn internal_value(&self) -> i128 {
        self.notes_value()
            + self.positions_collateral()
            + self.insurance_fund
            + self.vault_pool
            + self.treasury
    }

    /// The conservation identity. MUST hold after every operation (Proof-v1).
    pub fn conservation_holds(&self) -> bool {
        self.internal_value() == self.external_in - self.external_out
    }

    /// A deterministic digest over positions (owner, market, size, entry,
    /// collateral, funding_entry), order-independent via the BTreeMap ordering.
    pub fn positions_digest(&self) -> Digest {
        let mut words = alloc::vec::Vec::new();
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
    /// funding index is applied to positions at settlement, so it MUST be part of
    /// the committed root — otherwise a prover could misreport funding without
    /// changing the state root.
    pub fn funding_digest(&self) -> Digest {
        let mut words = alloc::vec::Vec::new();
        for (id, f) in &self.funding {
            words.push(word_u64(*id));
            words.push(word_i128(f.cumulative_index));
            words.push(word_u64(f.last_update_ms));
        }
        H::hash_words(Domain::StateRoot, &words)
    }

    /// A deterministic digest over the UNSPENT-note set (keyed by commitment). The
    /// tree root commits every note ever appended, but not which remain spendable;
    /// binding this set stops a forged pre-state from replaying a spent note as
    /// unspent (audit DP-002). Order-independent via the `BTreeMap` ordering.
    pub fn notes_digest(&self) -> Digest {
        let mut words = alloc::vec::Vec::new();
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
    pub fn markets_digest(&self) -> Digest {
        let mut words = alloc::vec::Vec::new();
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
        }
        H::hash_words(Domain::StateRoot, &words)
    }

    /// The L1-anchored state root (§1, §3). Binds every consensus-critical field:
    /// the note-commitment tree, the nullifier-set contents, the unspent-note set,
    /// positions, funding, market parameters, all balance counters, the operating
    /// mode, and the batch/sequence counters (audit DP-002).
    pub fn state_root(&self) -> Digest {
        let mode_word: u64 = match self.mode {
            Mode::Normal => 0,
            Mode::CloseOnly => 1,
        };
        H::hash_words(
            Domain::StateRoot,
            &[
                self.tree.root(),
                self.nullifiers.digest::<H>(),
                self.notes_digest(),
                self.positions_digest(),
                self.funding_digest(),
                self.markets_digest(),
                word_i128(self.insurance_fund),
                word_i128(self.vault_pool),
                word_i128(self.treasury),
                word_i128(self.external_in),
                word_i128(self.external_out),
                word_u64(mode_word),
                word_u64(self.next_batch_id),
                word_u64(self.next_seq),
            ],
        )
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
        assert_eq!(s.internal_value(), 0);
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
        assert!(a.nullifiers.insert::<Keccak256>([1u8; 32]));
        assert!(b.nullifiers.insert::<Keccak256>([2u8; 32])); // equal count (1), different contents
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

    // audit DP-002: the batch/sequence counters order settlement and must be bound.
    #[test]
    fn state_root_binds_sequence_and_batch() {
        let base: State<Keccak256> = State::new(16);
        let mut with_seq = base.clone();
        with_seq.next_seq += 1;
        assert_ne!(base.state_root(), with_seq.state_root(), "next_seq must be bound");
        let mut with_batch = base.clone();
        with_batch.next_batch_id += 1;
        assert_ne!(base.state_root(), with_batch.state_root(), "next_batch_id must be bound");
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
}
