//! Global shielded state and the state root (§1, §3).
//!
//! The state root is the single value anchored on L1 by every settled batch. It
//! binds: the note-commitment tree root, the nullifier count, the positions
//! digest, the insurance fund, and the external in/out counters. The conservation
//! identity — `Σ notes + Σ position collateral + insurance == external_in −
//! external_out` — is an invariant maintained by *every* operation (Proof-v1:
//! collateral conservation).

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

    /// The L1-anchored state root (§1, §3).
    pub fn state_root(&self) -> Digest {
        H::hash_words(
            Domain::StateRoot,
            &[
                self.tree.root(),
                word_u64(self.nullifiers.len() as u64),
                self.positions_digest(),
                self.funding_digest(),
                word_i128(self.insurance_fund),
                word_i128(self.vault_pool),
                word_i128(self.treasury),
                word_i128(self.external_in),
                word_i128(self.external_out),
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
}
