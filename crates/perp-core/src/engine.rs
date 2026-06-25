//! The batch state-transition function (§3, §4, §13 Faz 0).
//!
//! `apply_op` / `apply_batch` are the heart of the protocol: a *pure*,
//! deterministic transition over [`State`]. The same function runs natively in
//! the sequencer/matcher (hot path) and, compiled to a zkVM guest, becomes the
//! Proof-v1 circuit (§10b). Every operation preserves the collateral conservation
//! identity (`State::conservation_holds`); the engine asserts it defensively.
//!
//! Phase 0 deliberately does **not** prove CLOB matching fairness — that is
//! Proof-v2 (§4), backed in the interim by receipts + manifest + slashing (§2).
//! Here, fills arrive already matched (taker + maker at one price), and the
//! engine enforces *settlement validity*: funding, margin, liquidation,
//! conservation.

use crate::error::EngineError;
use crate::fixed::apply_rate;
use crate::hash::{Digest, Hasher};
use crate::market::MarketId;
use crate::note::{Note, PubKey};
use crate::oracle::OracleTranscript;
use crate::order::Side;
use crate::position::Position;
use crate::state::{Mode, State};
use alloc::vec::Vec;

/// One settlement-level operation within a batch.
#[derive(Clone, Debug)]
pub enum BatchOp {
    /// Bring external collateral in from the L1 vault as a fresh shielded note.
    Deposit {
        owner: PubKey,
        asset_id: u64,
        amount: i128,
        blinding: Digest,
    },
    /// Consume a note and move its value into a position's margin (open/fund).
    FundPosition {
        owner: PubKey,
        market_id: MarketId,
        note_commitment: Digest,
        spend_key: Digest,
    },
    /// A matched fill: `taker` takes `taker_side` for `size` at `price`; `maker`
    /// takes the opposite. Margin is checked against the validated oracle mark.
    Fill {
        taker: PubKey,
        maker: PubKey,
        market_id: MarketId,
        taker_side: Side,
        size: i128,
        price: i128,
        oracle: OracleTranscript,
        now_ms: u64,
    },
    /// Advance a market's funding index from the validated oracle index price.
    AccrueFunding {
        market_id: MarketId,
        mark: i128,
        oracle: OracleTranscript,
        now_ms: u64,
    },
    /// Liquidate an underwater position at the validated oracle price (§5).
    Liquidate {
        owner: PubKey,
        market_id: MarketId,
        oracle: OracleTranscript,
        now_ms: u64,
    },
    /// Move free margin out of a position into a fresh note (must remain ≥
    /// initial margin if still open). Value-preserving.
    Unbind {
        owner: PubKey,
        market_id: MarketId,
        amount: i128,
        blinding: Digest,
        oracle: OracleTranscript,
        now_ms: u64,
    },
    /// Burn a note and send its value out to the L1 vault (withdrawal).
    Withdraw {
        note_commitment: Digest,
        spend_key: Digest,
    },
    /// Forced-exit / circuit-breaker: switch the system to close-only (§6, §8).
    EnterCloseOnly,
}

impl<H: Hasher> State<H> {
    /// Apply a whole batch, asserting conservation after each op. Stops at the
    /// first error (the prover reproduces the same stop point deterministically).
    pub fn apply_batch(&mut self, ops: &[BatchOp]) -> Result<(), EngineError> {
        for op in ops {
            self.apply_op(op)?;
            debug_assert!(
                self.conservation_holds(),
                "conservation invariant broken by {op:?}"
            );
            if !self.conservation_holds() {
                return Err(EngineError::ConservationViolated);
            }
        }
        self.next_batch_id += 1;
        Ok(())
    }

    /// Apply a single operation.
    pub fn apply_op(&mut self, op: &BatchOp) -> Result<(), EngineError> {
        match op {
            BatchOp::Deposit {
                owner,
                asset_id,
                amount,
                blinding,
            } => self.op_deposit(owner, *asset_id, *amount, blinding),
            BatchOp::FundPosition {
                owner,
                market_id,
                note_commitment,
                spend_key,
            } => self.op_fund_position(owner, *market_id, note_commitment, spend_key),
            BatchOp::Fill {
                taker,
                maker,
                market_id,
                taker_side,
                size,
                price,
                oracle,
                now_ms,
            } => self.op_fill(
                taker,
                maker,
                *market_id,
                *taker_side,
                *size,
                *price,
                oracle,
                *now_ms,
            ),
            BatchOp::AccrueFunding {
                market_id,
                mark,
                oracle,
                now_ms,
            } => self.op_accrue_funding(*market_id, *mark, oracle, *now_ms),
            BatchOp::Liquidate {
                owner,
                market_id,
                oracle,
                now_ms,
            } => self.op_liquidate(owner, *market_id, oracle, *now_ms),
            BatchOp::Unbind {
                owner,
                market_id,
                amount,
                blinding,
                oracle,
                now_ms,
            } => self.op_unbind(owner, *market_id, *amount, blinding, oracle, *now_ms),
            BatchOp::Withdraw {
                note_commitment,
                spend_key,
            } => self.op_withdraw(note_commitment, spend_key),
            BatchOp::EnterCloseOnly => {
                self.mode = Mode::CloseOnly;
                Ok(())
            }
        }
    }

    // --- individual operations -------------------------------------------------

    fn op_deposit(
        &mut self,
        owner: &PubKey,
        asset_id: u64,
        amount: i128,
        blinding: &Digest,
    ) -> Result<(), EngineError> {
        if amount <= 0 {
            return Err(EngineError::NonPositiveAmount);
        }
        let note = Note::new(*owner, asset_id, amount, *blinding);
        let cm = note.commitment::<H>();
        self.tree.append(cm).map_err(|_| EngineError::Overflow)?;
        self.notes.insert(cm, note);
        self.external_in = self
            .external_in
            .checked_add(amount)
            .ok_or(EngineError::Overflow)?;
        Ok(())
    }

    /// Consume a note: verify ownership, mark nullifier, remove from unspent set.
    fn consume_note(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
        expected_owner: Option<&PubKey>,
    ) -> Result<Note, EngineError> {
        let note = *self
            .notes
            .get(note_commitment)
            .ok_or(EngineError::UnknownOrSpentNote)?;
        if let Some(o) = expected_owner {
            if &note.owner != o {
                return Err(EngineError::BadSpendKey);
            }
        }
        let nf = note.nullifier::<H>(spend_key);
        if self.nullifiers.contains(&nf) {
            return Err(EngineError::UnknownOrSpentNote);
        }
        // bind spend_key to owner: owner must equal H-derived pubkey of the key.
        // Phase 0 keeps owner == note.owner check above; nullifier secrecy is the
        // real guard. Insert nullifier and drop the note from the unspent set.
        let _ = self.nullifiers.insert(nf);
        self.notes.remove(note_commitment);
        Ok(note)
    }

    fn op_fund_position(
        &mut self,
        owner: &PubKey,
        market_id: MarketId,
        note_commitment: &Digest,
        spend_key: &Digest,
    ) -> Result<(), EngineError> {
        if !self.markets.contains_key(&market_id) {
            return Err(EngineError::UnknownMarket);
        }
        let note = self.consume_note(note_commitment, spend_key, Some(owner))?;
        let key = (*owner, market_id);
        let pos = self
            .positions
            .entry(key)
            .or_insert_with(|| Position::empty(*owner, market_id));
        pos.collateral = pos
            .collateral
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn op_fill(
        &mut self,
        taker: &PubKey,
        maker: &PubKey,
        market_id: MarketId,
        taker_side: Side,
        size: i128,
        price: i128,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        if size <= 0 || price <= 0 {
            return Err(EngineError::NonPositiveAmount);
        }
        let market = *self
            .markets
            .get(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        let mark = oracle.validate(&market, now_ms)?;
        let funding_index = self
            .funding
            .get(&market_id)
            .map(|f| f.cumulative_index)
            .unwrap_or(0);

        let taker_delta = match taker_side {
            Side::Buy => size,
            Side::Sell => -size,
        };
        let maker_delta = -taker_delta;

        // In close-only mode, neither side may increase exposure (§6).
        if self.mode == Mode::CloseOnly
            && (increases_exposure(self.position(taker, market_id), taker_delta)
                || increases_exposure(self.position(maker, market_id), maker_delta))
        {
            return Err(EngineError::CloseOnly);
        }

        // Compute both legs on COPIES; commit only if both pass margin. This
        // makes the op atomic — a rejected fill leaves state untouched, exactly
        // as the prover's all-or-nothing constraint system would.
        let mut pool_delta = 0i128;
        let mut staged: [((PubKey, MarketId), Position); 2] =
            [((*taker, market_id), Position::empty(*taker, market_id)); 2];
        for (i, (who, delta)) in [(taker, taker_delta), (maker, maker_delta)]
            .into_iter()
            .enumerate()
        {
            let key = (*who, market_id);
            let before = self.positions.get(&key).copied();
            let mut pos = before.unwrap_or_else(|| {
                let mut p = Position::empty(*who, market_id);
                p.funding_entry = funding_index;
                p
            });
            let increasing = increases_exposure(before.as_ref(), delta);
            let (realized, funding) = pos.apply_fill(delta, price, funding_index)?;
            pool_delta = pool_delta
                .checked_sub(realized)
                .ok_or(EngineError::Overflow)?
                .checked_add(funding)
                .ok_or(EngineError::Overflow)?;
            if increasing {
                pos.check_initial_margin(&market, mark, funding_index)?;
            }
            staged[i] = (key, pos);
        }
        // commit
        self.vault_pool = self
            .vault_pool
            .checked_add(pool_delta)
            .ok_or(EngineError::Overflow)?;
        for (key, pos) in staged {
            self.positions.insert(key, pos);
        }
        Ok(())
    }

    fn op_accrue_funding(
        &mut self,
        market_id: MarketId,
        mark: i128,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        let market = *self
            .markets
            .get(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        let index_price = oracle.validate(&market, now_ms)?;
        let f = self
            .funding
            .get_mut(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        f.accrue(mark, index_price, now_ms);
        Ok(())
    }

    fn op_liquidate(
        &mut self,
        owner: &PubKey,
        market_id: MarketId,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        let market = *self
            .markets
            .get(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        let price = oracle.validate(&market, now_ms)?;
        let funding_index = self
            .funding
            .get(&market_id)
            .map(|f| f.cumulative_index)
            .unwrap_or(0);
        let key = (*owner, market_id);
        let pos = self
            .positions
            .get(&key)
            .ok_or(EngineError::UnknownPosition)?;
        if !pos.is_open() || !pos.is_liquidatable(&market, price, funding_index) {
            return Err(EngineError::NotLiquidatable);
        }
        let notional = pos.notional(price).ok_or(EngineError::Overflow)?;
        let penalty =
            apply_rate(notional, market.liquidation_fee_ratio).ok_or(EngineError::Overflow)?;
        // close the whole position at oracle price
        let pos = self.positions.get_mut(&key).unwrap();
        let close_delta = -pos.size;
        let (realized, funding) = pos.apply_fill(close_delta, price, funding_index)?;
        self.vault_pool = self
            .vault_pool
            .checked_sub(realized)
            .ok_or(EngineError::Overflow)?
            .checked_add(funding)
            .ok_or(EngineError::Overflow)?;
        // take liquidation penalty from remaining collateral into insurance.
        let pos = self.positions.get_mut(&key).unwrap();
        let take = penalty.min(pos.collateral.max(0));
        pos.collateral -= take;
        self.insurance_fund = self
            .insurance_fund
            .checked_add(take)
            .ok_or(EngineError::Overflow)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn op_unbind(
        &mut self,
        owner: &PubKey,
        market_id: MarketId,
        amount: i128,
        blinding: &Digest,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> Result<(), EngineError> {
        if amount <= 0 {
            return Err(EngineError::NonPositiveAmount);
        }
        let market = *self
            .markets
            .get(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        let mark = oracle.validate(&market, now_ms)?;
        let funding_index = self
            .funding
            .get(&market_id)
            .map(|f| f.cumulative_index)
            .unwrap_or(0);
        let key = (*owner, market_id);
        let mut pos = *self
            .positions
            .get(&key)
            .ok_or(EngineError::UnknownPosition)?;
        if pos.collateral < amount {
            return Err(EngineError::Risk(
                crate::position::RiskError::InsufficientMargin,
            ));
        }
        pos.collateral -= amount;
        // if still open, must remain ≥ initial margin after the withdrawal.
        if pos.is_open() {
            pos.check_initial_margin(&market, mark, funding_index)?;
        }
        // all checks passed. Do the fallible mint FIRST (tree.append can fail if
        // full); only then commit the position, so the op stays atomic and
        // value-preserving.
        let note = Note::new(*owner, 0, amount, *blinding);
        let cm = note.commitment::<H>();
        self.tree.append(cm).map_err(|_| EngineError::Overflow)?;
        self.notes.insert(cm, note);
        self.positions.insert(key, pos);
        Ok(())
    }

    fn op_withdraw(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
    ) -> Result<(), EngineError> {
        let note = self.consume_note(note_commitment, spend_key, None)?;
        self.external_out = self
            .external_out
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;
        Ok(())
    }
}

/// Does applying `delta` to `pos` increase absolute exposure (open or grow)?
fn increases_exposure(pos: Option<&Position>, delta: i128) -> bool {
    match pos {
        None => true,
        Some(p) if p.size == 0 => true,
        Some(p) => {
            let new = p.size + delta;
            // same sign and larger magnitude, or flipped through zero to larger
            (p.size > 0) == (delta > 0) || crate::fixed::abs(new) > crate::fixed::abs(p.size)
        }
    }
}

/// Convenience: collect every order hash in a batch's fills for a manifest (§2).
pub fn _touched_owners(ops: &[BatchOp]) -> Vec<PubKey> {
    let mut v = Vec::new();
    for op in ops {
        if let BatchOp::Fill { taker, maker, .. } = op {
            v.push(*taker);
            v.push(*maker);
        }
    }
    v
}
