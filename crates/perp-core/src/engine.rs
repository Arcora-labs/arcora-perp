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
use crate::fixed::{abs, apply_rate, notional_quote, RATE_SCALE};
use crate::hash::{Digest, Hasher};
use crate::market::MarketId;
use crate::note::{owner_from_spend_key, Note, PubKey};
use crate::oracle::OracleTranscript;
use crate::order::Side;
use crate::position::Position;
use crate::state::{Mode, State};
use alloc::vec::Vec;

/// One settlement-level operation within a batch.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BatchOp {
    /// Bring external collateral in from the L1 vault as a fresh shielded note.
    /// `from` is the L1 address that emitted the `Deposited` event and `deposit_id`
    /// is its position in the L1 deposit stream (SEC-019) — together they are the
    /// leaf folded into the in-circuit deposit hash-chain accumulator, and
    /// `deposit_id` binds the op to strict L1 order (see `EngineError::DepositOutOfOrder`).
    ///
    /// `deposit_blind` is the privacy blind the depositor chose (spec §1a): the leaf
    /// binds `owner_commit = keccak(owner ‖ deposit_blind)`, NOT the raw `owner`, so
    /// the on-chain record never links the L1 payer to the shielded owner. It is a
    /// separate value from `blinding` (which hides the note commitment) — the two must
    /// not be conflated or re-used for each other.
    Deposit {
        owner: PubKey,
        asset_id: u64,
        amount: i128,
        blinding: Digest,
        from: [u8; 20],
        deposit_id: u64,
        deposit_blind: Digest,
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
    /// Burn a note. A REAL L1 withdrawal sets `to = Some(addr)` — the burned value is
    /// bound to its `withdrawals_root` leaf `(addr, note.amount, nonce)` inside the
    /// transition. An INTERNAL burn (LP debit / legacy re-fund) sets `to = None` and
    /// emits no withdrawal (it never becomes a vault claim). `nonce` is only
    /// meaningful when `to.is_some()`.
    Withdraw {
        note_commitment: Digest,
        spend_key: Digest,
        to: Option<[u8; 20]>,
        nonce: u64,
    },
    /// Forced-exit / circuit-breaker: switch the system to close-only (§6, §8).
    EnterCloseOnly,
    /// Capitalize the insurance fund with external collateral (§6, §9) — the
    /// backstop that absorbs liquidation bad debt before it socializes onto the
    /// clearing pool.
    SeedInsurance { amount: i128 },
}

/// One auto-deleverage haircut: `clawed` of `owner`'s unrealized profit was taken
/// to cover another position's liquidation bad debt (§6, §9; audit Q2/Q7). The
/// engine surfaces these from [`State::liquidate`] so a socialized loss can be
/// reported back to the affected account as an attributable receipt instead of
/// vanishing silently — the transparency half of the bad-debt backstop. It carries
/// no identifying salt itself; the sequencer publishes it under a secret-keyed tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdlHaircut {
    pub owner: PubKey,
    pub clawed: i128,
}

/// One withdrawal this batch authorizes: value `amount` (bound to the burned note)
/// released to L1 address `to`, unique by `nonce`. Its leaf enters the batch's
/// `withdrawals_root`. amount is the note's value — the transition, not the prover,
/// determines it (F2 closure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WithdrawalOut {
    pub to: [u8; 20],
    pub amount: i128,
    pub nonce: u64,
}

/// One deposit this batch consumed: external collateral `amount` credited to `owner`
/// as a fresh note, bound to the L1 `Deposited` event emitted by address `from` at
/// L1 position `deposit_id` (SEC-019). Its leaf (`merkle::deposit_leaf`) is folded, in
/// `deposit_id` order, into `State::consumed_deposit_tip`; the engine — not the prover
/// — determines these from the ordered op stream, so a deposit cannot be replayed,
/// skipped, or reordered without breaking the committed accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DepositIn {
    pub from: [u8; 20],
    pub owner: PubKey,
    pub amount: u128,
    pub deposit_id: u64,
}

/// The observable outputs of applying a batch that the proof roots are derived from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchOutputs {
    pub withdrawals: alloc::vec::Vec<WithdrawalOut>,
    pub deposits: alloc::vec::Vec<DepositIn>,
}

/// The optional per-op contributions a single applied op makes to [`BatchOutputs`].
/// An op contributes at most one of each: a real `Withdraw { to: Some }` yields a
/// [`WithdrawalOut`]; a `Deposit` yields a [`DepositIn`]; every other op yields
/// neither. `apply_batch` drains these into the batch outputs (mirrors the two
/// output roots the proof derives).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpOutput {
    pub withdrawal: Option<WithdrawalOut>,
    pub deposit: Option<DepositIn>,
}

impl From<&WithdrawalOut> for crate::merkle::WithdrawalLeaf {
    fn from(w: &WithdrawalOut) -> Self {
        // engine note amounts are non-negative; a withdrawal of a real settled note
        // is always ≥ 0. Saturating cast keeps this total (a negative would be a bug
        // upstream, not a silently-huge leaf).
        crate::merkle::WithdrawalLeaf { to: w.to, amount: w.amount.max(0) as u128, nonce: w.nonce }
    }
}

impl<H: Hasher> State<H> {
    /// Apply a whole batch, asserting conservation after each op. Stops at the
    /// first error (the prover reproduces the same stop point deterministically).
    pub fn apply_batch(&mut self, ops: &[BatchOp]) -> Result<BatchOutputs, EngineError> {
        let mut outputs = BatchOutputs::default();
        for op in ops {
            let out = self.apply_op(op)?;
            if let Some(w) = out.withdrawal {
                outputs.withdrawals.push(w);
            }
            if let Some(d) = out.deposit {
                outputs.deposits.push(d);
            }
            debug_assert!(
                self.conservation_holds(),
                "conservation invariant broken by {op:?}"
            );
            if !self.conservation_holds() {
                return Err(EngineError::ConservationViolated);
            }
        }
        self.next_batch_id += 1;
        Ok(outputs)
    }

    /// Apply a single operation, returning what it contributed to the batch outputs
    /// (an [`OpOutput`]). A real L1 `Withdraw` with `to = Some` yields a withdrawal; a
    /// `Deposit` yields a deposit; every other op yields an empty [`OpOutput`]. Both
    /// output-producing ops are special-cased here so their leaves reach `apply_batch`.
    pub fn apply_op(&mut self, op: &BatchOp) -> Result<OpOutput, EngineError> {
        match op {
            BatchOp::Withdraw {
                note_commitment,
                spend_key,
                to,
                nonce,
            } => self
                .op_withdraw(note_commitment, spend_key, to, *nonce)
                .map(|w| OpOutput {
                    withdrawal: w,
                    deposit: None,
                }),
            BatchOp::Deposit {
                owner,
                asset_id,
                amount,
                blinding,
                from,
                deposit_id,
                deposit_blind,
            } => self
                .op_deposit(
                    owner,
                    *asset_id,
                    *amount,
                    blinding,
                    from,
                    *deposit_id,
                    deposit_blind,
                )
                .map(|d| OpOutput {
                    withdrawal: None,
                    deposit: Some(d),
                }),
            other => self
                .apply_settlement_op(other)
                .map(|()| OpOutput::default()),
        }
    }

    /// Apply a non-withdraw settlement op. These are value-preserving within the
    /// shielded pool (or bring value in) and never produce an L1 withdrawal output.
    fn apply_settlement_op(&mut self, op: &BatchOp) -> Result<(), EngineError> {
        match op {
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
            } => self
                .op_liquidate(owner, *market_id, oracle, *now_ms)
                .map(|_| ()),
            BatchOp::Unbind {
                owner,
                market_id,
                amount,
                blinding,
                oracle,
                now_ms,
            } => self.op_unbind(owner, *market_id, *amount, blinding, oracle, *now_ms),
            BatchOp::EnterCloseOnly => {
                self.mode = Mode::CloseOnly;
                Ok(())
            }
            BatchOp::SeedInsurance { amount } => self.op_seed_insurance(*amount),
            BatchOp::Deposit { .. } => {
                unreachable!("Deposit is handled by apply_op, never delegated here")
            }
            BatchOp::Withdraw { .. } => {
                unreachable!("Withdraw is handled by apply_op, never delegated here")
            }
        }
    }

    /// Liquidate `owner`'s position, returning the auto-deleverage haircuts the
    /// cascade applied (empty when none — the penalty alone, or the insurance fund,
    /// covered it). This is the SAME state transition as `BatchOp::Liquidate`
    /// (which discards the attribution); the sequencer calls this entry so it can
    /// report each socialized haircut back to the clawed account (audit Q2).
    pub fn liquidate(
        &mut self,
        owner: &PubKey,
        market_id: MarketId,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> Result<Vec<AdlHaircut>, EngineError> {
        let haircuts = self.op_liquidate(owner, market_id, oracle, now_ms)?;
        debug_assert!(
            self.conservation_holds(),
            "conservation invariant broken by liquidate"
        );
        Ok(haircuts)
    }

    // --- individual operations -------------------------------------------------

    // these are exactly the `BatchOp::Deposit` fields, destructured; a params struct
    // would only re-declare the enum variant (same house rule as `op_fill` above)
    #[allow(clippy::too_many_arguments)]
    fn op_deposit(
        &mut self,
        owner: &PubKey,
        asset_id: u64,
        amount: i128,
        blinding: &Digest,
        from: &[u8; 20],
        deposit_id: u64,
        deposit_blind: &Digest,
    ) -> Result<DepositIn, EngineError> {
        // SEC-019: bind this deposit to strict L1 order BEFORE any state mutation.
        // `deposit_id` must be exactly the next unconsumed L1 leaf index — this
        // rejects a replayed, skipped, or reordered deposit with no partial credit
        // (nothing below has run yet), keeping the hash-chain fold bound to the real
        // L1 `Deposited` stream.
        if deposit_id != self.consumed_deposit_count {
            return Err(EngineError::DepositOutOfOrder);
        }
        if amount <= 0 {
            return Err(EngineError::NonPositiveAmount);
        }
        let note = Note::new(*owner, asset_id, amount, *blinding);
        let cm = note.commitment::<H>();
        if self.notes.contains_key(&cm) {
            return Err(EngineError::DuplicateCommitment);
        }
        self.tree.append(cm).map_err(|_| EngineError::Overflow)?;
        self.notes.insert(cm, note);
        self.external_in = self
            .external_in
            .checked_add(amount)
            .ok_or(EngineError::Overflow)?;
        // Fold the L1 deposit leaf onto the in-circuit accumulator. `amount as u128`
        // is safe: it is verified `> 0` above. This is the SAME leaf/fold the
        // on-chain vault computes (byte-parity via `merkle::deposit_leaf`), so the
        // committed `consumed_deposit_tip` tracks the real, ordered event stream.
        //
        // What is bound is the BLINDED owner commit, not the raw `owner` (spec §1a):
        // the raw owner is published nowhere on L1, yet crediting a different owner
        // still needs a different commit — which breaks the chain match against the
        // vault's tip. Misattribution stays closed; the payer↔owner link stays private.
        let commit = crate::merkle::owner_commit(owner, deposit_blind);
        let leaf = crate::merkle::deposit_leaf(from, &commit, amount as u128, deposit_id);
        self.consumed_deposit_tip =
            crate::merkle::deposit_chain_fold(&self.consumed_deposit_tip, &leaf);
        self.consumed_deposit_count += 1;
        Ok(DepositIn {
            from: *from,
            owner: *owner,
            amount: amount as u128,
            deposit_id,
        })
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
        // audit DP-003: bind spend authority to ownership — the spend key MUST derive
        // the note's owner (`owner == H(spend_key)`). This is the SOLE authorization on
        // the withdraw path (expected_owner = None), and closes the hole where anyone
        // knowing a note's public commitment could burn it with an arbitrary key.
        if owner_from_spend_key::<H>(spend_key) != note.owner {
            return Err(EngineError::BadSpendKey);
        }
        if let Some(o) = expected_owner {
            if &note.owner != o {
                return Err(EngineError::BadSpendKey);
            }
        }
        let nf = note.nullifier::<H>(spend_key);
        if self.nullifiers.contains(&nf) {
            return Err(EngineError::UnknownOrSpentNote);
        }
        // Insert nullifier and drop the note from the unspent set.
        let _ = self.nullifiers.insert::<H>(nf);
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
        // A self-trade would have both legs snapshot the same pre-state and the
        // second commit clobber the first, dropping a leg and breaking
        // conservation. The matcher prevents self-trades upstream; reject here too.
        if taker == maker {
            return Err(EngineError::SelfTrade);
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

        // Trading fee (§9): the taker pays `taker_fee` on the fill notional; the
        // maker is rebated `maker_rebate` (the market-maker incentive); the rest
        // funds the insurance fund. Zero on a fee-free market — so existing flows
        // are unchanged.
        let notional = notional_quote(size, price).ok_or(EngineError::Overflow)?;
        let taker_fee =
            apply_rate(notional, market.taker_fee_ratio).ok_or(EngineError::Overflow)?;
        let maker_rebate =
            apply_rate(notional, market.maker_rebate_ratio).ok_or(EngineError::Overflow)?;
        // The treasury cut (operator revenue) comes out of the net fee; the remainder
        // funds insurance. `is_coherent` bounds treasury ≤ taker − maker.
        let treasury_fee =
            apply_rate(notional, market.treasury_fee_ratio).ok_or(EngineError::Overflow)?;

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
            // Charge this leg its trading fee BEFORE the margin check, so a taker
            // that can't afford the fee on an opening fill is rejected (leg 0 =
            // taker pays, leg 1 = maker is rebated).
            pos.collateral = if i == 0 {
                pos.collateral
                    .checked_sub(taker_fee)
                    .ok_or(EngineError::Overflow)?
            } else {
                pos.collateral
                    .checked_add(maker_rebate)
                    .ok_or(EngineError::Overflow)?
            };
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
        // Route the treasury cut to the operator treasury and the remainder of the
        // net fee into the insurance fund. Conservation holds: taker −fee, maker
        // +rebate, treasury +treasury_fee, insurance +(fee−rebate−treasury_fee).
        self.treasury = self
            .treasury
            .checked_add(treasury_fee)
            .ok_or(EngineError::Overflow)?;
        self.insurance_fund = self
            .insurance_fund
            .checked_add(
                taker_fee
                    .checked_sub(maker_rebate)
                    .ok_or(EngineError::Overflow)?
                    .checked_sub(treasury_fee)
                    .ok_or(EngineError::Overflow)?,
            )
            .ok_or(EngineError::Overflow)?;
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
        // ZK-001 (Task 4) — bound the raw `mark` witness (the sequencer's book mid) to a
        // symmetric band around the SIGNED index: |mark − index| · RATE_SCALE
        // <= max_mark_deviation_ratio · index. Without this the mark is completely
        // unconstrained and a prover could pick any value to steer the funding rate. This
        // mirrors the checked-mul idiom of `oracle::validate`'s confidence/deviation gates
        // (same RATE_SCALE scaling; ANY overflow ⇒ reject, never wrap/panic). `index > 0`
        // is guaranteed by `validate`, but `mark` is an arbitrary prover witness — so, like
        // `funding_rate`, the difference is `checked_sub` and an i128::MIN mark rejects
        // cleanly with an `EngineError` instead of panicking the guest.
        let dev = match mark.checked_sub(index_price) {
            Some(d) => abs(d),
            None => return Err(EngineError::MarkOutOfBand),
        };
        match (
            dev.checked_mul(RATE_SCALE),
            market.max_mark_deviation_ratio.checked_mul(index_price),
        ) {
            (Some(lhs), Some(rhs)) if lhs <= rhs => {}
            _ => return Err(EngineError::MarkOutOfBand),
        }
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
    ) -> Result<Vec<AdlHaircut>, EngineError> {
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
        // Take the liquidation penalty from any remaining (positive) collateral
        // into the insurance fund. Bad debt (a close that left collateral < 0) is
        // then handled by the waterfall below: insurance backstop → ADL → close-only.
        let pos = self.positions.get_mut(&key).unwrap();
        let take = penalty.min(pos.collateral.max(0));
        pos.collateral -= take;
        self.insurance_fund = self
            .insurance_fund
            .checked_add(take)
            .ok_or(EngineError::Overflow)?;

        // Insurance backstop (§6, §9): if the close left the position underwater
        // (bad debt — a gap-down past the maintenance buffer), draw from the
        // insurance fund to cover it BEFORE it socializes onto the clearing pool.
        // Conservation-neutral: `insurance_fund` and the position's `collateral`
        // both sit in the conservation identity, so moving value between them
        // leaves it intact. If the fund cannot absorb the whole shortfall, the
        // residual is socialized and the system is undercollateralized — so it
        // trips to close-only (the depletion halt the audit flagged as missing).
        let bad_debt = {
            let pos = self.positions.get(&key).unwrap();
            (-pos.collateral).max(0)
        };
        let mut haircuts: Vec<AdlHaircut> = Vec::new();
        if bad_debt > 0 {
            // 1. Insurance backstop.
            let cover = bad_debt.min(self.insurance_fund.max(0));
            self.insurance_fund -= cover;
            self.positions.get_mut(&key).unwrap().collateral += cover;
            // 2. Auto-deleverage cascade: claw any residual from the winners. Each
            //    haircut is attributed (owner + amount) so it can be reported back.
            let residual = (bad_debt - cover).max(0);
            if residual > 0 {
                haircuts = self.auto_deleverage(market_id, owner, residual, price);
                let recovered: i128 = haircuts.iter().map(|h| h.clawed).sum();
                self.positions.get_mut(&key).unwrap().collateral += recovered;
            }
            // 3. If still underwater (insurance AND winners both insufficient — i.e.
            //    the winning side already cashed out), it is true insolvency: the
            //    residual stays parked (conservation-safe) and the system trips to
            //    close-only (the depletion halt).
            if self.positions.get(&key).unwrap().collateral < 0 {
                self.mode = Mode::CloseOnly;
            }
        }
        Ok(haircuts)
    }

    /// Auto-deleverage cascade (§6, §9): when insurance can't fully absorb a
    /// liquidation's bad debt, claw the `residual` from the **profitable** open
    /// positions in `market_id` (the winners), pro-rata to each winner's
    /// *clawable* = `min(unrealized profit at price, posted collateral)`, capped
    /// there so ADL can never push a winner's collateral below zero (which would
    /// mint fresh bad debt). Conservation-neutral — collateral only moves between
    /// positions, all inside the conservation identity. Returns one [`AdlHaircut`]
    /// per clawed winner (their sum is the amount recovered, ≤ `residual`), so the
    /// caller can report the socialized loss back to each account (audit Q2).
    /// BTreeMap iteration is sorted, so the distribution and the returned order are
    /// deterministic for the prover. NOTE: this haircuts a winner's collateral
    /// rather than reducing position size, so an ADL'd winner keeps full exposure
    /// on a thinner base; the burden is also computed per-liquidation, so across
    /// multiple bad-debt liquidations in one pass the split is order-dependent
    /// (deterministic by key order). Both are Phase-0 simplifications.
    fn auto_deleverage(
        &mut self,
        market_id: MarketId,
        exclude: &PubKey,
        residual: i128,
        price: i128,
    ) -> Vec<AdlHaircut> {
        if residual <= 0 {
            return Vec::new();
        }
        let mut winners: Vec<(PubKey, i128)> = Vec::new();
        let mut total: i128 = 0;
        for ((owner, mid), pos) in self.positions.iter() {
            if *mid != market_id || owner == exclude || !pos.is_open() {
                continue;
            }
            if let Some(profit) = pos.unrealized_pnl(price) {
                // Claw only realized-able gains, and never more collateral than the
                // winner actually holds (so ADL can't push a winner underwater).
                let claimable = profit.min(pos.collateral.max(0));
                if claimable > 0 {
                    winners.push((*owner, claimable));
                    total = total.saturating_add(claimable);
                }
            }
        }
        if total <= 0 {
            return Vec::new();
        }
        let coverable = residual.min(total);
        // Floor pro-rata, then hand the rounding remainder to winners with headroom.
        let mut takes: Vec<i128> = winners
            .iter()
            .map(|(_, p)| coverable.saturating_mul(*p) / total)
            .collect();
        let mut leftover = coverable - takes.iter().sum::<i128>();
        for i in 0..winners.len() {
            if leftover == 0 {
                break;
            }
            let headroom = winners[i].1 - takes[i];
            let add = leftover.min(headroom);
            takes[i] += add;
            leftover -= add;
        }
        let mut haircuts: Vec<AdlHaircut> = Vec::new();
        for (i, (owner, _)) in winners.iter().enumerate() {
            if takes[i] <= 0 {
                continue;
            }
            if let Some(pos) = self.positions.get_mut(&(*owner, market_id)) {
                pos.collateral -= takes[i];
            }
            haircuts.push(AdlHaircut {
                owner: *owner,
                clawed: takes[i],
            });
        }
        haircuts
    }

    /// Capitalize the insurance fund from external collateral (§6, §9). The fund
    /// is the backstop drawn on by [`Self::op_liquidate`] to absorb bad debt.
    /// Conservation-safe: `insurance_fund` and `external_in` rise together.
    fn op_seed_insurance(&mut self, amount: i128) -> Result<(), EngineError> {
        if amount <= 0 {
            return Err(EngineError::NonPositiveAmount);
        }
        self.insurance_fund = self
            .insurance_fund
            .checked_add(amount)
            .ok_or(EngineError::Overflow)?;
        self.external_in = self
            .external_in
            .checked_add(amount)
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
        if self.notes.contains_key(&cm) {
            return Err(EngineError::DuplicateCommitment);
        }
        self.tree.append(cm).map_err(|_| EngineError::Overflow)?;
        self.notes.insert(cm, note);
        self.positions.insert(key, pos);
        Ok(())
    }

    fn op_withdraw(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
        to: &Option<[u8; 20]>,
        nonce: u64,
    ) -> Result<Option<WithdrawalOut>, EngineError> {
        let note = self.consume_note(note_commitment, spend_key, None)?;
        self.external_out = self
            .external_out
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;
        // Only a real L1 withdrawal (`to = Some`) produces a withdrawals_root leaf;
        // an internal burn (`to = None`) burns value without an L1 exit.
        Ok(to.map(|addr| WithdrawalOut { to: addr, amount: note.amount, nonce }))
    }
}

/// Does applying `delta` to `pos` increase absolute exposure (open or grow)?
fn increases_exposure(pos: Option<&Position>, delta: i128) -> bool {
    match pos {
        None => true,
        Some(p) => p.increases_exposure(delta),
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

#[cfg(test)]
mod tests {
    use super::BatchOp;
    use crate::hash::Keccak256;
    use crate::note::Note;
    use crate::DefaultState;

    #[test]
    fn apply_batch_emits_only_real_l1_withdrawal_outputs() {
        use crate::fixed::QUOTE_SCALE;
        use crate::note::owner_from_spend_key;
        let spend_key = [3u8; 32];
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
        let amount = 4_000 * QUOTE_SCALE;
        let mut s = DefaultState::new(16);

        // real L1 withdrawal → one WithdrawalOut bound to the note
        let blind1 = [7u8; 32];
        let cm1 = Note::new(owner, 0, amount, blind1).commitment::<Keccak256>();
        // internal burn (to: None) → no WithdrawalOut, must not pollute the root
        let blind2 = [8u8; 32];
        let cm2 = Note::new(owner, 0, amount, blind2).commitment::<Keccak256>();

        let to = [0xAB; 20];
        let out = s
            .apply_batch(&[
                BatchOp::Deposit {
                    owner,
                    asset_id: 0,
                    amount,
                    blinding: blind1,
                    from: [0u8; 20],
                    deposit_id: 0,
                    deposit_blind: [0x71u8; 32],
                },
                BatchOp::Deposit {
                    owner,
                    asset_id: 0,
                    amount,
                    blinding: blind2,
                    from: [0u8; 20],
                    deposit_id: 1,
                    deposit_blind: [0x81u8; 32],
                },
                BatchOp::Withdraw {
                    note_commitment: cm1,
                    spend_key,
                    to: Some(to),
                    nonce: 42,
                },
                BatchOp::Withdraw {
                    note_commitment: cm2,
                    spend_key,
                    to: None,
                    nonce: 0,
                },
            ])
            .unwrap();
        assert_eq!(out.withdrawals.len(), 1, "internal burn (to:None) must not emit");
        assert_eq!(out.withdrawals[0].amount, amount); // bound to the real burned note
        assert_eq!(out.withdrawals[0].to, to);
        assert_eq!(out.withdrawals[0].nonce, 42);
    }

    #[test]
    fn deposit_binds_order_and_folds_chain() {
        use crate::error::EngineError;
        use crate::merkle::{deposit_chain_fold, deposit_leaf, owner_commit};
        // No `State::default()` exists (a State needs a tree depth); use the
        // canonical `DefaultState::new(16)` constructor as every other test does.
        let mut st = DefaultState::new(16);
        let owner = [9u8; 32];
        let from = [1u8; 20];
        let deposit_blind = [0x3Au8; 32];
        let op0 = BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount: 1000,
            blinding: [3u8; 32],
            from,
            deposit_id: 0,
            deposit_blind,
        };
        let out = st.apply_batch(&[op0]).expect("apply");
        assert_eq!(st.consumed_deposit_count, 1);
        assert_eq!(
            st.consumed_deposit_tip,
            deposit_chain_fold(
                &[0u8; 32],
                &deposit_leaf(&from, &owner_commit(&owner, &deposit_blind), 1000, 0)
            )
        );
        assert_eq!(st.external_in, 1000);
        assert_eq!(out.deposits.len(), 1);
        assert!(st.conservation_holds());
        // out-of-order id ⇒ error
        let bad = BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount: 5,
            blinding: [4u8; 32],
            from,
            deposit_id: 7,
            deposit_blind: [0x4Au8; 32],
        };
        assert!(matches!(
            st.apply_batch(&[bad]),
            Err(EngineError::DepositOutOfOrder)
        ));
    }

    /// SEC-019 privacy (spec §1a): what gets folded into the L1-bound hash-chain is
    /// the BLINDED binding `keccak(owner ‖ deposit_blind)`, never the raw shielded
    /// owner pubkey — publishing the raw owner as an L1 call arg + indexed event
    /// topic would permanently link the L1 payer to the internal note owner. The
    /// `assert_ne!` is the whole point: it proves the raw owner is no longer bound.
    #[test]
    fn deposit_folds_blinded_owner_commit_not_raw_owner() {
        use crate::merkle::{deposit_chain_fold, deposit_leaf, owner_commit};
        let mut st = DefaultState::new(16);
        let owner = [9u8; 32];
        // deliberately DIFFERENT from the note `blinding` below: the two serve
        // different purposes and a swap must be caught by this test.
        let deposit_blind = [5u8; 32];
        let from = [1u8; 20];
        let op = BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount: 1000,
            blinding: [3u8; 32],
            from,
            deposit_id: 0,
            deposit_blind,
        };
        st.apply_batch(&[op]).expect("apply");
        let commit = owner_commit(&owner, &deposit_blind);
        assert_eq!(
            st.consumed_deposit_tip,
            deposit_chain_fold(&[0u8; 32], &deposit_leaf(&from, &commit, 1000, 0)),
            "the chain must bind the blinded owner commit"
        );
        assert_ne!(
            st.consumed_deposit_tip,
            deposit_chain_fold(&[0u8; 32], &deposit_leaf(&from, &owner, 1000, 0)),
            "the RAW owner must not be what is bound (privacy: spec §1a)"
        );
    }

    // ZK-001 (Task 4): `AccrueFunding.mark` is a raw prover witness (the sequencer's
    // book mid) that is otherwise unconstrained — a prover could set it arbitrarily to
    // steer the funding rate. `op_accrue_funding` now bounds it to
    // `market.max_mark_deviation_ratio` around the SIGNED index price (the value
    // `validate()` returns AFTER the fail-closed publisher-signature gate). A valid
    // signature is required to even REACH the band check, and the band is measured
    // against the signed index — so a prover cannot widen it by inflating `mark`.
    #[test]
    fn accrue_funding_bounds_mark_against_signed_index() {
        use crate::error::EngineError;
        use crate::fixed::PRICE_SCALE;
        use crate::market::Market;
        use crate::oracle::{oracle_digest, OracleSig, OracleTranscript};
        use k256::ecdsa::SigningKey;

        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let now = 1_000_000u64;
        let index = 100_000 * PRICE_SCALE;
        // Sign over the exact tuple `validate()` re-derives, so the transcript clears the
        // ZK-001 signature gate (Task 3) and we genuinely reach the mark band.
        let d = oracle_digest(0, index, now, 10 * PRICE_SCALE, index);
        let signed = OracleTranscript {
            price: index,
            publish_time_ms: now,
            confidence: 10 * PRICE_SCALE, // 0.01% of $100k, well inside 1%
            backup_twap: index,
            signature: OracleSig::sign(&key, &d),
        };
        let mut m = Market::conservative(0); // max_mark_deviation_ratio = 5%
        m.oracle_pubkey = signed.signature.recover(&d).unwrap();

        let mut s = DefaultState::new(16);
        s.add_market(m);

        // in-band: mark = index * 101/100 (1% premium ⊂ the 5% band) ⇒ Ok.
        s.apply_op(&BatchOp::AccrueFunding {
            market_id: 0,
            mark: index * 101 / 100,
            oracle: signed,
            now_ms: now,
        })
        .expect("a mark within the band accrues");

        // out-of-band: mark = index * 2 (100% away ≫ 5%) ⇒ MarkOutOfBand. The band is
        // anchored to the SIGNED index, so a doubled mark cannot widen it.
        assert_eq!(
            s.apply_op(&BatchOp::AccrueFunding {
                market_id: 0,
                mark: index * 2,
                oracle: signed,
                now_ms: now,
            }),
            Err(EngineError::MarkOutOfBand),
        );
    }
}
