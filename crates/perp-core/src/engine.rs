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

use crate::error::{EngineError, FillLeg};
use crate::fixed::{abs, apply_rate, notional_quote, RATE_SCALE};
use crate::hash::{word_i128, word_u64, Digest, Domain, Hasher};
use crate::market::{Market, MarketId};
use crate::note::{owner_from_spend_key, Note, PubKey};
use crate::oracle::OracleTranscript;
use crate::order::Side;
use crate::position::{Position, RiskError};
use crate::state::{checked_sum, Mode, State};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// The largest amount by which one real L1 withdrawal may advance the withdrawal
/// nonce past [`State::last_withdrawal_nonce`]. A withdrawal to `Some(addr)` is
/// accepted only when `last < nonce <= last + MAX_WITHDRAWAL_NONCE_STEP`. Gaps are
/// allowed, so an off-chain counter that ran ahead of the engine still lines up;
/// the bound keeps a single withdrawal from using up the nonce space and locking
/// every later one out.
pub const MAX_WITHDRAWAL_NONCE_STEP: u64 = 1 << 32;

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
    ///
    /// Refused with `EngineError::CloseOnly` while the system is close-only, before
    /// anything is touched: no deposit is credited after the system has stopped
    /// trading, so a later deposit never shares in an earlier shortfall. Such a
    /// deposit stays unconsumed on L1, where the close-only refund path returns it.
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
    /// The market's open funding span is first committed up to `now_ms`
    /// ([`crate::funding::FundingState::settle_to`]), and every funding amount the
    /// fill computes uses that settled index. An accepted fill records the
    /// validated oracle price as the market's last price
    /// ([`crate::funding::FundingState::record_price`]).
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
    /// One funding tick: commit the market's open funding span up to `now_ms` at
    /// the stored rate, then store the clamped rate observed from `mark` against
    /// the validated oracle index price
    /// ([`crate::funding::FundingState::accrue`]). The stored rate prices the next
    /// span. A zero rate observed on a market whose stored rate is zero changes
    /// nothing.
    ///
    /// The tick records the validated index price as the market's last price
    /// ([`crate::funding::FundingState::record_price`]) when it changed the
    /// funding state, when the recorded price lies in an earlier price-refresh
    /// epoch ([`crate::funding::FundingState::price_refresh_due`]), or while the
    /// system is close-only. So a market that has recorded a price refreshes it at
    /// least once per epoch, and in close-only every tick keeps it current, while
    /// the ticks of a market that never recorded one stay root-neutral.
    AccrueFunding {
        market_id: MarketId,
        mark: i128,
        oracle: OracleTranscript,
        now_ms: u64,
    },
    /// Liquidate an underwater position at the validated oracle price (§5). A
    /// shortfall left by the close is covered by the insurance fund, then the
    /// treasury, then auto-deleverage of the market's winners (each bounded by
    /// [`Position::adl_clawable`]); anything still uncovered stays parked on the
    /// closed position and trips the system to close-only. Like `Fill`, it first
    /// commits the market's open funding span up to `now_ms`, and records the
    /// validated oracle price as the market's last price.
    Liquidate {
        owner: PubKey,
        market_id: MarketId,
        oracle: OracleTranscript,
        now_ms: u64,
    },
    /// Move free margin out of a position into a fresh note (must remain ≥
    /// initial margin if still open). Value-preserving. Like `Fill`, it first
    /// commits the market's open funding span up to `now_ms`, and records the
    /// validated oracle price as the market's last price.
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
    /// emits no withdrawal (it never becomes a vault claim).
    ///
    /// The nonce is bound to state. A real withdrawal's `nonce` must be strictly
    /// greater than [`State::last_withdrawal_nonce`], by at most
    /// [`MAX_WITHDRAWAL_NONCE_STEP`], and becomes the new last nonce; so every
    /// withdrawal leaf, across all batches and phases, carries a distinct nonce. An
    /// internal burn must carry `nonce = 0` and leaves the counter unchanged.
    Withdraw {
        note_commitment: Digest,
        spend_key: Digest,
        to: Option<[u8; 20]>,
        nonce: u64,
    },
    /// Forced-exit / circuit-breaker: switch the system to close-only (§6, §8).
    EnterCloseOnly,
    /// SEC-024: RETAINED AT ORDINAL 8 AND ALWAYS REJECTED. This op raised
    /// `insurance_fund` and `external_in` together with no note consumed and no L1
    /// binding — it fabricated the accounting representation of collateral that never
    /// entered the system, and the guest proved it. Kept rather than removed because
    /// `postcard` writes a variant's ordinal before its fields: replacing it in place
    /// would let legacy bytes decode as whatever took index 8 and consume the following
    /// bytes as its fields, a SILENT mis-parse. Retaining it means old bytes decode to
    /// their original meaning and are then refused deterministically. Fail loudly.
    DeprecatedSeedInsurance { amount: i128 },
    /// SEC-024: capitalize insurance by consuming a REAL note. `external_in` is NOT
    /// touched — that value entered the system through the L1-bound deposit path.
    FundInsurance {
        note_commitment: Digest,
        spend_key: Digest,
    },
    /// A06: one-shot, counterparty-free terminal settlement. In order:
    ///
    /// 1. Every open position is closed against the clearing pool at its market's
    ///    last recorded oracle price ([`crate::funding::FundingState::last_price`]),
    ///    or at its own entry price when the market never recorded one, after the
    ///    funding committed to the market's index is settled. The op carries no
    ///    time and no oracle, so a span still open since the market's last
    ///    settlement is not charged.
    /// 2. Every negative balance left (a position's collateral, the clearing
    ///    pool) is set to zero, and the sum is the deficit.
    /// 3. The deficit is covered, in order, by the clearing pool's positive
    ///    balance, the insurance fund and the treasury.
    /// 4. Any remainder is taken by one pro-rata haircut
    ///    ([`allocate_pro_rata`]) over all positive position collateral and
    ///    unspent notes; a haircut note is reissued at its reduced amount.
    /// 5. Whatever the three reserves still hold is paid out as one withdrawal
    ///    to [`State::wind_down_recipient`], carrying the next withdrawal nonce
    ///    (`last_withdrawal_nonce + 1`). With no recipient set (tests and demos)
    ///    the reserves stay in place.
    ///
    /// The system is then close-only, every remaining position is flat with
    /// positive collateral, and no value was created: the claims and reserves
    /// after the op plus the payout equal the claims and reserves before it. The
    /// op is atomic: when any step fails, nothing changes. L1 authorizes this only
    /// through `finalSettle`.
    SettleAll,
    /// A06 phase-2 price-free exit from a position already flattened by SettleAll.
    WindDownUnbind {
        owner: PubKey,
        market_id: MarketId,
        amount: i128,
        blinding: Digest,
    },
    /// A06 phase-2 withdrawal. Kept distinct from ordinary Withdraw so the proof
    /// commitment can derive the wind-down phase from the op grammar itself. It
    /// follows the same nonce rule as [`BatchOp::Withdraw`], against the same
    /// counter.
    WindDownWithdraw {
        note_commitment: Digest,
        spend_key: Digest,
        to: Option<[u8; 20]>,
        nonce: u64,
    },
}

/// One auto-deleverage haircut: `clawed` was taken from `owner`'s position
/// collateral to cover another position's liquidation bad debt (§6, §9; audit
/// Q2/Q7). It is never more than [`Position::adl_clawable`] for that position: its
/// gain net of funding, bounded so its collateral stays non-negative and its
/// equity stays at or above maintenance margin. The engine surfaces these from
/// [`State::liquidate`] so a socialized loss can be reported back to the affected
/// account as an attributable receipt instead of vanishing silently — the
/// transparency half of the bad-debt backstop. It carries no identifying salt
/// itself; the sequencer publishes it under a secret-keyed tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdlHaircut {
    pub owner: PubKey,
    pub clawed: i128,
}

/// One withdrawal this batch authorizes: value `amount` (bound to the burned note)
/// released to L1 address `to`, unique by `nonce` (nonces strictly increase across
/// every batch, see [`BatchOp::Withdraw`]). Its leaf enters the batch's
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
/// An op contributes at most one of each: a real `Withdraw { to: Some }` (or
/// `WindDownWithdraw { to: Some }`) and a `SettleAll` that pays out the reserves
/// yield a [`WithdrawalOut`]; a `Deposit` yields a [`DepositIn`]; every other op
/// yields neither. `apply_batch` drains these into the batch outputs (mirrors the two
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
        crate::merkle::WithdrawalLeaf {
            to: w.to,
            amount: w.amount.max(0) as u128,
            nonce: w.nonce,
        }
    }
}

#[cfg(test)]
std::thread_local! {
    /// Test-only hook: while set on the current thread, `store_position` stores an
    /// entry with zero size and zero collateral instead of removing it, so a unit
    /// test can show that the `apply_op` postcondition catches such a write.
    static KEEP_EMPTY_POSITIONS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

impl<H: Hasher> State<H> {
    /// Apply a whole batch, asserting conservation after each op. Stops at the
    /// first error (the prover reproduces the same stop point deterministically).
    pub fn apply_batch(&mut self, ops: &[BatchOp]) -> Result<BatchOutputs, EngineError> {
        crate::commitment::classify_wind_down_ops(ops)?;
        // Batch identity is committed into the state root. Reject exhaustion
        // before any operation can mint/burn value, in debug and release alike.
        let next_batch_id = self
            .next_batch_id
            .checked_add(1)
            .ok_or(EngineError::Overflow)?;
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
        self.next_batch_id = next_batch_id;
        Ok(outputs)
    }

    /// Apply a single operation, returning what it contributed to the batch outputs
    /// (an [`OpOutput`]). A real L1 `Withdraw` with `to = Some` and a `SettleAll`
    /// that pays out the reserves yield a withdrawal; a `Deposit` yields a deposit;
    /// every other op yields an empty [`OpOutput`]. The output-producing ops are
    /// special-cased here so their leaves reach `apply_batch`.
    ///
    /// Postcondition (checked in debug builds only, compiled out of release and the
    /// guest): the op stored no position entry with zero size and zero collateral.
    /// Such an entry already present in the pre-state and left untouched is allowed;
    /// it is root-bound and refusing it would make an anchored root unprovable.
    pub fn apply_op(&mut self, op: &BatchOp) -> Result<OpOutput, EngineError> {
        #[cfg(debug_assertions)]
        let empty_before = self.empty_position_keys();
        let out = self.dispatch_op(op);
        #[cfg(debug_assertions)]
        self.assert_no_new_empty_position(&empty_before, op);
        out
    }

    fn dispatch_op(&mut self, op: &BatchOp) -> Result<OpOutput, EngineError> {
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
            BatchOp::WindDownWithdraw {
                note_commitment,
                spend_key,
                to,
                nonce,
            } => self
                .op_wind_down_withdraw(note_commitment, spend_key, to, *nonce)
                .map(|w| OpOutput {
                    withdrawal: w,
                    deposit: None,
                }),
            BatchOp::SettleAll => self.op_settle_all().map(|w| OpOutput {
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
            // SEC-024: the retained ordinal-8 stub — refused deterministically, and
            // the `amount` is deliberately unused (binding it would imply meaning).
            BatchOp::DeprecatedSeedInsurance { .. } => Err(EngineError::DeprecatedOp),
            BatchOp::FundInsurance {
                note_commitment,
                spend_key,
            } => self.op_fund_insurance(note_commitment, spend_key),
            BatchOp::WindDownUnbind {
                owner,
                market_id,
                amount,
                blinding,
            } => self.op_wind_down_unbind(owner, *market_id, *amount, blinding),
            BatchOp::Deposit { .. } => {
                unreachable!("Deposit is handled by apply_op, never delegated here")
            }
            BatchOp::Withdraw { .. } => {
                unreachable!("Withdraw is handled by apply_op, never delegated here")
            }
            BatchOp::WindDownWithdraw { .. } => {
                unreachable!("WindDownWithdraw is handled by apply_op")
            }
            BatchOp::SettleAll => {
                unreachable!("SettleAll is handled by apply_op, never delegated here")
            }
        }
    }

    /// A06 terminal settlement ([`BatchOp::SettleAll`]; the steps are listed
    /// there). Every step is staged on copies of the positions, the notes and the
    /// balances; the commitment tree and the nullifier log are only read, never
    /// cloned. A reissued haircut note must be new to the tree and to the other
    /// notes this op reissues, the tree's free capacity is checked before any of
    /// them is staged, and they are appended only in the commit section. So a
    /// refusal (an overflow, a full tree, claims too small for the deficit, a
    /// failed postcondition) leaves the state byte-for-byte unchanged.
    fn op_settle_all(&mut self) -> Result<Option<WithdrawalOut>, EngineError> {
        let mut positions = self.positions.clone();
        let mut notes = self.notes.clone();
        let mut vault_pool = self.vault_pool;
        let mut insurance_fund = self.insurance_fund;
        let mut treasury = self.treasury;

        // 1. Close every open position against the clearing pool at its market's
        //    last recorded price, or at its own entry price when the market never
        //    recorded one, after settling the funding committed to the market's
        //    index. No span is accrued: the op carries no time.
        for ((_, market_id), pos) in positions.iter_mut() {
            if pos.size == 0 {
                continue;
            }
            let funding = self.funding.get(market_id).copied().unwrap_or_default();
            let price = if funding.last_price > 0 {
                funding.last_price
            } else {
                pos.entry_price
            };
            let close = pos.size.checked_neg().ok_or(EngineError::Overflow)?;
            let (realized, paid) = pos.apply_fill(close, price, funding.cumulative_index)?;
            vault_pool = vault_pool
                .checked_sub(realized)
                .and_then(|v| v.checked_add(paid))
                .ok_or(EngineError::Overflow)?;
        }

        // 2. Every negative balance is set to zero; together they are the deficit.
        let mut deficit = 0i128;
        for pos in positions.values_mut() {
            if pos.collateral < 0 {
                let debt = pos.collateral.checked_neg().ok_or(EngineError::Overflow)?;
                deficit = deficit.checked_add(debt).ok_or(EngineError::Overflow)?;
                pos.collateral = 0;
            }
        }
        if vault_pool < 0 {
            let debt = vault_pool.checked_neg().ok_or(EngineError::Overflow)?;
            deficit = deficit.checked_add(debt).ok_or(EngineError::Overflow)?;
            vault_pool = 0;
        }

        // 3. The reserves cover the deficit, in order: the clearing pool's positive
        //    balance, the insurance fund, the treasury.
        for reserve in [&mut vault_pool, &mut insurance_fund, &mut treasury] {
            let take = deficit.min((*reserve).max(0));
            *reserve = reserve.checked_sub(take).ok_or(EngineError::Overflow)?;
            deficit = deficit.checked_sub(take).ok_or(EngineError::Overflow)?;
        }

        // 4. One pro-rata haircut over the remaining claims takes the rest.
        let reissued = if deficit > 0 {
            self.stage_settlement_haircut(deficit, &mut positions, &mut notes)?
        } else {
            Vec::new()
        };

        // 5. What the reserves still hold is paid out to the wind-down recipient,
        //    as one withdrawal with the next nonce. With no recipient set it stays.
        let reserves = vault_pool
            .checked_add(insurance_fund)
            .and_then(|v| v.checked_add(treasury))
            .ok_or(EngineError::Overflow)?;
        let recipient = self.wind_down_recipient;
        let has_recipient = recipient != [0u8; 20];
        let mut external_out = self.external_out;
        let mut last_withdrawal_nonce = self.last_withdrawal_nonce;
        let mut payout = None;
        if reserves > 0 && has_recipient {
            let nonce = last_withdrawal_nonce
                .checked_add(1)
                .ok_or(EngineError::Overflow)?;
            external_out = external_out
                .checked_add(reserves)
                .ok_or(EngineError::Overflow)?;
            vault_pool = 0;
            insurance_fund = 0;
            treasury = 0;
            last_withdrawal_nonce = nonce;
            payout = Some(WithdrawalOut {
                to: recipient,
                amount: reserves,
                nonce,
            });
        }

        // 6. Drop the entries left with zero size and zero collateral.
        positions.retain(|_, p| !p.is_empty());

        // 7. Postconditions on the staged result: every position flat with
        //    positive collateral, no negative reserve, no reserve left when a
        //    recipient is set, and no value created — the value inside after the
        //    op plus the payout equals the value inside before it. With the
        //    pre-state conserving, and the payout added to `external_out` above,
        //    the post-state conserves too.
        let positions_ok = positions.values().all(|p| p.size == 0 && p.collateral > 0);
        let reserves_ok = vault_pool >= 0
            && insurance_fund >= 0
            && treasury >= 0
            && (!has_recipient || (vault_pool == 0 && insurance_fund == 0 && treasury == 0));
        let inside_after = checked_sum(notes.values().map(|n| n.amount))
            .zip(checked_sum(positions.values().map(|p| p.collateral)))
            .and_then(|(n, p)| checked_sum([n, p, insurance_fund, vault_pool, treasury]));
        let paid_out = payout.map_or(0, |w| w.amount);
        let no_value_created = self
            .internal_value()
            .zip(inside_after)
            .is_some_and(|(before, after)| after.checked_add(paid_out) == Some(before));
        if !(positions_ok && reserves_ok && no_value_created && self.conservation_holds()) {
            return Err(EngineError::WindDownInsolvent);
        }

        // commit — infallible from here down
        for cm in reissued {
            // capacity was checked and each commitment is new to the tree
            self.tree
                .append(cm)
                .expect("tree capacity is checked before the commit");
        }
        self.positions = positions;
        self.notes = notes;
        self.vault_pool = vault_pool;
        self.insurance_fund = insurance_fund;
        self.treasury = treasury;
        self.external_out = external_out;
        self.last_withdrawal_nonce = last_withdrawal_nonce;
        self.mode = Mode::CloseOnly;
        Ok(payout)
    }

    /// `SettleAll` step 4, staged: take `deficit` from the positive position
    /// collateral (in key order) and the positive unspent notes (in commitment
    /// order), pro rata ([`allocate_pro_rata`]). A note that keeps part of its
    /// value is replaced by a new note of the reduced amount with a derived
    /// blinding, unique against every commitment the tree holds and every other
    /// note reissued here. Returns the commitments to append, in order.
    ///
    /// `WindDownInsolvent` when the claims are smaller than the deficit,
    /// `Overflow` when the tree has no room for the reissued notes (checked before
    /// any is staged) or on an overflowing product, `DuplicateCommitment` when no
    /// fresh blinding is found.
    fn stage_settlement_haircut(
        &self,
        deficit: i128,
        positions: &mut BTreeMap<(PubKey, MarketId), Position>,
        notes: &mut BTreeMap<Digest, Note>,
    ) -> Result<Vec<Digest>, EngineError> {
        #[derive(Clone, Copy)]
        enum Claim {
            Pos((PubKey, MarketId)),
            Note(Digest),
        }
        let mut claims: Vec<Claim> = Vec::new();
        let mut weights: Vec<i128> = Vec::new();
        for (key, pos) in positions.iter() {
            if pos.collateral > 0 {
                claims.push(Claim::Pos(*key));
                weights.push(pos.collateral);
            }
        }
        for (cm, note) in notes.iter() {
            if note.amount > 0 {
                claims.push(Claim::Note(*cm));
                weights.push(note.amount);
            }
        }
        let total = checked_sum(weights.iter().copied()).ok_or(EngineError::Overflow)?;
        if total < deficit {
            return Err(EngineError::WindDownInsolvent);
        }
        // `0 < deficit <= total` and every weight is positive, so the shared
        // allocator can fail only on an overflowing product.
        let takes = allocate_pro_rata(deficit, &weights).ok_or(EngineError::Overflow)?;

        // A note that keeps part of its value is reissued once: check the tree has
        // room for all of them before staging any.
        let reissues = claims
            .iter()
            .zip(&weights)
            .zip(&takes)
            .filter(|((claim, weight), take)| {
                matches!(claim, Claim::Note(_)) && **take > 0 && **take < **weight
            })
            .count();
        let room = self.tree.capacity().saturating_sub(self.tree.len() as u128);
        if reissues as u128 > room {
            return Err(EngineError::Overflow);
        }

        let mut reissued: Vec<Digest> = Vec::with_capacity(reissues);
        let mut fresh: BTreeSet<Digest> = BTreeSet::new();
        for ((claim, amount), take) in claims.into_iter().zip(weights).zip(takes) {
            if take == 0 {
                continue;
            }
            match claim {
                Claim::Pos(key) => {
                    let pos = positions.get_mut(&key).expect("claim key");
                    pos.collateral = pos
                        .collateral
                        .checked_sub(take)
                        .ok_or(EngineError::Overflow)?;
                }
                Claim::Note(old_cm) => {
                    let old = notes.remove(&old_cm).expect("claim note");
                    let left = amount.checked_sub(take).ok_or(EngineError::Overflow)?;
                    if left > 0 {
                        let (cm, note) = (0u64..32)
                            .find_map(|nonce| {
                                let blind = H::hash_words(
                                    Domain::StateRoot,
                                    &[old_cm, word_i128(left), word_u64(0xA060_0000 + nonce)],
                                );
                                let note = Note::new(old.owner, old.asset_id, left, blind);
                                let cm = note.commitment::<H>();
                                (!self.tree.contains_leaf(&cm) && !fresh.contains(&cm))
                                    .then_some((cm, note))
                            })
                            .ok_or(EngineError::DuplicateCommitment)?;
                        fresh.insert(cm);
                        notes.insert(cm, note);
                        reissued.push(cm);
                    }
                }
            }
        }
        Ok(reissued)
    }

    fn op_wind_down_unbind(
        &mut self,
        owner: &PubKey,
        market_id: MarketId,
        amount: i128,
        blinding: &Digest,
    ) -> Result<(), EngineError> {
        if self.mode != Mode::CloseOnly {
            return Err(EngineError::CloseOnly);
        }
        if amount <= 0 {
            return Err(EngineError::NonPositiveAmount);
        }
        let key = (*owner, market_id);
        let mut pos = *self
            .positions
            .get(&key)
            .ok_or(EngineError::UnknownPosition)?;
        if pos.size != 0 || pos.collateral < amount {
            return Err(EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: None,
            });
        }
        pos.collateral = pos
            .collateral
            .checked_sub(amount)
            .ok_or(EngineError::Overflow)?;
        self.mint_note(Note::new(*owner, 0, amount, *blinding))?;
        self.store_position(key, pos);
        Ok(())
    }

    fn op_wind_down_withdraw(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
        to: &Option<[u8; 20]>,
        nonce: u64,
    ) -> Result<Option<WithdrawalOut>, EngineError> {
        if self.mode != Mode::CloseOnly {
            return Err(EngineError::CloseOnly);
        }
        self.op_withdraw(note_commitment, spend_key, to, nonce)
    }

    /// Liquidate `owner`'s position, returning the auto-deleverage haircuts the
    /// cascade applied (empty when none — the penalty alone, or the insurance fund
    /// and the treasury, covered it, or no winner had anything clawable). This is the SAME state transition as `BatchOp::Liquidate`
    /// (which discards the attribution); the sequencer calls this entry so it can
    /// report each socialized haircut back to the clawed account (audit Q2).
    pub fn liquidate(
        &mut self,
        owner: &PubKey,
        market_id: MarketId,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> Result<Vec<AdlHaircut>, EngineError> {
        #[cfg(debug_assertions)]
        let empty_before = self.empty_position_keys();
        let result = self.op_liquidate(owner, market_id, oracle, now_ms);
        #[cfg(debug_assertions)]
        self.assert_no_new_empty_position(&empty_before, &"liquidate");
        let haircuts = result?;
        debug_assert!(
            self.conservation_holds(),
            "conservation invariant broken by liquidate"
        );
        Ok(haircuts)
    }

    /// The only writer of `positions` (apart from `SettleAll`, which builds its
    /// result on a copy and drops the entries it empties before committing it).
    /// An entry with zero size and zero
    /// collateral is removed instead of stored: it carries nothing, its funding owed
    /// is zero, and a later fill re-seeds its entry price and funding index exactly
    /// as for a missing entry. Every other value is stored under `key`.
    fn store_position(&mut self, key: (PubKey, MarketId), pos: Position) {
        #[cfg(test)]
        if KEEP_EMPTY_POSITIONS.with(core::cell::Cell::get) {
            self.positions.insert(key, pos);
            return;
        }
        if pos.is_empty() {
            self.positions.remove(&key);
        } else {
            self.positions.insert(key, pos);
        }
    }

    /// Keys of the entries with zero size and zero collateral, in key order.
    #[cfg(debug_assertions)]
    fn empty_position_keys(&self) -> Vec<(PubKey, MarketId)> {
        self.positions
            .iter()
            .filter(|(_, p)| p.is_empty())
            .map(|(k, _)| *k)
            .collect()
    }

    /// Debug postcondition: every entry with zero size and zero collateral was
    /// already present before the op (`before` is sorted).
    #[cfg(debug_assertions)]
    fn assert_no_new_empty_position(
        &self,
        before: &[(PubKey, MarketId)],
        what: &dyn core::fmt::Debug,
    ) {
        for (key, pos) in &self.positions {
            assert!(
                !pos.is_empty() || before.binary_search(key).is_ok(),
                "a position entry with zero size and zero collateral was stored by {what:?}"
            );
        }
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
        // No deposit is credited once the system is close-only: a credited deposit
        // would join the haircut base of a later SettleAll and absorb a shortfall
        // that predates it. Refused before anything is touched; the deposit stays
        // unconsumed on L1.
        if self.mode == Mode::CloseOnly {
            return Err(EngineError::CloseOnly);
        }
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
        // Compute the fallible external_in update BEFORE any mutation (it used to
        // run after tree/notes had already changed, leaving a partial mutation on
        // overflow). Together with the all-or-nothing mint below, a rejected deposit
        // leaves the state byte-for-byte unchanged (SEC-026 failure atomicity).
        let external_in = self
            .external_in
            .checked_add(amount)
            .ok_or(EngineError::Overflow)?;
        // SEC-026: mint through the single shared primitive — historical commitment
        // uniqueness (every leaf ever appended), not just the live unspent map.
        self.mint_note(Note::new(*owner, asset_id, amount, *blinding))?;
        self.external_in = external_in;
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

    /// SEC-026: the ONE shared mint primitive — every note creation (`op_deposit`
    /// and `op_unbind` alike) funnels through here, so the two paths cannot drift
    /// apart again. Uniqueness is enforced against every commitment EVER appended
    /// to the tree (`MerkleTree::contains_leaf`, the historical root-bound list),
    /// not merely the live unspent map: nullifiers are retained forever, so
    /// re-minting a previously-SPENT tuple would credit value whose every later
    /// spend recomputes the same retained nullifier and is refused with
    /// `UnknownOrSpentNote` — accepted-but-frozen funds that `conservation_holds()`
    /// cannot see. All-or-nothing: on any error (duplicate, tree full) neither the
    /// tree, its index, nor the notes map has changed; callers must sequence their
    /// own fallible work BEFORE calling this (deposit) or commit copies after it
    /// (unbind) so the whole op stays atomic.
    fn mint_note(&mut self, note: Note) -> Result<(), EngineError> {
        let cm = note.commitment::<H>();
        if self.tree.contains_leaf(&cm) {
            return Err(EngineError::DuplicateCommitment);
        }
        self.tree.append(cm).map_err(|_| EngineError::Overflow)?;
        self.notes.insert(cm, note);
        Ok(())
    }

    /// SEC-024: the NON-MUTATING note-spend check — look the note up, check the spend
    /// authority and the nullifier, and return the note plus the nullifier the caller
    /// must insert to commit. Every spending op runs it, then its own fallible
    /// arithmetic, and only then inserts the nullifier and removes the note, so a
    /// refused spend never destroys the note.
    fn validate_note_spend(
        &self,
        note_commitment: &Digest,
        spend_key: &Digest,
        expected_owner: Option<&PubKey>,
    ) -> Result<(Note, Digest), EngineError> {
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
        Ok((note, nf))
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
        // Validate and compute BEFORE the first mutation, so a refused top-up leaves
        // the note spendable and the state byte-identical.
        let (note, nf) = self.validate_note_spend(note_commitment, spend_key, Some(owner))?;
        let key = (*owner, market_id);
        let mut pos = self
            .positions
            .get(&key)
            .copied()
            .unwrap_or_else(|| Position::empty(*owner, market_id));
        pos.collateral = pos
            .collateral
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;

        // commit — infallible from here. A top-up that exactly repays a flat
        // position's debt leaves it empty, and `store_position` removes it.
        let _ = self.nullifiers.insert(nf);
        self.notes.remove(note_commitment);
        self.store_position(key, pos);
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
        // SEC-022 §1 — bound the execution price to a symmetric band around the ATTESTED
        // mark: |price − mark| · RATE_SCALE <= max_fill_deviation_ratio · mark. Placed
        // after `validate` so no band check is reachable without a valid publisher
        // signature. Copied from `op_accrue_funding`'s mark band (ZK-001 Task 4), whose
        // properties were already reasoned through: division-free (both sides products);
        // the RHS multiplies the ATTESTED `mark`, never the untrusted `price`, so a prover
        // cannot widen its own band; every step `checked_*` with a catch-all reject, so
        // nothing wraps and nothing panics in-guest. `price > 0` is checked above and
        // `mark > 0` is guaranteed by `validate`.
        let fill_dev = match price.checked_sub(mark) {
            Some(d) => abs(d),
            None => return Err(EngineError::FillPriceOutOfBand),
        };
        match (
            fill_dev.checked_mul(RATE_SCALE),
            market.max_fill_deviation_ratio.checked_mul(mark),
        ) {
            (Some(lhs), Some(rhs)) if lhs <= rhs => {}
            _ => return Err(EngineError::FillPriceOutOfBand),
        }
        // Commit the open funding span up to this fill, on a copy, before any index
        // is read: every margin, PnL and funding_entry below uses the settled index,
        // so the span is charged to the positions that existed during it. The copy
        // is written back, with the validated price recorded, only in the commit
        // section.
        let mut settled = self.settled_funding(market_id, mark, now_ms)?;
        let funding_index = settled.cumulative_index;

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
            let leg = if i == 0 {
                FillLeg::Taker
            } else {
                FillLeg::Maker
            };
            if increasing {
                // SEC-024 (SEC-022 carry-in): name the failing leg. A leg-less Risk is
                // non-attributable, so the sequencer's dry run recorded BOTH order
                // hashes and accepted without rematching — burning the innocent
                // counterparty's already-consumed resting liquidity.
                pos.check_initial_margin(&market, mark, funding_index)
                    .map_err(|e| match e {
                        RiskError::Overflow => EngineError::Overflow,
                        source => EngineError::Risk {
                            source,
                            leg: Some(leg),
                        },
                    })?;
            }
            // SEC-022 §3 — the solvency postcondition, checked on the STAGED leg before
            // anything commits. Conditional by design:
            //   * a leg ending CLOSED must not carry negative collateral — nothing
            //     revisits a flat position (`engine.rs` liquidation and ADL, and the
            //     sequencer's maintenance pass, all require `is_open()`), so that debt is
            //     parked forever while the winner withdraws normally; and
            //   * a leg that stays OPEN must still be maintenance-compliant.
            // A flat `collateral >= 0` on BOTH cases would be a denial of service:
            // `apply_fill` settles the position's ENTIRE accrued funding while realizing
            // PnL only on the closed fragment, so small resting orders could make every
            // fragment of a solvent aggregate close fail while the victim stays
            // non-liquidatable. Requiring maintenance-compliance on a still-open leg
            // sidesteps that — the funding settled is the funding maintenance equity
            // already accounts for.
            if pos.is_open() {
                if pos
                    .check_maintenance_margin(&market, mark, funding_index)
                    .is_err()
                {
                    return Err(EngineError::FillWouldBankrupt(leg));
                }
            } else if pos.collateral < 0 {
                return Err(EngineError::FillWouldBankrupt(leg));
            }
            staged[i] = (key, pos);
        }
        // SEC-022 §4 — stage EVERY remaining fallible value BEFORE the first mutation.
        // This op used to commit `vault_pool` and both positions and only THEN run the
        // fallible `treasury` / `insurance_fund` additions, so a late overflow returned
        // `Err` with state already changed. The sequencer's rejection arm omits a failed
        // fill from the proven op-log (`sequencer/src/lib.rs:901-906`), so that divergence
        // is exactly what wedges the next proof. Nothing fallible may follow the commit.
        let new_vault_pool = self
            .vault_pool
            .checked_add(pool_delta)
            .ok_or(EngineError::Overflow)?;
        let new_treasury = self
            .treasury
            .checked_add(treasury_fee)
            .ok_or(EngineError::Overflow)?;
        // Conservation: taker −fee, maker +rebate, treasury +treasury_fee,
        // insurance +(fee − rebate − treasury_fee). `is_coherent` bounds the cut ≥ 0.
        let insurance_cut = taker_fee
            .checked_sub(maker_rebate)
            .ok_or(EngineError::Overflow)?
            .checked_sub(treasury_fee)
            .ok_or(EngineError::Overflow)?;
        let new_insurance_fund = self
            .insurance_fund
            .checked_add(insurance_cut)
            .ok_or(EngineError::Overflow)?;

        // commit — infallible from here down
        settled.record_price(mark, oracle.publish_time_ms);
        self.funding.insert(market_id, settled);
        self.vault_pool = new_vault_pool;
        self.treasury = new_treasury;
        self.insurance_fund = new_insurance_fund;
        for (key, pos) in staged {
            self.store_position(key, pos);
        }
        Ok(())
    }

    /// A copy of `market_id`'s funding state with its open span committed up to
    /// `now_ms` at the validated `index_price`. Callers read the index from the
    /// copy and store it back in their commit section, so a refused op changes
    /// nothing. A market without a funding state is refused, as `AccrueFunding`
    /// refuses it.
    fn settled_funding(
        &self,
        market_id: MarketId,
        index_price: i128,
        now_ms: u64,
    ) -> Result<crate::funding::FundingState, EngineError> {
        let mut funding = *self
            .funding
            .get(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        funding.settle_to(index_price, now_ms);
        Ok(funding)
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
        let close_only = self.mode == Mode::CloseOnly;
        let publish_ms = oracle.publish_time_ms;
        let f = self
            .funding
            .get_mut(&market_id)
            .ok_or(EngineError::UnknownMarket)?;
        // Whether the recorded price is from an earlier refresh epoch, judged
        // against the price recorded before this tick.
        let refresh_due = f.price_refresh_due(publish_ms);
        // commit — infallible: the span is charged at the stored rate, then the rate
        // observed now is stored for the next span
        let changed = f.accrue(mark, index_price, now_ms);
        // A tick that changed nothing on a market whose price is current (or that
        // never recorded one) stays root-neutral, except in close-only, where every
        // tick keeps the settlement price current.
        if changed || refresh_due || close_only {
            f.record_price(index_price, publish_ms);
        }
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
        // Liquidation and auto-deleverage both read the index settled up to now,
        // staged like every other value and written back, with the validated price
        // recorded, in the commit section.
        let mut settled = self.settled_funding(market_id, price, now_ms)?;
        let funding_index = settled.cumulative_index;
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
        // SEC-024 (SEC-022 §4, carried into op_liquidate): stage EVERY fallible value
        // on a COPY before the first mutation. This op used to close the position via
        // `apply_fill` and only THEN run the fallible vault-pool / insurance-fund
        // arithmetic, so a late overflow returned `Err` with the position already
        // closed — and `run_maintenance` logs an op only on success, so the live root
        // reflected a close the replayable op-log did not contain, wedging the next
        // proof. Close the whole position at oracle price, staged:
        let mut staged = *pos;
        let close_delta = -staged.size;
        let (realized, funding) = staged.apply_fill(close_delta, price, funding_index)?;
        let new_vault_pool = self
            .vault_pool
            .checked_sub(realized)
            .ok_or(EngineError::Overflow)?
            .checked_add(funding)
            .ok_or(EngineError::Overflow)?;
        // Take the liquidation penalty from any remaining (positive) collateral
        // into the insurance fund. Bad debt (a close that left collateral < 0) is
        // then handled by the waterfall below. `take ∈ [0, max(collateral, 0)]`, so
        // the sub cannot actually fail — checked anyway (crate rule: every
        // arithmetic step is `checked_*`), and still before the first mutation.
        let take = penalty.min(staged.collateral.max(0));
        staged.collateral = staged
            .collateral
            .checked_sub(take)
            .ok_or(EngineError::Overflow)?;
        let mut new_insurance_fund = self
            .insurance_fund
            .checked_add(take)
            .ok_or(EngineError::Overflow)?;

        // Bad-debt waterfall (§6, §9), staged like the close: a close that left the
        // position underwater (a gap past the maintenance buffer) is covered, in
        // order, by
        //   1. the insurance fund,
        //   2. the treasury,
        //   3. auto-deleverage of the winners in this market (see
        //      `auto_deleverage_plan`),
        // and whatever is still uncovered stays parked on the closed position while
        // the system trips to close-only (the depletion halt). Every step only moves
        // value between balances inside the conservation identity, and each draw is
        // bounded by the shortfall that remains, so the steps cannot overflow; they
        // are checked anyway and run before the first mutation.
        let mut loser = staged;
        let mut new_treasury = self.treasury;
        let mut winners: Vec<(AdlHaircut, Position)> = Vec::new();
        if loser.collateral < 0 {
            let bad_debt = loser
                .collateral
                .checked_neg()
                .ok_or(EngineError::Overflow)?;
            let from_insurance = bad_debt.min(new_insurance_fund.max(0));
            let after_insurance = bad_debt
                .checked_sub(from_insurance)
                .ok_or(EngineError::Overflow)?;
            let from_treasury = after_insurance.min(new_treasury.max(0));
            let residual = after_insurance
                .checked_sub(from_treasury)
                .ok_or(EngineError::Overflow)?;
            if residual > 0 {
                // Any overflow while planning leaves no haircuts: the residual stays
                // parked and the system trips to close-only (fail closed).
                winners = self
                    .auto_deleverage_plan(&market, market_id, owner, residual, price, funding_index)
                    .unwrap_or_default();
            }
            let mut recovered = 0i128;
            for (haircut, _) in &winners {
                recovered = recovered
                    .checked_add(haircut.clawed)
                    .ok_or(EngineError::Overflow)?;
            }
            debug_assert!(recovered <= residual, "ADL took more than the residual");
            new_insurance_fund = new_insurance_fund
                .checked_sub(from_insurance)
                .ok_or(EngineError::Overflow)?;
            new_treasury = new_treasury
                .checked_sub(from_treasury)
                .ok_or(EngineError::Overflow)?;
            loser.collateral = loser
                .collateral
                .checked_add(from_insurance)
                .and_then(|c| c.checked_add(from_treasury))
                .and_then(|c| c.checked_add(recovered))
                .ok_or(EngineError::Overflow)?;
        }

        // commit — infallible from here down. `store_position` removes the closed
        // entry when it ends with zero collateral.
        settled.record_price(price, oracle.publish_time_ms);
        self.funding.insert(market_id, settled);
        self.store_position(key, loser);
        let mut haircuts = Vec::with_capacity(winners.len());
        for (haircut, winner) in winners {
            self.store_position((haircut.owner, market_id), winner);
            haircuts.push(haircut);
        }
        self.vault_pool = new_vault_pool;
        self.insurance_fund = new_insurance_fund;
        self.treasury = new_treasury;
        if loser.collateral < 0 {
            // Insurance, the treasury and the winners' clawable amounts did not
            // cover the shortfall: the rest stays parked on the closed position
            // (conservation-safe) and the system trips to close-only.
            self.mode = Mode::CloseOnly;
        }
        Ok(haircuts)
    }

    /// Auto-deleverage plan (§6, §9): how much of `residual` each winner in
    /// `market_id` covers, together with that winner's position after its haircut.
    /// Nothing is mutated; the caller commits the plan.
    ///
    /// Every open position in the market other than `exclude`'s is weighted by
    /// [`Position::adl_clawable`] at `price` and `funding_index`, and the covered
    /// amount `min(residual, Σ clawable)` is split by [`allocate_pro_rata`]. So
    /// each winner gives at most its gain net of funding, its collateral stays at
    /// or above zero, and its equity stays at or above its maintenance margin: ADL
    /// never creates new bad debt and never makes a position liquidatable, and
    /// the haircuts sum to at most `residual`. Iteration is in key order, so the
    /// plan is deterministic.
    ///
    /// `None` on any overflow, including in one winner's clawable amount; the
    /// caller then applies no haircut at all.
    ///
    /// This takes collateral rather than reducing position size, so a clawed
    /// winner keeps its full exposure on a thinner margin above maintenance. The
    /// burden is computed per liquidation, so across several bad-debt liquidations
    /// in one batch the split follows op order.
    fn auto_deleverage_plan(
        &self,
        market: &Market,
        market_id: MarketId,
        exclude: &PubKey,
        residual: i128,
        price: i128,
        funding_index: i128,
    ) -> Option<Vec<(AdlHaircut, Position)>> {
        let mut candidates: Vec<(PubKey, Position)> = Vec::new();
        let mut weights: Vec<i128> = Vec::new();
        let mut total = 0i128;
        for ((owner, mid), pos) in self.positions.iter() {
            if *mid != market_id || owner == exclude || !pos.is_open() {
                continue;
            }
            let clawable = pos.adl_clawable(market, price, funding_index)?;
            if clawable > 0 {
                total = total.checked_add(clawable)?;
                candidates.push((*owner, *pos));
                weights.push(clawable);
            }
        }
        let covered = residual.max(0).min(total);
        let takes = allocate_pro_rata(covered, &weights)?;
        let mut plan = Vec::new();
        for (((owner, mut pos), weight), take) in candidates.into_iter().zip(weights).zip(takes) {
            debug_assert!(take <= weight, "a haircut exceeded its clawable amount");
            if take <= 0 {
                continue;
            }
            pos.collateral = pos.collateral.checked_sub(take)?;
            plan.push((
                AdlHaircut {
                    owner,
                    clawed: take,
                },
                pos,
            ));
        }
        Some(plan)
    }

    /// SEC-024: capitalize the insurance fund by consuming a REAL note (§6, §9) —
    /// a TRANSFER inside the shielded pool, never a mint. `external_in` is not
    /// touched: the note's value already entered through the L1-bound deposit path.
    /// No destination-owner constraint (`expected_owner = None`), matching
    /// `op_withdraw`: adding value to a communal backstop can only help the
    /// protocol, and the spend key still prevents donating someone else's note.
    fn op_fund_insurance(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
    ) -> Result<(), EngineError> {
        // SEC-024 — validate and precompute BEFORE the first mutation. Inserting the
        // nullifier and removing the note first would let a fallible `checked_add`
        // return Err with the note already destroyed; the sequencer logs an op only
        // on success, so live state would diverge from the proven op-log and wedge
        // the next proof.
        let (note, nf) = self.validate_note_spend(note_commitment, spend_key, None)?;
        // Without this, the op becomes wrong the moment non-canonical note assets
        // become meaningful. Checked BEFORE any mutation, so a wrong asset leaves
        // state byte-identical.
        if note.asset_id != 0 {
            return Err(EngineError::WrongAsset);
        }
        let new_insurance = self
            .insurance_fund
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;

        // commit — infallible from here
        let _ = self.nullifiers.insert(nf);
        self.notes.remove(note_commitment);
        self.insurance_fund = new_insurance;
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
        // The margin check reads the index settled up to now (staged; written back
        // with the position, together with the validated price).
        let mut settled = self.settled_funding(market_id, mark, now_ms)?;
        let funding_index = settled.cumulative_index;
        let key = (*owner, market_id);
        let mut pos = *self
            .positions
            .get(&key)
            .ok_or(EngineError::UnknownPosition)?;
        if pos.collateral < amount {
            // Not a fill: no leg to name (SEC-024 / SEC-022 carry-in).
            return Err(EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: None,
            });
        }
        pos.collateral -= amount;
        // if still open, must remain ≥ initial margin after the withdrawal.
        if pos.is_open() {
            pos.check_initial_margin(&market, mark, funding_index)?;
        }
        // all checks passed. Do the fallible mint FIRST (SEC-026 shared primitive:
        // historical-uniqueness gate + append, which can fail on a duplicate or a
        // full tree); only then commit the position, so the op stays atomic and
        // value-preserving.
        self.mint_note(Note::new(*owner, 0, amount, *blinding))?;
        settled.record_price(mark, oracle.publish_time_ms);
        self.funding.insert(market_id, settled);
        self.store_position(key, pos);
        Ok(())
    }

    fn op_withdraw(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
        to: &Option<[u8; 20]>,
        nonce: u64,
    ) -> Result<Option<WithdrawalOut>, EngineError> {
        // Validate and precompute BEFORE the first mutation, so a refused withdrawal
        // leaves the state byte-identical and the note still spendable.
        let (note, nf) = self.validate_note_spend(note_commitment, spend_key, None)?;
        match to {
            // A real L1 withdrawal: the nonce must advance the stored counter, by at
            // most MAX_WITHDRAWAL_NONCE_STEP. `nonce - last` cannot underflow once
            // `nonce > last` holds.
            Some(_) => {
                let last = self.last_withdrawal_nonce;
                if nonce <= last || nonce - last > MAX_WITHDRAWAL_NONCE_STEP {
                    return Err(EngineError::WithdrawalNonceNotIncreasing);
                }
            }
            // An internal burn emits no leaf and carries no nonce.
            None => {
                if nonce != 0 {
                    return Err(EngineError::InternalBurnNonceNotZero);
                }
            }
        }
        let new_out = self
            .external_out
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;

        // commit — infallible from here
        let _ = self.nullifiers.insert(nf);
        self.notes.remove(note_commitment);
        self.external_out = new_out;
        // Only a real L1 withdrawal (`to = Some`) produces a withdrawals_root leaf
        // and advances the counter; an internal burn (`to = None`) burns value
        // without an L1 exit.
        Ok(to.map(|addr| {
            self.last_withdrawal_nonce = nonce;
            WithdrawalOut {
                to: addr,
                amount: note.amount,
                nonce,
            }
        }))
    }
}

/// Split `need` across `weights` in proportion to each weight, exactly.
///
/// Each share is first the floor of `need · w_i / Σw`; the rounding remainder is
/// then handed out in slice order, each share capped at its own weight. The result
/// has one entry per weight, with `0 ≤ take_i ≤ w_i` and `Σ take_i == need`.
///
/// `None` unless every weight is non-negative and `0 ≤ need ≤ Σw`, and on any
/// arithmetic overflow. Auto-deleverage and `SettleAll` both allocate through this
/// one function, so a deficit is shared by the same rule wherever it arises.
pub fn allocate_pro_rata(need: i128, weights: &[i128]) -> Option<Vec<i128>> {
    let mut total = 0i128;
    for &w in weights {
        if w < 0 {
            return None;
        }
        total = total.checked_add(w)?;
    }
    if need < 0 || need > total {
        return None;
    }
    let mut takes = Vec::with_capacity(weights.len());
    let mut used = 0i128;
    for &w in weights {
        // `total == 0` implies `need == 0`, so every share is zero.
        let take = if total == 0 {
            0
        } else {
            need.checked_mul(w)? / total
        };
        used = used.checked_add(take)?;
        takes.push(take);
    }
    let mut left = need.checked_sub(used)?;
    for (take, &w) in takes.iter_mut().zip(weights) {
        if left == 0 {
            break;
        }
        let add = left.min(w.checked_sub(*take)?);
        *take = take.checked_add(add)?;
        left = left.checked_sub(add)?;
    }
    // Σ(w_i − floor_i) = Σw − used ≥ need − used, so the loop always hands out the
    // whole remainder; this guard only keeps the result exact by construction.
    if left != 0 {
        return None;
    }
    Some(takes)
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
        assert_eq!(
            out.withdrawals.len(),
            1,
            "internal burn (to:None) must not emit"
        );
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

    /// A flat position carrying `-debt` of collateral, plus an unspent note of
    /// `debt` owned by the same key: funding the note into the position repays the
    /// debt exactly. Conservation holds (both sides net to zero).
    fn flat_debt_with_matching_note(debt: i128) -> (DefaultState, [u8; 32], [u8; 32]) {
        use crate::market::Market;
        use crate::note::owner_from_spend_key;
        use crate::position::Position;
        let spend_key = [0x5Au8; 32];
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        let mut p = Position::empty(owner, 0);
        p.collateral = -debt;
        s.positions.insert((owner, 0), p);
        let note = Note::new(owner, 0, debt, [0x5Bu8; 32]);
        let cm = note.commitment::<Keccak256>();
        s.tree.append(cm).unwrap();
        s.notes.insert(cm, note);
        assert!(s.conservation_holds());
        (s, owner, cm)
    }

    fn repay(owner: [u8; 32], cm: [u8; 32]) -> BatchOp {
        BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: cm,
            spend_key: [0x5Au8; 32],
        }
    }

    /// Resets the test-only hook even when the test panics.
    struct KeepEmptyPositions;
    impl KeepEmptyPositions {
        fn set() -> Self {
            super::KEEP_EMPTY_POSITIONS.with(|k| k.set(true));
            KeepEmptyPositions
        }
    }
    impl Drop for KeepEmptyPositions {
        fn drop(&mut self) {
            super::KEEP_EMPTY_POSITIONS.with(|k| k.set(false));
        }
    }

    #[test]
    fn repaying_a_flat_positions_debt_removes_the_entry() {
        let (mut s, owner, cm) = flat_debt_with_matching_note(7_000_000);
        s.apply_op(&repay(owner, cm)).expect("repay");
        assert!(s.position(&owner, 0).is_none());
        assert!(s.positions.is_empty());
        assert!(s.notes.is_empty());
        assert!(s.conservation_holds());
    }

    /// The postcondition catches an op that stores an entry with zero size and zero
    /// collateral. The test-only hook disables the removal in `store_position`.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "zero size and zero collateral was stored")]
    fn apply_op_postcondition_catches_a_stored_empty_entry() {
        let (mut s, owner, cm) = flat_debt_with_matching_note(7_000_000);
        let _hook = KeepEmptyPositions::set();
        let _ = s.apply_op(&repay(owner, cm));
    }

    /// An entry with zero size and zero collateral that the pre-state already holds
    /// is not the op's write, so the postcondition accepts every op that leaves it
    /// untouched (an anchored pre-state is never refused for it).
    #[test]
    fn apply_op_accepts_a_pre_existing_empty_entry_it_does_not_touch() {
        use crate::position::Position;
        let (mut s, owner, cm) = flat_debt_with_matching_note(7_000_000);
        let other = crate::hash::word_u64(77);
        s.positions.insert((other, 0), Position::empty(other, 0));
        s.apply_op(&repay(owner, cm)).expect("repay");
        s.apply_op(&BatchOp::EnterCloseOnly).expect("mode op");
        assert_eq!(s.positions.len(), 1);
        assert!(s.position(&other, 0).unwrap().is_empty());
    }

    /// A refused top-up leaves the note spendable and the state byte-identical.
    #[test]
    fn a_refused_top_up_changes_nothing() {
        use crate::error::EngineError;
        let (mut s, owner, cm) = flat_debt_with_matching_note(7_000_000);
        // collateral at the i128 ceiling: adding the note overflows
        s.positions.get_mut(&(owner, 0)).unwrap().collateral = i128::MAX;
        let before = s.state_root();
        assert_eq!(s.apply_op(&repay(owner, cm)), Err(EngineError::Overflow));
        assert_eq!(s.state_root(), before);
        assert!(s.notes.contains_key(&cm));
    }
}
