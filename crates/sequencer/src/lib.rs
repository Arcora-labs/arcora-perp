//! # sequencer — the native settlement spine (§2, §3)
//!
//! This is the host-side component that ties the protocol together on the hot
//! path: it accepts orders, runs the [`matcher`], issues **secp256k1-signed
//! receipts** (the §2 inclusion proof a user keeps, L1-verifiable via `ecrecover`),
//! settles the resulting fills
//! through [`perp_core`]'s engine, publishes a **batch manifest**, and tracks the
//! three-layer finality (`ACCEPTED → MATCHED → SETTLED`, §3).
//!
//! It also implements **inclusion accountability** (§2): every issued receipt is
//! tracked until its order hash appears in a sealed manifest; receipts that go
//! unseen past the inclusion timeout are surfaced as violations that, on L1,
//! trigger slashing / forced-exit.
//!
//! Unlike `perp-core` and `matcher`, the sequencer is a *native* component (it
//! holds enclave keys and real signatures), so it is plain `std`. The pieces it
//! drives — the matcher and the settlement engine — remain zkVM-reproducible.

mod cancellation;

use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest as _, Keccak256 as RawKeccak};

use matcher::{ImpactWindow, Match, MatchingEngine, OrderRemoval, RestingQuote, SubmitStatus};
use perp_core::engine::BatchOp;
use perp_core::fixed::{notional_quote, QUOTE_SCALE, RATE_SCALE};
use perp_core::funding::MAX_FUNDING_RATE_PER_INTERVAL;
use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use perp_core::market::{Market, MarketId};
use perp_core::note::PubKey;
use perp_core::oracle::OracleTranscript;
use perp_core::order::{BatchManifest, Finality, Order, Receipt, RejectReason, Side};
use perp_core::position::Position;
use perp_core::{DefaultState, EngineError, FillLeg, Mode};

/// Compute the Ethereum-style 20-byte address of a secp256k1 verifying key:
/// `keccak256(uncompressed_pubkey[1..])[12..]` — exactly what L1 `ecrecover`
/// yields, so a receipt verifies identically off-chain and on-chain.
fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false); // 0x04 || X || Y (65 bytes)
    let hash = RawKeccak::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// The enclave's signing identity: a **secp256k1** key (so receipts are
/// L1-verifiable, §2) plus the attested measurement and key epoch the manifest
/// commits to. In production the key lives only inside the enclave; here it is a
/// normal key for the local/testnet build.
pub struct EnclaveIdentity {
    signing: SigningKey,
    pub epoch: u64,
    pub measurement: Digest,
    address: [u8; 20],
}

impl EnclaveIdentity {
    /// Derive a deterministic identity from a 32-byte secp256k1 scalar seed.
    pub fn from_seed(seed: [u8; 32], epoch: u64, measurement: Digest) -> Self {
        let signing = SigningKey::from_bytes((&seed).into()).expect("valid secp256k1 scalar");
        let address = eth_address(signing.verifying_key());
        Self {
            signing,
            epoch,
            measurement,
            address,
        }
    }

    /// The enclave's L1 address — deploy `DarkPerpSettlement(enclaveSigner = ...)`
    /// with this so on-chain inclusion challenges recover to it.
    pub fn eth_address(&self) -> [u8; 20] {
        self.address
    }

    /// Sign a 32-byte prehash with the enclave's **secp256k1** identity, returning
    /// a recoverable `(r, s, v)` with `v` in Ethereum convention (27/28). This is
    /// the SAME key and recovery scheme used for receipts (§2, [`Sequencer::issue_receipt`]),
    /// reused so any off-chain artifact signed here (e.g. the published order-ingress
    /// epoch key) recovers to the enclave's attested L1 signer — no separate key.
    pub fn sign_prehash(&self, digest: &[u8; 32]) -> ([u8; 32], [u8; 32], u8) {
        let (signature, recid) = self.signing.sign_prehash_recoverable(digest).expect("sign");
        let sig_bytes = signature.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);
        (r, s, 27 + recid.to_byte())
    }

    /// A stable secret salt bound to this enclave key, for keying off-chain privacy
    /// artifacts (e.g. the fail-closed liquidation-tag fallback) that must be
    /// unpredictable to a public-key-only observer. The raw scalar never leaves this
    /// method — only its domain-separated hash is returned.
    pub fn secret_salt(&self, domain: Domain) -> Digest {
        let sk: [u8; 32] = self.signing.to_bytes().into();
        Keccak256::hash_words(domain, &[sk])
    }
}

/// A receipt with the enclave's recoverable secp256k1 signature (§2). The `(r, s,
/// v)` triple is exactly what L1 `ecrecover` consumes, so the same receipt that
/// proves ACCEPTED off-chain also drives on-chain slashing.
#[derive(Clone, Debug)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// Recovery id in Ethereum convention (27 or 28).
    pub v: u8,
    pub enclave_address: [u8; 20],
}

impl SignedReceipt {
    /// Recover the signer address from the receipt and check it matches.
    pub fn verify(&self) -> bool {
        let digest = self.receipt.signing_digest::<Keccak256>();
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&self.r);
        rs[32..].copy_from_slice(&self.s);
        let Ok(sig) = Signature::from_slice(&rs) else {
            return false;
        };
        let Some(recid) = self.v.checked_sub(27).and_then(RecoveryId::from_byte) else {
            return false;
        };
        match VerifyingKey::recover_from_prehash(&digest, &sig, recid) {
            Ok(vk) => eth_address(&vk) == self.enclave_address,
            Err(_) => false,
        }
    }
}

/// Inclusion-tracking record for one issued receipt (§2).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
struct InclusionRecord {
    /// The authoritative sequencer-assigned receipt sequence number. Owned by the
    /// sequencer (not the matcher) so an order has exactly ONE seq across an
    /// out-of-band `accept_order` and a later `seal_batch`.
    seq_no: u64,
    issued_batch: u64,
    seen_in_batch: Option<u64>,
}

/// The output of sealing one batch.
#[derive(Clone, Debug)]
pub struct SealedBatch {
    /// Native execution attribution. The amounts/prices correspond one-for-one
    /// to successful Fill ops, but the order-hash association is NOT ZK-proven.
    pub applied_fills: Vec<Match>,
    pub removals: Vec<OrderRemoval>,
    pub batch_id: u64,
    pub prev_state_root: Digest,
    pub new_state_root: Digest,
    pub manifest: BatchManifest,
    pub manifest_hash: Digest,
    /// Order hashes whose matched fills settled into state (MATCHED).
    pub settled_order_hashes: Vec<Digest>,
    /// Fills that matched but failed settlement (e.g. margin) — reported, not applied.
    pub settlement_rejected: Vec<(Digest, RejectReason)>,
    pub receipts: Vec<SignedReceipt>,
    /// Per-liquidation **tags** for this batch's maintenance pass (§5, §7). Each is
    /// `liquidation_tag(secret_tag_key, market, batch)`, keyed on a per-account
    /// SECRET (derived from the account's spend key): the liquidated account
    /// recomputes its own tag to detect it was liquidated, but an observer — even
    /// one who knows the public owner id — cannot link a tag to an account without
    /// the spend key. (The on-chain manifest already excludes liquidations.)
    /// Residual: the tag COUNT per batch is still observable.
    pub liquidation_tags: Vec<Digest>,
    /// Per-haircut **auto-deleverage receipts** for this batch (§6, §9; audit Q2).
    /// When a liquidation's bad debt is socialized onto the winning side, each
    /// clawed account gets a receipt: a secret-keyed [`adl_tag`] only that account
    /// can recognize, paired with the amount clawed. This is the transparency
    /// surface — a socialized loss is recorded and self-detectable, not silent —
    /// while staying unlinkable to an observer who knows only the public owner id.
    pub adl_receipts: Vec<AdlReceipt>,
    /// The batch's replayable op-log: `[applied fills] ++ [maintenance AccrueFunding/
    /// Liquidate]`, in application order. Replaying it against the batch's pre-state
    /// (the retained snapshot) via `apply_batch` reproduces `new_state_root` — the
    /// witness a real ZK proof attests (Slice 3a).
    pub ops: Vec<BatchOp>,
}

/// The replayable witness for one settle window: `derive_roots(pre_state, ops, manifest)
/// .new_state_root` equals the live state root after this `seal_window`. This is the tuple
/// Slice 3b-2 seals and POSTs to the prover-service. Serde: the gateway also persists it
/// (sealed) in its crash-recovery rollback journal, so a restart mid-settle can replay the
/// exact in-flight window instead of wedging on a counter/root desync.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowWitness {
    pub batch_id: u64,
    pub pre_state: DefaultState,
    pub ops: Vec<BatchOp>,
    pub manifest: BatchManifest,
}

/// What a void ([`Sequencer::void_window`], [`Sequencer::void_open_window`])
/// discarded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VoidedWindow {
    /// Every order hash the discarded windows ordered, rejected or filled, first
    /// occurrence first: the sealed window's ordered then rejected hashes, the
    /// open window's, then the hashes each discarded tick filled (makers resting
    /// from earlier windows included). Each one is off the book; the caller
    /// publishes them as rejected in a later manifest.
    pub hashes: Vec<Digest>,
    /// The per-tick batch ids (Counter A) whose fills were discarded. None of
    /// them is pending any more, and no window settle hardens them.
    pub ticks: BTreeSet<u64>,
}

/// Why [`Sequencer::void_window`] refused a witness. Nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoidError {
    /// Counter B is not `batch_id + 1`, or the witness's pre-state does not open
    /// `batch_id`: the witness is not the sealed, unsettled window.
    NotTheSealedWindow { counter_b: u64, batch_id: u64 },
    /// This tick is still pending a settle but belongs to a window below the
    /// witness's: a settled window's tick that was never hardened. A void never
    /// discards it.
    UnhardenedEarlierTick(u64),
}

impl core::fmt::Display for VoidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotTheSealedWindow {
                counter_b,
                batch_id,
            } => write!(
                f,
                "window {batch_id} is not the sealed, unsettled window (window counter {counter_b})"
            ),
            Self::UnhardenedEarlierTick(tick) => write!(
                f,
                "tick {tick} of an earlier window is still pending; it is never voided"
            ),
        }
    }
}

impl std::error::Error for VoidError {}

/// A published auto-deleverage haircut: the affected account recognizes `tag` by
/// recomputing `adl_tag(&adl_tag_key(spend_key), market, batch)`, and reads how
/// much of its profit was clawed from `clawed` (quote-scaled). Unlinkable to any
/// other observer (audit Q2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdlReceipt {
    pub tag: Digest,
    pub clawed: i128,
}

/// The liquidated owners and ADL haircuts produced by one [`Sequencer::run_maintenance`]
/// pass. The haircuts carry `(owner, market, clawed)` so the seal can tag them.
pub struct MaintenanceOutcome {
    pub removals: Vec<OrderRemoval>,
    pub liquidated: Vec<(PubKey, MarketId)>,
    pub adl: Vec<(PubKey, MarketId, i128)>,
    /// The AccrueFunding + Liquidate ops applied this pass, in application order —
    /// the maintenance half of the batch's replayable op-log (Slice 3a).
    pub ops: Vec<BatchOp>,
}

/// The per-account SECRET liquidation-tag key, derived from the account's spend
/// key. Only the account (which holds its spend key) and the enclave (which sees
/// it at fund time) can compute it — a holder of the merely-public owner id
/// cannot. This is the secret salt that makes the tag unlinkable, mirroring the
/// note nullifier's `H(commitment, spend_key)` construction.
pub fn liquidation_tag_key(spend_key: &Digest) -> Digest {
    Keccak256::hash_words(Domain::Liquidation, &[*spend_key])
}

/// A per-`(account, market, batch)` liquidation tag keyed on the SECRET
/// `tag_key` (see [`liquidation_tag_key`]). The liquidated account self-detects by
/// recomputing `liquidation_tag(&liquidation_tag_key(spend_key), market, batch)`;
/// an observer who knows only the public owner id cannot recompute it (it would
/// need the spend key). This replaces the cleartext liquidated-owner list so
/// liquidation privacy holds at the sequencer layer against a realistic
/// known-pubkey adversary, not just a fully-blind observer (§5, §7).
pub fn liquidation_tag(tag_key: &Digest, market_id: MarketId, batch_id: u64) -> Digest {
    Keccak256::hash_words(
        Domain::Liquidation,
        &[*tag_key, word_u64(market_id), word_u64(batch_id)],
    )
}

/// The per-account SECRET auto-deleverage-tag key, derived from the account's
/// spend key — the ADL analog of [`liquidation_tag_key`]. A distinct domain
/// (`Domain::Adl`) so a liquidation tag and an ADL tag for the same account never
/// collide, and only the account (or the enclave at fund time) can compute it.
pub fn adl_tag_key(spend_key: &Digest) -> Digest {
    Keccak256::hash_words(Domain::Adl, &[*spend_key])
}

/// A per-`(account, market, batch)` auto-deleverage tag keyed on the SECRET
/// `tag_key` (see [`adl_tag_key`]). The clawed account self-detects its haircut by
/// recomputing `adl_tag(&adl_tag_key(spend_key), market, batch)`; an observer who
/// knows only the public owner id cannot (audit Q2). Published in [`AdlReceipt`]
/// alongside the clawed amount.
pub fn adl_tag(tag_key: &Digest, market_id: MarketId, batch_id: u64) -> Digest {
    Keccak256::hash_words(
        Domain::Adl,
        &[*tag_key, word_u64(market_id), word_u64(batch_id)],
    )
}

/// The smallest notional, quote-scaled ($10), of an order the sequencer admits
/// when the order adds exposure: it opens, grows or flips its owner's position and
/// is not reduce-only. The notional is the order's full size at the validated
/// oracle price, the price the pre-trade margin check uses. This is admission
/// policy, not an engine rule, so it can change without a new program key: an
/// order that only reduces a position is exempt, and a resting remainder that a
/// partial fill left below the minimum keeps matching (the book never re-checks
/// it). A refused order is recorded as [`RejectReason::BelowMinimumSize`].
///
/// The exemption holds only while the order really reduces. In a batch, an order
/// is measured against its owner's position before the batch and against that
/// position after the owner's earlier orders of the batch, filled in full; it is
/// exempt only if it reduces against both. An exempt order whose fill would add
/// exposure when it executes (in its own batch, or later while it rests) is
/// refused at settlement with the same reason, so no order below the minimum ever
/// opens, grows or flips a position.
pub const MIN_ORDER_NOTIONAL: i128 = 10 * QUOTE_SCALE;

/// The notional, quote-scaled ($1,000), at which the funding mark takes its impact
/// prices: the average price at which this much would fill against each side of
/// the book. A side holding less than this gives no impact price, and the mark
/// falls back to the oracle index (see [`Sequencer::run_maintenance`]).
pub const FUNDING_IMPACT_NOTIONAL: i128 = 1_000 * QUOTE_SCALE;

/// The shortest span, in ms, the funding mark's window average divides by: ten
/// 700 ms ticks, about one settle window under the launch clock policy. While the
/// open window has run for less, the missing time counts at the oracle index (a
/// zero premium), so a few early samples move the mark by at most their share of
/// this span.
pub const FUNDING_MARK_MIN_SPAN_MS: u64 = 7_000;

/// The most resting orders one side's impact sweep visits, inside the fill band,
/// before it reaches [`FUNDING_IMPACT_NOTIONAL`]. A side that needs more gives no
/// impact price, and the mark falls back to the oracle index, as for a side
/// without the depth. Honest depth reaches the notional in far fewer orders: a
/// hundred orders at the order minimum hold it. The bound keeps the cost of a
/// funding sample independent of how many orders rest on the book.
pub const FUNDING_IMPACT_MAX_ORDERS: usize = 4_096;

/// Whether the minimum order size ([`MIN_ORDER_NOTIONAL`]) refuses `order` against
/// its owner's current `position` (an empty one when the owner holds none), at the
/// validated oracle price `mark`. Reduce-only orders and orders that do not increase
/// the position's exposure are never refused; neither is an order with a
/// non-positive size (the matcher refuses it as malformed). An order whose notional
/// overflows is far above the minimum.
pub fn below_minimum_order_notional(position: &Position, order: &Order, mark: i128) -> bool {
    if order.reduce_only || order.size <= 0 || !position.increases_exposure(order.signed_size()) {
        return false;
    }
    under_minimum_notional(order, mark)
}

/// Whether `order`'s full size at `mark` is below [`MIN_ORDER_NOTIONAL`]. An order
/// with a non-positive size, or whose notional overflows, is not.
fn under_minimum_notional(order: &Order, mark: i128) -> bool {
    order.size > 0
        && notional_quote(order.size, mark).is_some_and(|notional| notional < MIN_ORDER_NOTIONAL)
}

/// The widest funding premium, in price units, that `AccrueFunding` accepts for
/// `market` at the validated `index`: the market's mark band
/// (`max_mark_deviation_ratio`), rounded down so a mark of `index ± band` always
/// passes the engine's check. 0 if the product overflows, which pins the mark to
/// the index.
fn mark_band(market: &Market, index: i128) -> i128 {
    market
        .max_mark_deviation_ratio
        .checked_mul(index)
        .map_or(0, |v| v / RATE_SCALE)
        .max(0)
}

/// The largest funding premium, in price units, the sequencer lets a sample or the
/// window average carry at the validated `index`: the smallest premium at which the
/// engine's rate reaches its clamp, `ceil(MAX_FUNDING_RATE_PER_INTERVAL · index /
/// RATE_SCALE)`, and never more than the mark band ([`mark_band`]). A larger
/// premium cannot raise the rate further, so the cap changes no single tick's rate;
/// it keeps one sample from weighing more than a premium at the cap would over its
/// share of the window. 0 for a non-positive index.
fn premium_cap(market: &Market, index: i128) -> i128 {
    let band = mark_band(market, index);
    if index <= 0 {
        return 0;
    }
    let saturating = MAX_FUNDING_RATE_PER_INTERVAL
        .checked_mul(index)
        .map_or(band, |v| v / RATE_SCALE + i128::from(v % RATE_SCALE != 0));
    saturating.clamp(0, band)
}

/// Whether a fill at `price` lies inside `market`'s fill band around the validated
/// `index`: `|price − index| · RATE_SCALE <= max_fill_deviation_ratio · index`, the
/// engine's own division-free test (`op_fill`). Any overflow is outside the band.
fn within_fill_band(market: &Market, index: i128, price: i128) -> bool {
    let Some(deviation) = price.checked_sub(index).and_then(i128::checked_abs) else {
        return false;
    };
    match (
        deviation.checked_mul(RATE_SCALE),
        market.max_fill_deviation_ratio.checked_mul(index),
    ) {
        (Some(lhs), Some(rhs)) => lhs <= rhs,
        _ => false,
    }
}

/// `position` after a resting maker's fill of `delta` at the `quote`'s price, if
/// the engine could settle that fill for the maker at the validated `index`: a reduce-only
/// maker, a maker whose order was admitted below the minimum because it reduced
/// (`minimum_exempt`, which [`settle_fills`] holds to reducing) and, in close-only
/// mode, any maker may only reduce; a fill that adds exposure must leave initial
/// margin; and the position must stay maintenance-compliant while open, or end
/// with no debt. This mirrors the maker leg of `op_fill` without its fee rebate,
/// so it errs toward refusing depth. `None` when the fill would be refused.
// one argument per rule the fill must pass, all read from the caller's state
#[allow(clippy::too_many_arguments)]
fn maker_fill_settles(
    position: &Position,
    market: &Market,
    quote: &RestingQuote,
    delta: i128,
    index: i128,
    funding_index: i128,
    close_only: bool,
    minimum_exempt: bool,
) -> Option<Position> {
    let increasing = position.increases_exposure(delta);
    if increasing && (quote.reduce_only || close_only || minimum_exempt) {
        return None;
    }
    let mut after = *position;
    after.apply_fill(delta, quote.price, funding_index).ok()?;
    if increasing
        && after
            .check_initial_margin(market, index, funding_index)
            .is_err()
    {
        return None;
    }
    let solvent = if after.is_open() {
        after
            .check_maintenance_margin(market, index, funding_index)
            .is_ok()
    } else {
        after.collateral >= 0
    };
    solvent.then_some(after)
}

/// The running time average of one market's funding premium over the open settle
/// window (see [`Sequencer::run_maintenance`]).
///
/// The premium is the impact-notional book mid minus the validated oracle index.
/// It is sampled at each tick from the book the tick's takers face, before the
/// tick matches, and it prices the span that ends at that tick: the time since the
/// previous sample. A quote therefore weighs only on the spans that end at ticks
/// whose takers could still trade against it. Averaging the premium rather than
/// the mid keeps a move of the index during the window from reading as a premium.
/// Each sample is capped at the premium that saturates the rate ([`premium_cap`]),
/// and the average divides by at least [`FUNDING_MARK_MIN_SPAN_MS`], so no single
/// tick outweighs its share of the window.
///
/// Off-chain sequencer state only: it decides the marks the sequencer puts into
/// future `AccrueFunding` ops, and every emitted op carries its own mark, so
/// replaying a sealed window never reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FundingMarkWindow {
    /// Σ premium · dt over the closed spans, price units × ms.
    weighted: i128,
    /// Σ dt over the same spans, ms.
    elapsed: u64,
    /// The newest sample, `(time, premium)`. The next span runs from its time.
    last: Option<(u64, i128)>,
}

impl FundingMarkWindow {
    /// Take the sample `premium` at `now_ms`: it prices the span from the newest
    /// sample's time up to `now_ms`, and `now_ms` starts the next span. The first
    /// sample of a window only starts the clock. A sample at the newest sample's
    /// time or earlier changes nothing, so the first sample taken at a time stands.
    fn observe(&mut self, now_ms: u64, premium: i128) {
        match self.last {
            Some((t, _)) if now_ms > t => {
                let dt = now_ms - t;
                self.weighted = self
                    .weighted
                    .saturating_add(premium.saturating_mul(i128::from(dt)));
                self.elapsed = self.elapsed.saturating_add(dt);
                self.last = Some((now_ms, premium));
            }
            Some(_) => {}
            None => self.last = Some((now_ms, premium)),
        }
    }

    /// Whether a sample was taken at `now_ms` or later: a sample at `now_ms` would
    /// then change nothing.
    fn sampled_since(&self, now_ms: u64) -> bool {
        self.last.is_some_and(|(t, _)| now_ms <= t)
    }

    /// The time-weighted average premium over the closed spans, rounded toward
    /// zero, divided by at least [`FUNDING_MARK_MIN_SPAN_MS`]; 0 while no span has
    /// closed.
    fn average(&self) -> i128 {
        let span = self.elapsed.max(FUNDING_MARK_MIN_SPAN_MS);
        self.weighted / i128::from(span)
    }
}

#[cfg(test)]
thread_local! {
    /// Funding-premium samples computed on this thread (each walks the book).
    static PREMIUM_SAMPLES: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Why an order was rejected at settlement, mapped from an engine error.
fn settlement_reason(e: &EngineError) -> RejectReason {
    match e {
        EngineError::Risk { .. } => RejectReason::InsufficientMargin,
        EngineError::Oracle(_) => RejectReason::OracleUnavailable,
        EngineError::CloseOnly => RejectReason::MarketCloseOnly,
        EngineError::SelfTrade => RejectReason::SelfTradePrevented,
        EngineError::FillPriceOutOfBand => RejectReason::FillPriceOutOfBand,
        EngineError::FillWouldBankrupt(_) => RejectReason::FillWouldBankrupt,
        // audit Tier-3: an HONEST catch-all for the remaining engine errors (UnknownMarket,
        // NonPositiveAmount, Overflow, DuplicateCommitment, …) instead of mis-tagging them
        // all as ReduceOnlyViolation in the manifest.
        _ => RejectReason::InvalidOrder,
    }
}

/// Which order a failed fill is attributable to, if the engine identified one (SEC-022 §6).
/// `None` means the failure is not attributable and both legs are recorded, as before.
fn offending_leg(e: &EngineError) -> Option<FillLeg> {
    match e {
        // The engine names the leg whose staged result violated the postcondition.
        EngineError::FillWouldBankrupt(leg) => Some(*leg),
        // SEC-024 (SEC-022 carry-in): a margin failure raised INSIDE a fill names the
        // staged leg that violated; a leg-less Risk (op_unbind, generic From) stays
        // non-attributable and falls through to the catch-all.
        EngineError::Risk { leg: Some(l), .. } => Some(*l),
        // The execution price is the RESTING MAKER's (`matcher/book.rs:295`); the taker
        // only supplied a limit it was willing to cross. An out-of-band price is therefore
        // the maker's order to cancel, not the taker's.
        EngineError::FillPriceOutOfBand => Some(FillLeg::Maker),
        _ => None,
    }
}

/// The outcome of settling one batch's matched fills ([`settle_fills`]).
/// `Default` is the no-fills settlement: settling an empty fill stream is a
/// no-op, so its outcome is empty everywhere.
#[derive(Default)]
struct FillSettlement {
    applied_fills: Vec<Match>,
    /// The batch's replayable fill op-log, in application order. Only ops whose
    /// application SUCCEEDED are logged, so replaying it via `apply_batch`
    /// reproduces the resulting state root (Slice 3a).
    ops: Vec<BatchOp>,
    /// Order hashes recorded against a failed fill, with the reason. An
    /// ATTRIBUTABLE failure records only the offending leg (see [`settle_fills`]).
    rejected: Vec<(Digest, RejectReason)>,
    /// Order hashes with at least one settled fill, deduplicated, in fill order.
    settled_order_hashes: Vec<Digest>,
    /// SEC-022 §6: order hashes whose fill failed for an ATTRIBUTABLE reason
    /// (band / bankruptcy / reduce_only settlement violation), each paired with
    /// the reason recorded at its OWN push site. `seal_batch`'s dry-run bans
    /// these — book restored, offender excised, stream rematched — before the
    /// committed pass runs, and commits the paired reason into the manifest.
    /// The reason travels here (not via a lookup in `rejected`) because a hash
    /// can appear in `rejected` earlier in the same pass as an INNOCENT
    /// counterparty of a non-attributable both-leg rejection — a first-match
    /// lookup would commit that earlier, wrong reason into `manifest_hash`
    /// (whole-branch review I2).
    offenders: Vec<(Digest, RejectReason)>,
}

/// Whether a signed `delta` would INCREASE `owner`'s absolute exposure in
/// `market_id` (open from flat, grow in the same direction, or flip) — used to
/// enforce reduce_only at settlement (audit DP-009).
fn exposure_increases_in(
    state: &DefaultState,
    owner: &PubKey,
    market_id: MarketId,
    delta: i128,
) -> bool {
    match state.position(owner, market_id) {
        None => true,
        Some(p) => p.increases_exposure(delta),
    }
}

/// Settle matched `fills` through the engine against `state`, attaching the
/// per-market oracle. Extracted from `seal_batch` for SEC-022 §6's probe
/// dry-run (Task 7); a clean probe is ADOPTED as the committed settlement
/// (review I4), so the probe and the commit are one run by construction.
/// Deterministic in exactly `(state, oracles, fills, now_ms, minimum_exempt)` —
/// the adoption relies on that.
///
/// The pre-trade gate covers the *taker* against current state, but a *resting
/// maker* admitted in an earlier batch can have drifted below initial margin
/// since (funding / a prior liquidation), so a fill can still fail to settle.
/// Failure attribution (SEC-022 §6): an ATTRIBUTABLE failure ([`offending_leg`]
/// returns `Some`, or one of the leg checks below fires) records ONLY the
/// offending leg in `rejected` (and `offenders`); `seal_batch`'s dry-run then
/// bans the offender, restores the book, and rematches, so the innocent
/// counterparty's fill is re-routed rather than left in limbo. A NON-attributable
/// failure still records BOTH legs, and `seal_batch` still moves an order all of
/// whose recorded fills failed into the manifest's `rejected`.
///
/// Before a fill is applied, each leg is checked against the position it would
/// change, in this order: a reduce-only order may not add exposure
/// ([`RejectReason::ReduceOnlyViolation`]); in close-only mode no order may add
/// exposure ([`RejectReason::MarketCloseOnly`], the engine's own rule, named per
/// leg); and an order in `minimum_exempt` (admitted below [`MIN_ORDER_NOTIONAL`]
/// because it reduced) may not add exposure either
/// ([`RejectReason::BelowMinimumSize`]).
fn settle_fills(
    state: &mut DefaultState,
    oracles: &BTreeMap<MarketId, OracleTranscript>,
    fills: &[Match],
    now_ms: u64,
    minimum_exempt: &BTreeSet<Digest>,
) -> FillSettlement {
    let mut out = FillSettlement::default();
    for m in fills {
        let Some(oracle) = oracles.get(&m.market_id).copied() else {
            for oh in [m.taker_order_hash, m.maker_order_hash] {
                out.rejected.push((oh, RejectReason::OracleUnavailable));
            }
            continue;
        };
        // audit DP-009: a reduce_only order may only SHRINK its owner's position. Drop
        // the fill if it would increase a reduce_only party's absolute exposure. (Matching
        // is trusted in Phase 0; op_fill's margin checks still guard fund safety.)
        // The pre-trade gate already rejects a reduce_only order that would open against
        // the pre-batch position; this is the live backstop for an intra-batch change.
        //
        // The violation is attributed ONLY to the offending order(s), never to an
        // innocent counterparty (adversarial-review follow-up). SEC-022 §6 (Task 7
        // review I1a): it is ATTRIBUTABLE, so the offender is also BANNED like any
        // other offending leg — without the ban the dropped fill still burned the
        // innocent counterparty's consumed depth. Reachable cross-batch: a reduce_only
        // maker resting since batch N whose position an EARLIER fill of this very
        // settlement pass closed (the pre-trade gate and the owners_with_order guard
        // see only current-batch orders). Where both legs offend, both are banned.
        //
        // The close-only and minimum checks follow the same rule. In close-only mode
        // the engine refuses a fill when either leg adds exposure; naming that leg here
        // lets a close that crossed a resting opener (admitted before the mode
        // changed) be rematched instead of rejected with it.
        let taker_delta = if m.taker_side == Side::Buy {
            m.size
        } else {
            -m.size
        };
        let close_only = state.mode == Mode::CloseOnly;
        let leg_offense = |owner: &PubKey, hash: &Digest, reduce_only: bool, delta: i128| {
            if !exposure_increases_in(state, owner, m.market_id, delta) {
                None
            } else if reduce_only {
                Some(RejectReason::ReduceOnlyViolation)
            } else if close_only {
                Some(RejectReason::MarketCloseOnly)
            } else if minimum_exempt.contains(hash) {
                Some(RejectReason::BelowMinimumSize)
            } else {
                None
            }
        };
        let taker_offense = leg_offense(
            &m.taker,
            &m.taker_order_hash,
            m.taker_reduce_only,
            taker_delta,
        );
        let maker_offense = leg_offense(
            &m.maker,
            &m.maker_order_hash,
            m.maker_reduce_only,
            -taker_delta,
        );
        if taker_offense.is_some() || maker_offense.is_some() {
            for (hash, offense) in [
                (m.taker_order_hash, taker_offense),
                (m.maker_order_hash, maker_offense),
            ] {
                if let Some(reason) = offense {
                    out.rejected.push((hash, reason));
                    out.offenders.push((hash, reason));
                }
            }
            continue;
        }
        let op = BatchOp::Fill {
            taker: m.taker,
            maker: m.maker,
            market_id: m.market_id,
            taker_side: m.taker_side,
            size: m.size,
            price: m.price,
            oracle,
            now_ms,
        };
        match state.apply_op(&op) {
            // A Fill never yields a withdrawal output, so discard it.
            Ok(_) => {
                for oh in [m.taker_order_hash, m.maker_order_hash] {
                    if !out.settled_order_hashes.contains(&oh) {
                        out.settled_order_hashes.push(oh);
                    }
                }
                // log the fill only after it settled — a failed fill (Err arm) is
                // dropped, so it never enters the replayable op-log.
                out.ops.push(op);
                out.applied_fills.push(*m);
            }
            Err(e) => {
                let reason = settlement_reason(&e);
                // Attribute the rejection to the offending leg ONLY, never to an
                // innocent counterparty — the same rule the reduce_only arm above
                // already follows.
                match offending_leg(&e) {
                    Some(FillLeg::Taker) => {
                        out.rejected.push((m.taker_order_hash, reason));
                        out.offenders.push((m.taker_order_hash, reason));
                    }
                    Some(FillLeg::Maker) => {
                        out.rejected.push((m.maker_order_hash, reason));
                        out.offenders.push((m.maker_order_hash, reason));
                    }
                    None => {
                        for oh in [m.taker_order_hash, m.maker_order_hash] {
                            out.rejected.push((oh, reason));
                        }
                    }
                }
            }
        }
    }
    out
}

/// serde default for the skipped `enclave` field: a placeholder identity a
/// restore MUST overwrite via [`Sequencer::set_enclave`] before serving. The
/// snapshot deliberately never carries the enclave signing secret — it is
/// rebuilt from `ENCLAVE_SEED` at boot (and may legitimately rotate).
fn enclave_restore_placeholder() -> EnclaveIdentity {
    EnclaveIdentity::from_seed([7u8; 32], 0, [0u8; 32])
}

/// serde default for the skipped `retain_tick_snapshots` flag: legacy per-tick
/// retention stays on for any restore not explicitly switched to window mode.
fn retain_tick_snapshots_default() -> bool {
    true
}

/// Keep tick→window map entries for this many settled windows past the on-chain batchCount, so
/// `/v1/batch/:id` + `WBatch.window_id` reconciliation (and `settled:true`) stay observable for a
/// grace period after a window settles — decoupled from the much faster per-tick soft-finality.
const TICK_WINDOW_GRACE_WINDOWS: u64 = 8;
/// Hard backstop on the tick→window map so no path can leak (the legacy path never settles a
/// window, so it has no window-settle prune event) — evict the oldest entries beyond this cap.
const TICK_WINDOW_MAX: usize = 16_384;

/// The pre-trade gate's verdict on an order it admits.
struct Admitted {
    /// The order is below [`MIN_ORDER_NOTIONAL`] and was admitted only because it
    /// reduces its owner's position; settlement refuses it a fill that adds exposure.
    below_minimum_exempt: bool,
}

/// The sequencer / matcher node.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Sequencer {
    pub state: DefaultState,
    matcher: MatchingEngine<Keccak256>,
    #[serde(skip, default = "enclave_restore_placeholder")]
    enclave: EnclaveIdentity,
    oracles: BTreeMap<MarketId, OracleTranscript>,
    next_batch_id: u64,
    next_receipt_seq: u64,
    matching_rule_version: u32,
    inclusion: BTreeMap<Digest, InclusionRecord>,
    finality: BTreeMap<Digest, Finality>,
    /// order hashes settled per batch, for `mark_settled` / rollback.
    batch_orders: BTreeMap<u64, Vec<Digest>>,
    /// Maps each per-tick Counter-A batch id to the Counter-B window id (`state.next_batch_id`)
    /// it settles into, so a bare tick id (a `WBatch`, a log line) without a receipt can be
    /// reconciled to its on-chain window. Pruned on WINDOW settle (Counter B) by
    /// `prune_tick_window_settled` with a [`TICK_WINDOW_GRACE_WINDOWS`] grace — NOT on the
    /// ~10x-faster per-tick soft-finality, which would drop entries before their window even
    /// seals — plus the [`TICK_WINDOW_MAX`] size-cap backstop in `seal_batch`, so it stays
    /// bounded on every path (Slice 3b-4).
    ///
    /// Persistence: this map IS part of the gateway's postcard boot snapshot — `Gw` derives
    /// Serialize/Deserialize and its `seq: Sequencer` field is not serde-skipped, so the whole
    /// `Sequencer` (this field included) is serialized by `snapshot_plain`. Under positional
    /// (non-self-describing) postcard, `#[serde(default)]` gives no tolerance for a snapshot
    /// that lacks the field, so adding it is a snapshot wire-format change: old snapshots fail
    /// to decode (fail-closed on boot). Same as the Slice 3b-1 `window_*` additions, and
    /// covered by the live migration's already-required snapshot reset.
    #[serde(default)]
    tick_window: BTreeMap<u64, u64>,
    /// Snapshot of (state, matcher) taken BEFORE each not-yet-proven batch, so a
    /// batch that fails to prove can be rolled back to the last hard state (§3
    /// failure matrix). Pruned as batches settle. Keeping a snapshot only per
    /// *pending* batch bounds the memory. NOTE: this map is NOT serde-skipped, so
    /// retained entries also serialize into the gateway's postcard boot snapshot —
    /// bounding it bounds both memory and disk.
    snapshots: BTreeMap<u64, (DefaultState, MatchingEngine<Keccak256>)>,
    /// Runtime-only switch for the per-tick rollback snapshots above (Task 5 fix
    /// round 1). The WINDOW settle path never consumes them (`mark_failed` is
    /// legacy/test-only; window recovery is `rollback_window` + `window_start_state`),
    /// yet Task 5 turned off the tick-loop SETTLE_TICKS simulation whose
    /// `mark_settled` used to prune them every ~3.5s — leaving a full (state,
    /// matcher) clone per 700ms tick retained for a whole ~13-min proof interval
    /// (~1100 clones), unbounded if settles wedge. The gateway sets this `false`
    /// alongside `window_settle_mode` so `seal_batch` skips the insert entirely.
    /// `#[serde(skip)]` + a `true` default: NOT part of the snapshot wire format
    /// (postcard is positional; a skipped field is never written or read), and a
    /// legacy restore keeps legacy retention byte-identical.
    #[serde(skip, default = "retain_tick_snapshots_default")]
    retain_tick_snapshots: bool,
    /// Every op applied since the current window opened, in application order — the
    /// replayable op-log the window proof attests. Fed by `Sequencer::apply` (deposits)
    /// and each `seal_batch` (its `[fills] ++ maintenance` ops). Drained by `seal_window`.
    #[serde(default)]
    window_ops: Vec<BatchOp>,
    /// Union of the window's ticks' settled/rejected order hashes, for the combined manifest.
    #[serde(default)]
    window_ordered: Vec<Digest>,
    #[serde(default)]
    window_rejected: Vec<(Digest, RejectReason)>,
    /// The state at the current window's open — the witness pre-state. Re-captured after
    /// each `seal_window`. (Not `#[serde(default)]`: `DefaultState` has no `Default`. The
    /// Sequencer IS persisted — it rides inside `Gw` in the gateway snapshot — but this
    /// field is always written, so no missing-field case arises. The comment here used to
    /// claim the Sequencer was never persisted; that was false, and it is the same premise
    /// the snapshot magic depends on, so do not restore it.)
    window_start_state: DefaultState,
    /// Per-account secret liquidation-tag keys, derived from the spend key the
    /// account presents when funding a position and captured inside the enclave.
    /// Used to publish liquidation tags that only the account (which knows its own
    /// spend key) can recompute — never a mere holder of the public owner id (§7).
    liq_tag_keys: BTreeMap<PubKey, Digest>,
    /// Parallel secret ADL-tag keys, captured the same way, for publishing
    /// auto-deleverage receipts only the clawed account can recognize (audit Q2).
    adl_tag_keys: BTreeMap<PubKey, Digest>,
    /// Secret salt for the fail-closed liquidation/ADL tag fallback (§7). When a
    /// position's per-account secret key is somehow absent (funded outside `apply`),
    /// the tag is keyed on `H(domain, [salt, owner])` — never on the public owner id,
    /// which any known-pubkey observer could recompute. Derived from the enclave key,
    /// refreshed on `set_enclave`. Off-chain only (tags are not in the proof).
    liq_fallback_salt: Digest,
    /// Per-market running average of the funding premium over the open settle
    /// window, from which `run_maintenance` takes each `AccrueFunding` mark. Reset
    /// when a window is sealed. Persisted with the rest of the sequencer so a
    /// restart mid-window keeps the window's average; it is never part of a
    /// witness (each op carries the mark it was given).
    #[serde(default)]
    funding_marks: BTreeMap<MarketId, FundingMarkWindow>,
    /// Hashes of resting orders admitted below [`MIN_ORDER_NOTIONAL`] only because
    /// they reduced their owner's position. Settlement refuses such an order a fill
    /// that would add exposure. Pruned to the orders still resting after each batch
    /// and on cancellation. Persisted with the sequencer so the rule survives a
    /// restart; never part of a witness.
    #[serde(default)]
    minimum_exempt: BTreeSet<Digest>,
    /// An owner whose orders are not subject to [`MIN_ORDER_NOTIONAL`] at all: the
    /// gateway's house market maker, whose counter order mirrors a taker that the
    /// sequencer measures itself. Boot configuration, not persisted: the gateway
    /// sets it after every boot or restore ([`Sequencer::set_minimum_exempt_owner`]).
    #[serde(skip)]
    minimum_exempt_owner: Option<PubKey>,
}

impl Sequencer {
    pub fn new(enclave: EnclaveIdentity, tree_depth: u8) -> Self {
        let liq_fallback_salt = enclave.secret_salt(Domain::Liquidation);
        Self {
            state: DefaultState::new(tree_depth),
            matcher: MatchingEngine::new(),
            enclave,
            oracles: BTreeMap::new(),
            next_batch_id: 0,
            next_receipt_seq: 0,
            matching_rule_version: 1,
            inclusion: BTreeMap::new(),
            finality: BTreeMap::new(),
            batch_orders: BTreeMap::new(),
            tick_window: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            retain_tick_snapshots: true,
            window_ops: Vec::new(),
            window_ordered: Vec::new(),
            window_rejected: Vec::new(),
            window_start_state: DefaultState::new(tree_depth),
            liq_tag_keys: BTreeMap::new(),
            adl_tag_keys: BTreeMap::new(),
            liq_fallback_salt,
            funding_marks: BTreeMap::new(),
            minimum_exempt: BTreeSet::new(),
            minimum_exempt_owner: None,
        }
    }

    /// Rebind the enclave identity after a snapshot restore. The snapshot skips
    /// the enclave (its signing secret must never persist to disk and may
    /// legitimately rotate), so a deserialized `Sequencer` signs with a public
    /// placeholder until this is called — callers MUST invoke it with the real
    /// identity before serving traffic.
    pub fn set_enclave(&mut self, enclave: EnclaveIdentity) {
        self.liq_fallback_salt = enclave.secret_salt(Domain::Liquidation);
        self.enclave = enclave;
    }

    /// Turn per-tick rollback-snapshot retention off (window-settle mode) or back
    /// on (the legacy default). Turning it off also drops anything already
    /// retained — including entries restored from a snapshot persisted under the
    /// legacy default — since the window path never reads them; `mark_failed`
    /// tolerates the absence (returns `false`, rolls nothing back), and the
    /// `mark_settled` / `mark_window_settled` prunes are remove-if-present.
    pub fn set_retain_tick_snapshots(&mut self, retain: bool) {
        self.retain_tick_snapshots = retain;
        if !retain {
            self.snapshots.clear();
        }
    }

    /// The bound enclave signing identity (attested `measurement` + secp256k1
    /// signer). The gateway uses this to publish the signed order-ingress epoch
    /// key ([`EnclaveIdentity::sign_prehash`]) bound to the attested measurement.
    pub fn enclave(&self) -> &EnclaveIdentity {
        &self.enclave
    }

    /// Register a market in both settlement state and the matcher.
    pub fn add_market(&mut self, market: Market) {
        self.matcher.open_market(market.id);
        self.state.add_market(market);
        // Market registration is boot-time CONFIG, not a replayable `BatchOp` (there is
        // no `AddMarket` op), so it can never live in the window op-log. Re-capture the
        // window baseline to include it, or the window witness would replay from a
        // market-less pre-state and fail (`UnknownMarket`) on the first fill/fund. This
        // is only ever called before any window ops (deposits/orders), so `window_ops`
        // is empty here and re-cloning the state is the true window-open baseline.
        //
        // The window witness's pre-state must carry markets (they mutate state.markets,
        // bound in state_root, with no BatchOp). Re-capturing window_start_state here is
        // only sound while no window ops have accumulated — markets are genesis/setup
        // config, registered before any deposit/order. A mid-window add_market would strand
        // the accumulated ops (they'd be in both pre_state and window_ops → double-apply).
        debug_assert!(
            self.window_ops.is_empty(),
            "add_market must run before any window ops (markets are setup config, not mid-window)"
        );
        self.window_start_state = self.state.clone();
    }

    /// Set the L1 address the wind-down pays the protocol's remaining reserves to
    /// ([`perp_core::State::set_wind_down_recipient`]). Like [`Sequencer::add_market`]
    /// this is setup config with no `BatchOp`, so it re-captures the window
    /// baseline and must run before any window op: a recapture over accumulated ops
    /// would put them in both the witness pre-state and its op-log. The recipient is
    /// a state-root word, so it is set before the genesis root is taken and never
    /// changes afterwards.
    ///
    /// # Panics
    ///
    /// If the open window already holds ops or manifest entries, if a window has
    /// already been sealed, or if a different recipient is already set. Unlike
    /// `add_market`'s debug-only check this holds in release builds too: the call
    /// is boot-time only, and a late call would silently change a root that is
    /// already anchored or corrupt the next window witness. Setting the recipient
    /// already in place again changes nothing and is allowed.
    pub fn set_wind_down_recipient(&mut self, recipient: [u8; 20]) {
        assert!(
            self.window_ops.is_empty()
                && self.window_ordered.is_empty()
                && self.window_rejected.is_empty(),
            "set_wind_down_recipient must run before any window ops (the recipient is setup config)"
        );
        assert_eq!(
            self.state.next_batch_id, 0,
            "set_wind_down_recipient must run before the first window is sealed"
        );
        let current = self.state.wind_down_recipient;
        assert!(
            current == [0u8; 20] || current == recipient,
            "the wind-down recipient is fixed once set"
        );
        self.state.set_wind_down_recipient(recipient);
        self.window_start_state = self.state.clone();
    }

    /// Exempt `owner`'s orders from [`MIN_ORDER_NOTIONAL`], or clear the exemption
    /// with `None`. Meant for the gateway's house market maker: its counter order
    /// has the size of the taker it answers, and the taker is measured against the
    /// minimum itself, so without the exemption a small exempt close could find its
    /// counter refused. Boot configuration, not persisted.
    pub fn set_minimum_exempt_owner(&mut self, owner: Option<PubKey>) {
        self.minimum_exempt_owner = owner;
    }

    /// Set / refresh the oracle transcript a market settles against (§8).
    pub fn set_oracle(&mut self, market_id: MarketId, transcript: OracleTranscript) {
        self.oracles.insert(market_id, transcript);
    }

    /// The oracle transcript currently set for `market_id` (§8) — the exact value the
    /// engine marks/settles against. Read-only accessor so the host can re-observe what
    /// it stored (e.g. ZK-001: verify a live-path transcript still validates after the
    /// gateway re-stamps + re-signs it).
    pub fn oracle(&self, market_id: MarketId) -> Option<&OracleTranscript> {
        self.oracles.get(&market_id)
    }

    /// Apply a raw settlement op (deposits, funding, etc.) outside the matched
    /// flow. Thin passthrough used for setup and admin actions.
    pub fn apply(&mut self, op: &BatchOp) -> Result<(), EngineError> {
        // Capture the account's secret liquidation-tag key from the spend key it
        // presents at fund time, so a later liquidation can be tagged unlinkably.
        if let BatchOp::FundPosition {
            owner, spend_key, ..
        } = op
        {
            self.liq_tag_keys
                .insert(*owner, liquidation_tag_key(spend_key));
            self.adl_tag_keys.insert(*owner, adl_tag_key(spend_key));
        }
        // Discard any withdrawal output: the sealed-batch path derives
        // `withdrawals_root` from `apply_batch`'s `BatchOutputs`; this thin
        // passthrough is used for setup/admin ops and returns only success/failure.
        self.state.apply_op(op)?;
        // Log the op at its real position in the open window's op-log so out-of-band
        // deposits/funds land in the replayable witness `seal_window` drains.
        self.window_ops.push(op.clone());
        Ok(())
    }

    /// Apply an ordered group without exposing a partially applied deposit/funding pair.
    /// Validate on a cloned engine state; commit state, replay log and tag keys together.
    /// No witness encoding or commitment rule is changed.
    pub fn apply_atomic(&mut self, ops: &[BatchOp]) -> Result<(), EngineError> {
        let mut next = self.state.clone();
        for op in ops {
            next.apply_op(op)?;
        }
        self.state = next;
        for op in ops {
            if let BatchOp::FundPosition {
                owner, spend_key, ..
            } = op
            {
                self.liq_tag_keys
                    .insert(*owner, liquidation_tag_key(spend_key));
                self.adl_tag_keys.insert(*owner, adl_tag_key(spend_key));
            }
        }
        self.window_ops.extend_from_slice(ops);
        Ok(())
    }

    /// Fail-closed fallback liquidation-tag key for an account whose captured
    /// secret key is missing (funded outside `apply`, §7). Keyed on the enclave's
    /// secret salt — NOT the public owner id, which any known-pubkey observer
    /// could recompute and use to link the tag back to the account.
    fn liq_fallback_key(&self, owner: &PubKey) -> Digest {
        Keccak256::hash_words(Domain::Liquidation, &[self.liq_fallback_salt, *owner])
    }

    /// ADL analog of [`Sequencer::liq_fallback_key`].
    fn adl_fallback_key(&self, owner: &PubKey) -> Digest {
        Keccak256::hash_words(Domain::Adl, &[self.liq_fallback_salt, *owner])
    }

    /// Test-only: drop a captured liquidation tag-key to exercise the fail-closed
    /// fallback (a position "funded outside apply"). Not `#[cfg(test)]`: that gate
    /// only compiles into this crate's own unit-test build, not the normal rlib
    /// integration tests in `tests/spine.rs` link against, so it would be
    /// unreachable there. Mirrors the existing `mark_failed` precedent in this file
    /// (legacy/test-only, always compiled). Harmless in production: it only forces
    /// an account onto the fail-closed fallback path this task makes safe (still
    /// deterministic, never keyed on the public owner id) — it exposes no secret
    /// and cannot be reached from any gateway RPC surface.
    pub fn forget_liq_key(&mut self, owner: &PubKey) {
        self.liq_tag_keys.remove(owner);
    }

    /// ADL analog of [`Sequencer::forget_liq_key`]: test-only, drop a captured
    /// ADL tag-key to exercise the fail-closed fallback. Same rationale for not
    /// being `#[cfg(test)]` (unreachable from `tests/spine.rs` otherwise) and same
    /// harmlessness in production (no gateway RPC surface reaches it).
    pub fn forget_adl_key(&mut self, owner: &PubKey) {
        self.adl_tag_keys.remove(owner);
    }

    pub fn current_batch_id(&self) -> u64 {
        self.next_batch_id
    }

    /// The currently open window id (Counter B) — the `batchCount`-space id that orders
    /// sequenced now will settle into. Directly comparable to the on-chain `batchCount`.
    pub fn current_window_id(&self) -> u64 {
        self.state.next_batch_id
    }

    /// A06 operator guard: SettleAll must be the only op in its phase-1 window.
    pub fn open_window_has_ops(&self) -> bool {
        !self.window_ops.is_empty()
    }

    /// The on-chain window (Counter B) a per-tick batch (Counter A) settled into, if still
    /// mapped. `None` once pruned (its window settled more than the grace period ago, or the
    /// size cap evicted it), or for an unknown/future tick.
    pub fn window_for_tick(&self, tick_batch: u64) -> Option<u64> {
        self.tick_window.get(&tick_batch).copied()
    }

    /// Evict the oldest tick→window entries beyond the hard cap (a leak backstop; the primary
    /// bound is `prune_tick_window_settled` on window settle).
    fn enforce_tick_window_cap(&mut self) {
        while self.tick_window.len() > TICK_WINDOW_MAX {
            let oldest = *self.tick_window.keys().next().expect("non-empty above cap");
            self.tick_window.remove(&oldest);
        }
    }

    /// Prune the tick→window map on WINDOW settle (Counter B), keeping entries whose window is
    /// within `TICK_WINDOW_GRACE_WINDOWS` of `settled_batch_count` (the on-chain batchCount AFTER
    /// the settle) so a settled tick's window stays queryable for a grace period. Unsettled
    /// windows (`w >= settled_batch_count`) are always kept.
    pub fn prune_tick_window_settled(&mut self, settled_batch_count: u64) {
        let cutoff = settled_batch_count.saturating_sub(TICK_WINDOW_GRACE_WINDOWS);
        self.tick_window.retain(|_, w| *w >= cutoff);
    }

    /// Read access to a market's order book (inspection / tests).
    pub fn book(&self, market_id: MarketId) -> Option<&matcher::OrderBook<Keccak256>> {
        self.matcher.book(market_id)
    }

    pub fn finality_of(&self, order_hash: &Digest) -> Option<Finality> {
        self.finality.get(order_hash).copied()
    }

    /// Issue (or re-issue) the signed receipt for an order. **Idempotent**: the
    /// first call assigns the order a sequencer-owned `seq_no` and records it; any
    /// later call for the same order rebuilds the SAME receipt (same seq). This is
    /// what keeps `accept_order` and `seal_batch` from emitting two receipts with
    /// different seqs for one order. The seq is owned by the sequencer, not the
    /// matcher (whose internal seq is only book-priority).
    fn issue_receipt(&mut self, order_hash: Digest, now_ms: u64) -> SignedReceipt {
        let seq_no = match self.inclusion.get(&order_hash) {
            Some(rec) => rec.seq_no,
            None => {
                let seq = self.next_receipt_seq;
                self.next_receipt_seq += 1;
                self.inclusion.insert(
                    order_hash,
                    InclusionRecord {
                        seq_no: seq,
                        issued_batch: self.next_batch_id,
                        seen_in_batch: None,
                    },
                );
                seq
            }
        };
        let receipt = Receipt {
            order_hash,
            seq_no,
            recv_time_ms: now_ms,
            batch_id_hint: self.next_batch_id,
            window_id: self.state.next_batch_id,
        };
        let digest = receipt.signing_digest::<Keccak256>();
        let (signature, recid) = self
            .enclave
            .signing
            .sign_prehash_recoverable(&digest)
            .expect("sign");
        let sig_bytes = signature.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);
        self.finality
            .entry(order_hash)
            .or_insert(Finality::Accepted);
        SignedReceipt {
            receipt,
            r,
            s,
            v: 27 + recid.to_byte(),
            enclave_address: self.enclave.address,
        }
    }

    /// Accept an order immediately and return its signed receipt (§2 ACCEPTED),
    /// independent of when/whether it is later included in a batch. This is the
    /// honest enclave's instant acknowledgement; a subsequent failure to include
    /// the order in a manifest within the timeout is an inclusion violation
    /// (censorship/withholding) detectable via [`Sequencer::inclusion_violations`].
    /// The receipt's `seq_no` is the authoritative sequencer seq and is preserved
    /// if the same order is later sealed.
    pub fn accept_order(&mut self, order: &Order, now_ms: u64) -> SignedReceipt {
        let order_hash = order.order_hash::<Keccak256>();
        self.issue_receipt(order_hash, now_ms)
    }

    /// Pre-trade risk (§12, Phase 3): would this order, filled in full at the
    /// oracle mark, leave the trader above initial margin? Reducing/closing
    /// orders always pass. Rejecting here — *before* matching — guarantees no fill
    /// can match-but-fail-to-settle, so `ordered`/`rejected` stay honest (§2).
    ///
    /// The funding index is read through [`perp_core::funding::FundingState::index_at`]
    /// at `now_ms`: a fill first commits the market's open funding span up to its
    /// own time, so after a pause the trader's equity already carries the pause's
    /// funding, and this check must see the same index the fill will.
    ///
    /// An order that adds exposure must also reach [`MIN_ORDER_NOTIONAL`]
    /// ([`below_minimum_order_notional`]); otherwise it is refused with
    /// [`RejectReason::BelowMinimumSize`]. While the engine is close-only, an order
    /// that adds exposure is refused with [`RejectReason::MarketCloseOnly`], the
    /// engine's own rule.
    ///
    /// This is the check for an order on its own, against its owner's committed
    /// position. [`Sequencer::seal_batch`] applies the same check to each order of a
    /// batch, also against the position after the owner's earlier orders of the
    /// batch.
    pub fn pre_trade_check(&self, order: &Order, now_ms: u64) -> Result<(), RejectReason> {
        self.admission(order, now_ms, 0).map(|_| ())
    }

    /// [`Sequencer::pre_trade_check`] for an order whose owner already has orders
    /// of net signed size `earlier` admitted in this market in the same batch. The
    /// minimum and the close-only rule are judged against the committed position and
    /// against that position after the earlier orders fill in full; the order adds
    /// exposure if it does so against either. Returns whether the order was admitted
    /// below the minimum because it reduces (settlement then holds it to that).
    fn admission(
        &self,
        order: &Order,
        now_ms: u64,
        earlier: i128,
    ) -> Result<Admitted, RejectReason> {
        let Some(market) = self.state.markets.get(&order.market_id) else {
            // audit Tier-3: an unknown market is not a reduce-only violation.
            return Err(RejectReason::InvalidOrder);
        };
        let Some(oracle) = self.oracles.get(&order.market_id) else {
            return Err(RejectReason::OracleUnavailable);
        };
        let mark = oracle
            .validate(market, now_ms)
            .map_err(|_| RejectReason::OracleUnavailable)?;
        let funding_index = self.funding_index_at(order.market_id, mark, now_ms);
        let base = self
            .state
            .position(&order.owner, order.market_id)
            .copied()
            .unwrap_or_else(|| Position::empty(order.owner, order.market_id));
        let mut projected = base;
        projected.size = base.size.saturating_add(earlier);
        // audit DP-009 (adversarial-review follow-up): reject a reduce_only order that
        // would OPEN or GROW the owner's position BEFORE matching — otherwise the matcher
        // consumes a counterparty's resting liquidity for a fill that is then dropped at
        // settlement, destroying that liquidity and mis-tagging the innocent maker.
        if order.reduce_only && base.increases_exposure(order.signed_size()) {
            return Err(RejectReason::ReduceOnlyViolation);
        }
        let adds_exposure = base.increases_exposure(order.signed_size())
            || projected.increases_exposure(order.signed_size());
        if self.state.mode == Mode::CloseOnly && adds_exposure {
            return Err(RejectReason::MarketCloseOnly);
        }
        let minimum_applies = self.minimum_exempt_owner != Some(order.owner);
        if minimum_applies
            && (below_minimum_order_notional(&base, order, mark)
                || below_minimum_order_notional(&projected, order, mark))
        {
            return Err(RejectReason::BelowMinimumSize);
        }
        if !base.fits_initial_after(market, order.signed_size(), mark, funding_index) {
            return Err(RejectReason::InsufficientMargin);
        }
        Ok(Admitted {
            below_minimum_exempt: minimum_applies
                && !order.reduce_only
                && under_minimum_notional(order, mark),
        })
    }

    /// The funding index an op on `market_id` at `now_ms` reads, with the validated
    /// oracle `index_price`: the stored index with the open span committed up to
    /// `now_ms` ([`perp_core::funding::FundingState::index_at`]), exactly what the
    /// engine's `Fill`, `Liquidate` and `Unbind` compute. 0 for a market with no
    /// funding state (the engine refuses such a market).
    fn funding_index_at(&self, market_id: MarketId, index_price: i128, now_ms: u64) -> i128 {
        self.state
            .funding
            .get(&market_id)
            .map_or(0, |f| f.index_at(index_price, now_ms))
    }

    /// The impact-notional book mid of `market_id` at `now_ms`: the midpoint of the
    /// average prices at which [`FUNDING_IMPACT_NOTIONAL`] would fill against the
    /// bids and against the asks. Only depth the engine could fill counts: a
    /// resting order inside the market's fill band around the validated index
    /// whose maker could settle the fill. `None` when either side holds less than
    /// that within its first [`FUNDING_IMPACT_MAX_ORDERS`] in-band orders, or when
    /// the market's oracle does not validate at `now_ms`.
    pub fn impact_mid(&self, market_id: MarketId, now_ms: u64) -> Option<i128> {
        let market = self.state.markets.get(&market_id)?;
        let index = self
            .oracles
            .get(&market_id)?
            .validate(market, now_ms)
            .ok()?;
        self.impact_mid_at(market, index, now_ms)
    }

    /// [`Sequencer::impact_mid`] at the validated oracle `index`.
    fn impact_mid_at(&self, market: &Market, index: i128, now_ms: u64) -> Option<i128> {
        let bid = self.impact_price(market, index, Side::Buy, now_ms)?;
        let ask = self.impact_price(market, index, Side::Sell, now_ms)?;
        Some(book_mid(bid, ask))
    }

    /// The impact price of one side of `market`'s book at the validated oracle
    /// `index`: the bids for [`Side::Buy`], the asks for [`Side::Sell`]. A resting
    /// order counts as depth only if the engine could fill it now: its price lies
    /// inside the market's fill band around the index ([`within_fill_band`]), and
    /// its maker could settle the fill ([`maker_fill_settles`]), taking the maker's
    /// orders met earlier in the sweep as filled first. A quote nothing could
    /// trade against therefore cannot move the funding mark; in particular an
    /// order admitted below the minimum because it reduced counts only while it
    /// still reduces, so stacking such orders gives no depth beyond the maker's
    /// position. The sweep walks only the levels inside the fill band and visits
    /// at most [`FUNDING_IMPACT_MAX_ORDERS`] orders; a side that needs more has no
    /// impact price.
    fn impact_price(&self, market: &Market, index: i128, side: Side, now_ms: u64) -> Option<i128> {
        let book = self.matcher.book(market.id)?;
        // the fill band as a price range: |price − index| · RATE_SCALE <= ratio · index
        let reach = market.max_fill_deviation_ratio.checked_mul(index)? / RATE_SCALE;
        let window = ImpactWindow {
            lo: index.checked_sub(reach)?,
            hi: index.checked_add(reach)?,
            max_orders: FUNDING_IMPACT_MAX_ORDERS,
        };
        let funding_index = self.funding_index_at(market.id, index, now_ms);
        let close_only = self.state.mode == Mode::CloseOnly;
        // each maker's position after the fills of its orders counted so far
        let mut staged: BTreeMap<PubKey, Position> = BTreeMap::new();
        book.impact_price_within(side, FUNDING_IMPACT_NOTIONAL, now_ms, window, |quote| {
            if !within_fill_band(market, index, quote.price) {
                return false;
            }
            // the maker buys against a resting bid and sells against a resting ask
            let delta = match side {
                Side::Buy => quote.remaining,
                Side::Sell => -quote.remaining,
            };
            let position = staged.get(&quote.owner).copied().unwrap_or_else(|| {
                self.state
                    .position(&quote.owner, market.id)
                    .copied()
                    .unwrap_or_else(|| Position::empty(quote.owner, market.id))
            });
            match maker_fill_settles(
                &position,
                market,
                quote,
                delta,
                index,
                funding_index,
                close_only,
                self.minimum_exempt.contains(&quote.order_hash),
            ) {
                Some(after) => {
                    staged.insert(quote.owner, after);
                    true
                }
                None => false,
            }
        })
    }

    /// This tick's funding-premium sample for `market`: the impact mid minus the
    /// validated oracle index, capped at [`premium_cap`]. 0 (the index itself) when
    /// either side of the book lacks the impact depth or the oracle does not
    /// validate at `now_ms`.
    fn funding_premium_sample(
        &self,
        market: &Market,
        oracle: &OracleTranscript,
        now_ms: u64,
    ) -> i128 {
        #[cfg(test)]
        PREMIUM_SAMPLES.with(|n| n.set(n.get() + 1));
        let Ok(index) = oracle.validate(market, now_ms) else {
            return 0;
        };
        let cap = premium_cap(market, index);
        self.impact_mid_at(market, index, now_ms)
            .map_or(0, |mid| mid.saturating_sub(index).clamp(-cap, cap))
    }

    /// Take the funding-premium sample at `now_ms` for every market with an oracle,
    /// closing the span since each market's previous sample. Only the first sample
    /// at a given time counts: [`Sequencer::seal_batch`] takes it from the book the
    /// tick's takers face, before matching, and a later call at the same time
    /// changes nothing.
    fn sample_funding_premiums(&mut self, now_ms: u64) {
        let market_ids: Vec<MarketId> = self.state.markets.keys().copied().collect();
        for mid in market_ids {
            // A later sample at the newest sample's time (or earlier) would change
            // nothing, so it is not computed: `run_maintenance` within `seal_batch`
            // costs no second book walk.
            if self
                .funding_marks
                .get(&mid)
                .is_some_and(|window| window.sampled_since(now_ms))
            {
                continue;
            }
            let (Some(market), Some(oracle)) = (
                self.state.markets.get(&mid).copied(),
                self.oracles.get(&mid).copied(),
            ) else {
                continue;
            };
            let premium = self.funding_premium_sample(&market, &oracle, now_ms);
            self.funding_marks
                .entry(mid)
                .or_default()
                .observe(now_ms, premium);
        }
    }

    /// The funding mark for `market` at the validated oracle `index`: the index
    /// plus the window's time-averaged funding premium, capped at [`premium_cap`]
    /// (which lies inside the mark band, so the `AccrueFunding` op is always
    /// admissible). With no closed span yet in the window (its first tick) the mark
    /// is the index itself.
    fn funding_mark(&self, market: &Market, index: i128) -> i128 {
        let cap = premium_cap(market, index);
        let premium = self
            .funding_marks
            .get(&market.id)
            .map_or(0, FundingMarkWindow::average)
            .clamp(-cap, cap);
        index.saturating_add(premium)
    }

    /// Per-batch maintenance (§5, §8): accrue funding, then liquidate every
    /// position that is underwater at the oracle price. Runs regardless of user
    /// liveness — the enclave holds positions, so an offline user is still
    /// liquidated. Returns the liquidated owners and any auto-deleverage haircuts
    /// the cascade applied (audit Q2/Q7).
    ///
    /// **Funding mark.** Each tick samples, per market, the premium of the
    /// impact-notional book mid ([`Sequencer::impact_mid`]) over the validated
    /// oracle index, or 0 when either side lacks [`FUNDING_IMPACT_NOTIONAL`] of
    /// depth the engine could fill (within [`FUNDING_IMPACT_MAX_ORDERS`] orders of
    /// the fill band). [`Sequencer::seal_batch`] takes the sample from
    /// the book the tick's takers face, before it matches, and the sample prices
    /// the span since the previous tick. The `AccrueFunding` mark is the index plus
    /// the time-weighted average of those spans since the open window began (reset
    /// by [`Sequencer::seal_window`]), with each sample and the average capped at the
    /// premium that saturates the rate, and the average taken over at least
    /// [`FUNDING_MARK_MIN_SPAN_MS`]. So moving the mark takes fillable depth that
    /// takers can trade against, held over time: a quote withdrawn before the next
    /// tick never counts, a quote placed in a tick does not move that tick's mark,
    /// and one sample moves the mark by at most its share of the window. The engine
    /// still bounds the mark to the market's mark band and the rate to its clamp.
    ///
    /// Called on its own (outside `seal_batch`), it samples the book as it rests at
    /// `now_ms`.
    pub fn run_maintenance(&mut self, now_ms: u64) -> MaintenanceOutcome {
        // reap good-till-time makers that have expired before reading the book for
        // the funding mark — an expired order must not count as depth (§8), and
        // matching already refuses to trade against it. Within `seal_batch` the
        // sample at `now_ms` was taken before matching, so this one changes nothing.
        let removals = self.matcher.reap_expired_with_events(now_ms);
        self.sample_funding_premiums(now_ms);
        let mut liquidated = Vec::new();
        let mut adl: Vec<(PubKey, MarketId, i128)> = Vec::new();
        // The replayable op-log for this maintenance pass: every AccrueFunding/Liquidate
        // we actually apply is recorded here, in application order, so the proof can
        // reproduce the maintenance transition (Slice 3a). An op is pushed ONLY when its
        // application succeeded — a skipped/failed op must not enter the log or replay
        // would diverge.
        let mut ops: Vec<BatchOp> = Vec::new();
        let market_ids: Vec<MarketId> = self.state.markets.keys().copied().collect();
        for mid in market_ids {
            let Some(oracle) = self.oracles.get(&mid).copied() else {
                continue;
            };
            let Some(market) = self.state.markets.get(&mid).copied() else {
                continue;
            };
            // Neither funding nor liquidation runs on an oracle that does not
            // validate now; the engine would refuse both ops.
            let Ok(price) = oracle.validate(&market, now_ms) else {
                continue;
            };
            // funding accrual (best-effort: a refused op is not logged)
            let funding_op = BatchOp::AccrueFunding {
                market_id: mid,
                mark: self.funding_mark(&market, price),
                oracle,
                now_ms,
            };
            if self.state.apply_op(&funding_op).is_ok() {
                ops.push(funding_op);
            }
            // liquidation pass at the oracle price, against the index the engine's
            // Liquidate reads (the open span committed up to now)
            let funding_index = self.funding_index_at(mid, price, now_ms);
            let candidates: Vec<PubKey> = self
                .state
                .positions
                .iter()
                .filter(|((_, m), p)| {
                    *m == mid && p.is_open() && p.is_liquidatable(&market, price, funding_index)
                })
                .map(|((o, _), _)| *o)
                .collect();
            for owner in candidates {
                if let Ok(haircuts) = self.state.liquidate(&owner, mid, &oracle, now_ms) {
                    liquidated.push((owner, mid));
                    // `state.liquidate` is the SAME transition as `BatchOp::Liquidate`
                    // (both dispatch to `op_liquidate`, incl. the ADL cascade), so record
                    // the op right where it was applied — after this market's funding op
                    // and in owner order — to keep the log's order == application order.
                    ops.push(BatchOp::Liquidate {
                        owner,
                        market_id: mid,
                        oracle,
                        now_ms,
                    });
                    // Carry each auto-deleverage haircut up with its market so the
                    // seal can publish an attributable receipt for it (audit Q2).
                    for h in haircuts {
                        adl.push((h.owner, mid, h.clawed));
                    }
                }
            }
        }
        MaintenanceOutcome {
            removals,
            liquidated,
            adl,
            ops,
        }
    }

    /// Run one batch: match `orders`, issue receipts, settle fills, run the
    /// funding+liquidation maintenance pass, publish a manifest, advance finality,
    /// and update inclusion tracking.
    pub fn seal_batch(&mut self, orders: &[Order], now_ms: u64) -> SealedBatch {
        let prev_state_root = self.state.state_root();
        let batch_id = self.next_batch_id;

        // snapshot the pre-batch (state, matcher) so this batch can be rolled back
        // if it later fails to prove (§3 failure matrix). Skipped in window-settle
        // mode: nothing on the window path consumes per-tick snapshots, and without
        // the legacy tick-loop prune each one is a full state clone retained until
        // the window's ~13-min proof lands (Task 5 fix round 1).
        if self.retain_tick_snapshots {
            self.snapshots
                .insert(batch_id, (self.state.clone(), self.matcher.clone()));
        }

        // 0. pre-trade risk gate: drop unmarginable orders before matching, so a
        //    matched fill can never fail to settle on margin (§12, Phase 3).
        let mut pre_rejected: Vec<(Digest, RejectReason)> = Vec::new();
        let mut admitted: Vec<Order> = Vec::new();
        // owners with an already-admitted order for a market this batch. A reduce_only order
        // whose owner is here could have its position shift intra-batch (via that earlier
        // order's fill) and then OPEN at settlement — where the drop would consume an innocent
        // maker's resting depth. Reject it up front instead (audit DP-009 review follow-up); the
        // owner can resubmit in a later batch. The pre-trade gate below handles the pre-batch case.
        let mut owners_with_order: BTreeSet<(PubKey, MarketId)> = BTreeSet::new();
        // the net signed size of each owner's orders admitted so far this batch, per
        // market: the minimum and the close-only rule also judge an order against the
        // position after these fill in full
        let mut earlier: BTreeMap<(PubKey, MarketId), i128> = BTreeMap::new();
        // orders below the minimum admitted only because they reduce: the ones
        // resting from earlier batches plus this batch's
        let mut minimum_exempt = self.minimum_exempt.clone();
        for o in orders {
            if o.reduce_only && owners_with_order.contains(&(o.owner, o.market_id)) {
                pre_rejected.push((
                    o.order_hash::<Keccak256>(),
                    RejectReason::ReduceOnlyViolation,
                ));
                continue;
            }
            let key = (o.owner, o.market_id);
            match self.admission(o, now_ms, earlier.get(&key).copied().unwrap_or(0)) {
                Ok(admitted_order) => {
                    owners_with_order.insert(key);
                    let net = earlier.entry(key).or_default();
                    *net = net.saturating_add(o.signed_size());
                    if admitted_order.below_minimum_exempt {
                        minimum_exempt.insert(o.order_hash::<Keccak256>());
                    }
                    admitted.push(*o);
                }
                Err(reason) => pre_rejected.push((o.order_hash::<Keccak256>(), reason)),
            }
        }

        // The funding-mark sample for the span that ends at this tick is the book
        // this tick's takers face: taken before matching, so only a quote still on
        // the book when this batch matches is weighed.
        self.sample_funding_premiums(now_ms);

        // 1. match, then DRY-RUN settlement against a probe clone before the book's
        //    mutation is allowed to stand (SEC-022 §6). The matcher consumes resting
        //    depth during `process_stream`, but settlement only discovers an
        //    out-of-band or bankrupting fill afterwards — so a rejected fill used to
        //    burn liquidity that never executed. On any ATTRIBUTABLE failure we
        //    restore the book, ban the offending order, and rematch. `MatchingEngine`
        //    is `Clone` and the restore carries `next_seq` with it, so the final pass
        //    assigns exactly the seq numbers the banned orders' absence would have
        //    produced. An offender need not be in `live` at all: a maker resting
        //    since an EARLIER batch (the drifted-Gtc case) survives the restore, so
        //    a ban also cancels the hash from the rematch base book — for a
        //    current-batch offender that cancel is a no-op (it never rested there).
        let mut rematch_base = self.matcher.clone();
        let mut live: Vec<Order> = admitted;
        let mut banned: Vec<(Digest, RejectReason)> = Vec::new();
        let mut banned_set: BTreeSet<Digest> = BTreeSet::new();
        let (stream, probe_outcome) = loop {
            let stream = self.matcher.process_stream(&live, now_ms);
            // no fills → nothing to probe (`settle_fills` over no fills is a no-op,
            // so its outcome is `FillSettlement::default()` and the state is left
            // untouched), which also spares the idle 700ms ticks the per-round
            // state clone.
            if stream.fills.is_empty() {
                break (stream, None);
            }
            let mut probe = self.state.clone();
            let probed = settle_fills(
                &mut probe,
                &self.oracles,
                &stream.fills,
                now_ms,
                &minimum_exempt,
            );
            if probed.offenders.is_empty() {
                // Clean: carry the probe state + its settlement out of the loop;
                // step 3 ADOPTS them instead of settling the same fills a second
                // time (whole-branch review I4).
                break (stream, Some((probe, probed)));
            }
            // Roll the book back to exactly where this batch started, drop the
            // offenders, and match again. Each offender carries the reason from
            // its own `settle_fills` push site — never looked up in `rejected`,
            // where an earlier fill of the same pass can have recorded the same
            // hash as an innocent counterparty with a different reason (I2).
            let banned_before = banned_set.len();
            for (oh, reason) in &probed.offenders {
                if banned_set.insert(*oh) {
                    banned.push((*oh, *reason));
                    // M3: a ban must make progress — the offender has to leave the
                    // next round's inputs, either cancelled from the batch-start
                    // book here (a maker resting since an earlier batch) or removed
                    // from `live` by the `retain` below (a current-batch order). If
                    // neither holds, the next round reproduces the same offender
                    // and trips the termination assert with a far less actionable
                    // message — fail loudly at the cause instead. Unreachable
                    // through the gateway today (per-account nonce monotonicity
                    // makes duplicate order hashes impossible), but the library
                    // API does not enforce that.
                    let cancelled = rematch_base.cancel_order(oh).is_some();
                    assert!(
                        cancelled || live.iter().any(|o| o.order_hash::<Keccak256>() == *oh),
                        "ban made no progress: offender {oh:?} neither rests in the \
                         batch-start book nor is a live order of this batch",
                    );
                }
            }
            // Termination, made explicit: every round that reaches here bans at least
            // one NEW hash — an already-banned order can appear in no fill, because a
            // banned taker was removed from `live` and a banned resting maker was
            // cancelled from the rematch base. The bannable set is finite (this
            // batch's admitted orders + the makers resting at batch start), so the
            // loop runs at most once per member of it.
            assert!(
                banned_set.len() > banned_before,
                "rematch loop must terminate: a round that produced offenders banned no new order",
            );
            live.retain(|o| !banned_set.contains(&o.order_hash::<Keccak256>()));
            self.matcher = rematch_base.clone();
        };

        // 2. issue signed receipts for every accepted (non-rejected) order in the
        //    FINAL stream. A banned order never entered the book on that pass, so it
        //    gets no receipt — it is resolved in `manifest.rejected` (bound by
        //    `manifest_hash`) instead, which step 5b already treats as a justified
        //    rejection rather than censorship.
        let mut receipts = Vec::new();
        for p in &stream.processed {
            if !matches!(p.outcome.status, SubmitStatus::Rejected(_)) {
                receipts.push(self.issue_receipt(p.outcome.order_hash, now_ms));
            }
        }

        // 3. adopt the dry-run as the committed settlement (I4). The probe ran
        //    `settle_fills` — deterministic in exactly (state, oracles, fills,
        //    now_ms) — against a clone of the CURRENT pre-state with the final
        //    stream's fills, and nothing since has mutated `self.state`: the only
        //    code between the probe and here is `issue_receipt`, which writes only
        //    `inclusion`/`finality`/`next_receipt_seq` and READS
        //    `state.next_batch_id`. Re-running the settlement against `self.state`
        //    (as this used to) could therefore only reproduce the identical result,
        //    at the cost of a second full pass on the per-tick hot path of a system
        //    whose proof RSS already scales with state size. Swapping the probe in
        //    IS the committed settlement; the old "committed pass must reproduce
        //    the dry run" assert is structurally unnecessary now — the loop's break
        //    condition (`probed.offenders.is_empty()`) is the guarantee, so
        //    `offenders` is dropped unread. A no-fills break settles nothing and
        //    leaves `self.state` untouched. See [`settle_fills`] for the
        //    failure-attribution rule; NON-attributable failures (no offender)
        //    still reject here, and an order all of whose recorded fills failed is
        //    moved out of `ordered` into `rejected` below. `ops` becomes the
        //    batch's replayable op-log: `[applied fills] ++ [maintenance ops]`, in
        //    application order (Slice 3a).
        let FillSettlement {
            applied_fills,
            mut ops,
            rejected: settlement_rejected,
            settled_order_hashes,
            offenders: _,
        } = match probe_outcome {
            Some((mut probe, probed)) => {
                std::mem::swap(&mut self.state, &mut probe);
                probed
            }
            None => FillSettlement::default(),
        };
        // Advance finality for every hash with a settled fill. Lives at the call
        // site (not in `settle_fills`) so a Task-7 probe run cannot touch the real
        // finality map; inserting once per deduped hash is identical to the old
        // per-fill insert of the same value.
        for oh in &settled_order_hashes {
            // A later partial fill must not rewrite an earlier hard-finality fact.
            // Clients separately track the unproven quantity of each tick.
            if self.finality.get(oh) != Some(&Finality::Settled) {
                self.finality.insert(*oh, Finality::Matched);
            }
        }

        // 3b. maintenance: accrue funding + liquidate underwater positions (§5,§8).
        //     Liquidating an owner also cancels its resting orders, so a
        //     bad-debt account can't leave stale makers that would fail to settle.
        let MaintenanceOutcome {
            mut removals,
            liquidated: liquidations,
            adl: adl_haircuts,
            ops: maintenance_ops,
        } = self.run_maintenance(now_ms);
        ops.extend(maintenance_ops);
        for (owner, _market) in &liquidations {
            removals.extend(self.matcher.cancel_owner_with_events(owner));
        }
        // Keep the minimum-exempt orders that still rest; the rest have filled,
        // been banned, expired or been cancelled with a liquidated owner.
        self.matcher.retain_resting(&mut minimum_exempt);
        self.minimum_exempt = minimum_exempt;

        removals.extend(
            stream
                .processed
                .iter()
                .flat_map(|p| p.outcome.removals.iter().copied()),
        );

        // 4. build the manifest, keeping `ordered`/`rejected` DISJOINT and HONEST.
        //    `rejected` = pre-trade rejects + dry-run BANS (attributable offenders,
        //    which never entered the final stream at all — a banned cross-batch
        //    resting maker was `ordered` in its own batch and is rejected here, the
        //    batch that discovered it) + matcher rejects + orders RECORDED against a
        //    failed fill (per the attribution rule in `settle_fills`) none of whose
        //    fills settled. An order with at least one settled fill (a partial
        //    multi-counterparty fill) stays in `ordered` — it really did trade.
        //    Orders moved here are removed from `ordered` below.
        let settled_set: std::collections::BTreeSet<Digest> =
            settled_order_hashes.iter().copied().collect();
        let mut failed_unsettled: Vec<(Digest, RejectReason)> = Vec::new();
        let mut seen_failed: std::collections::BTreeSet<Digest> = std::collections::BTreeSet::new();
        for (oh, reason) in &settlement_rejected {
            if !settled_set.contains(oh) && seen_failed.insert(*oh) {
                failed_unsettled.push((*oh, *reason));
            }
        }
        let reject_set: std::collections::BTreeSet<Digest> =
            failed_unsettled.iter().map(|(h, _)| *h).collect();
        let ordered: Vec<Digest> = stream
            .ordered
            .iter()
            .copied()
            .filter(|h| !reject_set.contains(h))
            .collect();
        let mut rejected = pre_rejected.clone();
        rejected.extend_from_slice(&banned);
        rejected.extend_from_slice(&stream.rejected);
        rejected.extend_from_slice(&failed_unsettled);
        let oracle_updates: Vec<Digest> = self
            .oracles
            .values()
            .map(|t| t.hash::<Keccak256>())
            .collect();
        let manifest = BatchManifest {
            previous_state_root: prev_state_root,
            batch_id,
            // A consistency summary only. Preserve the original operation times.
            batch_time_ms: perp_core::commitment::batch_time_ms(&ops),
            ordered,
            rejected,
            oracle_updates,
            matching_rule_version: self.matching_rule_version,
            enclave_measurement: self.enclave.measurement,
            sequencer_pubkey_epoch: self.enclave.epoch,
        };
        let manifest_hash = manifest.hash::<Keccak256>();

        // 5. inclusion tracking: mark every ordered hash as seen in this batch.
        for oh in &manifest.ordered {
            if let Some(rec) = self.inclusion.get_mut(oh) {
                if rec.seen_in_batch.is_none() {
                    rec.seen_in_batch = Some(batch_id);
                }
            }
        }
        // 5b. an order the sequencer REJECTED for cause is resolved, not withheld:
        //     it is committed in `manifest.rejected` (bound by manifest_hash), so the
        //     enclave demonstrably handled it. Clear any still-unseen inclusion record
        //     for it so `inclusion_violations` does not mistake a justified rejection
        //     (insufficient margin, post-only-would-take, FOK-unfillable, all-fills-
        //     failed) for censorship and trigger a wrongful slash. A record already
        //     `seen` in an earlier batch (a drifted resting maker) is left intact.
        for (oh, _) in &manifest.rejected {
            if self
                .inclusion
                .get(oh)
                .is_some_and(|rec| rec.seen_in_batch.is_none())
            {
                self.inclusion.remove(oh);
            }
        }
        self.batch_orders
            .insert(batch_id, settled_order_hashes.clone());
        // Record which on-chain window (Counter B) this per-tick batch (Counter A) settles
        // into, for off-chain receipt/inclusion reconciliation (Slice 3b-4). state.next_batch_id
        // is the open window and is stable across the window's ticks.
        self.tick_window.insert(batch_id, self.state.next_batch_id);
        self.enforce_tick_window_cap();

        // The per-window batch counter now advances once in `seal_window` (mirroring
        // apply_batch's single bump over the whole window op-log), NOT per tick — so
        // `state.next_batch_id` stays == the open window's batch_id across every tick.
        let new_state_root = self.state.state_root();
        self.next_batch_id += 1;

        // Publish privacy-preserving liquidation TAGS keyed on each account's
        // secret tag key (captured at fund time), not cleartext owners. If that
        // key is absent (a position funded outside this sequencer's `apply`,
        // never in normal operation), the tag falls closed onto `liq_fallback_key`
        // — a key derived from the enclave's secret salt, never the public owner
        // id — so it stays unlinkable to a known-pubkey observer.
        let liquidation_tags: Vec<Digest> = liquidations
            .iter()
            .map(|(owner, market)| {
                let tag_key = self
                    .liq_tag_keys
                    .get(owner)
                    .copied()
                    .unwrap_or_else(|| self.liq_fallback_key(owner));
                liquidation_tag(&tag_key, *market, batch_id)
            })
            .collect();

        // Publish each auto-deleverage haircut as a secret-keyed receipt the clawed
        // account can recognize, paired with the amount (audit Q2). Same fail-closed
        // fallback as above: an absent key falls onto `adl_fallback_key` (secret-salt
        // derived), never the public owner id.
        let adl_receipts: Vec<AdlReceipt> = adl_haircuts
            .iter()
            .map(|(owner, market, clawed)| {
                let tag_key = self
                    .adl_tag_keys
                    .get(owner)
                    .copied()
                    .unwrap_or_else(|| self.adl_fallback_key(owner));
                AdlReceipt {
                    tag: adl_tag(&tag_key, *market, batch_id),
                    clawed: *clawed,
                }
            })
            .collect();

        // Append this tick's ops + settled/rejected hashes to the open window's
        // accumulators, in application order. `seal_window` drains these into the
        // per-window `WindowWitness`; `ops`/`manifest` are still moved into `SealedBatch`
        // below (the internal per-tick record stays for rollback/inclusion).
        self.window_ops.extend_from_slice(&ops);
        self.window_ordered.extend_from_slice(&manifest.ordered);
        self.window_rejected.extend_from_slice(&manifest.rejected);

        SealedBatch {
            applied_fills,
            removals,
            batch_id,
            prev_state_root,
            new_state_root,
            manifest,
            manifest_hash,
            settled_order_hashes,
            settlement_rejected,
            receipts,
            liquidation_tags,
            adl_receipts,
            ops,
        }
    }

    pub fn remaining_order_size(&self, hash: &Digest) -> Option<i128> {
        self.matcher.remaining(hash)
    }

    /// Pending fill ticks are removed when a window settle hardens them on the
    /// gateway's window path, or when a void discards them (`void_window`,
    /// `void_open_window`). Its rollback_window retains them; mark_failed is a
    /// legacy-only API.
    pub fn fill_tick_pending(&self, tick: u64) -> bool {
        self.batch_orders.contains_key(&tick)
    }

    /// Fold boot-time ops into the genesis baseline: the deployed `GENESIS_ROOT` is
    /// `state.state_root()` AFTER boot funding + insurance seeding, so those ops are
    /// part of the trusted deploy-time genesis, not a pending window-0 op-log. Reset
    /// the window baseline to the current full state and drop the accumulated boot
    /// ops so window 0 opens FROM genesis — its `pre_state` root equals the deployed
    /// `GENESIS_ROOT` (otherwise the first settle submits the post-`add_market`,
    /// pre-funding baseline as `prev` and reverts with `BadPrevRoot`). Must NOT
    /// change `self.state` and must NOT bump `state.next_batch_id`: this closes no
    /// window, it only re-bases the open one.
    pub fn seal_genesis_baseline(&mut self) {
        // Drop every per-window accumulator `seal_window` would drain for the open
        // window (op-log + ordered/rejected manifest unions): the boot ops are baked
        // into the genesis root, not provable window-0 ops.
        self.window_ops.clear();
        self.window_ordered.clear();
        self.window_rejected.clear();
        // Re-open the window from the full boot state (== the deployed genesis).
        self.window_start_state = self.state.clone();
        // The funding-mark average runs over the open window, which opens here.
        self.funding_marks.clear();
    }

    /// SEC-025-B break 4: does the open window carry manifest content that must be
    /// settled even though the engine root has not moved? An accepted order that rests
    /// without crossing lands in `window_ordered` while changing no engine state (the
    /// book is matcher state, not `State`), and a settle is what publishes the ordered/
    /// rejected roots an inclusion challenge is answered from. Deliberately keyed on
    /// the ordered/rejected manifest unions ONLY — never `window_ops`, which grows a
    /// zero-delta `AccrueFunding` op on ordinary idle ticks — so a window empty of
    /// user submissions still settles nothing and idle ticks burn no proofs.
    pub fn window_has_pending_manifest(&self) -> bool {
        !self.window_ordered.is_empty() || !self.window_rejected.is_empty()
    }

    /// SEC-025-C: does the open window carry staged ops in its op-log? Complements
    /// `window_has_pending_manifest` — boot funding stages `Deposit` ops in
    /// `window_ops` (via `apply`), never the ordered/rejected manifest, so the
    /// manifest probe alone cannot observe ops staged after `seal_genesis_baseline`.
    /// A production genesis must leave BOTH empty, or the first settle's witness
    /// pre-state would not be the deployed GENESIS_ROOT. Read-only accessor so the
    /// field itself stays private.
    pub fn window_has_staged_ops(&self) -> bool {
        !self.window_ops.is_empty()
    }

    /// SettleAll requires a phase-1 proof even when it leaves the engine root
    /// unchanged. Ordinary zero-delta ops must not force idle proofs. This is
    /// intent only: the prover still rejects mixed or duplicate phase windows.
    pub fn window_has_pending_settle_all(&self) -> bool {
        self.window_ops
            .iter()
            .any(|op| matches!(op, BatchOp::SettleAll))
    }

    /// SEC-025-C (unbacked-mint refusal tests): the number of ops staged in the
    /// open window's op-log. `state_root()` commits only `perp_core::State`, so a
    /// "refused call mutated nothing" assertion cannot observe a stray op pushed
    /// into the window log through the root alone — it must count the log
    /// directly. Read-only accessor so the field itself stays private.
    /// Drop only unreceipted funding-only no-ops whose complete canonical state
    /// equals the window baseline. No batch counter is advanced and no user intent,
    /// withdrawal or terminal operation can enter this branch. This prevents an
    /// idle period from accumulating old clock witnesses without burning proofs.
    pub fn discard_idle_funding_window(&mut self) -> bool {
        if self.window_ops.is_empty()
            || self.window_has_pending_manifest()
            || self
                .window_ops
                .iter()
                .any(|op| !matches!(op, BatchOp::AccrueFunding { .. }))
            || self.state.state_root() != self.window_start_state.state_root()
        {
            return false;
        }
        self.window_ops.clear();
        true
    }

    /// Seal the open window only when it is empty: no operation, no manifest entry
    /// and a state equal to the window baseline. This is the gateway's liveness
    /// keepalive. An empty window has batch time 0 and no timed operation, so it
    /// registers untimed, and replaying it only advances the batch counter.
    /// Returns `None` and changes nothing when the window holds anything.
    pub fn seal_empty_window(&mut self) -> Option<WindowWitness> {
        if !self.window_ops.is_empty()
            || self.window_has_pending_manifest()
            || self.state.state_root() != self.window_start_state.state_root()
        {
            return None;
        }
        Some(self.seal_window())
    }

    pub fn window_op_count(&self) -> usize {
        self.window_ops.len()
    }

    /// Close the current settle window: build the combined manifest over the window's
    /// accumulated ordered/rejected hashes, advance the batch counter once (mirroring
    /// `apply_batch`), drain the window op-log into the witness, and reopen a fresh
    /// window from the current (post-bump) state. `derive_roots(pre_state, ops, manifest)
    /// .new_state_root` equals the live state root after this call.
    ///
    /// Seal the exact execution log, including each operation's original clock
    /// and signed oracle. The manifest timestamp is only the maximum operation
    /// time; it is not proof of external time. Never refresh historical inputs
    /// from the live feed: a delayed proof or retry must replay the original state.
    pub fn seal_window(&mut self) -> WindowWitness {
        let batch_id = self.state.next_batch_id;
        // Commit observations actually used by these operations, not the mutable
        // live feed. This also preserves manifest identity on rollback/re-seal.
        let oracle_updates: Vec<Digest> = self
            .window_ops
            .iter()
            .filter_map(|op| match op {
                BatchOp::Fill { oracle, .. }
                | BatchOp::AccrueFunding { oracle, .. }
                | BatchOp::Liquidate { oracle, .. }
                | BatchOp::Unbind { oracle, .. } => Some(oracle.hash::<Keccak256>()),
                _ => None,
            })
            .collect();
        let now_ms = perp_core::commitment::batch_time_ms(&self.window_ops);
        let manifest = BatchManifest {
            previous_state_root: self.window_start_state.state_root(),
            batch_id,
            batch_time_ms: now_ms,
            ordered: self.window_ordered.clone(),
            rejected: self.window_rejected.clone(),
            oracle_updates,
            matching_rule_version: self.matching_rule_version,
            enclave_measurement: self.enclave.measurement,
            sequencer_pubkey_epoch: self.enclave.epoch,
        };
        // the single per-window counter bump (mirrors apply_batch's engine.rs:156)
        self.state.next_batch_id += 1;
        // Prepare the post-bump baseline before draining anything, then move the
        // prior owned baseline into the witness instead of cloning it.
        let next_window_state = self.state.clone();
        let pre_state = core::mem::replace(&mut self.window_start_state, next_window_state);
        let ops = core::mem::take(&mut self.window_ops);
        self.window_ordered.clear();
        self.window_rejected.clear();
        // The next window's funding marks average only what that window observes:
        // no sample carries over, so the time the stack spends sealing and proving
        // (when nothing can trade against the book) never weighs in a mark.
        self.funding_marks.clear();
        WindowWitness {
            batch_id,
            pre_state,
            ops,
            manifest,
        }
    }

    /// Undo an optimistic `seal_window` whose off-chain settle failed: restore the
    /// per-window counter and re-inject the failed window's ops/orders AHEAD of anything the
    /// 700ms tick loop appended since the seal, and restore the window baseline. The next
    /// `seal_window` then re-seals `[failed ops ++ intervening ops]` from the old baseline
    /// under the SAME batch_id (== the unchanged on-chain batchCount) — no op is lost and the
    /// desync guard is satisfied. Leaves the per-tick soft-finality (Counter A / snapshots /
    /// finality / inclusion) untouched.
    pub fn rollback_window(&mut self, w: &WindowWitness) {
        debug_assert_eq!(self.state.next_batch_id, w.batch_id + 1, "rollback_window is at-most-once: expects exactly one un-settled seal (Counter B == batch_id+1) — a double rollback or stale-witness rollback trips this");
        // seal_window bumped Counter B once; ticks never touch it, so restore the pre-seal id.
        self.state.next_batch_id = w.batch_id;
        // prepend the failed window's ops/orders before anything accumulated since the seal.
        let mut ops = w.ops.clone();
        ops.append(&mut self.window_ops);
        self.window_ops = ops;
        let mut ordered = w.manifest.ordered.clone();
        ordered.append(&mut self.window_ordered);
        self.window_ordered = ordered;
        let mut rejected = w.manifest.rejected.clone();
        rejected.append(&mut self.window_rejected);
        self.window_rejected = rejected;
        // Intervening ticks' ops now belong to W, not W+1. Rebind immediately so
        // a reseal with no additional tick can still harden their fill quantities.
        for window in self.tick_window.values_mut() {
            if *window == w.batch_id + 1 {
                *window = w.batch_id;
            }
        }
        // restore the window baseline (seal_window re-captured it to the post-bump state).
        self.window_start_state = w.pre_state.clone();
    }

    /// The state the open window started from: the witness pre-state of the next
    /// `seal_window`. After a window settles it is the settled state.
    pub fn window_baseline(&self) -> &DefaultState {
        &self.window_start_state
    }

    /// The open window's rejected order hashes with their reasons, in manifest
    /// order: what the next `seal_window` publishes as `manifest.rejected`.
    pub fn window_rejected(&self) -> &[(Digest, RejectReason)] {
        &self.window_rejected
    }

    /// The checks [`Self::void_window`] makes before it changes anything, made
    /// without changing anything.
    ///
    /// The witness must be the one sealed, unsettled window: the window counter
    /// (Counter B) is `w.batch_id + 1` and `w.pre_state` opens `w.batch_id`. And
    /// no tick still pending a settle may belong to a window below `w.batch_id`.
    /// Every such window has settled, and its settle hardened its ticks, so the
    /// ticks still pending are exactly the ones the void discards. A tick that no
    /// window maps counts as one of them.
    pub fn void_preconditions(&self, w: &WindowWitness) -> Result<(), VoidError> {
        if w.batch_id.checked_add(1) != Some(self.state.next_batch_id)
            || w.pre_state.next_batch_id != w.batch_id
        {
            return Err(VoidError::NotTheSealedWindow {
                counter_b: self.state.next_batch_id,
                batch_id: w.batch_id,
            });
        }
        match self
            .batch_orders
            .keys()
            .find(|tick| !self.tick_in_windows_from(**tick, w.batch_id))
        {
            Some(tick) => Err(VoidError::UnhardenedEarlierTick(*tick)),
            None => Ok(()),
        }
    }

    /// Discard a sealed window that can never settle, and everything the open
    /// window gathered since it was sealed. Unlike [`Self::rollback_window`] no op is
    /// kept: the state, the window baseline and the window counter return to
    /// `w.pre_state`.
    ///
    /// The fills go with the state. Every tick still pending a settle is
    /// discarded, so no later window settle can harden its fills: the order
    /// hashes those ticks filled keep no `Matched` finality (it returns to
    /// `Accepted`; a `Settled` finality from an earlier window is kept). Every
    /// returned hash also leaves the book, the minimum-size exemptions and
    /// inclusion tracking. That covers the orders the windows ordered or
    /// rejected and the makers from earlier windows that a discarded fill
    /// touched, whose remainder the book no longer matches with the restored
    /// state. The caller publishes the hashes as rejected in a later manifest.
    ///
    /// Every check runs first ([`Self::void_preconditions`]); on `Err` nothing
    /// changed. Counter A, the receipt sequence and the oracles do not move.
    #[must_use = "the voided order hashes must be published in a later manifest"]
    pub fn void_window(&mut self, w: &WindowWitness) -> Result<VoidedWindow, VoidError> {
        self.void_preconditions(w)?;
        let mut hashes: Vec<Digest> = w.manifest.ordered.clone();
        hashes.extend(w.manifest.rejected.iter().map(|(h, _)| *h));
        hashes.extend(self.discard_open_window_manifest());
        let voided = self.discard_unsettled_ticks(w.batch_id, hashes);
        self.window_ops.clear();
        self.state = w.pre_state.clone();
        self.window_start_state = w.pre_state.clone();
        self.forget_windows_from(w.batch_id);
        self.funding_marks.clear();
        Ok(voided)
    }

    /// Discard the open window: the state returns to the window baseline (the
    /// last sealed, and after a settle the settled, state) and the window's ops
    /// and manifest are dropped. The window counter does not move.
    ///
    /// The open window's pending ticks are discarded as in
    /// [`Self::void_window`], with the same book, finality, exemption and
    /// inclusion cleanup for the returned hashes: the window's ordered and
    /// rejected hashes, then the hashes its discarded ticks filled.
    #[must_use = "the voided order hashes must be published in a later manifest"]
    pub fn void_open_window(&mut self) -> VoidedWindow {
        let window = self.state.next_batch_id;
        let hashes = self.discard_open_window_manifest();
        let voided = self.discard_unsettled_ticks(window, hashes);
        self.window_ops.clear();
        self.state = self.window_start_state.clone();
        self.forget_windows_from(window);
        self.funding_marks.clear();
        voided
    }

    /// Whether a pending tick belongs to window `window` or a later one. A tick
    /// that no window maps (its entry was evicted, or its window was discarded
    /// before) counts as one: it is pending, so no settle hardened it.
    fn tick_in_windows_from(&self, tick: u64, window: u64) -> bool {
        self.tick_window.get(&tick).is_none_or(|w| *w >= window)
    }

    /// Discard every pending tick of window `from_window` or later, and end the
    /// orders in `hashes` together with the orders those ticks filled. Each
    /// discarded tick leaves the pending set (and its rollback snapshot goes), so
    /// a later `mark_settled` never hardens its fills. Each hash leaves the book
    /// (and every retained snapshot's book), the minimum-size exemptions and
    /// inclusion tracking; a `Matched` finality returns to `Accepted`, as in
    /// [`Self::mark_failed`], and a `Settled` one is kept.
    fn discard_unsettled_ticks(
        &mut self,
        from_window: u64,
        mut hashes: Vec<Digest>,
    ) -> VoidedWindow {
        let ticks: BTreeSet<u64> = self
            .batch_orders
            .keys()
            .copied()
            .filter(|tick| self.tick_in_windows_from(*tick, from_window))
            .collect();
        for tick in &ticks {
            if let Some(filled) = self.batch_orders.remove(tick) {
                hashes.extend(filled);
            }
            self.snapshots.remove(tick);
        }
        let hashes = dedup_in_order(hashes);
        for hash in &hashes {
            let _ = self.matcher.cancel_order(hash);
            for (_, matcher) in self.snapshots.values_mut() {
                let _ = matcher.cancel_order(hash);
            }
            self.minimum_exempt.remove(hash);
            self.inclusion.remove(hash);
            if self.finality.get(hash) == Some(&Finality::Matched) {
                self.finality.insert(*hash, Finality::Accepted);
            }
        }
        VoidedWindow { hashes, ticks }
    }

    /// Record order hashes as rejected in the open window's manifest, after any
    /// rejection already there. Hashes the window already orders or rejects are
    /// skipped, so each hash appears at most once in the manifest.
    pub fn reject_in_window(&mut self, hashes: &[Digest], reason: RejectReason) {
        for hash in hashes {
            if self.window_ordered.contains(hash)
                || self.window_rejected.iter().any(|(h, _)| h == hash)
            {
                continue;
            }
            self.window_rejected.push((*hash, reason));
        }
    }

    fn discard_open_window_manifest(&mut self) -> Vec<Digest> {
        let mut hashes = core::mem::take(&mut self.window_ordered);
        hashes.extend(
            core::mem::take(&mut self.window_rejected)
                .into_iter()
                .map(|(h, _)| h),
        );
        hashes
    }

    /// Drop tick-to-window entries that point at `window` or later: those windows
    /// were discarded, so their ticks no longer settle anywhere.
    fn forget_windows_from(&mut self, window: u64) {
        self.tick_window.retain(|_, w| *w < window);
    }

    /// Mark a sealed batch — and every still-pending batch before it — as SETTLED
    /// (a ZK proof for this height verified on L1). Until this is called, the fills
    /// are only MATCHED — soft, not withdrawable (§3). A proof attests the state
    /// transition *through* `batch_id`, so it makes this batch AND everything
    /// before it hard: their rollback snapshots are pruned and their orders advance
    /// to SETTLED. Finalizing a height directly (without a per-batch call for each
    /// earlier batch) must therefore not strand an earlier batch at MATCHED — hard
    /// yet un-withdrawable would violate §3.
    pub fn mark_settled(&mut self, batch_id: u64) {
        // advance finality for this batch and every earlier one the proof hardens.
        let hardened: Vec<u64> = self
            .batch_orders
            .range(..=batch_id)
            .map(|(b, _)| *b)
            .collect();
        for b in hardened {
            if let Some(orders) = self.batch_orders.get(&b) {
                let ohs: Vec<Digest> = orders.clone();
                for oh in ohs {
                    self.finality.insert(oh, Finality::Settled);
                }
            }
        }
        // a proven batch can no longer be rolled back; drop snapshots ≤ batch_id.
        self.snapshots = self.snapshots.split_off(&(batch_id + 1));
        // its per-batch order list is now immutable settled history that neither
        // rollback nor re-settlement needs — drop it too so the map stays bounded.
        self.batch_orders = self.batch_orders.split_off(&(batch_id + 1));
    }

    /// Task 5: advance per-tick finality from an ON-CHAIN window settle (Counter B).
    /// A verified window proof attests every tick batch (Counter A) sealed into
    /// windows ≤ `window_id`, so harden through the NEWEST tick batch mapped
    /// at-or-before that window via `mark_settled` (which settles it and everything
    /// earlier). Scanning from the newest entry also covers the window-rollback
    /// interleaving: ticks sealed while a failed settle was proving map to W+1 in
    /// `tick_window`, but `rollback_window` folds their ops into window W's re-seal —
    /// they sit BELOW W's newest post-rollback tick, so the settle of W honestly
    /// hardens them too. No-op when no tick batch maps that far (e.g. a
    /// deposits-only window) — there is nothing new to harden.
    pub fn mark_window_settled(&mut self, window_id: u64) {
        let newest = self
            .tick_window
            .iter()
            .rev()
            .find(|&(_, w)| *w <= window_id)
            .map(|(a, _)| *a);
        if let Some(a) = newest {
            self.mark_settled(a);
        }
    }

    /// Roll back a sealed batch that FAILED to prove (§3 failure matrix): revert
    /// (state, matcher) to the snapshot taken before it, drop that batch and every
    /// later still-pending batch, and revert their orders from MATCHED back to
    /// ACCEPTED — those fills were never binding (only SETTLED is). Returns `true`
    /// if a rollback happened. The user can then force-exit against the last hard
    /// root (§6); an honest re-sequence can re-include the dropped orders.
    pub fn mark_failed(&mut self, batch_id: u64) -> bool {
        let Some((state, matcher)) = self.snapshots.get(&batch_id).cloned() else {
            return false; // already proven/pruned or never existed
        };
        // revert live state + matcher to before the failed batch
        self.state = state;
        self.matcher = matcher;
        // drop this and all later pending batches; revert their finality
        let dropped: Vec<u64> = self.snapshots.range(batch_id..).map(|(k, _)| *k).collect();
        for b in &dropped {
            if let Some(orders) = self.batch_orders.remove(b) {
                for oh in orders {
                    // a rolled-back fill is no longer matched; back to ACCEPTED
                    if self.finality.get(&oh) == Some(&Finality::Matched) {
                        self.finality.insert(oh, Finality::Accepted);
                    }
                }
            }
            self.snapshots.remove(b);
        }
        // un-see inclusion records that were marked seen in a dropped batch, so a
        // rolled-back order that is never re-included can still surface as an
        // inclusion violation (§2).
        for rec in self.inclusion.values_mut() {
            if rec.seen_in_batch.is_some_and(|seen| seen >= batch_id) {
                rec.seen_in_batch = None;
            }
        }
        // the next batch to seal is the failed one (re-sequence from here)
        self.next_batch_id = batch_id;
        true
    }

    /// Receipts whose order hash never appeared in a sealed manifest within
    /// `timeout` batches of issuance — the §2 inclusion violations that justify
    /// slashing / forced-exit. `now_batch` is the current batch height.
    pub fn inclusion_violations(&self, timeout: u64) -> Vec<Digest> {
        let now_batch = self.next_batch_id;
        self.inclusion
            .iter()
            .filter(|(_, rec)| {
                rec.seen_in_batch.is_none() && now_batch.saturating_sub(rec.issued_batch) >= timeout
            })
            .map(|(oh, _)| *oh)
            .collect()
    }
}

/// Keep the first occurrence of each hash, in order.
fn dedup_in_order(hashes: Vec<Digest>) -> Vec<Digest> {
    let mut seen = BTreeSet::new();
    hashes.into_iter().filter(|h| seen.insert(*h)).collect()
}

/// Overflow-safe midpoint of the two impact prices behind the funding mark. Halving
/// each side before summing keeps the mid from overflowing `i128` when an
/// unvalidated resting price sits near the type bound (audit DP-008): a plain
/// `(bid + ask) / 2` panics in a debug build and wraps in release. At most one unit
/// of precision is lost.
fn book_mid(bid: i128, ask: i128) -> i128 {
    (bid / 2).saturating_add(ask / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
    use perp_core::note::owner_from_spend_key;
    use perp_core::oracle::{oracle_digest, OracleSig};
    use perp_core::order::TimeInForce;
    use perp_core::{Note, RiskError};

    // ZK-001: a fixed dev oracle-publisher key every test transcript is signed with,
    // and the address its signatures recover to. A market whose `oracle_pubkey` is this
    // address admits these transcripts through the fail-closed §8 signature gate.
    fn oracle_key() -> SigningKey {
        SigningKey::from_bytes((&[7u8; 32]).into()).expect("valid dev scalar")
    }
    fn oracle_addr() -> [u8; 20] {
        // Recover through the REAL perp-core path (sign a fixed probe digest, then
        // recover) so it is byte-identical to what `validate` compares against.
        let probe = oracle_digest(0, 0, 0, 0, 0);
        OracleSig::sign(&oracle_key(), &probe)
            .recover(&probe)
            .expect("fresh signature recovers")
    }
    /// A conservative market whose `oracle_pubkey` is the shared test signer's address,
    /// so a transcript signed by [`signed_oracle`] clears the ZK-001 gate.
    fn test_market(id: MarketId) -> Market {
        let mut m = Market::conservative(id);
        m.oracle_pubkey = oracle_addr();
        m
    }
    /// A publisher-signed transcript for `market_id`, signed over the FINAL field values
    /// via `oracle_digest` (never hand-rolled) so it recovers to [`oracle_addr`].
    fn signed_oracle(
        market_id: MarketId,
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

    /// Each sample prices the span that ends at it, the first sample of a window
    /// only starts the clock, the first sample at a time stands, a time before the
    /// newest sample closes nothing, and the average divides by at least
    /// `FUNDING_MARK_MIN_SPAN_MS`.
    #[test]
    fn funding_mark_window_prices_each_span_by_the_sample_at_its_end() {
        let mut w = FundingMarkWindow::default();
        assert_eq!(w.average(), 0, "no sample yet");
        w.observe(1_000, 300);
        assert_eq!(
            (w.weighted, w.elapsed),
            (0, 0),
            "the first sample starts the clock"
        );
        assert_eq!(w.average(), 0);
        w.observe(1_000, 600);
        assert_eq!(
            w.last,
            Some((1_000, 300)),
            "the first sample at a time stands"
        );
        w.observe(2_000, -900);
        assert_eq!((w.weighted, w.elapsed), (-900_000, 1_000));
        assert_eq!(
            w.average(),
            -900_000 / i128::from(FUNDING_MARK_MIN_SPAN_MS),
            "1,000 ms of a short window count over the minimum span"
        );
        w.observe(9_000, 600);
        // −900 · 1,000 + 600 · 7,000 over 8,000 ms
        assert_eq!(w.average(), (4_200_000 - 900_000) / 8_000);
        let before = w;
        w.observe(8_000, 77);
        assert_eq!(w, before, "a time before the newest sample closes no span");
        w.observe(10_000, 10);
        assert_eq!(w.weighted, before.weighted + 10 * 1_000);
        assert_eq!(w.elapsed, before.elapsed + 1_000);
    }

    /// One tick computes each market's premium sample once: the maintenance pass
    /// inside `seal_batch` at the same time does not walk the book again, while a
    /// maintenance pass at a later time does.
    #[test]
    fn a_tick_samples_each_market_once() {
        let t = 10_000u64;
        let mut s = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
        s.add_market(test_market(0));
        s.set_oracle(
            0,
            signed_oracle(
                0,
                100_000 * PRICE_SCALE,
                t,
                PRICE_SCALE,
                100_000 * PRICE_SCALE,
            ),
        );
        let samples = || PREMIUM_SAMPLES.with(core::cell::Cell::get);
        let before = samples();
        let _ = s.seal_batch(&[], t);
        assert_eq!(samples() - before, 1, "seal_batch samples once");
        let window = s.funding_marks.clone();
        let _ = s.run_maintenance(t);
        assert_eq!(samples() - before, 1, "no second walk at the same time");
        assert_eq!(s.funding_marks, window);
        s.set_oracle(
            0,
            signed_oracle(
                0,
                100_000 * PRICE_SCALE,
                t + 700,
                PRICE_SCALE,
                100_000 * PRICE_SCALE,
            ),
        );
        let _ = s.run_maintenance(t + 700);
        assert_eq!(samples() - before, 2, "a later pass samples");
    }

    /// The premium cap is the smallest premium at which the engine's rate reaches
    /// its clamp, and it never exceeds the mark band.
    #[test]
    fn the_premium_cap_is_the_smallest_premium_that_saturates_the_rate() {
        use perp_core::funding::FundingState;
        let m = Market::conservative(0);
        for index in [
            100_000 * PRICE_SCALE,
            3_456 * PRICE_SCALE + 7,
            PRICE_SCALE / 3,
            1,
        ] {
            let cap = premium_cap(&m, index);
            assert!(cap <= mark_band(&m, index));
            if cap < mark_band(&m, index) {
                assert_eq!(
                    FundingState::funding_rate(index + cap, index),
                    perp_core::funding::MAX_FUNDING_RATE_PER_INTERVAL
                );
                assert_eq!(
                    FundingState::funding_rate(index - cap, index),
                    -perp_core::funding::MAX_FUNDING_RATE_PER_INTERVAL
                );
                assert!(
                    FundingState::funding_rate(index + cap - 1, index)
                        < perp_core::funding::MAX_FUNDING_RATE_PER_INTERVAL,
                    "one unit less does not saturate at {index}"
                );
            }
        }
        assert_eq!(premium_cap(&m, 100_000 * PRICE_SCALE), 50 * PRICE_SCALE);
        assert_eq!(premium_cap(&m, 0), 0);
        assert_eq!(premium_cap(&m, -5), 0);
        assert_eq!(
            premium_cap(&m, i128::MAX),
            0,
            "an overflowing band pins the index"
        );
    }

    /// The fill band is the engine's own bound: a fill at the band's edge settles,
    /// one unit beyond is refused.
    #[test]
    fn the_fill_band_matches_the_engine_bound() {
        let m = Market::conservative(0);
        let index = 100_000 * PRICE_SCALE;
        let edge = index * m.max_fill_deviation_ratio / RATE_SCALE;
        assert!(within_fill_band(&m, index, index));
        assert!(within_fill_band(&m, index, index + edge));
        assert!(within_fill_band(&m, index, index - edge));
        assert!(!within_fill_band(&m, index, index + edge + 1));
        assert!(!within_fill_band(&m, index, index - edge - 1));
        assert!(!within_fill_band(&m, index, i128::MIN));
        assert!(!within_fill_band(&m, i128::MAX, i128::MAX));
    }

    #[test]
    fn mark_band_matches_the_engine_bound_and_fails_toward_the_index() {
        let m = Market::conservative(0);
        let index = 100_000 * PRICE_SCALE;
        let band = mark_band(&m, index);
        assert_eq!(band, 5_000 * PRICE_SCALE, "5% of the index");
        // the engine's own check: |mark − index| · RATE_SCALE <= ratio · index
        assert!(band * RATE_SCALE <= m.max_mark_deviation_ratio * index);
        assert!((band + 1) * RATE_SCALE > m.max_mark_deviation_ratio * index);
        assert_eq!(
            mark_band(&m, i128::MAX),
            0,
            "an overflow pins the mark to the index"
        );
    }

    /// The wind-down recipient is setup config: it lands in the window baseline,
    /// so the first window's witness pre-state binds it and replays.
    #[test]
    fn wind_down_recipient_is_part_of_the_window_baseline() {
        let mut seq = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
        seq.add_market(test_market(0));
        let unset = seq.state.state_root();
        seq.set_wind_down_recipient([0x5Au8; 20]);
        assert_eq!(seq.state.wind_down_recipient, [0x5Au8; 20]);
        assert_ne!(
            seq.state.state_root(),
            unset,
            "the recipient is a root word"
        );
        assert_eq!(
            seq.window_baseline().state_root(),
            seq.state.state_root(),
            "the baseline is re-captured with the recipient"
        );
        seq.seal_genesis_baseline();
        let genesis = seq.state.state_root();
        seq.set_oracle(
            0,
            signed_oracle(
                0,
                100_000 * PRICE_SCALE,
                now(),
                10 * PRICE_SCALE,
                100_000 * PRICE_SCALE,
            ),
        );
        fund(&mut seq, 1, 1_000, 0x11);
        let w = seq.seal_window();
        assert_eq!(w.pre_state.wind_down_recipient, [0x5Au8; 20]);
        assert_eq!(w.manifest.previous_state_root, genesis);
        let derived =
            perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest)
                .expect("the first window replays from the recipient-bound genesis");
        assert_eq!(derived.new_state_root, seq.state.state_root());
    }

    #[test]
    #[should_panic(expected = "set_wind_down_recipient must run before any window ops")]
    fn wind_down_recipient_cannot_be_set_mid_window() {
        let mut seq = test_sequencer(); // has funded two accounts in the open window
        seq.set_wind_down_recipient([0x5Au8; 20]);
    }

    // audit DP-008: an unvalidated resting price near the i128 bound must not overflow
    // the funding mark (a plain (bid+ask)/2 panics in debug / wraps in release).
    #[test]
    fn book_mid_is_overflow_safe_at_extreme_prices() {
        let m = book_mid(i128::MAX, i128::MAX);
        assert!(
            m > i128::MAX / 2,
            "an extreme two-sided book yields a large but finite mid"
        );
        // …and it stays a correct midpoint for normal prices
        assert_eq!(book_mid(100, 200), 150);
        assert_eq!(book_mid(-100, 100), 0);
    }

    /// SEC-022 §6: settlement assigned the SAME reason to BOTH order hashes. When the
    /// resting maker supplied the out-of-band price, rejecting the innocent taker is the
    /// larger unfairness — and the reduce_only arm directly above already follows the
    /// opposite (correct) rule. A bankruptcy is attributable to one leg; the band price
    /// comes from the resting maker (`matcher/book.rs:295`), so it is the maker's.
    #[test]
    fn a_failed_fill_is_attributed_to_the_offending_leg_only() {
        assert_eq!(
            offending_leg(&EngineError::FillWouldBankrupt(FillLeg::Taker)),
            Some(FillLeg::Taker),
        );
        assert_eq!(
            offending_leg(&EngineError::FillWouldBankrupt(FillLeg::Maker)),
            Some(FillLeg::Maker),
        );
        assert_eq!(
            offending_leg(&EngineError::FillPriceOutOfBand),
            Some(FillLeg::Maker),
            "the execution price is the resting maker's, not the taker's limit",
        );
        // Errors with no attributable leg still reject both, as before.
        assert_eq!(offending_leg(&EngineError::Overflow), None);
        assert_eq!(offending_leg(&EngineError::UnknownMarket), None);
    }

    /// SEC-024 (SEC-022 carry-in): a margin failure on a fill must name the leg, so
    /// the dry run bans the offender and rematches instead of recording both legs and
    /// burning the innocent counterparty's consumed liquidity.
    #[test]
    fn a_fill_margin_failure_names_the_offending_leg() {
        assert_eq!(
            offending_leg(&EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: Some(FillLeg::Maker),
            }),
            Some(FillLeg::Maker),
        );
        assert_eq!(
            offending_leg(&EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: Some(FillLeg::Taker),
            }),
            Some(FillLeg::Taker),
        );
        // A non-fill Risk (op_unbind) has no leg and must stay non-attributable.
        assert_eq!(
            offending_leg(&EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: None,
            }),
            None,
        );
    }

    /// The witness-shape and withdrawal-nonce errors have no specific manifest
    /// code: they are recorded under the honest catch-all, and none names a leg.
    #[test]
    fn shape_and_nonce_errors_map_to_the_catch_all() {
        for e in [
            EngineError::FundingStateInvalid,
            EngineError::PositionKeyMismatch,
            EngineError::WithdrawalNonceNotIncreasing,
            EngineError::InternalBurnNonceNotZero,
        ] {
            assert_eq!(settlement_reason(&e), RejectReason::InvalidOrder, "{e:?}");
            assert_eq!(offending_leg(&e), None, "{e:?}");
        }
        // a deposit refused in close-only reads as close-only
        assert_eq!(
            settlement_reason(&EngineError::CloseOnly),
            RejectReason::MarketCloseOnly
        );
    }

    /// The manifest reason must not change — a margin failure is still
    /// InsufficientMargin whether or not a leg is attached.
    #[test]
    fn settlement_reason_is_unchanged_by_the_leg() {
        for leg in [None, Some(FillLeg::Taker), Some(FillLeg::Maker)] {
            assert_eq!(
                settlement_reason(&EngineError::Risk {
                    source: RiskError::InsufficientMargin,
                    leg,
                }),
                RejectReason::InsufficientMargin,
            );
        }
    }

    // --- Slice 3b-4 harness (mirrors tests/spine.rs::setup) ---------------------

    fn now() -> u64 {
        1_000
    }

    fn owner_id(owner: u64) -> PubKey {
        owner_from_spend_key::<Keccak256>(&[owner as u8; 32])
    }

    /// Fund a trader: deposit a note and bind it to a market-0 position.
    fn fund(seq: &mut Sequencer, owner: u64, amount_usd: i128, blind: u8) {
        let o = owner_id(owner);
        let amount = amount_usd * QUOTE_SCALE;
        let cm = Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>();
        // SEC-019: test path — placeholder L1 binding; deposit_id reads the live consumed
        // count so the strict in-order gate passes across successive funds.
        let deposit_id = seq.state.consumed_deposit_count;
        seq.apply(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount,
            blinding: [blind; 32],
            from: [0u8; 20],
            deposit_id,
            deposit_blind: [0u8; 32],
        })
        .unwrap();
        seq.apply(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [owner as u8; 32],
        })
        .unwrap();
    }

    fn test_sequencer() -> Sequencer {
        let mut s = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
        s.add_market(test_market(0));
        s.set_oracle(
            0,
            signed_oracle(
                0,
                100_000 * PRICE_SCALE,
                now(),
                10 * PRICE_SCALE,
                100_000 * PRICE_SCALE,
            ),
        );
        fund(&mut s, 1, 20_000, 0x11);
        fund(&mut s, 2, 20_000, 0x22);
        s
    }

    fn t_order(owner: u64, side: Side, nonce: u64) -> Order {
        Order {
            owner: owner_id(owner),
            market_id: 0,
            side,
            size: SIZE_SCALE / 10,
            limit_price: 100_000 * PRICE_SCALE,
            tif: TimeInForce::Gtc,
            reduce_only: false,
            nonce,
            expiry_ms: 0,
            ciphertext_commit: word_u64(nonce.wrapping_mul(13)),
        }
    }

    /// A GTC order at an explicit limit price and size. `t_order` is pinned to
    /// $100k / 0.1 BTC; the SEC-022 §6 tests need makers resting away from the mark.
    fn t_order_at(owner: u64, side: Side, price_usd: i128, size: i128, nonce: u64) -> Order {
        Order {
            limit_price: price_usd * PRICE_SCALE,
            size,
            ..t_order(owner, side, nonce)
        }
    }

    /// A crossing maker/taker pair that settles a fill, with fresh nonces per call
    /// so consecutive ticks carry distinct orders.
    fn sample_orders(nonce_base: u64) -> Vec<Order> {
        vec![
            t_order(1, Side::Sell, nonce_base),
            t_order(2, Side::Buy, nonce_base + 1),
        ]
    }

    #[test]
    fn receipt_window_id_is_open_window_and_map_tracks_it() {
        let mut seq = test_sequencer();
        // window M = state.next_batch_id at the start.
        let m = seq.state.next_batch_id;
        let sealed0 = seq.seal_batch(&sample_orders(1), now());
        assert!(
            !sealed0.receipts.is_empty(),
            "the tick must issue receipts for the harness to be meaningful"
        );
        // every receipt issued this tick carries window_id == the open window M.
        for sr in &sealed0.receipts {
            assert_eq!(sr.receipt.window_id, m);
        }
        // the A→B map records this tick (Counter A) -> window M.
        assert_eq!(seq.window_for_tick(sealed0.batch_id), Some(m));
        // a second tick in the same window still maps to M and current_window_id == M.
        let sealed1 = seq.seal_batch(&sample_orders(3), now());
        assert_eq!(seq.window_for_tick(sealed1.batch_id), Some(m));
        assert_eq!(seq.current_window_id(), m);
        // close the window: Counter B advances; the next tick maps to M+1.
        let _w = seq.seal_window();
        assert_eq!(seq.current_window_id(), m + 1);
        let sealed2 = seq.seal_batch(&sample_orders(5), now());
        assert_eq!(seq.window_for_tick(sealed2.batch_id), Some(m + 1));
    }

    #[test]
    fn rollback_keeps_the_window_map_correct() {
        let mut seq = test_sequencer();
        let m = seq.state.next_batch_id;
        let s = seq.seal_batch(&sample_orders(1), now());
        let w = seq.seal_window(); // Counter B -> m+1
        seq.rollback_window(&w); // restore Counter B to m
        assert_eq!(seq.current_window_id(), m);
        // the failed window's ticks still map to m; re-sealing keeps them at m.
        assert_eq!(seq.window_for_tick(s.batch_id), Some(m));
    }

    /// A void ends the voided orders' minimum-size exemption and inclusion record
    /// and resets the funding-mark average, for a sealed window and for the open
    /// window alike. An order received but never sequenced is not touched.
    #[test]
    fn a_void_drops_minimum_exempt_inclusion_and_funding_marks_of_voided_orders() {
        let mut seq = test_sequencer();
        seq.seal_genesis_baseline();
        let fill = sample_orders(1);
        let _ = seq.seal_batch(&fill, now());
        // Trader 2 is now long; a sell below the minimum rests only because it
        // reduces.
        let tiny = t_order_at(2, Side::Sell, 101_000, SIZE_SCALE / 100_000, 3);
        let tiny_hash = tiny.order_hash::<Keccak256>();
        let _ = seq.seal_batch(&[tiny], now());
        assert!(seq.minimum_exempt.contains(&tiny_hash));
        assert!(seq.matcher.remaining(&tiny_hash).is_some());
        let unsequenced = t_order(1, Side::Buy, 9);
        let unsequenced_hash = unsequenced.order_hash::<Keccak256>();
        let _ = seq.accept_order(&unsequenced, now());
        let w = seq.seal_window();
        // The open window samples the book again before the void.
        let _ = seq.seal_batch(&[], now() + 700);
        assert!(!seq.funding_marks.is_empty());
        let hashes: Vec<Digest> = fill
            .iter()
            .chain([&tiny])
            .map(|o| o.order_hash::<Keccak256>())
            .collect();
        for h in &hashes {
            assert!(seq.inclusion.contains_key(h));
        }
        let voided = seq.void_window(&w).unwrap();
        for h in &hashes {
            assert!(voided.hashes.contains(h));
            assert!(!seq.inclusion.contains_key(h));
            assert!(!seq.minimum_exempt.contains(h));
        }
        assert!(seq.matcher.remaining(&tiny_hash).is_none());
        assert!(seq.funding_marks.is_empty());
        assert!(seq.batch_orders.is_empty());
        assert!(
            seq.snapshots.is_empty(),
            "the voided ticks' snapshots go too"
        );
        assert!(!voided.hashes.contains(&unsequenced_hash));
        assert!(seq.inclusion.contains_key(&unsequenced_hash));
        assert_eq!(seq.finality_of(&unsequenced_hash), Some(Finality::Accepted));
        // The open-window void resets the average the same way.
        let _ = seq.seal_batch(&[], now() + 1_400);
        assert!(!seq.funding_marks.is_empty());
        let voided = seq.void_open_window();
        assert!(voided.hashes.is_empty() && voided.ticks.len() == 1);
        assert!(seq.funding_marks.is_empty());
        assert!(seq.batch_orders.is_empty() && seq.snapshots.is_empty());
    }

    #[test]
    fn mark_settled_no_longer_prunes_the_window_map() {
        let mut seq = test_sequencer();
        let s = seq.seal_batch(&sample_orders(1), now());
        assert!(seq.window_for_tick(s.batch_id).is_some());
        seq.mark_settled(s.batch_id);
        // per-tick soft-finality is decoupled from the A→B map: the entry survives until
        // its WINDOW settles (`prune_tick_window_settled`) or the size cap evicts it —
        // soft-finality fires ~10x faster than the window horizon and must not drop it.
        assert!(seq.window_for_tick(s.batch_id).is_some());
    }

    // Task 5: an on-chain WINDOW settle (Counter B) is what hardens per-tick finality
    // on the real-proof path — every tick batch sealed into windows ≤ the settled
    // window advances MATCHED → SETTLED; ticks in a later window stay soft.
    #[test]
    fn mark_window_settled_hardens_through_window() {
        let mut seq = test_sequencer();
        // no tick batch sealed yet → the helper is a no-op (must not panic).
        seq.mark_window_settled(u64::MAX);
        let w = seq.current_window_id();
        // two tick batches in window W, each settling a crossing fill.
        let s0 = seq.seal_batch(&sample_orders(1), now());
        let s1 = seq.seal_batch(&sample_orders(3), now());
        assert!(!s0.settled_order_hashes.is_empty());
        assert!(!s1.settled_order_hashes.is_empty());
        for oh in s0
            .settled_order_hashes
            .iter()
            .chain(&s1.settled_order_hashes)
        {
            assert_eq!(seq.finality_of(oh), Some(Finality::Matched));
        }
        // close window W; a tick sealed after it belongs to window W+1.
        let _witness = seq.seal_window();
        let s2 = seq.seal_batch(&sample_orders(5), now());
        assert!(!s2.settled_order_hashes.is_empty());

        // window W's proof verified on L1 → both of W's tick batches harden…
        seq.mark_window_settled(w);
        for oh in s0
            .settled_order_hashes
            .iter()
            .chain(&s1.settled_order_hashes)
        {
            assert_eq!(seq.finality_of(oh), Some(Finality::Settled));
        }
        // …while the W+1 tick stays MATCHED (its window has not settled).
        for oh in &s2.settled_order_hashes {
            assert_eq!(seq.finality_of(oh), Some(Finality::Matched));
        }
    }

    // Task 5 fix round 1: in window-settle mode the per-tick rollback snapshots are
    // never consumed (mark_failed is legacy/test-only; window recovery is
    // rollback_window + window_start_state), and with the tick-loop simulation off
    // nothing prunes them until the window settles — so the gateway turns retention
    // off and seal_batch must skip the insert while every other piece of per-tick
    // bookkeeping (ids, receipts, finality, tick_window) advances identically.
    #[test]
    fn window_mode_skips_tick_rollback_snapshots() {
        // Legacy default: seal_batch retains one snapshot per tick…
        let mut seq = test_sequencer();
        let s0 = seq.seal_batch(&sample_orders(1), now());
        assert_eq!(seq.snapshots.len(), 1, "legacy default retains per tick");
        // …and mark_settled prunes it, exactly as before.
        seq.mark_settled(s0.batch_id);
        assert!(seq.snapshots.is_empty(), "legacy prune-on-settle unchanged");

        // Turning retention off also reclaims anything already held (covers a
        // persisted legacy snapshot restored into window mode).
        let s1 = seq.seal_batch(&sample_orders(3), now());
        assert_eq!(seq.snapshots.len(), 1);
        seq.set_retain_tick_snapshots(false);
        assert!(
            seq.snapshots.is_empty(),
            "disable reclaims retained entries"
        );

        // Window mode: several ticks, zero snapshots retained.
        let s2 = seq.seal_batch(&sample_orders(5), now());
        let s3 = seq.seal_batch(&sample_orders(7), now());
        assert!(
            seq.snapshots.is_empty(),
            "window mode must not retain per-tick rollback snapshots"
        );
        // All other per-tick bookkeeping advances identically.
        assert_eq!(s2.batch_id, s1.batch_id + 1);
        assert_eq!(s3.batch_id, s2.batch_id + 1);
        assert!(!s2.settled_order_hashes.is_empty());
        for oh in s2
            .settled_order_hashes
            .iter()
            .chain(&s3.settled_order_hashes)
        {
            assert_eq!(seq.finality_of(oh), Some(Finality::Matched));
        }
        let w = seq.current_window_id();
        assert_eq!(seq.window_for_tick(s2.batch_id), Some(w));
        assert_eq!(seq.window_for_tick(s3.batch_id), Some(w));

        // The window settle still hardens finality with no snapshots present
        // (mark_settled's prune tolerates the absent entries).
        let _witness = seq.seal_window();
        seq.mark_window_settled(w);
        for oh in s2
            .settled_order_hashes
            .iter()
            .chain(&s3.settled_order_hashes)
        {
            assert_eq!(seq.finality_of(oh), Some(Finality::Settled));
        }
    }

    #[test]
    fn mark_failed_no_longer_prunes_the_window_map() {
        let mut seq = test_sequencer();
        let s = seq.seal_batch(&sample_orders(1), now());
        assert!(seq.window_for_tick(s.batch_id).is_some());
        // a pre-batch snapshot exists for this batch, so the rollback must happen.
        assert!(seq.mark_failed(s.batch_id));
        // the mapping survives the per-tick rollback (the re-sealed tick maps to the same
        // still-open window); pruning is window-settle + size-cap only now.
        assert!(seq.window_for_tick(s.batch_id).is_some());
    }

    #[test]
    fn prune_tick_window_settled_keeps_grace_drops_old() {
        let mut seq = test_sequencer();
        seq.tick_window.insert(100, 2); // old settled window
        seq.tick_window.insert(101, 5); // still old (< cutoff)
        seq.tick_window.insert(104, 11); // one below cutoff -> dropped
        seq.tick_window.insert(105, 12); // exactly at cutoff -> kept
        seq.tick_window.insert(102, 15); // within grace
        seq.tick_window.insert(103, 25); // unsettled (>= count)
                                         // settled batchCount = 20, TICK_WINDOW_GRACE_WINDOWS = 8 -> cutoff = 12: keep
                                         // window >= 12. The w=11/w=12 probes straddle the exact boundary, so this test
                                         // fails if GRACE changes or the retain flips >= to > (pins the off-by-one).
        seq.prune_tick_window_settled(20);
        assert_eq!(seq.window_for_tick(100), None);
        assert_eq!(seq.window_for_tick(101), None);
        assert_eq!(seq.window_for_tick(104), None); // 11 < 12 cutoff
        assert_eq!(seq.window_for_tick(105), Some(12)); // 12 == cutoff, kept
        assert_eq!(seq.window_for_tick(102), Some(15));
        assert_eq!(seq.window_for_tick(103), Some(25));
    }

    #[test]
    fn enforce_tick_window_cap_bounds_the_map() {
        let mut seq = test_sequencer();
        let n = TICK_WINDOW_MAX as u64 + 50;
        for i in 0..n {
            seq.tick_window.insert(i, i);
        }
        seq.enforce_tick_window_cap();
        assert_eq!(seq.tick_window.len(), TICK_WINDOW_MAX);
        // the smallest-keyed (oldest) entries were the ones evicted…
        assert_eq!(seq.window_for_tick(0), None);
        assert_eq!(seq.window_for_tick(49), None);
        // …and the newest survive.
        assert_eq!(seq.window_for_tick(50), Some(50));
        assert_eq!(seq.window_for_tick(n - 1), Some(n - 1));
    }

    // BadPrevRoot fix: boot funding + the insurance transfer run AFTER add_market's
    // last window_start_state capture, so without re-basing, window 0's pre_state is
    // the pre-funding state while the deployed GENESIS_ROOT is the FULL boot state
    // root. seal_genesis_baseline folds the boot ops into the trusted genesis baseline.
    #[test]
    fn seal_genesis_baseline_rebases_window_zero_to_full_boot_state() {
        // mirrors Gw::boot: add_market + oracle (test_sequencer), then funding
        // (Deposit + FundPosition per account) and an insurance seed — which since
        // SEC-024 is its own Deposit → FundInsurance pair (a transfer, not a mint).
        let mut seq = test_sequencer();
        let ins_owner = owner_id(9);
        let ins_amount = 1_000 * QUOTE_SCALE;
        let ins_blind = [0x39u8; 32];
        let ins_cm = Note::new(ins_owner, 0, ins_amount, ins_blind).commitment::<Keccak256>();
        seq.apply(&BatchOp::Deposit {
            owner: ins_owner,
            asset_id: 0,
            amount: ins_amount,
            blinding: ins_blind,
            from: [0u8; 20],
            deposit_id: seq.state.consumed_deposit_count,
            deposit_blind: [0u8; 32],
        })
        .unwrap();
        seq.apply(&BatchOp::FundInsurance {
            note_commitment: ins_cm,
            spend_key: [9u8; 32],
        })
        .unwrap();
        // the bug precondition: boot ops accumulated after the last baseline capture,
        // so the window baseline (the would-be submitted `prev`) lags the boot state.
        assert!(!seq.window_ops.is_empty());
        assert_ne!(
            seq.window_start_state.state_root(),
            seq.state.state_root(),
            "harness must reproduce the drifted baseline the fix targets"
        );
        let batch_id_before = seq.state.next_batch_id;
        let root_before = seq.state.state_root();

        seq.seal_genesis_baseline();

        // (a) the window baseline now equals the full boot state (== deployed
        // GENESIS_ROOT)… and the live state itself was untouched.
        assert_eq!(seq.window_start_state.state_root(), seq.state.state_root());
        assert_eq!(seq.state.state_root(), root_before);
        // (b) every per-window accumulator seal_window drains is empty again.
        assert!(seq.window_ops.is_empty());
        assert!(seq.window_ordered.is_empty());
        assert!(seq.window_rejected.is_empty());
        // no window was closed: Counter B is unchanged.
        assert_eq!(seq.state.next_batch_id, batch_id_before);

        // the first REAL window now opens from genesis: a post-boot deposit seals
        // into a witness whose pre_state (the submitted `prev`) == the genesis root.
        let genesis_root = seq.state.state_root();
        fund(&mut seq, 3, 1_000, 0x33);
        let w = seq.seal_window();
        assert_eq!(w.batch_id, batch_id_before);
        assert_eq!(w.pre_state.state_root(), genesis_root);
        assert_eq!(w.manifest.previous_state_root, genesis_root);
    }

    /// SEC-022 §6 wiring: the unit test above pins `offending_leg` itself, but would
    /// still pass if the settlement `Err` arm never called it — so drive the REAL
    /// `seal_batch` path. A maker rests 5% below the attested mark (outside the 2%
    /// `max_fill_deviation_ratio` band of `Market::conservative`); the taker crosses and
    /// the fill executes at the MAKER's resting price (`matcher/book.rs:295`), so
    /// settlement fails with `FillPriceOutOfBand` — attributable to the maker alone.
    /// That reason can originate nowhere but settlement's `Err` arm; since the Task-7
    /// dry-run it surfaces via the probe run's `offenders` → ban → `manifest.rejected`
    /// (the committed pass replays only the clean rematch), so the exact-equality pin
    /// lives on `manifest.rejected` now.
    #[test]
    fn a_band_violation_at_settlement_rejects_only_the_resting_maker() {
        let mut seq = test_sequencer();
        // maker: owner 1 rests a sell at 95k against a 100k attested mark (out of band);
        // the pre-trade gate margins the order AT THE MARK, so it admits it.
        let mut maker = t_order(1, Side::Sell, 1);
        maker.limit_price = 95_000 * PRICE_SCALE;
        // taker: owner 2 buys at its 100k limit, crossing the resting 95k ask.
        let taker = t_order(2, Side::Buy, 2);
        let maker_hash = maker.order_hash::<Keccak256>();
        let taker_hash = taker.order_hash::<Keccak256>();

        let sealed = seq.seal_batch(&[maker, taker], now());

        // ONLY the maker leg is banned, with the settlement-time band reason. Exact
        // equality: nothing else may be rejected — in particular not the innocent taker.
        assert_eq!(
            sealed.manifest.rejected,
            vec![(maker_hash, RejectReason::FillPriceOutOfBand)],
            "the failed fill is attributed to the offending maker leg only",
        );
        // The committed settlement pass replays only the clean rematch (the offender was
        // excised before it), so it rejects nothing…
        assert!(sealed.settlement_rejected.is_empty());
        // …and the taker stays in `ordered` (it rests after the rematch), the maker does
        // not enter it at all.
        assert!(sealed.manifest.ordered.contains(&taker_hash));
        assert!(!sealed.manifest.ordered.contains(&maker_hash));
        // The banned fill settled nothing.
        assert!(sealed.settled_order_hashes.is_empty());
        // Receipt behaviour (intentional, Task 7): a banned order never enters the book
        // on the final pass, so it receives NO receipt — it is resolved in
        // `manifest.rejected` (bound by `manifest_hash`) instead. The taker still gets one.
        assert_eq!(sealed.receipts.len(), 1);
        assert_eq!(sealed.receipts[0].receipt.order_hash, taker_hash);
    }

    /// SEC-022 §6: an out-of-band match must not permanently consume resting liquidity.
    /// The matcher decrements the resting maker (`matcher/book.rs:295-308`) before
    /// settlement discovers the fill is invalid, and the rejection arm never restored
    /// it — so an attacker could burn a book without ever executing.
    ///
    /// FIXTURE FIX vs the plan draft: at 0.1 BTC the taker was fully satisfied by the
    /// honest $100k maker (price priority) and never REACHED the $150k ask — the
    /// out-of-band fill this test exists for never happened, and the expected final
    /// book contradicted ban semantics (a banned offender is cancelled with cause, not
    /// re-rested). The taker takes 0.2 so its sweep consumes the honest maker AND the
    /// poisoned one; the book pin is "nothing was consumed by a fill that didn't
    /// settle".
    #[test]
    fn a_rejected_fill_does_not_consume_resting_liquidity() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33); // a third account, for the honest maker
        let size = SIZE_SCALE / 10; // 0.1 BTC — $10k notional, $1k initial margin

        // Owner 1 rests 50% above the $100k mark: any fill against it is out of band.
        // Owner 3 rests AT the mark. Owner 2 takes 0.2 with a limit wide enough to
        // cross both.
        let bad_maker = t_order_at(1, Side::Sell, 150_000, size, 100);
        let good_maker = t_order_at(3, Side::Sell, 100_000, size, 101);
        let taker = t_order_at(2, Side::Buy, 200_000, 2 * size, 102);
        let sealed = sq.seal_batch(&[bad_maker, good_maker, taker], now());

        let bad_h = bad_maker.order_hash::<Keccak256>();
        let good_h = good_maker.order_hash::<Keccak256>();
        let taker_h = taker.order_hash::<Keccak256>();
        assert!(
            sealed
                .manifest
                .rejected
                .iter()
                .any(|(h, r)| *h == bad_h && *r == RejectReason::FillPriceOutOfBand),
            "the out-of-band MAKER is rejected, with a specific reason: {:?}",
            sealed.manifest.rejected,
        );
        assert!(
            !sealed.manifest.rejected.iter().any(|(h, _)| *h == taker_h),
            "the innocent taker must not be rejected alongside it",
        );
        assert!(
            sealed.manifest.ordered.contains(&taker_h),
            "on the rematch the taker really does trade, against the honest maker",
        );
        assert!(
            sealed.settled_order_hashes.contains(&taker_h)
                && sealed.settled_order_hashes.contains(&good_h),
            "the rematched fill actually settled",
        );
        // Nothing was consumed by a fill that failed to settle: the honest maker's
        // 0.1 BTC went to a settled fill, the poisoned quote is cancelled with cause
        // (it is in `manifest.rejected`, not resting), and the taker's unfilled
        // remainder rests on the book instead of being burned by the phantom fill.
        let book = sq.matcher.book(0).expect("market 0");
        assert_eq!(book.resting_size(Side::Sell), 0);
        assert_eq!(
            book.resting_size(Side::Buy),
            size,
            "the taker's unfilled half rests; the old path burned it inside the poisoned FilledFull",
        );
        assert_eq!(sq.state.position(&owner_id(2), 0).unwrap().size, size);
        assert!(sq.state.conservation_holds());
    }

    /// SEC-022 §6, the BANKRUPTCY class: `fits_initial_after` passes ANY reduction
    /// (`perp-core/src/position.rs:171-173`), so a reducing order that will trip the §3
    /// solvency postcondition has NO pre-match screen at all — it matches, consumes the
    /// counterparty's resting liquidity, and is dropped at settlement. The dry-run is
    /// the only thing standing between that order and a free liquidity burn (the
    /// band-class twin is `a_rejected_fill_does_not_consume_resting_liquidity`).
    #[test]
    fn a_bankrupting_reduction_is_banned_and_burns_no_resting_liquidity() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33);
        // Owner 1 opens 1.0 BTC long at the $100k mark against owner 2 ($20k collateral
        // against a $10k initial requirement — admitted with room to spare).
        sq.seal_batch(
            &[
                t_order_at(2, Side::Sell, 100_000, SIZE_SCALE, 600),
                t_order_at(1, Side::Buy, 100_000, SIZE_SCALE, 601),
            ],
            now(),
        );
        assert_eq!(sq.state.position(&owner_id(1), 0).unwrap().size, SIZE_SCALE);

        // The oracle gaps to $80k: owner 1's equity is exactly 0 (−$20k PnL on $20k
        // collateral) — under maintenance, but maintenance/liquidation runs AFTER
        // settlement inside `seal_batch`, so a close order still reaches matching first.
        sq.set_oracle(
            0,
            signed_oracle(
                0,
                80_000 * PRICE_SCALE,
                now() + 10,
                10 * PRICE_SCALE,
                80_000 * PRICE_SCALE,
            ),
        );

        // Owner 3 innocently bids $78.5k — within the 2% band of the $80k mark. Owner 1
        // dumps its whole position into that bid: closing at $78.5k realizes −$21.5k
        // against $20k collateral, so the closed leg ends with NEGATIVE collateral.
        // Nothing screens this before matching; without the dry-run it burned owner 3's
        // bid for nothing.
        let bid = t_order_at(3, Side::Buy, 78_500, SIZE_SCALE, 602);
        let close = t_order_at(1, Side::Sell, 78_000, SIZE_SCALE, 603);
        let bid_h = bid.order_hash::<Keccak256>();
        let close_h = close.order_hash::<Keccak256>();
        let sealed = sq.seal_batch(&[bid, close], now() + 10);

        assert!(
            sealed
                .manifest
                .rejected
                .iter()
                .any(|(h, r)| *h == close_h && *r == RejectReason::FillWouldBankrupt),
            "the bankrupting reduction is banned with the specific reason: {:?}",
            sealed.manifest.rejected,
        );
        assert!(
            !sealed.manifest.rejected.iter().any(|(h, _)| *h == bid_h),
            "the innocent maker is not blamed",
        );
        assert!(sealed.manifest.ordered.contains(&bid_h));
        assert!(sealed.settled_order_hashes.is_empty(), "nothing settled");
        // The whole point: the innocent bid SURVIVES on the book instead of being
        // consumed by a fill that was then dropped at settlement.
        assert_eq!(
            sq.matcher
                .book(0)
                .expect("market 0")
                .resting_size(Side::Buy),
            SIZE_SCALE,
            "the innocent maker's resting depth must not be burned by the banned fill",
        );
        assert!(sq.state.conservation_holds());
    }

    /// Whole-branch review I2, updated for SEC-024's leg attribution: the reason
    /// committed with a BAN must be the one recorded at the offender's own
    /// `settle_fills` push site. Originally, fill 2 failed with a NON-attributable
    /// `Risk` (owner 4's SECOND buy fails initial margin at settlement because its
    /// FIRST buy — admitted in the same batch, both gated against the pre-batch
    /// state — consumed the margin), recording X as the INNOCENT counterparty under
    /// `InsufficientMargin` before fill 3 banned X for its own
    /// `FillWouldBankrupt(Maker)` — and the old first-match lookup committed X's ban
    /// as `InsufficientMargin`, a falsehood folded permanently into `manifest_hash`.
    ///
    /// SEC-024 (SEC-022 carry-in) closes that construction at the source: a fill
    /// margin failure now NAMES its staged leg, so fill 2 bans ITS OWN offender (the
    /// degraded taker) and records nothing against the innocent X. The same fixture
    /// now pins the successor properties: two offenders in one probe pass are each
    /// banned under the reason from their OWN push site, and the margin offender is
    /// excised (banned, not ordered) instead of dragging X into a both-legs record.
    #[test]
    fn a_ban_commits_the_offending_legs_reason_not_an_earlier_innocent_records() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33); // M0 — the honest maker owner 4's first buy hits
        fund(&mut sq, 4, 5_000, 0x44); // P — margined for ONE 0.5 BTC open, gated twice
        fund(&mut sq, 5, 20_000, 0x55); // T2 — the well-funded taker that reaches X's leg

        // Batch 1: X (owner 1, $20k) opens 1.0 BTC long at the $100k mark vs owner 2.
        sq.seal_batch(
            &[
                t_order_at(2, Side::Sell, 100_000, SIZE_SCALE, 800),
                t_order_at(1, Side::Buy, 100_000, SIZE_SCALE, 801),
            ],
            now(),
        );
        assert_eq!(sq.state.position(&owner_id(1), 0).unwrap().size, SIZE_SCALE);

        // The oracle gaps to $80k: X's equity is exactly 0. Its close at $78.5k is in
        // band (|78.5k−80k| = $1.5k ≤ 2% of $80k = $1.6k) but realizes −$10.75k per
        // half, leaving the surviving half below maintenance → bankrupting.
        sq.set_oracle(
            0,
            signed_oracle(
                0,
                80_000 * PRICE_SCALE,
                now() + 10,
                10 * PRICE_SCALE,
                80_000 * PRICE_SCALE,
            ),
        );

        let half = SIZE_SCALE / 2;
        // Stream order matters: P's FIRST buy must fill before X's close rests (so it
        // matches M0, not X), degrading P before its SECOND buy crosses X.
        let m0 = t_order_at(3, Side::Sell, 80_000, half, 802);
        let alpha = t_order_at(4, Side::Buy, 80_000, half, 803);
        let x_close = t_order_at(1, Side::Sell, 78_500, SIZE_SCALE, 804);
        let beta = t_order_at(4, Side::Buy, 78_500, half, 805);
        let t2 = t_order_at(5, Side::Buy, 78_500, half, 806);
        let x_h = x_close.order_hash::<Keccak256>();
        let beta_h = beta.order_hash::<Keccak256>();
        let alpha_h = alpha.order_hash::<Keccak256>();
        let m0_h = m0.order_hash::<Keccak256>();

        // Probe pass, in match order: [alpha×M0 @80k settles] → [beta×X @78.5k fails
        // Risk{leg: Taker} on P's degraded taker leg: VWAP entry $79.25k on 1.0 BTC,
        // equity $5.75k < $8k initial — banning beta, sparing X] → [t2×X @78.5k fails
        // FillWouldBankrupt(Maker) on X's leg — the second offender]. Ban both,
        // rematch clean.
        let sealed = sq.seal_batch(&[m0, alpha, x_close, beta, t2], now() + 10);

        // THE PIN: each ban carries the reason from its OWN offending leg's push
        // site. Pre-SEC-024, fill 2's leg-less Risk recorded (beta, IM) AND (X, IM)
        // with no offender — and X's later ban could inherit that earlier innocent
        // record's reason via a first-match lookup.
        assert_eq!(
            sealed.manifest.rejected,
            vec![
                (beta_h, RejectReason::InsufficientMargin),
                (x_h, RejectReason::FillWouldBankrupt),
            ],
            "each ban must commit the reason recorded at its own offender push site",
        );
        // The degraded second buy is a banned offender now — excised from the final
        // stream entirely, not resting in `ordered` as it did when Risk was
        // non-attributable.
        assert!(!sealed.manifest.ordered.contains(&beta_h));
        // The honest first fill really settled on the committed pass.
        assert!(sealed.settled_order_hashes.contains(&alpha_h));
        assert!(sealed.settled_order_hashes.contains(&m0_h));
        assert!(sq.state.conservation_holds());
    }

    /// Whole-branch review I2, the REBUILT pin (SEC-024 Task 4). The ban commit
    /// site pairs each banned order with the reason pushed at its OWN
    /// `settle_fills` push site — never looked up first-match in `rejected`, where
    /// the same hash can already sit under a DIFFERENT reason from earlier in the
    /// same pass. A non-attributable failure still records BOTH legs; here fill 1
    /// is in a market with no oracle, so X (owner 1) is recorded as an innocent
    /// counterparty under `OracleUnavailable`, and fill 2 (owner 2 taker × X's
    /// out-of-band resting ask) is X's OWN offense.
    #[test]
    fn a_ban_survives_an_earlier_innocent_record_of_the_same_hash() {
        let sq = test_sequencer();
        let size = SIZE_SCALE / 10;
        let x_h = word_u64(0x51);
        let other_h = word_u64(0x52);
        let t2_h = word_u64(0x53);
        let fill = |market_id, taker, maker, price, taker_hash, maker_hash| Match {
            market_id,
            taker: owner_id(taker),
            maker: owner_id(maker),
            taker_side: Side::Buy,
            size,
            price,
            taker_order_hash: taker_hash,
            maker_order_hash: maker_hash,
            taker_reduce_only: false,
            maker_reduce_only: false,
        };
        let fills = [
            fill(1, 2, 1, 100_000 * PRICE_SCALE, other_h, x_h),
            fill(0, 2, 1, 90_000 * PRICE_SCALE, t2_h, x_h),
        ];
        let mut probe = sq.state.clone();
        let out = settle_fills(&mut probe, &sq.oracles, &fills, now(), &BTreeSet::new());
        assert_eq!(
            out.rejected,
            vec![
                (other_h, RejectReason::OracleUnavailable),
                (x_h, RejectReason::OracleUnavailable),
                (x_h, RejectReason::FillPriceOutOfBand),
            ],
            "X is recorded first as an innocent counterparty"
        );
        assert_eq!(
            out.offenders,
            vec![(x_h, RejectReason::FillPriceOutOfBand)],
            "the offender carries the reason of its own offense"
        );
        assert!(out.applied_fills.is_empty());
        assert_eq!(probe.state_root(), sq.state.state_root());
    }

    /// In close-only mode the pre-trade gate refuses an order that adds exposure,
    /// with the engine's own reason, before it can reach the book.
    #[test]
    fn close_only_refuses_an_opening_order_before_matching() {
        let mut sq = test_sequencer();
        let size = SIZE_SCALE / 100;
        sq.seal_batch(
            &[
                t_order_at(1, Side::Sell, 100_000, size, 1),
                t_order_at(2, Side::Buy, 100_000, size, 2),
            ],
            now(),
        );
        sq.apply(&BatchOp::EnterCloseOnly).unwrap();
        let open = t_order_at(1, Side::Sell, 100_000, size, 3);
        let flip = t_order_at(2, Side::Sell, 100_000, 2 * size, 4);
        let close = t_order_at(2, Side::Sell, 100_000, size, 5);
        assert_eq!(
            sq.pre_trade_check(&open, now()),
            Err(RejectReason::MarketCloseOnly)
        );
        assert_eq!(
            sq.pre_trade_check(&flip, now()),
            Err(RejectReason::MarketCloseOnly)
        );
        assert_eq!(sq.pre_trade_check(&close, now()), Ok(()));
        let sealed = sq.seal_batch(&[open], now());
        assert_eq!(
            sealed.manifest.rejected,
            vec![(
                open.order_hash::<Keccak256>(),
                RejectReason::MarketCloseOnly
            )]
        );
        assert!(sealed.receipts.is_empty());
        assert_eq!(sq.matcher.book(0).unwrap().resting_size(Side::Sell), 0);
    }

    /// An opener that rested before the engine became close-only cannot settle. A
    /// close that crosses it is not rejected with it: the opener alone is banned
    /// with `MarketCloseOnly`, and the close is rematched to a maker it can trade
    /// with.
    #[test]
    fn close_only_bans_a_resting_opener_and_reroutes_the_close() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33);
        let size = SIZE_SCALE / 100;
        // owner 2 is long, owner 1 short
        sq.seal_batch(
            &[
                t_order_at(1, Side::Sell, 100_000, size, 1),
                t_order_at(2, Side::Buy, 100_000, size, 2),
            ],
            now(),
        );
        // a bid from owner 3, flat, opens on a fill; a lower bid from owner 1 closes
        // its short
        let opener = t_order_at(3, Side::Buy, 100_000, size, 3);
        let closer = t_order_at(1, Side::Buy, 99_990, size, 4);
        sq.seal_batch(&[opener, closer], now());
        sq.apply(&BatchOp::EnterCloseOnly).unwrap();

        let close = Order {
            reduce_only: true,
            tif: TimeInForce::Ioc,
            ..t_order_at(2, Side::Sell, 99_000, size, 5)
        };
        let sealed = sq.seal_batch(&[close], now() + 10);
        let opener_h = opener.order_hash::<Keccak256>();
        let close_h = close.order_hash::<Keccak256>();
        assert_eq!(
            sealed.manifest.rejected,
            vec![(opener_h, RejectReason::MarketCloseOnly)]
        );
        assert!(sealed.settled_order_hashes.contains(&close_h));
        assert!(sealed
            .settled_order_hashes
            .contains(&closer.order_hash::<Keccak256>()));
        assert!(sealed.manifest.ordered.contains(&close_h));
        assert_eq!(
            sq.remaining_order_size(&opener_h),
            None,
            "banned from the book"
        );
        for owner in [1, 2, 3] {
            assert!(sq
                .state
                .position(&owner_id(owner), 0)
                .is_none_or(|p| p.size == 0));
        }
        assert!(sq.state.conservation_holds());
    }

    /// The cross-batch arm of the same hazard (the spec's "a Gtc maker admitted in-band
    /// drifts out of band as the oracle moves"): the offender is a maker RESTING FROM AN
    /// EARLIER BATCH, so it is in no later batch's admitted stream — banning it from
    /// `live` alone removes nothing, and restoring the book resurrects it, reproducing
    /// the same doomed fill forever. The ban must cancel it from the rematch base book,
    /// and the loop must still terminate.
    #[test]
    fn a_drifted_resting_maker_is_banned_from_the_book_not_just_the_stream() {
        let mut sq = test_sequencer();
        let size = SIZE_SCALE / 10;
        // Batch 1: owner 1 rests a sell AT the $100k mark — in band, honestly admitted.
        let maker = t_order_at(1, Side::Sell, 100_000, size, 700);
        let maker_h = maker.order_hash::<Keccak256>();
        let s1 = sq.seal_batch(&[maker], now());
        assert!(s1.manifest.ordered.contains(&maker_h));
        assert_eq!(sq.matcher.book(0).unwrap().resting_size(Side::Sell), size);

        // The oracle moves to $110k: the resting $100k ask is now >2% below the mark.
        sq.set_oracle(
            0,
            signed_oracle(
                0,
                110_000 * PRICE_SCALE,
                now() + 10,
                10 * PRICE_SCALE,
                110_000 * PRICE_SCALE,
            ),
        );

        // Batch 2: owner 2 crosses it; the fill executes at the maker's drifted price.
        let taker = t_order_at(2, Side::Buy, 110_000, size, 701);
        let taker_h = taker.order_hash::<Keccak256>();
        let s2 = sq.seal_batch(&[taker], now() + 10);

        assert!(
            s2.manifest
                .rejected
                .iter()
                .any(|(h, r)| *h == maker_h && *r == RejectReason::FillPriceOutOfBand),
            "the drifted maker is rejected in the batch that discovered it: {:?}",
            s2.manifest.rejected,
        );
        assert!(!s2.manifest.rejected.iter().any(|(h, _)| *h == taker_h));
        assert!(s2.manifest.ordered.contains(&taker_h));
        let book = sq.matcher.book(0).unwrap();
        assert_eq!(
            book.resting_size(Side::Sell),
            0,
            "the poisoned quote is cancelled, not left to trap the next taker",
        );
        assert_eq!(
            book.resting_size(Side::Buy),
            size,
            "the taker rests unfilled instead of being burned by the phantom fill",
        );
    }

    /// **Fragmentation regression at the sequencer level** (the core-level twin lives in
    /// `perp-core/tests/sec022_fill_band.rs`). A solvent aggregate close must not become
    /// impossible because the counterparty fragmented it across many small resting orders.
    #[test]
    fn a_healthy_position_closes_against_fragmented_resting_liquidity() {
        let mut sq = test_sequencer();
        // Owner 1 opens 0.5 BTC long against owner 2, at the mark.
        let half = SIZE_SCALE / 2;
        sq.seal_batch(
            &[
                t_order_at(2, Side::Sell, 100_000, half, 200),
                t_order_at(1, Side::Buy, 100_000, half, 201),
            ],
            now(),
        );
        assert_eq!(sq.state.position(&owner_id(1), 0).unwrap().size, half);

        // Owner 2 fragments the other side into five 0.1 BTC resting bids at the mark;
        // owner 1 closes across all of them in one batch. Every fragment must settle.
        let mut orders: Vec<Order> = (0..5)
            .map(|i| t_order_at(2, Side::Buy, 100_000, SIZE_SCALE / 10, 300 + i))
            .collect();
        orders.push(t_order_at(1, Side::Sell, 100_000, half, 400));
        let sealed = sq.seal_batch(&orders, now() + 10);

        assert!(
            sealed.manifest.rejected.iter().all(|(_, r)| !matches!(
                r,
                RejectReason::FillWouldBankrupt | RejectReason::FillPriceOutOfBand
            )),
            "no fragment may be rejected as bankrupting or out of band: {:?}",
            sealed.manifest.rejected,
        );
        assert_eq!(
            sq.state.position(&owner_id(1), 0).unwrap().size,
            0,
            "the aggregate close completed across every fragment",
        );
        assert!(sq.state.conservation_holds());
    }

    /// The loop terminates when EVERY fill this batch produces is offending: each round
    /// bans at least one new order, so the loop is bounded and still seals a batch.
    #[test]
    fn rematch_loop_terminates_when_every_fill_is_offending() {
        let mut sq = test_sequencer();
        let size = SIZE_SCALE / 100;
        // Four crossing pairs, all far off the mark — every resulting fill is out of band.
        let mut orders = Vec::new();
        for i in 0..4u64 {
            orders.push(t_order_at(1, Side::Sell, 150_000, size, 500 + i * 2));
            orders.push(t_order_at(2, Side::Buy, 160_000, size, 501 + i * 2));
        }
        let sealed = sq.seal_batch(&orders, now());
        assert!(
            !sealed.manifest.rejected.is_empty(),
            "every fill was out of band, so the batch rejects rather than hanging",
        );
        // Every out-of-band maker is banned; no taker is blamed (they rest unfilled).
        for o in &orders {
            let h = o.order_hash::<Keccak256>();
            match o.side {
                Side::Sell => assert!(
                    sealed
                        .manifest
                        .rejected
                        .iter()
                        .any(|(rh, r)| *rh == h && *r == RejectReason::FillPriceOutOfBand),
                    "each out-of-band maker is rejected: {:?}",
                    sealed.manifest.rejected,
                ),
                Side::Buy => assert!(sealed.manifest.ordered.contains(&h)),
            }
        }
        assert!(sealed.settled_order_hashes.is_empty());
        assert!(sq.state.conservation_holds());
    }

    /// SEC-022 §6 review I1a: the reduce_only SETTLEMENT backstop must ban its
    /// offender like every other attributable failure. Reachable only cross-batch:
    /// a reduce_only maker rests from batch N (its owner still held the position,
    /// so the pre-trade gate passed it — pinned below); in batch N+1 a DIFFERENT
    /// order of the same owner closes that position via an EARLIER fill of the
    /// same settlement pass, so the resting maker now OPENS at settlement. Neither
    /// the pre-trade gate nor the `owners_with_order` guard can see it (both cover
    /// only current-batch orders; the liquidation sub-case is `cancel_owner_orders`),
    /// so the drop can only happen at settlement — where, before this fix, it
    /// rejected without banning and burned the innocent taker's consumed depth.
    #[test]
    fn a_reduce_only_settlement_violation_bans_the_offender_and_spares_the_counterparty() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33);
        let size = SIZE_SCALE / 10;

        // Batch 1: owner 1 opens a 0.1 BTC long at the $100k mark against owner 2.
        sq.seal_batch(
            &[
                t_order_at(2, Side::Sell, 100_000, size, 800),
                t_order_at(1, Side::Buy, 100_000, size, 801),
            ],
            now(),
        );
        assert_eq!(sq.state.position(&owner_id(1), 0).unwrap().size, size);

        // Batch 2: owner 1 rests a reduce_only ask at $101k — INSIDE the 2% band, so
        // the band check cannot fire and mask the reduce_only class. It reduces the
        // live long, so the pre-trade gate ADMITS it; pinning that here proves the
        // batch-3 rejection below cannot originate at the pre-trade gate.
        let mut ro = t_order_at(1, Side::Sell, 101_000, size, 802);
        ro.reduce_only = true;
        let ro_h = ro.order_hash::<Keccak256>();
        let s2 = sq.seal_batch(&[ro], now());
        assert!(s2.manifest.rejected.is_empty());
        assert!(s2.manifest.ordered.contains(&ro_h));
        assert_eq!(sq.matcher.book(0).unwrap().resting_size(Side::Sell), size);

        // Batch 3: owner 2 rests a bid; owner 1's PLAIN sell closes the long against
        // it (fill 1); innocent owner 3 crosses the still-resting reduce_only ask
        // (fill 2). Fill 1 settles first and closes the position, so fill 2 would
        // OPEN a short for a reduce_only order — the settlement backstop fires.
        let lp_bid = t_order_at(2, Side::Buy, 100_000, size, 803);
        let close = t_order_at(1, Side::Sell, 100_000, size, 804);
        let innocent = t_order_at(3, Side::Buy, 101_000, size, 805);
        let lp_h = lp_bid.order_hash::<Keccak256>();
        let close_h = close.order_hash::<Keccak256>();
        let innocent_h = innocent.order_hash::<Keccak256>();
        let s3 = sq.seal_batch(&[lp_bid, close, innocent], now());

        // The offending reduce_only maker is BANNED with the specific reason…
        assert!(
            s3.manifest
                .rejected
                .iter()
                .any(|(h, r)| *h == ro_h && *r == RejectReason::ReduceOnlyViolation),
            "the reduce_only offender is banned in the batch that discovered it: {:?}",
            s3.manifest.rejected,
        );
        // …and nobody else is blamed.
        assert!(!s3
            .manifest
            .rejected
            .iter()
            .any(|(h, _)| *h == innocent_h || *h == close_h || *h == lp_h));
        assert!(s3.manifest.ordered.contains(&innocent_h));
        // The committed pass replays only the clean rematch: the close settled and
        // the dropped reduce_only fill never re-executed.
        assert!(s3.settlement_rejected.is_empty());
        assert!(
            s3.settled_order_hashes.contains(&close_h)
                && s3.settled_order_hashes.contains(&lp_h)
                && !s3.settled_order_hashes.contains(&innocent_h)
        );
        assert_eq!(sq.state.position(&owner_id(1), 0).unwrap().size, 0);
        // The hazard closure: the poisoned quote is CANCELLED (not resting), and
        // the innocent taker's unfilled size rests instead of being burned inside
        // the dropped fill. Without the `offenders` push the Buy depth is 0.
        let book = sq.matcher.book(0).unwrap();
        assert_eq!(book.resting_size(Side::Sell), 0);
        assert_eq!(
            book.resting_size(Side::Buy),
            size,
            "the innocent taker rests unfilled; the unbanned path burned it in the dropped fill",
        );
        assert!(sq.state.conservation_holds());
    }

    /// Review M2: the ≥3-round rematch path — the flow that falsifies the plan's
    /// old `rounds <= live.len() + 1` bound. TWO makers rested in-band in batch 1
    /// and drift out of band together; price priority lets the taker's 0.1 BTC
    /// touch only ONE per round (each level fully absorbs it), so the bans MUST
    /// land in separate rounds: round 1 bans the $100k ask, round 2's rematch
    /// sweeps deeper and bans the $101k ask, round 3 settles clean against the
    /// honest $110k ask (3 rounds verified by temporary loop instrumentation —
    /// see the task report). `live` is just the taker throughout and never
    /// shrinks, so the old bound allowed 2 rounds; the strict banned-set-growth
    /// witness is what lets this legitimate flow terminate instead of panicking.
    #[test]
    fn two_drifted_makers_are_banned_in_separate_rounds_before_the_loop_settles() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33);
        fund(&mut sq, 4, 20_000, 0x44);
        let size = SIZE_SCALE / 10;

        // Batch 1: three asks rest at distinct levels, all honestly admitted at the
        // $100k mark. After the drift only the $110k one is still in band.
        let drift_a = t_order_at(1, Side::Sell, 100_000, size, 900);
        let drift_b = t_order_at(3, Side::Sell, 101_000, size, 901);
        let honest = t_order_at(4, Side::Sell, 110_000, size, 902);
        let a_h = drift_a.order_hash::<Keccak256>();
        let b_h = drift_b.order_hash::<Keccak256>();
        let honest_h = honest.order_hash::<Keccak256>();
        let s1 = sq.seal_batch(&[drift_a, drift_b, honest], now());
        assert!(s1.manifest.rejected.is_empty());
        assert_eq!(
            sq.matcher.book(0).unwrap().resting_size(Side::Sell),
            3 * size
        );

        // The oracle moves to $110k: the $100k and $101k asks are now >2% below the
        // mark; the $110k ask sits exactly at it.
        sq.set_oracle(
            0,
            signed_oracle(
                0,
                110_000 * PRICE_SCALE,
                now() + 10,
                10 * PRICE_SCALE,
                110_000 * PRICE_SCALE,
            ),
        );

        // Batch 2: one taker whose size equals each level's, with a limit crossing
        // all three. Round 1 fills only against the $100k ask (fully absorbed →
        // the $101k quote is untouched, so the two bans cannot share a round).
        let taker = t_order_at(2, Side::Buy, 110_000, size, 903);
        let taker_h = taker.order_hash::<Keccak256>();
        let sealed = sq.seal_batch(&[taker], now() + 10);

        // Exactly the two drifted makers are rejected, in ban order, each with the
        // settlement band reason — and nothing else (not the taker, not the honest
        // maker).
        assert_eq!(
            sealed.manifest.rejected,
            vec![
                (a_h, RejectReason::FillPriceOutOfBand),
                (b_h, RejectReason::FillPriceOutOfBand),
            ],
        );
        // The loop went PAST both bans and settled the third round's clean fill.
        assert!(sealed.manifest.ordered.contains(&taker_h));
        assert!(
            sealed.settled_order_hashes.contains(&taker_h)
                && sealed.settled_order_hashes.contains(&honest_h),
            "the final rematch settles against the honest depth",
        );
        assert_eq!(sq.state.position(&owner_id(2), 0).unwrap().size, size);
        // Both poisoned quotes were cancelled with cause; the honest one traded.
        let book = sq.matcher.book(0).unwrap();
        assert_eq!(book.resting_size(Side::Sell), 0);
        assert_eq!(book.resting_size(Side::Buy), 0, "the taker fully filled");
        assert!(sq.state.conservation_holds());
    }
}
