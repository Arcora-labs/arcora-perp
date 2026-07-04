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

use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest as _, Keccak256 as RawKeccak};

use matcher::{MatchingEngine, SubmitStatus};
use perp_core::engine::BatchOp;
use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use perp_core::market::{Market, MarketId};
use perp_core::note::PubKey;
use perp_core::oracle::OracleTranscript;
use perp_core::order::{BatchManifest, Finality, Order, Receipt, RejectReason, Side};
use perp_core::position::Position;
use perp_core::{DefaultState, EngineError};

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
}

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
    pub liquidated: Vec<(PubKey, MarketId)>,
    pub adl: Vec<(PubKey, MarketId, i128)>,
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

/// Why an order was rejected at settlement, mapped from an engine error.
fn settlement_reason(e: &EngineError) -> RejectReason {
    match e {
        EngineError::Risk(_) => RejectReason::InsufficientMargin,
        EngineError::Oracle(_) => RejectReason::OracleUnavailable,
        EngineError::CloseOnly => RejectReason::MarketCloseOnly,
        EngineError::SelfTrade => RejectReason::SelfTradePrevented,
        // audit Tier-3: an HONEST catch-all for the remaining engine errors (UnknownMarket,
        // NonPositiveAmount, Overflow, DuplicateCommitment, …) instead of mis-tagging them
        // all as ReduceOnlyViolation in the manifest.
        _ => RejectReason::InvalidOrder,
    }
}

/// serde default for the skipped `enclave` field: a placeholder identity a
/// restore MUST overwrite via [`Sequencer::set_enclave`] before serving. The
/// snapshot deliberately never carries the enclave signing secret — it is
/// rebuilt from `ENCLAVE_SEED` at boot (and may legitimately rotate).
fn enclave_restore_placeholder() -> EnclaveIdentity {
    EnclaveIdentity::from_seed([7u8; 32], 0, [0u8; 32])
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
    /// Snapshot of (state, matcher) taken BEFORE each not-yet-proven batch, so a
    /// batch that fails to prove can be rolled back to the last hard state (§3
    /// failure matrix). Pruned as batches settle. Keeping a snapshot only per
    /// *pending* batch bounds the memory.
    snapshots: BTreeMap<u64, (DefaultState, MatchingEngine<Keccak256>)>,
    /// Per-account secret liquidation-tag keys, derived from the spend key the
    /// account presents when funding a position and captured inside the enclave.
    /// Used to publish liquidation tags that only the account (which knows its own
    /// spend key) can recompute — never a mere holder of the public owner id (§7).
    liq_tag_keys: BTreeMap<PubKey, Digest>,
    /// Parallel secret ADL-tag keys, captured the same way, for publishing
    /// auto-deleverage receipts only the clawed account can recognize (audit Q2).
    adl_tag_keys: BTreeMap<PubKey, Digest>,
}

impl Sequencer {
    pub fn new(enclave: EnclaveIdentity, tree_depth: u8) -> Self {
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
            snapshots: BTreeMap::new(),
            liq_tag_keys: BTreeMap::new(),
            adl_tag_keys: BTreeMap::new(),
        }
    }

    /// Rebind the enclave identity after a snapshot restore. The snapshot skips
    /// the enclave (its signing secret must never persist to disk and may
    /// legitimately rotate), so a deserialized `Sequencer` signs with a public
    /// placeholder until this is called — callers MUST invoke it with the real
    /// identity before serving traffic.
    pub fn set_enclave(&mut self, enclave: EnclaveIdentity) {
        self.enclave = enclave;
    }

    /// Register a market in both settlement state and the matcher.
    pub fn add_market(&mut self, market: Market) {
        self.matcher.open_market(market.id);
        self.state.add_market(market);
    }

    /// Set / refresh the oracle transcript a market settles against (§8).
    pub fn set_oracle(&mut self, market_id: MarketId, transcript: OracleTranscript) {
        self.oracles.insert(market_id, transcript);
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
        self.state.apply_op(op)
    }

    pub fn current_batch_id(&self) -> u64 {
        self.next_batch_id
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
    pub fn pre_trade_check(&self, order: &Order, now_ms: u64) -> Result<(), RejectReason> {
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
        let funding_index = self
            .state
            .funding
            .get(&order.market_id)
            .map(|f| f.cumulative_index)
            .unwrap_or(0);
        let base = self
            .state
            .position(&order.owner, order.market_id)
            .copied()
            .unwrap_or_else(|| Position::empty(order.owner, order.market_id));
        // audit DP-009 (adversarial-review follow-up): reject a reduce_only order that
        // would OPEN or GROW the owner's position BEFORE matching — otherwise the matcher
        // consumes a counterparty's resting liquidity for a fill that is then dropped at
        // settlement, destroying that liquidity and mis-tagging the innocent maker.
        if order.reduce_only && base.increases_exposure(order.signed_size()) {
            return Err(RejectReason::ReduceOnlyViolation);
        }
        if base.fits_initial_after(market, order.signed_size(), mark, funding_index) {
            Ok(())
        } else {
            Err(RejectReason::InsufficientMargin)
        }
    }

    /// Whether a signed `delta` would INCREASE `owner`'s absolute exposure in `market`
    /// (open from flat, grow in the same direction, or flip) — used to enforce reduce_only
    /// at settlement (audit DP-009).
    fn exposure_increases(&self, owner: &PubKey, market: MarketId, delta: i128) -> bool {
        match self.state.position(owner, market) {
            None => true,
            Some(p) => p.increases_exposure(delta),
        }
    }

    /// Best book mid as the perp mark price; falls back to the oracle index if a
    /// side is empty. Used as the funding mark (§8).
    fn mark_price(&self, market_id: MarketId) -> Option<i128> {
        let book = self.matcher.book(market_id)?;
        match (book.best_bid(), book.best_ask()) {
            (Some(bid), Some(ask)) => Some(book_mid(bid, ask)),
            _ => self.oracles.get(&market_id).map(|o| o.price),
        }
    }

    /// Per-batch maintenance (§5, §8): accrue funding from the mark-vs-index
    /// premium, then liquidate every position that is underwater at the oracle
    /// price. Runs regardless of user liveness — the enclave holds positions, so
    /// an offline user is still liquidated. Returns the liquidated owners and any
    /// auto-deleverage haircuts the cascade applied (audit Q2/Q7).
    pub fn run_maintenance(&mut self, now_ms: u64) -> MaintenanceOutcome {
        // reap good-till-time makers that have expired before reading the book as
        // the funding mark — an expired order must not anchor `best_bid`/`best_ask`
        // (§8), and matching already refuses to trade against it.
        self.matcher.reap_expired(now_ms);
        let mut liquidated = Vec::new();
        let mut adl: Vec<(PubKey, MarketId, i128)> = Vec::new();
        let market_ids: Vec<MarketId> = self.state.markets.keys().copied().collect();
        for mid in market_ids {
            let Some(oracle) = self.oracles.get(&mid).copied() else {
                continue;
            };
            // funding accrual (best-effort; skip if oracle is out of bounds)
            let mark = self.mark_price(mid).unwrap_or(oracle.price);
            let _ = self.state.apply_op(&BatchOp::AccrueFunding {
                market_id: mid,
                mark,
                oracle,
                now_ms,
            });
            // liquidation pass at the oracle price
            let Some(market) = self.state.markets.get(&mid).copied() else {
                continue;
            };
            let Ok(price) = oracle.validate(&market, now_ms) else {
                continue;
            };
            let funding_index = self
                .state
                .funding
                .get(&mid)
                .map(|f| f.cumulative_index)
                .unwrap_or(0);
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
                    // Carry each auto-deleverage haircut up with its market so the
                    // seal can publish an attributable receipt for it (audit Q2).
                    for h in haircuts {
                        adl.push((h.owner, mid, h.clawed));
                    }
                }
            }
        }
        MaintenanceOutcome { liquidated, adl }
    }

    /// Run one batch: match `orders`, issue receipts, settle fills, run the
    /// funding+liquidation maintenance pass, publish a manifest, advance finality,
    /// and update inclusion tracking.
    pub fn seal_batch(&mut self, orders: &[Order], now_ms: u64) -> SealedBatch {
        let prev_state_root = self.state.state_root();
        let batch_id = self.next_batch_id;

        // snapshot the pre-batch (state, matcher) so this batch can be rolled back
        // if it later fails to prove (§3 failure matrix).
        self.snapshots
            .insert(batch_id, (self.state.clone(), self.matcher.clone()));

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
        for o in orders {
            if o.reduce_only && owners_with_order.contains(&(o.owner, o.market_id)) {
                pre_rejected.push((
                    o.order_hash::<Keccak256>(),
                    RejectReason::ReduceOnlyViolation,
                ));
                continue;
            }
            match self.pre_trade_check(o, now_ms) {
                Ok(()) => {
                    owners_with_order.insert((o.owner, o.market_id));
                    admitted.push(*o);
                }
                Err(reason) => pre_rejected.push((o.order_hash::<Keccak256>(), reason)),
            }
        }

        // 1. match the arrival-ordered stream of admitted orders
        let stream = self.matcher.process_stream(&admitted, now_ms);

        // 2. issue signed receipts for every accepted (non-rejected) order
        let mut receipts = Vec::new();
        for p in &stream.processed {
            if !matches!(p.outcome.status, SubmitStatus::Rejected(_)) {
                receipts.push(self.issue_receipt(p.outcome.order_hash, now_ms));
            }
        }

        // 3. settle matched fills through the engine, attaching the oracle. The
        //    pre-trade gate covers the *taker* against current state, but a
        //    *resting maker* admitted in an earlier batch can have drifted below
        //    initial margin since (funding / a prior liquidation), so a fill can
        //    still fail to settle. We record BOTH legs of any failed fill and,
        //    below, keep the manifest honest: an order whose fills ALL failed is
        //    moved out of `ordered` into `rejected` (it did not settle).
        let mut settled_order_hashes = Vec::new();
        let mut settlement_rejected: Vec<(Digest, RejectReason)> = Vec::new();
        for m in &stream.fills {
            let Some(oracle) = self.oracles.get(&m.market_id).copied() else {
                for oh in [m.taker_order_hash, m.maker_order_hash] {
                    settlement_rejected.push((oh, RejectReason::OracleUnavailable));
                }
                continue;
            };
            // audit DP-009: a reduce_only order may only SHRINK its owner's position. Drop
            // the fill if it would increase a reduce_only party's absolute exposure. (Matching
            // is trusted in Phase 0; op_fill's margin checks still guard fund safety.)
            // The pre-trade gate already rejects a reduce_only order that would open against
            // the pre-batch position; this is the live backstop for an intra-batch change.
            let taker_delta = if m.taker_side == Side::Buy {
                m.size
            } else {
                -m.size
            };
            let taker_opens =
                m.taker_reduce_only && self.exposure_increases(&m.taker, m.market_id, taker_delta);
            let maker_opens =
                m.maker_reduce_only && self.exposure_increases(&m.maker, m.market_id, -taker_delta);
            if taker_opens || maker_opens {
                // attribute the violation ONLY to the offending reduce_only order(s), never
                // to an innocent counterparty (adversarial-review follow-up).
                if taker_opens {
                    settlement_rejected
                        .push((m.taker_order_hash, RejectReason::ReduceOnlyViolation));
                }
                if maker_opens {
                    settlement_rejected
                        .push((m.maker_order_hash, RejectReason::ReduceOnlyViolation));
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
            match self.state.apply_op(&op) {
                Ok(()) => {
                    for oh in [m.taker_order_hash, m.maker_order_hash] {
                        self.finality.insert(oh, Finality::Matched);
                        if !settled_order_hashes.contains(&oh) {
                            settled_order_hashes.push(oh);
                        }
                    }
                }
                Err(e) => {
                    let reason = settlement_reason(&e);
                    for oh in [m.taker_order_hash, m.maker_order_hash] {
                        settlement_rejected.push((oh, reason));
                    }
                }
            }
        }

        // 3b. maintenance: accrue funding + liquidate underwater positions (§5,§8).
        //     Liquidating an owner also cancels its resting orders, so a
        //     bad-debt account can't leave stale makers that would fail to settle.
        let MaintenanceOutcome {
            liquidated: liquidations,
            adl: adl_haircuts,
        } = self.run_maintenance(now_ms);
        for (owner, _market) in &liquidations {
            self.matcher.cancel_owner_orders(owner);
        }

        // 4. build the manifest, keeping `ordered`/`rejected` DISJOINT and HONEST.
        //    `rejected` = pre-trade rejects + matcher rejects + orders whose fills
        //    ALL failed settlement. An order with at least one settled fill (a
        //    partial multi-counterparty fill) stays in `ordered` — it really did
        //    trade. Orders moved here are removed from `ordered` below.
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

        let new_state_root = self.state.state_root();
        self.next_batch_id += 1;

        // Publish privacy-preserving liquidation TAGS keyed on each account's
        // secret tag key (captured at fund time), not cleartext owners. The
        // fallback to the owner id only fires for a position funded outside this
        // sequencer's `apply` (never in normal operation).
        let liquidation_tags: Vec<Digest> = liquidations
            .iter()
            .map(|(owner, market)| {
                let tag_key = self.liq_tag_keys.get(owner).copied().unwrap_or(*owner);
                liquidation_tag(&tag_key, *market, batch_id)
            })
            .collect();

        // Publish each auto-deleverage haircut as a secret-keyed receipt the clawed
        // account can recognize, paired with the amount (audit Q2). Same fallback
        // to the owner id as above for positions funded outside `apply`.
        let adl_receipts: Vec<AdlReceipt> = adl_haircuts
            .iter()
            .map(|(owner, market, clawed)| {
                let tag_key = self.adl_tag_keys.get(owner).copied().unwrap_or(*owner);
                AdlReceipt {
                    tag: adl_tag(&tag_key, *market, batch_id),
                    clawed: *clawed,
                }
            })
            .collect();

        SealedBatch {
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
        }
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

/// Overflow-safe book midpoint used as the funding mark. Halving each side before
/// summing keeps the mid from overflowing `i128` when an unvalidated resting price
/// sits near the type bound (audit DP-008): a plain `(bid + ask) / 2` panics in a
/// debug build and wraps in release. At most one unit of precision is lost.
fn book_mid(bid: i128, ask: i128) -> i128 {
    (bid / 2).saturating_add(ask / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
