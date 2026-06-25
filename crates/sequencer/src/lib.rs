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

use std::collections::BTreeMap;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest as _, Keccak256 as RawKeccak};

use matcher::{MatchingEngine, SubmitStatus};
use perp_core::engine::BatchOp;
use perp_core::hash::{Digest, Keccak256};
use perp_core::market::{Market, MarketId};
use perp_core::note::PubKey;
use perp_core::order::{BatchManifest, Finality, Order, Receipt, RejectReason};
use perp_core::oracle::OracleTranscript;
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
#[derive(Clone, Copy, Debug)]
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
    /// Owners liquidated during this batch's maintenance pass (§5).
    pub liquidations: Vec<PubKey>,
}

/// Why an order was rejected at settlement, mapped from an engine error.
fn settlement_reason(e: &EngineError) -> RejectReason {
    match e {
        EngineError::Risk(_) => RejectReason::InsufficientMargin,
        EngineError::Oracle(_) => RejectReason::OracleUnavailable,
        EngineError::CloseOnly => RejectReason::MarketCloseOnly,
        _ => RejectReason::ReduceOnlyViolation,
    }
}

/// The sequencer / matcher node.
pub struct Sequencer {
    pub state: DefaultState,
    matcher: MatchingEngine<Keccak256>,
    enclave: EnclaveIdentity,
    oracles: BTreeMap<MarketId, OracleTranscript>,
    next_batch_id: u64,
    next_receipt_seq: u64,
    matching_rule_version: u32,
    inclusion: BTreeMap<Digest, InclusionRecord>,
    finality: BTreeMap<Digest, Finality>,
    /// order hashes settled per batch, for `mark_settled`.
    batch_orders: BTreeMap<u64, Vec<Digest>>,
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
        }
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
        self.finality.entry(order_hash).or_insert(Finality::Accepted);
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
            return Err(RejectReason::ReduceOnlyViolation);
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
        if base.fits_initial_after(market, order.signed_size(), mark, funding_index) {
            Ok(())
        } else {
            Err(RejectReason::InsufficientMargin)
        }
    }

    /// Best book mid as the perp mark price; falls back to the oracle index if a
    /// side is empty. Used as the funding mark (§8).
    fn mark_price(&self, market_id: MarketId) -> Option<i128> {
        let book = self.matcher.book(market_id)?;
        match (book.best_bid(), book.best_ask()) {
            (Some(bid), Some(ask)) => Some((bid + ask) / 2),
            _ => self.oracles.get(&market_id).map(|o| o.price),
        }
    }

    /// Per-batch maintenance (§5, §8): accrue funding from the mark-vs-index
    /// premium, then liquidate every position that is underwater at the oracle
    /// price. Runs regardless of user liveness — the enclave holds positions, so
    /// an offline user is still liquidated. Returns the liquidated owners.
    pub fn run_maintenance(&mut self, now_ms: u64) -> Vec<PubKey> {
        let mut liquidated = Vec::new();
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
                if self
                    .state
                    .apply_op(&BatchOp::Liquidate {
                        owner,
                        market_id: mid,
                        oracle,
                        now_ms,
                    })
                    .is_ok()
                {
                    liquidated.push(owner);
                }
            }
        }
        liquidated
    }

    /// Run one batch: match `orders`, issue receipts, settle fills, run the
    /// funding+liquidation maintenance pass, publish a manifest, advance finality,
    /// and update inclusion tracking.
    pub fn seal_batch(&mut self, orders: &[Order], now_ms: u64) -> SealedBatch {
        let prev_state_root = self.state.state_root();
        let batch_id = self.next_batch_id;

        // 0. pre-trade risk gate: drop unmarginable orders before matching, so a
        //    matched fill can never fail to settle on margin (§12, Phase 3).
        let mut pre_rejected: Vec<(Digest, RejectReason)> = Vec::new();
        let mut admitted: Vec<Order> = Vec::new();
        for o in orders {
            match self.pre_trade_check(o, now_ms) {
                Ok(()) => admitted.push(*o),
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
        let liquidations = self.run_maintenance(now_ms);
        for owner in &liquidations {
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
        let mut seen_failed: std::collections::BTreeSet<Digest> =
            std::collections::BTreeSet::new();
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
        self.batch_orders
            .insert(batch_id, settled_order_hashes.clone());

        let new_state_root = self.state.state_root();
        self.next_batch_id += 1;

        SealedBatch {
            batch_id,
            prev_state_root,
            new_state_root,
            manifest,
            manifest_hash,
            settled_order_hashes,
            settlement_rejected,
            receipts,
            liquidations,
        }
    }

    /// Mark a previously sealed batch as SETTLED (its ZK proof verified on L1).
    /// Until this is called, the batch's fills are only MATCHED — soft, not
    /// withdrawable (§3).
    pub fn mark_settled(&mut self, batch_id: u64) {
        if let Some(orders) = self.batch_orders.get(&batch_id) {
            for oh in orders {
                self.finality.insert(*oh, Finality::Settled);
            }
        }
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
