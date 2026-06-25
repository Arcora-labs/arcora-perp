//! # sequencer — the native settlement spine (§2, §3)
//!
//! This is the host-side component that ties the protocol together on the hot
//! path: it accepts orders, runs the [`matcher`], issues **Ed25519-signed
//! receipts** (the §2 inclusion proof a user keeps), settles the resulting fills
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

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use matcher::{MatchingEngine, SubmitStatus};
use perp_core::engine::BatchOp;
use perp_core::hash::{Digest, Keccak256};
use perp_core::market::{Market, MarketId};
use perp_core::order::{BatchManifest, Finality, Order, Receipt, RejectReason};
use perp_core::oracle::OracleTranscript;
use perp_core::{DefaultState, EngineError};

/// The enclave's signing identity: an Ed25519 key plus the attested measurement
/// and key epoch that the manifest commits to (§2). In production the key lives
/// only inside the enclave; here it is a normal key for the local/testnet build.
pub struct EnclaveIdentity {
    signing: SigningKey,
    pub epoch: u64,
    pub measurement: Digest,
}

impl EnclaveIdentity {
    /// Derive a deterministic identity from a 32-byte seed (testnet convenience).
    pub fn from_seed(seed: [u8; 32], epoch: u64, measurement: Digest) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
            epoch,
            measurement,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

/// A receipt with the enclave's signature over its signing digest (§2).
#[derive(Clone, Debug)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signature: [u8; 64],
    pub enclave_pubkey: [u8; 32],
}

impl SignedReceipt {
    /// Verify the signature binds this exact receipt to the given enclave key.
    pub fn verify(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.enclave_pubkey) else {
            return false;
        };
        let digest = self.receipt.signing_digest::<Keccak256>();
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&digest, &sig).is_ok()
    }
}

/// Inclusion-tracking record for one issued receipt (§2).
#[derive(Clone, Copy, Debug)]
struct InclusionRecord {
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

    pub fn finality_of(&self, order_hash: &Digest) -> Option<Finality> {
        self.finality.get(order_hash).copied()
    }

    fn issue_receipt(&mut self, order_hash: Digest, seq_no: u64, now_ms: u64) -> SignedReceipt {
        let receipt = Receipt {
            order_hash,
            seq_no,
            recv_time_ms: now_ms,
            batch_id_hint: self.next_batch_id,
        };
        let digest = receipt.signing_digest::<Keccak256>();
        let signature: Signature = self.enclave.signing.sign(&digest);
        self.inclusion.entry(order_hash).or_insert(InclusionRecord {
            issued_batch: self.next_batch_id,
            seen_in_batch: None,
        });
        self.finality.entry(order_hash).or_insert(Finality::Accepted);
        SignedReceipt {
            receipt,
            signature: signature.to_bytes(),
            enclave_pubkey: self.enclave.verifying_key().to_bytes(),
        }
    }

    /// Accept an order immediately and return its signed receipt (§2 ACCEPTED),
    /// independent of when/whether it is later included in a batch. This is the
    /// honest enclave's instant acknowledgement; a subsequent failure to include
    /// the order in a manifest within the timeout is an inclusion violation
    /// (censorship/withholding) detectable via [`Sequencer::inclusion_violations`].
    pub fn accept_order(&mut self, order: &Order, now_ms: u64) -> SignedReceipt {
        let order_hash = order.order_hash::<Keccak256>();
        // peek the seq the matcher would assign next, for the receipt.
        let seq_no = self.matcher.peek_seq();
        self.issue_receipt(order_hash, seq_no, now_ms)
    }

    /// Run one batch: match `orders`, issue receipts, settle fills, publish a
    /// manifest, advance finality, and update inclusion tracking.
    pub fn seal_batch(&mut self, orders: &[Order], now_ms: u64) -> SealedBatch {
        let prev_state_root = self.state.state_root();
        let batch_id = self.next_batch_id;

        // 1. match the arrival-ordered stream
        let stream = self.matcher.process_stream(orders, now_ms);

        // 2. issue signed receipts for every accepted (non-rejected) order
        let mut receipts = Vec::new();
        for p in &stream.processed {
            if !matches!(p.outcome.status, SubmitStatus::Rejected(_)) {
                receipts.push(self.issue_receipt(p.outcome.order_hash, p.seq_no, now_ms));
            }
        }

        // 3. settle matched fills through the engine, attaching the oracle.
        let mut settled_order_hashes = Vec::new();
        let mut settlement_rejected = Vec::new();
        for m in &stream.fills {
            let Some(oracle) = self.oracles.get(&m.market_id).copied() else {
                settlement_rejected.push((m.taker_order_hash, RejectReason::OracleUnavailable));
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
                    settlement_rejected.push((m.taker_order_hash, settlement_reason(&e)));
                }
            }
        }

        // 4. build the manifest. `ordered` / `rejected` are the *matcher's*
        //    sequencing view and are kept disjoint (§2). Settlement failures are
        //    NOT folded into `rejected` — an order the matcher sequenced stays in
        //    `ordered`. A fill that matched but failed settlement margin is a
        //    symptom of the missing pre-trade risk check; closing that gap (so an
        //    unmarginable order is rejected *before* matching) is Phase 3
        //    hardening. Until then settlement rejects are surfaced separately on
        //    the SealedBatch for the operator/insurance path, never double-listed.
        let rejected = stream.rejected.clone();
        let oracle_updates: Vec<Digest> = self
            .oracles
            .values()
            .map(|t| t.hash::<Keccak256>())
            .collect();
        let manifest = BatchManifest {
            previous_state_root: prev_state_root,
            batch_id,
            ordered: stream.ordered.clone(),
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
