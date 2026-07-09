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

    /// Sign a 32-byte prehash with the enclave's **secp256k1** identity, returning
    /// a recoverable `(r, s, v)` with `v` in Ethereum convention (27/28). This is
    /// the SAME key and recovery scheme used for receipts (§2, [`Sequencer::issue_receipt`]),
    /// reused so any off-chain artifact signed here (e.g. the published order-ingress
    /// epoch key) recovers to the enclave's attested L1 signer — no separate key.
    pub fn sign_prehash(&self, digest: &[u8; 32]) -> ([u8; 32], [u8; 32], u8) {
        let (signature, recid) = self
            .signing
            .sign_prehash_recoverable(digest)
            .expect("sign");
        let sig_bytes = signature.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);
        (r, s, 27 + recid.to_byte())
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
    /// The batch's replayable op-log: `[applied fills] ++ [maintenance AccrueFunding/
    /// Liquidate]`, in application order. Replaying it against the batch's pre-state
    /// (the retained snapshot) via `apply_batch` reproduces `new_state_root` — the
    /// witness a real ZK proof attests (Slice 3a).
    pub ops: Vec<BatchOp>,
}

/// The replayable witness for one settle window: `derive_roots(pre_state, ops, manifest)
/// .new_state_root` equals the live state root after this `seal_window`. This is the tuple
/// Slice 3b-2 seals and POSTs to the prover-service.
#[derive(Clone)]
pub struct WindowWitness {
    pub batch_id: u64,
    pub pre_state: DefaultState,
    pub ops: Vec<BatchOp>,
    pub manifest: BatchManifest,
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

/// Keep tick→window map entries for this many settled windows past the on-chain batchCount, so
/// `/v1/batch/:id` + `WBatch.window_id` reconciliation (and `settled:true`) stay observable for a
/// grace period after a window settles — decoupled from the much faster per-tick soft-finality.
const TICK_WINDOW_GRACE_WINDOWS: u64 = 8;
/// Hard backstop on the tick→window map so no path can leak (the legacy path never settles a
/// window, so it has no window-settle prune event) — evict the oldest entries beyond this cap.
const TICK_WINDOW_MAX: usize = 16_384;

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
    /// *pending* batch bounds the memory.
    snapshots: BTreeMap<u64, (DefaultState, MatchingEngine<Keccak256>)>,
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
    /// each `seal_window`. (Not `#[serde(default)]`: `DefaultState` has no `Default`; the
    /// Sequencer is not persisted, so no missing-field case arises.)
    window_start_state: DefaultState,
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
            tick_window: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            window_ops: Vec::new(),
            window_ordered: Vec::new(),
            window_rejected: Vec::new(),
            window_start_state: DefaultState::new(tree_depth),
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
        // Discard any withdrawal output: the sealed-batch path derives
        // `withdrawals_root` from `apply_batch`'s `BatchOutputs`; this thin
        // passthrough is used for setup/admin ops and returns only success/failure.
        self.state.apply_op(op)?;
        // Log the op at its real position in the open window's op-log so out-of-band
        // deposits/funds land in the replayable witness `seal_window` drains.
        self.window_ops.push(op.clone());
        Ok(())
    }

    pub fn current_batch_id(&self) -> u64 {
        self.next_batch_id
    }

    /// The currently open window id (Counter B) — the `batchCount`-space id that orders
    /// sequenced now will settle into. Directly comparable to the on-chain `batchCount`.
    pub fn current_window_id(&self) -> u64 {
        self.state.next_batch_id
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
            // funding accrual (best-effort; skip if oracle is out of bounds)
            let mark = self.mark_price(mid).unwrap_or(oracle.price);
            let funding_op = BatchOp::AccrueFunding {
                market_id: mid,
                mark,
                oracle,
                now_ms,
            };
            if self.state.apply_op(&funding_op).is_ok() {
                ops.push(funding_op);
            }
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
        // The batch's replayable op-log: `[applied fills] ++ [maintenance ops]`, in
        // application order. Only ops whose application SUCCEEDED are logged, so
        // replaying it via `apply_batch` reproduces the sealed `new_state_root` (Slice 3a).
        let mut ops: Vec<BatchOp> = Vec::new();
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
                // A Fill never yields a withdrawal output, so discard it.
                Ok(_) => {
                    for oh in [m.taker_order_hash, m.maker_order_hash] {
                        self.finality.insert(oh, Finality::Matched);
                        if !settled_order_hashes.contains(&oh) {
                            settled_order_hashes.push(oh);
                        }
                    }
                    // log the fill only after it settled — a failed fill (Err arm) is
                    // dropped, so it never enters the replayable op-log.
                    ops.push(op);
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
            ops: maintenance_ops,
        } = self.run_maintenance(now_ms);
        ops.extend(maintenance_ops);
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

        // Append this tick's ops + settled/rejected hashes to the open window's
        // accumulators, in application order. `seal_window` drains these into the
        // per-window `WindowWitness`; `ops`/`manifest` are still moved into `SealedBatch`
        // below (the internal per-tick record stays for rollback/inclusion).
        self.window_ops.extend_from_slice(&ops);
        self.window_ordered.extend_from_slice(&manifest.ordered);
        self.window_rejected.extend_from_slice(&manifest.rejected);

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
            ops,
        }
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
    }

    /// Close the current settle window: build the combined manifest over the window's
    /// accumulated ordered/rejected hashes, advance the batch counter once (mirroring
    /// `apply_batch`), drain the window op-log into the witness, and reopen a fresh
    /// window from the current (post-bump) state. `derive_roots(pre_state, ops, manifest)
    /// .new_state_root` equals the live state root after this call.
    pub fn seal_window(&mut self) -> WindowWitness {
        let batch_id = self.state.next_batch_id;
        let oracle_updates: Vec<Digest> =
            self.oracles.values().map(|t| t.hash::<Keccak256>()).collect();
        let manifest = BatchManifest {
            previous_state_root: self.window_start_state.state_root(),
            batch_id,
            ordered: self.window_ordered.clone(),
            rejected: self.window_rejected.clone(),
            oracle_updates,
            matching_rule_version: self.matching_rule_version,
            enclave_measurement: self.enclave.measurement,
            sequencer_pubkey_epoch: self.enclave.epoch,
        };
        // the single per-window counter bump (mirrors apply_batch's engine.rs:156)
        self.state.next_batch_id += 1;
        let pre_state = self.window_start_state.clone();
        let ops = core::mem::take(&mut self.window_ops);
        // reopen the next window from the post-bump state
        self.window_ordered.clear();
        self.window_rejected.clear();
        self.window_start_state = self.state.clone();
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
        // restore the window baseline (seal_window re-captured it to the post-bump state).
        self.window_start_state = w.pre_state.clone();
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
    use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
    use perp_core::note::owner_from_spend_key;
    use perp_core::order::TimeInForce;
    use perp_core::Note;

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
        seq.apply(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount,
            blinding: [blind; 32],
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
        let mut s = Sequencer::new(
            EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]),
            20,
        );
        s.add_market(Market::conservative(0));
        s.set_oracle(
            0,
            OracleTranscript {
                price: 100_000 * PRICE_SCALE,
                publish_time_ms: now(),
                confidence: 10 * PRICE_SCALE,
                backup_twap: 100_000 * PRICE_SCALE,
            },
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

    // BadPrevRoot fix: boot funding + SeedInsurance run AFTER add_market's last
    // window_start_state capture, so without re-basing, window 0's pre_state is the
    // pre-funding state while the deployed GENESIS_ROOT is the FULL boot state root.
    // seal_genesis_baseline folds the boot ops into the trusted genesis baseline.
    #[test]
    fn seal_genesis_baseline_rebases_window_zero_to_full_boot_state() {
        // mirrors Gw::boot: add_market + oracle (test_sequencer), then funding
        // (Deposit + FundPosition per account) and an insurance seed.
        let mut seq = test_sequencer();
        seq.apply(&BatchOp::SeedInsurance {
            amount: 1_000 * QUOTE_SCALE,
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
}
