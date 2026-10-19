//! Crash-recovery rollback journal — the sealed sidecar that survives a restart
//! mid-window-settle.
//!
//! The settle loop's rollback inputs (`WindowWitness` + the window's drained
//! withdrawals) are in-memory clones only; if the gateway dies between
//! `begin_window_settle` and commit/rollback, the restored snapshot has Counter B
//! ahead of (or the settled root behind) the chain and the rollup wedges forever
//! (the 0xEa11 stack's fate). This module persists exactly those inputs to
//! `<DARKPERP_STATE>.rollback` so boot can decide — from the journal, the restored
//! snapshot, and the chain — whether the in-flight window is stale, must be rolled
//! back, or (if the tx landed but the commit was lost) rolled forward.
//!
//! ## Sealing
//!
//! The journal carries the full `WindowWitness` (incl. `pre_state` — private
//! notes), so it is sealed EXACTLY like the snapshot: [`snapshot::seal`]/
//! [`snapshot::open`] under the enclave seed, written via
//! [`snapshot::write_atomic`]. The snapshot format itself is untouched — this is a
//! separate file with its own magic/version inside the sealed plaintext, so a
//! future journal layout change fails closed instead of misreading.

use crate::snapshot;
use crate::withdrawals::Withdrawal;
use std::path::{Path, PathBuf};

/// Journal plaintext magic + format version (INSIDE the sealed payload; the sealed
/// file itself starts with the snapshot module's `snapshot::MAGIC` framing). Bump the
/// trailing digit on layout changes so an old binary refuses a new journal (and
/// vice versa) instead of postcard-misreading it.
/// v2: SEC-022 added `Market.max_fill_deviation_ratio`, carried here via
/// `witness: WindowWitness.pre_state` — same positional-postcard hazard as the
/// snapshot's v2 bump (see `snapshot.rs::MAGIC`).
/// v3: SEC-025-B — `ProveOutcome` gained `new_deposit_count`, and `PreparedSettle`
/// is journaled, so the positional postcard layout changed. SEC-022 already moved
/// this to DPRBJL2 and a pre-025-B binary can therefore already have written
/// DPRBJL2 — reusing it would make an old journal a silent postcard misparse
/// instead of a versioned rejection.
/// v4: SEC-024 — `BatchOp`'s MEANING changed, not just its layout: ordinal 8
/// (`SeedInsurance`, the unbound insurance mint) now always rejects, and ordinal 9
/// (`FundInsurance`) exists. `BatchOp` is positional in the journaled witness via
/// `window_ops`, so a pending pre-SEC-024 journal must be REFUSED here rather than
/// decoded under the new meaning — replaying it would either reject a formerly
/// valid seed op mid-recovery or misread a trailing variant.
/// v5: SEC-025-D — `ProveOutcome` gained `post_mode_is_normal` + `post_insurance_fund`
/// (the launch-gate terms), and `PreparedSettle` embeds it in the journaled
/// `prepared`, so the positional postcard layout moved again. A pre-025-D journal
/// decoded by a post-025-D binary would misparse the outcome — and a roll-forward
/// re-submits those roots to `_requireDepositPrefix`, so this must be a versioned
/// refusal, never a silent misparse.
/// v7: the journaled `WindowWitness.pre_state` carries the new engine state
/// wire (note tree and nullifier log, funding state, last withdrawal nonce,
/// wind-down recipient), so v5 and v6 journals are refused; there is no reader
/// for them.
const MAGIC: &[u8; 8] = b"DPRBJL7\0";

/// Candidate (opt-in Chainlink report archive) journal magic. A v8 journal is a
/// v7 `RollbackJournal` PLUS an authenticated `ArchiveEnvelope`; the distinct magic
/// keeps the plain journal read/write path byte-identical and makes a pre-candidate
/// binary refuse this journal (and a candidate-required boot refuse a plain
/// journal) as a versioned mismatch, never a silent postcard misparse. It moved
/// from v6 to v8 with the v7 bump of the journal it wraps.
const CANDIDATE_MAGIC: &[u8; 8] = b"DPRBJL8\0";

/// One oracle-bearing op's exact binding to an immutable archived report pair:
/// the op's (market_id, now_ms) plus the archive record's content hash. Repeated
/// use of the same record yields one ref PER OP, in op order — the archive stream,
/// not a manifest/reference list, is what is bound.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchiveRef {
    pub market_id: u64,
    pub now_ms: u64,
    pub archive_id: chainlink_streams_client::report_archive::ArchiveId,
}

/// The candidate envelope sealed inside the candidate journal. `policy_binding` is
/// `chainlink_streams_client::report_pair::policy_binding` of the operator-pinned
/// policy; recovery refuses a journal whose envelope does not match the configured
/// policy, and every referenced record must decode and re-normalize to the exact
/// op transcript under that policy.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ArchiveEnvelope {
    pub policy_binding: [u8; 32],
    pub refs: Vec<ArchiveRef>,
}

/// The sealed candidate payload: the unchanged plain journal plus its archive envelope.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct CandidateJournalV6 {
    journal: RollbackJournal,
    envelope: ArchiveEnvelope,
}

/// Serialize the same candidate fields without copying the full recovery state. Decode
/// still uses the owned payload above, so no borrowed data escapes recovery.
#[derive(serde::Serialize)]
struct CandidateJournalV6Ref<'a> {
    journal: &'a RollbackJournal,
    envelope: &'a ArchiveEnvelope,
}

/// Boot-facing decode result: which authenticated envelope the sealed bytes carry.
pub enum OpenedJournal {
    /// Plain journal (`MAGIC`) — no archive binding. Refused in archive-required mode.
    Legacy(RollbackJournal),
    /// Candidate journal (`CANDIDATE_MAGIC`) with its archive envelope.
    Candidate {
        journal: RollbackJournal,
        envelope: ArchiveEnvelope,
    },
}

/// Everything boot recovery needs to resolve one in-flight window settle:
/// the sequencer rollback input (`witness`), the withdrawal rollback input (`ww`,
/// the set `begin_window_settle` drained), and — once the prove has returned —
/// the `prepared` outcome whose `new_root`/claim proofs a roll-forward re-commits.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackJournal {
    pub batch_id: u64,
    pub witness: sequencer::WindowWitness,
    pub ww: Vec<Withdrawal>,
    /// `None` before any potential chain mutation (Stage 1). Clock mode first
    /// stores `Some` with an EMPTY proof as its durable registration intent;
    /// that may HOLD/resume the exact witness but is never broadcast as a proof.
    /// A nonempty prepared proof is persisted again before settlement broadcast.
    pub prepared: Option<crate::prover_client::PreparedSettle>,
}

/// The journal's on-disk location: `<state_path>.rollback` (appended, not
/// `with_extension` — `/var/lib/darkperp/state.snap` → `state.snap.rollback`, so
/// the sidecar never shadows the snapshot itself).
pub fn journal_path(state_path: &Path) -> PathBuf {
    let mut os = state_path.as_os_str().to_os_string();
    os.push(".rollback");
    PathBuf::from(os)
}

/// Persist the journal: magic-prefixed postcard plaintext → `snapshot::seal` under
/// the enclave seed → `snapshot::write_atomic` (a crash mid-write never leaves a
/// torn journal). `Err` means durability was not acknowledged. The live settle
/// loop must stop before proving/broadcasting when configured persistence fails;
/// it must not delete the existing recovery record or treat the write as success.
/// Plain write path — the exact pre-candidate bytes. Retained for the
/// existing tests and any non-candidate tooling; production writes go through
/// [`write_versioned`].
#[allow(dead_code)]
pub fn write(path: &Path, j: &RollbackJournal, seed: &[u8; 32]) -> Result<(), String> {
    write_versioned(path, j, None, seed)
}

/// Versioned persistence: `None` writes exactly the plain journal envelope;
/// `Some` writes the candidate envelope (same seal, same atomic write).
pub fn write_versioned(
    path: &Path,
    j: &RollbackJournal,
    envelope: Option<&ArchiveEnvelope>,
    seed: &[u8; 32],
) -> Result<(), String> {
    let (magic, body) = match envelope {
        None => (
            MAGIC,
            postcard::to_allocvec(j).map_err(|e| format!("journal encode: {e}"))?,
        ),
        Some(env) => {
            let payload = CandidateJournalV6Ref {
                journal: j,
                envelope: env,
            };
            (
                CANDIDATE_MAGIC,
                postcard::to_allocvec(&payload).map_err(|e| format!("journal encode: {e}"))?,
            )
        }
    };
    let mut plain = Vec::with_capacity(magic.len() + body.len());
    plain.extend_from_slice(magic);
    plain.extend_from_slice(&body);
    let sealed = snapshot::seal(&plain, seed);
    snapshot::write_atomic(path, &sealed).map_err(|e| format!("journal write: {e}"))
}

/// Decode a sealed journal of EITHER authenticated version, dispatching on the
/// inner magic. Same fail-closed posture as `open`: wrong seed/tamper/trailing
/// bytes/magic mismatch are `Err`, never a guess.
///
/// postcard note: `postcard::from_bytes` SILENTLY DISCARDS a remaining suffix
/// (postcard 1.x docs) — a body that decodes cleanly but carries trailing bytes
/// must be refused, not truncated-accepted. Both versions therefore decode with
/// `take_from_bytes` and require an EMPTY remainder; the candidate body must
/// ALSO re-encode to exactly the input bytes (postcard's encoding is canonical,
/// so a decodable-but-differently-encoded body is treated as corrupt). The plain
/// journal gets the trailing-byte check only: its writers are
/// `to_allocvec`-canonical by construction.
pub fn open_versioned(sealed: &[u8], seed: &[u8; 32]) -> Result<OpenedJournal, String> {
    let plain = snapshot::open(sealed, seed).map_err(|e| format!("journal open: {e}"))?;
    if let Some(body) = plain.strip_prefix(CANDIDATE_MAGIC.as_slice()) {
        let (CandidateJournalV6 { journal, envelope }, rest) =
            postcard::take_from_bytes(body).map_err(|e| format!("journal decode: {e}"))?;
        if !rest.is_empty() {
            return Err(format!(
                "candidate journal decode: {} trailing bytes after the envelope",
                rest.len()
            ));
        }
        // Canonical re-encoding: postcard's derive encoding is deterministic, so
        // a body produced by `write_versioned` round-trips byte-exactly. A body
        // that decodes but re-encodes differently is corrupt in a way the length-
        // blind decode happened to tolerate — refuse it.
        let reencoded = postcard::to_allocvec(&CandidateJournalV6Ref {
            journal: &journal,
            envelope: &envelope,
        })
        .map_err(|e| format!("journal re-encode: {e}"))?;
        if reencoded != body {
            return Err("candidate journal decode: non-canonical body encoding".into());
        }
        if journal.batch_id != journal.witness.batch_id {
            return Err(format!(
                "journal batch_id mismatch: batch_id {} != witness.batch_id {}",
                journal.batch_id, journal.witness.batch_id
            ));
        }
        // An empty REF list is legitimate (a window with no oracle-bearing ops —
        // recovery verifies `refs.len() == used-op count`); only a missing policy
        // binding would be indistinguishable from a legacy journal under downgrade.
        if envelope.policy_binding == [0; 32] {
            return Err("candidate journal carries an empty policy binding".into());
        }
        return Ok(OpenedJournal::Candidate { journal, envelope });
    }
    open(sealed, seed).map(OpenedJournal::Legacy)
}

/// Load the journal, distinguishing the three boot cases: `Ok(None)` = no journal
/// (clean shutdown — the common case), `Ok(Some)` = an in-flight window to resolve,
/// `Err` = a journal EXISTS but is unreadable (wrong seed / tampered / truncated /
/// future format) — the caller must HOLD, never treat it as absent.
#[cfg(test)]
pub fn read(path: &Path, seed: &[u8; 32]) -> Result<Option<RollbackJournal>, String> {
    let sealed = match snapshot::read_file(path) {
        Ok(bytes) => bytes,
        // The ONLY absent case: the file does not exist. Every other I/O failure
        // (permissions, etc.) is a present-but-unreadable journal → Err → HOLD.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("journal read: {e}")),
    };
    open(&sealed, seed).map(Some)
}

/// Decode exactly the bytes admitted by the startup checkpoint. Never reopen a
/// file after comparing its hash; the existing authenticated format is unchanged.
pub fn open(sealed: &[u8], seed: &[u8; 32]) -> Result<RollbackJournal, String> {
    let plain = snapshot::open(sealed, seed).map_err(|e| format!("journal open: {e}"))?;
    let body = plain
        .strip_prefix(MAGIC.as_slice())
        .ok_or("journal magic/version mismatch")?;
    // `from_bytes` would silently discard a remaining suffix (postcard 1.x):
    // a journal that decodes cleanly but carries trailing bytes is refused, so
    // a candidate payload (or anything else) concatenated after a valid plain
    // body can never read as an accepted plain journal. Everything `write`
    // produces is `to_allocvec`-canonical with no suffix.
    let (j, rest): (RollbackJournal, &[u8]) =
        postcard::take_from_bytes(body).map_err(|e| format!("journal decode: {e}"))?;
    if !rest.is_empty() {
        return Err(format!(
            "journal decode: {} trailing bytes after the journal payload",
            rest.len()
        ));
    }
    // Defense-in-depth: the window id lives in the journal twice — `batch_id`
    // (what the boot recovery table keys on) and `witness.batch_id` (what
    // `rollback_window` asserts on). They are written equal; a decoded journal
    // where they disagree is corrupt/tampered in a way the seal + postcard framing
    // happened not to catch — fail closed like any other unreadable journal (the
    // caller HOLDs), never hand recovery a self-inconsistent journal.
    if j.batch_id != j.witness.batch_id {
        return Err(format!(
            "journal batch_id mismatch: batch_id {} != witness.batch_id {}",
            j.batch_id, j.witness.batch_id
        ));
    }
    Ok(j)
}

/// Best-effort removal once the window is resolved (commit, rollback, or stale).
/// A failed delete only logs: the recovery decision is idempotent against a
/// re-read journal (Stale/SealNeverPersisted re-derive to delete again).
pub fn delete(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("[recovery] rollback journal delete {}: {e}", path.display());
        }
    }
}

/// What boot recovery must do about the journaled window (the spec's
/// recovery_action table, normative).
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Commit already happened and was persisted — delete the journal.
    Stale,
    /// Pre-seal snapshot and stage 1 proves no broadcast occurred; delete the journal.
    SealNeverPersisted,
    /// Seal persisted and stage 1 proves no broadcast occurred; replay rollback
    /// inputs, persist the resolution, then delete.
    RollBack,
    /// The tx landed but the commit was lost — re-commit from the journal's
    /// `prepared`, then delete.
    RollForward,
    /// A clock intent whose window can never settle on L1 (see [`DeadIntent`]).
    /// What to do about it is [`dead_intent_action`]'s decision.
    VoidDeadIntent(DeadIntent),
    /// Anything else: retain the journal and refuse startup until reconciled.
    Hold,
}

/// The anchor slot of the journaled (batch, phase) at the finalized block the
/// dead-intent evidence was read at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorSlot {
    /// An anchor for this window is registered: the same receipt, or with no
    /// local receipt the same previous root and base commitment.
    Matching,
    /// `cancelledReceipt(receipt)` is set for the journal's receipt.
    Cancelled,
    /// No anchor is registered for this batch and phase.
    Empty,
    /// An anchor with another receipt or another base is registered.
    Different,
}

/// What identifies a journaled clock intent on L1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockIntent {
    pub batch: u64,
    pub phase: u8,
    pub prev_root: perp_core::Digest,
    /// The base commitment the anchor binds.
    pub base: perp_core::Digest,
    /// The anchor's receipt, known once a bound proof was journaled.
    pub receipt: Option<perp_core::Digest>,
    /// Whether the window holds timed operations. A window whose bounds cannot be
    /// derived counts as timed.
    pub timed: bool,
}
impl ClockIntent {
    /// The intent of a journal with a prepared outcome; `None` at stage 1.
    pub fn of(j: &RollbackJournal) -> Option<Self> {
        let p = j.prepared.as_ref()?;
        Some(Self {
            batch: j.batch_id,
            phase: p.outcome.wind_down_phase,
            prev_root: p.outcome.prev_root,
            base: p.outcome.commitment,
            receipt: p
                .outcome
                .proof
                .strip_prefix(perp_core::clock::PROOF_MAGIC)
                .and_then(|body| body.get(..32))
                .and_then(|r| r.try_into().ok()),
            timed: perp_core::clock::TimeBounds::derive(&j.witness.ops)
                .map_or(true, |b| b.count > 0),
        })
    }
}

/// Everything the dead-intent row needs, read at one finalized block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadIntentEvidence {
    pub block: u64,
    pub batch_count: u64,
    pub close_only: bool,
    pub slot: AnchorSlot,
    /// The sequencer's account nonce at the block is past every nonce this
    /// gateway has handed to a sequencer-key transaction, so no register or
    /// settle of the journaled window can still be mined.
    pub fenced: bool,
}

/// Why a journaled clock intent can never settle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadIntent {
    /// (a) its anchor was cancelled.
    Cancelled,
    /// (b) a phase-0 window while the settlement is in close-only: `settleBatch`
    /// and phase-0 registration both revert there, for good.
    CloseOnlyPhaseZero,
    /// (c) no anchor exists and no pending transaction can create one.
    EmptyAfterFence,
    /// (d) another anchor holds this batch and phase.
    Replaced,
}

/// Classify a journaled clock intent at one finalized block. `None` when the
/// window may still settle: the batch moved on, a transaction of ours could still
/// be mined, or its own anchor is registered (outside close-only).
///
/// A phase-0 window in close-only needs no nonce fence: close-only never ends, and
/// from then on every phase-0 `register` reverts (`BadContext`) and every
/// `settleBatch` reverts (`InCloseOnly`), so a transaction of ours that is still
/// pending can never land. It also takes precedence over a cancelled receipt, since
/// its recovery (the close-only rebase) is the one a cancelled timed phase-0
/// window is directed to.
pub fn classify_dead_intent(
    j_batch: u64,
    j_phase: u8,
    e: &DeadIntentEvidence,
) -> Option<DeadIntent> {
    if e.batch_count != j_batch {
        return None;
    }
    if j_phase == 0 && e.close_only {
        return Some(DeadIntent::CloseOnlyPhaseZero);
    }
    if !e.fenced {
        return None;
    }
    if e.slot == AnchorSlot::Cancelled {
        Some(DeadIntent::Cancelled)
    } else if e.slot == AnchorSlot::Empty {
        Some(DeadIntent::EmptyAfterFence)
    } else if e.slot == AnchorSlot::Different {
        Some(DeadIntent::Replaced)
    } else {
        None
    }
}

/// What recovery does with a dead intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadIntentAction {
    /// Return the window's ops to the open window, exactly as a rollback does.
    /// Nothing exists on L1 to undo. An untimed window re-registers unchanged
    /// under a fresh anchor; a phase-0 window in close-only never settles and the
    /// close-only rebase of the wind-down discards it.
    ReturnToOpenWindow,
    /// Keep the journal and refuse to resolve it automatically.
    Hold(&'static str),
}

/// Automatic only where nothing on L1 has to be undone and no operation time has
/// to be re-registered; every other dead intent holds for the operator, with the
/// recovery path in the reason.
pub fn dead_intent_action(dead: DeadIntent, phase: u8, timed: bool) -> DeadIntentAction {
    match dead {
        DeadIntent::CloseOnlyPhaseZero => DeadIntentAction::ReturnToOpenWindow,
        DeadIntent::Cancelled | DeadIntent::EmptyAfterFence if !timed => {
            DeadIntentAction::ReturnToOpenWindow
        }
        DeadIntent::Cancelled | DeadIntent::EmptyAfterFence if phase == 0 => DeadIntentAction::Hold(
            "a timed phase-0 window cannot be re-registered with its original operation times; \
             have governance call enterCloseOnly(), then restart: the window is then discarded \
             by the close-only rebase, uncredited deposits are refunded by the vault and the \
             wind-down settles the rest",
        ),
        DeadIntent::Cancelled | DeadIntent::EmptyAfterFence => DeadIntentAction::Hold(
            "a timed wind-down window cannot be re-registered with its original operation times",
        ),
        DeadIntent::Replaced => DeadIntentAction::Hold(
            "another anchor holds this batch and phase; once it is older than anchorTimeoutMs, \
             cancel it with POST /v1/admin/settlement/cancel-anchor and restart",
        ),
    }
}

/// Pure decision over the spec's recovery table (unit-testable as a full matrix,
/// mirroring `settle_failure_action`). Inputs: `j_batch` = the journaled window's
/// batch id, `has_prepared` = journal carries a prove outcome, `b_snap` = restored
/// Counter B (`seq.state.next_batch_id`), `chain_bc` = on-chain `batchCount`,
/// `root_matches_prepared` = chain `currentStateRoot == prepared.new_root` (false
/// when `prepared` is None), `root_matches_settled` = chain `currentStateRoot ==`
/// restored `l1_status.settled_root`.
#[cfg(test)]
pub fn recovery_action(
    j_batch: u64,
    has_prepared: bool,
    b_snap: u64,
    chain_bc: u64,
    root_matches_prepared: bool,
    root_matches_settled: bool,
) -> RecoveryAction {
    recovery_action_classified(
        j_batch,
        has_prepared,
        b_snap,
        chain_bc,
        root_matches_prepared,
        root_matches_settled,
        None,
    )
}

/// [`recovery_action`] plus the dead-intent row. `dead` is the classification of
/// a prepared clock intent at one finalized block ([`classify_dead_intent`]),
/// `None` when it was not read or the intent may still settle. The row needs a
/// prepared journal whose batch is still the chain's batch, with the seal still
/// persisted (`b_snap == j + 1`) or already rolled back (`b_snap == j`). It is
/// disjoint from every other row: those need stage 1 or a landed transaction.
pub fn recovery_action_classified(
    j_batch: u64,
    has_prepared: bool,
    b_snap: u64,
    chain_bc: u64,
    root_matches_prepared: bool,
    root_matches_settled: bool,
    dead: Option<DeadIntent>,
) -> RecoveryAction {
    // `checked_add` so a (theoretical) u64::MAX journal can never panic a boot;
    // an overflowed "next" simply matches nothing sealed/landed → HOLD.
    let sealed_persisted = Some(b_snap) == j_batch.checked_add(1);
    let tx_landed = Some(chain_bc) == j_batch.checked_add(1);

    // A prepared stage-2 journal is evidence a transaction MAY have been sent.
    // Unchanged counters, even after a long wait, cannot prove it will never land.
    // Rollback and pre-seal deletion therefore require stage 1 (no prepared data).
    // Row order IS the precedence: STALE must beat ROLL-FORWARD (same counters —
    // if the settled root already matches the chain, the commit was persisted and
    // re-committing would double-apply the window).
    //
    // WHY the precedence is sound (i.e. why STALE can never shadow a genuine
    // roll-forward): `root_matches_settled` and `root_matches_prepared` can never
    // both be true, because consecutive settle roots always differ —
    // `state_root()` binds `next_batch_id` into the root
    // (crates/perp-core/src/state.rs:240) and `apply_batch` increments it exactly
    // once per window (crates/perp-core/src/engine.rs:204), so `prepared.new_root`
    // (the new window's post-state) cannot equal the restored
    // `l1_status.settled_root` (the previous window's post-state) even for a
    // window that changed nothing else. A lost commit therefore always presents
    // as `root_matches_settled == false` and falls through to ROLL-FORWARD.
    if sealed_persisted && tx_landed && root_matches_settled {
        RecoveryAction::Stale
    } else if !has_prepared && b_snap == j_batch && chain_bc == j_batch {
        RecoveryAction::SealNeverPersisted
    } else if !has_prepared && sealed_persisted && chain_bc == j_batch {
        RecoveryAction::RollBack
    } else if sealed_persisted && tx_landed && has_prepared && root_matches_prepared {
        RecoveryAction::RollForward
    } else if let Some(dead) = dead
        .filter(|_| has_prepared && chain_bc == j_batch && (sealed_persisted || b_snap == j_batch))
    {
        RecoveryAction::VoidDeadIntent(dead)
    } else {
        RecoveryAction::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover_client::{prove_and_prepare, MockProverClient, ProverClient as _};
    use crate::Gw;
    use perp_core::fixed::QUOTE_SCALE;

    /// Unpredictable per-test scratch path under the OS temp dir (the l1.rs
    /// keystore pattern) — parallel tests never collide on a fixed name.
    fn scratch_path(tag: &str) -> PathBuf {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).expect("OS CSPRNG");
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("darkperp-journal-{tag}-{suffix}"))
    }

    /// A REAL sealed window (deposit + withdrawal), exactly what the settle loop
    /// would journal — not a hand-built stand-in. SEC-021: the withdrawal goes
    /// through the full authorization path — a caller-signed account whose
    /// registered signer signs the real `withdraw_auth_digest` (no exemption).
    fn sealed_window() -> (sequencer::WindowWitness, Vec<Withdrawal>) {
        use sha3::{Digest as _, Keccak256};
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x51u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&hash[12..]);

        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(Some(signer));
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let (amount, to, nonce) = (5_000 * QUOTE_SCALE, [7u8; 20], 1u64);
        let digest =
            crate::withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, nonce);
        let (s, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&s.to_bytes());
        sig[64] = 27 + recid.to_byte();
        gw.account_withdraw(&key, 0, amount, to, nonce, &sig)
            .unwrap();
        let bc = gw.seq.state.next_batch_id;
        gw.begin_window_settle(bc).unwrap().expect("window sealed")
    }

    /// Fixed native fixture: no gateway boot, env, clock, network, or prover service.
    /// Two full-note withdrawals exercise nonempty claim paths as well as state.
    fn candidate_fixture() -> RollbackJournal {
        use perp_core::engine::BatchOp;
        use perp_core::hash::Keccak256;
        use perp_core::market::Market;
        use perp_core::note::owner_from_spend_key;
        use perp_core::Note;
        let mut seq = sequencer::Sequencer::new(
            sequencer::EnclaveIdentity::from_seed([9; 32], 3, [0xab; 32]),
            8,
        );
        seq.add_market(Market::conservative(0));
        seq.set_retain_tick_snapshots(false);
        for key in 1..=3u8 {
            let owner = owner_from_spend_key::<Keccak256>(&[key; 32]);
            seq.apply(&BatchOp::Deposit {
                owner,
                asset_id: 0,
                amount: i128::from(key) * 1_000 * QUOTE_SCALE,
                blinding: [key * 0x11; 32],
                from: [key; 20],
                deposit_id: seq.state.consumed_deposit_count,
                deposit_blind: [key + 0x10; 32],
            })
            .unwrap();
        }
        let insurance = Note::new(
            owner_from_spend_key::<Keccak256>(&[1; 32]),
            0,
            1_000 * QUOTE_SCALE,
            [0x11; 32],
        );
        seq.apply(&BatchOp::FundInsurance {
            note_commitment: insurance.commitment::<Keccak256>(),
            spend_key: [1; 32],
        })
        .unwrap();
        seq.seal_genesis_baseline();
        assert_eq!(seq.state.notes.len(), 2);
        seq.apply(&BatchOp::Deposit {
            owner: owner_from_spend_key::<Keccak256>(&[4; 32]),
            asset_id: 0,
            amount: 4_000 * QUOTE_SCALE,
            blinding: [0x44; 32],
            from: [4; 20],
            deposit_id: seq.state.consumed_deposit_count,
            deposit_blind: [0x14; 32],
        })
        .unwrap();
        let mut ww = Vec::new();
        for key in 2..=3u8 {
            let owner = owner_from_spend_key::<Keccak256>(&[key; 32]);
            let amount = i128::from(key) * 1_000 * QUOTE_SCALE;
            let note = Note::new(owner, 0, amount, [key * 0x11; 32]);
            let nonce = u64::from(key) * 128;
            seq.apply(&BatchOp::Withdraw {
                note_commitment: note.commitment::<Keccak256>(),
                spend_key: [key; 32],
                to: Some([key; 20]),
                nonce,
            })
            .unwrap();
            ww.push(Withdrawal {
                owner,
                to: [key; 20],
                amount: amount as u128,
                nonce,
            });
        }
        let witness = seq.seal_window();
        assert_eq!(witness.pre_state.notes.len(), 2);
        assert_eq!(witness.ops.len(), 3);
        RollbackJournal {
            batch_id: witness.batch_id,
            witness,
            ww,
            prepared: None,
        }
    }

    fn candidate_stages() -> Vec<RollbackJournal> {
        let stage1 = candidate_fixture();
        let mut intent = stage1.clone();
        intent.prepared =
            Some(crate::prover_client::prepare_unproved(&intent.witness, &intent.ww).unwrap());
        let mut stage2 = stage1.clone();
        stage2.prepared =
            Some(prove_and_prepare(&MockProverClient, &stage2.witness, &stage2.ww).unwrap());
        assert!(intent.prepared.as_ref().unwrap().outcome.proof.is_empty());
        let prepared = stage2.prepared.as_ref().unwrap();
        assert!(!prepared.outcome.proof.is_empty());
        assert_eq!(prepared.outcome.new_deposit_count, 4);
        assert!(prepared.outcome.post_mode_is_normal);
        assert!(prepared.outcome.post_insurance_fund > 0);
        assert_eq!(prepared.withdraw_proofs.len(), 2);
        assert!(prepared
            .withdraw_proofs
            .values()
            .all(|(_, proof)| !proof.is_empty()));
        vec![stage1, intent, stage2]
    }

    fn candidate_envelopes() -> Vec<ArchiveEnvelope> {
        use chainlink_streams_client::report_archive::ArchiveId;
        // Deliberately synthetic metadata: codec fidelity, not archive authenticity.
        let first = ArchiveRef {
            market_id: 0,
            now_ms: 127,
            archive_id: ArchiveId::parse(&"11".repeat(32)).unwrap(),
        };
        let second = ArchiveRef {
            market_id: u64::MAX,
            now_ms: 128,
            archive_id: ArchiveId::parse(&"22".repeat(32)).unwrap(),
        };
        let refs = vec![first.clone(), second, first];
        assert_eq!(refs[0], refs[2]);
        assert_ne!(refs[0], refs[1]);
        vec![
            ArchiveEnvelope {
                policy_binding: [7; 32],
                refs: Vec::new(),
            },
            ArchiveEnvelope {
                policy_binding: [0xa5; 32],
                refs,
            },
        ]
    }

    /// Independent old owned-clone representation, unchanged from BASE16fde84.
    fn old_owned_v6_body(j: &RollbackJournal, env: &ArchiveEnvelope) -> Vec<u8> {
        postcard::to_allocvec(&CandidateJournalV6 {
            journal: j.clone(),
            envelope: env.clone(),
        })
        .unwrap()
    }

    #[test]
    fn candidate_v6_borrowed_body_matches_old_owned_all_stages() {
        for j in candidate_stages() {
            for env in candidate_envelopes() {
                let old = old_owned_v6_body(&j, &env);
                let borrowed = postcard::to_allocvec(&CandidateJournalV6Ref {
                    journal: &j,
                    envelope: &env,
                })
                .unwrap();
                assert_eq!(
                    borrowed, old,
                    "whole body, including state/proof/claims/ref order"
                );
            }
        }
    }

    #[test]
    fn candidate_v6_write_plaintext_and_owned_open_match_old_reference() {
        let seed = [42; 32];
        let path = scratch_path("borrowed-write");
        for j in candidate_stages() {
            let old_v5 = postcard::to_allocvec(&j).unwrap();
            write_versioned(&path, &j, None, &seed).unwrap();
            let sealed = std::fs::read(&path).unwrap();
            assert_eq!(
                snapshot::open(&sealed, &seed).unwrap(),
                [MAGIC.as_slice(), old_v5.as_slice()].concat()
            );
            let OpenedJournal::Legacy(back) = open_versioned(&sealed, &seed).unwrap() else {
                panic!("v5 must remain legacy");
            };
            assert_eq!(postcard::to_allocvec(&back).unwrap(), old_v5);
            assert_eq!(
                postcard::to_allocvec(&open(&sealed, &seed).unwrap()).unwrap(),
                old_v5
            );
            for env in candidate_envelopes() {
                let old = old_owned_v6_body(&j, &env);
                write_versioned(&path, &j, Some(&env), &seed).unwrap();
                let sealed = std::fs::read(&path).unwrap();
                assert_eq!(
                    snapshot::open(&sealed, &seed).unwrap(),
                    [CANDIDATE_MAGIC.as_slice(), old.as_slice()].concat()
                );
                let OpenedJournal::Candidate {
                    journal: back,
                    envelope: back_env,
                } = open_versioned(&sealed, &seed).unwrap()
                else {
                    panic!("v6 must return owned candidate fields");
                };
                assert_eq!(old_owned_v6_body(&back, &back_env), old);
                assert_eq!(
                    open(&sealed, &seed).err().unwrap(),
                    "journal magic/version mismatch"
                );
            }
        }
        std::fs::remove_file(path).unwrap();
    }

    // The pre-change v6 decoder below is copied from the BASE Git blob. Its
    // owned canonical encoder is intentionally retained as the error-order oracle.
    fn old_owned_open_versioned(sealed: &[u8], seed: &[u8; 32]) -> Result<OpenedJournal, String> {
        let plain = snapshot::open(sealed, seed).map_err(|e| format!("journal open: {e}"))?;
        if let Some(body) = plain.strip_prefix(CANDIDATE_MAGIC.as_slice()) {
            let (CandidateJournalV6 { journal, envelope }, rest) =
                postcard::take_from_bytes(body).map_err(|e| format!("journal decode: {e}"))?;
            if !rest.is_empty() {
                return Err(format!(
                    "candidate journal decode: {} trailing bytes after the envelope",
                    rest.len()
                ));
            }
            // Canonical re-encoding: postcard's derive encoding is deterministic, so
            // a body produced by `write_versioned` round-trips byte-exactly. A body
            // that decodes but re-encodes differently is corrupt in a way the length-
            // blind decode happened to tolerate — refuse it.
            let reencoded = postcard::to_allocvec(&CandidateJournalV6 {
                journal: journal.clone(),
                envelope: envelope.clone(),
            })
            .map_err(|e| format!("journal re-encode: {e}"))?;
            if reencoded != body {
                return Err("candidate journal decode: non-canonical body encoding".into());
            }
            if journal.batch_id != journal.witness.batch_id {
                return Err(format!(
                    "journal batch_id mismatch: batch_id {} != witness.batch_id {}",
                    journal.batch_id, journal.witness.batch_id
                ));
            }
            // An empty REF list is legitimate (a window with no oracle-bearing ops —
            // recovery verifies `refs.len() == used-op count`); only a missing policy
            // binding would be indistinguishable from a legacy journal under downgrade.
            if envelope.policy_binding == [0; 32] {
                return Err("candidate journal carries an empty policy binding".into());
            }
            return Ok(OpenedJournal::Candidate { journal, envelope });
        }
        open(sealed, seed).map(OpenedJournal::Legacy)
    }

    fn opened_bytes(result: Result<OpenedJournal, String>) -> Result<(bool, Vec<u8>), String> {
        result.map(|opened| match opened {
            OpenedJournal::Legacy(j) => (false, postcard::to_allocvec(&j).unwrap()),
            OpenedJournal::Candidate { journal, envelope } => {
                (true, old_owned_v6_body(&journal, &envelope))
            }
        })
    }

    fn noncanonical_batch_varint(body: &[u8], batch_id: u64) -> Vec<u8> {
        let mut prefix = postcard::to_allocvec(&batch_id).unwrap();
        assert!(prefix.len() < 10);
        assert!(body.starts_with(&prefix));
        *prefix.last_mut().unwrap() |= 0x80;
        prefix.push(0);
        prefix.extend_from_slice(&body[postcard::to_allocvec(&batch_id).unwrap().len()..]);
        let (decoded, rest): (CandidateJournalV6, &[u8]) =
            postcard::take_from_bytes(&prefix).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.journal.batch_id, batch_id);
        assert_ne!(postcard::to_allocvec(&decoded).unwrap(), prefix);
        prefix
    }

    #[test]
    fn candidate_v6_refusals_match_old_decoder_and_error_precedence() {
        let j = candidate_fixture();
        let env = candidate_envelopes().remove(0);
        let seed = [42; 32];
        let body = old_owned_v6_body(&j, &env);
        let mut bad = j.clone();
        bad.batch_id += 1;
        let zero = ArchiveEnvelope {
            policy_binding: [0; 32],
            refs: Vec::new(),
        };
        let bad_body = old_owned_v6_body(&bad, &zero);
        let noncanonical = noncanonical_batch_varint(&body, j.batch_id);
        let bad_noncanonical = noncanonical_batch_varint(&bad_body, bad.batch_id);
        let batch_error = format!(
            "journal batch_id mismatch: batch_id {} != witness.batch_id {}",
            bad.batch_id, bad.witness.batch_id
        );
        let cases = [
            (
                "suffix",
                [body.as_slice(), &[0xde, 0xad]].concat(),
                "candidate journal decode: 2 trailing bytes after the envelope",
            ),
            (
                "noncanonical",
                noncanonical,
                "candidate journal decode: non-canonical body encoding",
            ),
            ("batch before policy", bad_body, batch_error.as_str()),
            (
                "policy",
                old_owned_v6_body(&j, &zero),
                "candidate journal carries an empty policy binding",
            ),
            (
                "canonical before batch/policy",
                bad_noncanonical.clone(),
                "candidate journal decode: non-canonical body encoding",
            ),
            (
                "suffix before canonical/batch/policy",
                [bad_noncanonical.as_slice(), &[0xde, 0xad]].concat(),
                "candidate journal decode: 2 trailing bytes after the envelope",
            ),
        ];
        for (label, body, expected) in cases {
            let sealed = snapshot::seal(
                &[CANDIDATE_MAGIC.as_slice(), body.as_slice()].concat(),
                &seed,
            );
            let old = opened_bytes(old_owned_open_versioned(&sealed, &seed));
            let new = opened_bytes(open_versioned(&sealed, &seed));
            assert_eq!(
                old.as_ref().err().unwrap(),
                expected,
                "old refusal guard: {label}"
            );
            assert_eq!(new, old, "exact error and check order: {label}");
        }
        let valid = snapshot::seal(
            &[CANDIDATE_MAGIC.as_slice(), body.as_slice()].concat(),
            &seed,
        );
        assert_eq!(
            opened_bytes(open_versioned(&valid, &seed)),
            opened_bytes(old_owned_open_versioned(&valid, &seed))
        );
        let mut tampered = valid.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let truncated = snapshot::seal(
            &[CANDIDATE_MAGIC.as_slice(), &body[..body.len() - 1]].concat(),
            &seed,
        );
        let confusion = snapshot::seal(&[MAGIC.as_slice(), body.as_slice()].concat(), &seed);
        let legacy_body = postcard::to_allocvec(&j).unwrap();
        // v5 deliberately accepts a decodable noncanonical integer; v6 must not
        // accidentally strengthen the legacy path while changing its encoder.
        let mut legacy_noncanonical = vec![0x80, 0];
        assert_eq!(j.batch_id, 0);
        assert_eq!(legacy_body[0], 0);
        legacy_noncanonical.extend_from_slice(&legacy_body[1..]);
        let legacy = snapshot::seal(
            &[MAGIC.as_slice(), legacy_noncanonical.as_slice()].concat(),
            &seed,
        );
        assert_eq!(
            opened_bytes(open_versioned(&legacy, &seed)).unwrap(),
            (false, legacy_body.clone())
        );
        for (label, sealed, decode_seed) in [
            ("wrong seed", valid, [43; 32]),
            ("tamper", tampered, seed),
            ("truncated envelope", truncated, seed),
            ("v6 under v5", confusion, seed),
            (
                "v5 under v6",
                snapshot::seal(
                    &[CANDIDATE_MAGIC.as_slice(), legacy_body.as_slice()].concat(),
                    &seed,
                ),
                seed,
            ),
            (
                "stale magic",
                snapshot::seal(
                    &[b"DPRBJL4\0".as_slice(), legacy_body.as_slice()].concat(),
                    &seed,
                ),
                seed,
            ),
        ] {
            let old = opened_bytes(old_owned_open_versioned(&sealed, &decode_seed));
            assert!(old.is_err(), "old refusal guard: {label}");
            assert_eq!(
                opened_bytes(open_versioned(&sealed, &decode_seed)),
                old,
                "{label}"
            );
        }
        assert_eq!(
            opened_bytes(open_versioned(&legacy, &seed)),
            opened_bytes(old_owned_open_versioned(&legacy, &seed))
        );
    }

    #[test]
    fn journal_seal_round_trip() {
        let (witness, ww) = sealed_window();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");

        // capture the expectations before the journal takes ownership
        let batch_id = witness.batch_id;
        let ops_len = witness.ops.len();
        let pre_root = witness.pre_state.state_root();
        let ww_leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
        let commitment = prepared.outcome.commitment;
        let new_root = prepared.outcome.new_root;
        let new_deposit_count = prepared.outcome.new_deposit_count;
        let post_insurance_fund = prepared.outcome.post_insurance_fund;
        let proof = prepared.outcome.proof.clone();
        let withdraw_proofs = prepared.withdraw_proofs.clone();
        assert!(ops_len > 0, "a real window has ops");
        assert!(!ww_leaves.is_empty(), "a real window has a withdrawal");
        // Fixture guard: the window contains a deposit, so the cumulative count is
        // non-zero — the round-trip assert below can never pass vacuously as 0 == 0.
        assert!(
            new_deposit_count > 0,
            "a real window has a consumed deposit"
        );
        // Fixture guards for the SEC-025-D terms (the DPRBJL5 bump): both captured
        // values must differ from what a silently-defaulted decode would produce
        // (false / 0), or the survival asserts below prove nothing.
        assert!(
            prepared.outcome.post_mode_is_normal,
            "a demo-boot window replays to a Normal post-state"
        );
        assert!(
            post_insurance_fund > 0,
            "boot seeds a non-zero insurance fund"
        );

        let j = RollbackJournal {
            batch_id,
            witness,
            ww,
            prepared: Some(prepared),
        };
        let path = scratch_path("round-trip");
        let seed = [42u8; 32];
        write(&path, &j, &seed).expect("journal write");
        let back = read(&path, &seed).expect("journal read").expect("present");

        assert_eq!(back.batch_id, batch_id);
        assert_eq!(back.witness.batch_id, batch_id);
        assert_eq!(back.witness.ops.len(), ops_len);
        assert_eq!(
            back.witness.pre_state.state_root(),
            pre_root,
            "pre_state survives"
        );
        let back_leaves: Vec<[u8; 32]> = back.ww.iter().map(|w| w.leaf()).collect();
        assert_eq!(back_leaves, ww_leaves, "withdrawal set survives byte-exact");
        // the strongest witness check: the restored witness REPLAYS to the same
        // commitment the original prove produced (pre_state + ops + manifest all intact)
        let replay = MockProverClient.prove(&back.witness).expect("replay");
        assert_eq!(
            replay.commitment, commitment,
            "restored witness replays identically"
        );

        let bp = back.prepared.expect("prepared survives");
        assert_eq!(bp.outcome.new_root, new_root);
        assert_eq!(
            bp.outcome.new_deposit_count, new_deposit_count,
            "new_deposit_count survives — the field whose addition motivated the \
             DPRBJL3 bump, and the one a roll-forward resubmits to _requireDepositPrefix"
        );
        // The SEC-025-D terms (the DPRBJL5 bump) survive with non-default values —
        // guarded above, so a decode that silently defaulted them would fail here.
        assert!(bp.outcome.post_mode_is_normal, "gate mode term survives");
        assert_eq!(
            bp.outcome.post_insurance_fund, post_insurance_fund,
            "gate insurance term survives"
        );
        assert_eq!(bp.outcome.proof, proof);
        assert_eq!(bp.withdraw_proofs, withdraw_proofs, "claim proofs survive");

        std::fs::remove_file(&path).ok();
    }

    /// A journal sealed under one enclave seed must never decode under another —
    /// same fail-closed posture as the snapshot restore path.
    #[test]
    fn journal_wrong_seed_fails_closed() {
        let (witness, ww) = sealed_window();
        let j = RollbackJournal {
            batch_id: witness.batch_id,
            witness,
            ww,
            prepared: None,
        };
        let path = scratch_path("wrong-seed");
        write(&path, &j, &[42u8; 32]).expect("journal write");
        // Err — NOT Ok(None): the file exists, so a wrong seed must read as
        // "unreadable journal → HOLD", never as "no journal → clean boot".
        assert!(read(&path, &[43u8; 32]).is_err());
        std::fs::remove_file(&path).ok();
    }

    /// Decoder review: `postcard::from_bytes` DISCARDS a remaining suffix, so a
    /// journal whose AUTHENTICATED plaintext (MAC-verified by `snapshot::open`)
    /// decodes cleanly but carries trailing bytes must be refused — for BOTH
    /// versions. Such bytes can only be produced with the enclave seed, but the
    /// decoder must not be the place that trusts the writer's framing.
    #[test]
    fn authenticated_plaintext_with_trailing_bytes_is_refused_both_versions() {
        let (witness, ww) = sealed_window();
        let seed = [42u8; 32];
        let j = RollbackJournal {
            batch_id: witness.batch_id,
            witness,
            ww,
            prepared: None,
        };

        // v5: valid payload + 2 trailing bytes inside the sealed plaintext.
        let mut v5_plain = MAGIC.to_vec();
        v5_plain.extend_from_slice(&postcard::to_allocvec(&j).expect("v5 encode"));
        v5_plain.extend_from_slice([0xde, 0xad].as_slice());
        let sealed = snapshot::seal(&v5_plain, &seed);
        let err = match open(&sealed, &seed) {
            Err(e) => e,
            Ok(_) => panic!("v5 with trailing bytes must fail closed"),
        };
        assert!(err.contains("trailing"), "unexpected error: {err}");
        let err = match open_versioned(&sealed, &seed) {
            Err(e) => e,
            Ok(_) => panic!("v5 with trailing bytes must fail closed (versioned path)"),
        };
        assert!(err.contains("trailing"), "unexpected error: {err}");

        // v6: valid candidate payload + trailing bytes, same refusal.
        let payload = CandidateJournalV6 {
            journal: j.clone(),
            envelope: ArchiveEnvelope {
                policy_binding: [7; 32],
                refs: Vec::new(),
            },
        };
        let mut v6_plain = CANDIDATE_MAGIC.to_vec();
        v6_plain.extend_from_slice(&postcard::to_allocvec(&payload).expect("v6 encode"));
        v6_plain.extend_from_slice([0xbe, 0xef].as_slice());
        let sealed = snapshot::seal(&v6_plain, &seed);
        let err = match open_versioned(&sealed, &seed) {
            Err(e) => e,
            Ok(_) => panic!("v6 with trailing bytes must fail closed"),
        };
        assert!(err.contains("trailing"), "unexpected error: {err}");
    }

    /// Version confusion: a candidate (v6) payload sealed under the LEGACY v5
    /// magic must never present as an acceptable legacy journal. `take_from_bytes`
    /// either fails to decode or leaves a non-empty remainder — both are Err.
    #[test]
    fn v6_payload_under_v5_magic_is_version_confusion_refused() {
        let (witness, ww) = sealed_window();
        let seed = [42u8; 32];
        let j = RollbackJournal {
            batch_id: witness.batch_id,
            witness,
            ww,
            prepared: None,
        };
        let payload = CandidateJournalV6 {
            journal: j,
            envelope: ArchiveEnvelope {
                policy_binding: [7; 32],
                refs: Vec::new(),
            },
        };
        let mut plain = MAGIC.to_vec();
        plain.extend_from_slice(&postcard::to_allocvec(&payload).expect("v6 encode"));
        let sealed = snapshot::seal(&plain, &seed);
        assert!(
            open(&sealed, &seed).is_err(),
            "a v6 payload under the v5 magic must never decode as a legacy journal"
        );
        match open_versioned(&sealed, &seed) {
            Err(_) => {}
            Ok(OpenedJournal::Legacy(_)) => {
                panic!("version confusion must not yield an accepted legacy journal")
            }
            Ok(OpenedJournal::Candidate { .. }) => {
                panic!("the v5 magic must never dispatch to the candidate decoder")
            }
        }
    }

    /// Deliberate v5 compatibility: a journal written by the legacy `write` path
    /// (everything pre-candidate binaries produce) still opens through BOTH
    /// decoders — the trailing-byte tightening touches only non-canonical input.
    #[test]
    fn v5_write_output_still_opens_through_both_decoders() {
        let (witness, ww) = sealed_window();
        let j = RollbackJournal {
            batch_id: witness.batch_id,
            witness,
            ww,
            prepared: None,
        };
        let path = scratch_path("v5-compat");
        let seed = [42u8; 32];
        write(&path, &j, &seed).expect("legacy write");
        let sealed = std::fs::read(&path).unwrap();
        let legacy = open(&sealed, &seed).expect("v5 open");
        assert_eq!(legacy.batch_id, j.batch_id);
        match open_versioned(&sealed, &seed).expect("v5 versioned open") {
            OpenedJournal::Legacy(v) => assert_eq!(v.batch_id, j.batch_id),
            OpenedJournal::Candidate { .. } => {
                panic!("a v5-magic journal must never open as Candidate")
            }
        }
        std::fs::remove_file(&path).ok();
    }

    /// Defense-in-depth (Task 3 fix round 1): the journal carries the window id
    /// twice — `batch_id` (keyed on by the recovery table) and `witness.batch_id`
    /// (asserted by `rollback_window`). A journal where they disagree is
    /// corrupt/tampered in a way postcard can't catch; `read` fails closed (Err →
    /// the caller HOLDs), never handing recovery a self-inconsistent journal.
    #[test]
    fn journal_batch_id_mismatch_fails_closed() {
        let (witness, ww) = sealed_window();
        let j = RollbackJournal {
            batch_id: witness.batch_id + 1, // disagrees with witness.batch_id
            witness,
            ww,
            prepared: None,
        };
        let path = scratch_path("id-mismatch");
        let seed = [42u8; 32];
        write(&path, &j, &seed).expect("journal write");
        // Err — NOT Ok: a self-inconsistent journal must read as unreadable.
        // (no expect_err: RollbackJournal carries a full WindowWitness, no Debug)
        let err = match read(&path, &seed) {
            Err(e) => e,
            Ok(_) => panic!("mismatched window ids must fail closed"),
        };
        assert!(
            err.contains("batch_id mismatch"),
            "unexpected error text: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    /// Each journal bump's claim, made executable: a journal written under an
    /// EARLIER magic is refused as a versioned mismatch, never handed to postcard
    /// under the current layout. v5 and v6 are the plain and candidate journals of
    /// the earlier engine state wire, which this binary no longer reads.
    #[test]
    fn journal_with_a_stale_magic_is_refused() {
        assert_eq!(MAGIC, b"DPRBJL7\0");
        assert_eq!(CANDIDATE_MAGIC, b"DPRBJL8\0");
        let seed = [42u8; 32];
        for stale in [b"DPRBJL4\0", b"DPRBJL5\0", b"DPRBJL6\0"] {
            let path = scratch_path("stale-magic");
            // A well-formed earlier payload is unnecessary: the magic check runs
            // BEFORE postcard, so any body under an earlier magic is refused.
            let mut plain = Vec::new();
            plain.extend_from_slice(stale);
            plain.extend_from_slice(&[0u8; 16]);
            let sealed = snapshot::seal(&plain, &seed);
            snapshot::write_atomic(&path, &sealed).expect("write");
            let err = match read(&path, &seed) {
                Err(e) => e,
                Ok(_) => panic!("a stale-magic journal must be refused"),
            };
            // Under a reverted MAGIC this dies either way: the old-magic journal then
            // strips cleanly and yields Ok (panic above) or a postcard decode error
            // (which does not name the magic) — never this exact refusal.
            assert!(err.contains("magic"), "{stale:?}: unexpected error: {err}");
            assert!(open_versioned(&sealed, &seed).is_err(), "{stale:?}");
            std::fs::remove_file(&path).ok();
        }
    }

    /// No journal file = the common clean-shutdown boot: Ok(None), not an error.
    #[test]
    fn journal_missing_is_none() {
        let path = scratch_path("missing");
        assert!(matches!(read(&path, &[42u8; 32]), Ok(None)));
    }

    /// Every row of the spec's recovery table, with the "any" slots expanded over
    /// both bool values so no wildcard hides a precedence bug.
    #[test]
    fn recovery_action_full_matrix() {
        use RecoveryAction::*;
        let bools = [false, true];

        // STALE: seal persisted (B=j+1), tx landed (bc=j+1), and the restored
        // settled root already matches the chain — the commit was persisted too.
        // Wins regardless of prepared/rm_prep (precedence over ROLL-FORWARD).
        for prep in bools {
            for rmp in bools {
                assert_eq!(recovery_action(5, prep, 6, 6, rmp, true), Stale);
            }
        }
        // A stage-1 pre-seal snapshot can resolve; stage 2 remains ambiguous.
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(
                        recovery_action(5, prep, 5, 5, rmp, rms),
                        if prep { Hold } else { SealNeverPersisted }
                    );
                }
            }
        }
        // A stage-1 post-seal snapshot can roll back; stage 2 must HOLD.
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(
                        recovery_action(5, prep, 6, 5, rmp, rms),
                        if prep { Hold } else { RollBack }
                    );
                }
            }
        }
        // ROLL-FORWARD: tx landed, commit lost (settled root stale), and the chain
        // root is exactly the journaled prepared new_root.
        assert_eq!(recovery_action(5, true, 6, 6, true, false), RollForward);

        // HOLD: landed but nothing proves the chain root is ours —
        // no prepared outcome at all…
        assert_eq!(recovery_action(5, false, 6, 6, false, false), Hold);
        // …or a prepared outcome whose root does NOT match the chain.
        assert_eq!(recovery_action(5, true, 6, 6, false, false), Hold);
        // HOLD: pre-seal snapshot but the chain advanced past the journal.
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(recovery_action(5, prep, 5, 6, rmp, rms), Hold);
                }
            }
        }
        // HOLD: chain advanced BEYOND the journaled window (bc = j+2).
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(recovery_action(5, prep, 6, 7, rmp, rms), Hold);
                }
            }
        }
        // HOLD: Counter B implausibly ahead of the journal (B = j+2), any chain.
        for bc in [4u64, 5, 6, 7] {
            for prep in bools {
                for rmp in bools {
                    for rms in bools {
                        assert_eq!(recovery_action(5, prep, 7, bc, rmp, rms), Hold);
                    }
                }
            }
        }
    }
    fn evidence(
        slot: AnchorSlot,
        close_only: bool,
        fenced: bool,
        batch_count: u64,
    ) -> DeadIntentEvidence {
        DeadIntentEvidence {
            block: 100,
            batch_count,
            close_only,
            slot,
            fenced,
        }
    }

    #[test]
    fn dead_intent_classification_matrix() {
        use AnchorSlot::{Different, Empty, Matching};
        use DeadIntent::{CloseOnlyPhaseZero, EmptyAfterFence, Replaced};
        // (a) a cancelled receipt is dead in every phase, inside or outside
        // close-only, except a phase-0 window in close-only, which is (b).
        for (phase, close_only) in [(0, false), (1, false), (1, true), (2, false), (2, true)] {
            assert_eq!(
                classify_dead_intent(
                    5,
                    phase,
                    &evidence(AnchorSlot::Cancelled, close_only, true, 5)
                ),
                Some(DeadIntent::Cancelled)
            );
        }
        // (b) phase 0 in close-only is dead whatever the slot holds, with or without
        // the nonce fence: no pending register or settle of it can land there.
        for slot in [Matching, AnchorSlot::Cancelled, Empty, Different] {
            for fenced in [false, true] {
                assert_eq!(
                    classify_dead_intent(5, 0, &evidence(slot, true, fenced, 5)),
                    Some(CloseOnlyPhaseZero)
                );
            }
        }
        // (c) an empty slot after the fence, and (d) another anchor.
        for (phase, close_only) in [(0, false), (1, true), (2, true)] {
            assert_eq!(
                classify_dead_intent(5, phase, &evidence(Empty, close_only, true, 5)),
                Some(EmptyAfterFence)
            );
            assert_eq!(
                classify_dead_intent(5, phase, &evidence(Different, close_only, true, 5)),
                Some(Replaced)
            );
            // Our own registered anchor may still settle.
            assert_eq!(
                classify_dead_intent(5, phase, &evidence(Matching, close_only, true, 5)),
                None
            );
        }
        // Nothing else is dead before the fence, and nothing once the batch moved on.
        for slot in [Matching, AnchorSlot::Cancelled, Empty, Different] {
            for close_only in [false, true] {
                for phase in 0..=2 {
                    if !(phase == 0 && close_only) {
                        assert_eq!(
                            classify_dead_intent(5, phase, &evidence(slot, close_only, false, 5)),
                            None
                        );
                    }
                    for bc in [4, 6] {
                        assert_eq!(
                            classify_dead_intent(5, phase, &evidence(slot, close_only, true, bc)),
                            None
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dead_intent_row_needs_a_prepared_intent_on_the_unsettled_batch() {
        use RecoveryAction::*;
        let bools = [false, true];
        for dead in [
            DeadIntent::Cancelled,
            DeadIntent::CloseOnlyPhaseZero,
            DeadIntent::EmptyAfterFence,
            DeadIntent::Replaced,
        ] {
            // Seal persisted, or already returned to the open window.
            for b_snap in [5, 6] {
                for rmp in bools {
                    for rms in bools {
                        assert_eq!(
                            recovery_action_classified(5, true, b_snap, 5, rmp, rms, Some(dead)),
                            VoidDeadIntent(dead)
                        );
                    }
                }
            }
            // Stage 1 keeps its rows; a landed batch keeps Stale/RollForward/Hold.
            assert_eq!(
                recovery_action_classified(5, false, 6, 5, false, false, Some(dead)),
                RollBack
            );
            assert_eq!(
                recovery_action_classified(5, false, 5, 5, false, false, Some(dead)),
                SealNeverPersisted
            );
            assert_eq!(
                recovery_action_classified(5, true, 6, 6, true, false, Some(dead)),
                RollForward
            );
            assert_eq!(
                recovery_action_classified(5, true, 6, 6, false, true, Some(dead)),
                Stale
            );
            for (b_snap, bc) in [(6, 6), (6, 7), (7, 5), (5, 6), (4, 5)] {
                assert_eq!(
                    recovery_action_classified(5, true, b_snap, bc, false, false, Some(dead)),
                    Hold,
                    "b_snap {b_snap} bc {bc}"
                );
            }
        }
        // Without a classification the table is unchanged.
        for b_snap in [5, 6] {
            assert_eq!(
                recovery_action_classified(5, true, b_snap, 5, false, false, None),
                Hold
            );
            assert_eq!(recovery_action(5, true, b_snap, 5, false, false), Hold);
        }
    }

    #[test]
    fn dead_intent_policy_is_automatic_only_without_a_time_to_reregister() {
        use DeadIntentAction::*;
        for phase in 0..=2 {
            for timed in [false, true] {
                assert_eq!(
                    dead_intent_action(DeadIntent::CloseOnlyPhaseZero, phase, timed),
                    ReturnToOpenWindow
                );
                assert!(matches!(
                    dead_intent_action(DeadIntent::Replaced, phase, timed),
                    Hold(m) if m.contains("cancel-anchor")
                ));
                for dead in [DeadIntent::Cancelled, DeadIntent::EmptyAfterFence] {
                    let action = dead_intent_action(dead, phase, timed);
                    if timed {
                        assert!(matches!(action, Hold(_)), "{dead:?} phase {phase}");
                    } else {
                        assert_eq!(action, ReturnToOpenWindow);
                    }
                }
            }
        }
        assert!(matches!(
            dead_intent_action(DeadIntent::EmptyAfterFence, 0, true),
            Hold(m) if m.contains("enterCloseOnly")
        ));
    }
}
