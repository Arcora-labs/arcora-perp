//! Candidate gateway binding: Chainlink report archive → oracle admission →
//! sealed rollback journal → recovery verification. CANDIDATE, opt-in only;
//! PRODUCTION RELEASE HOLD. The reviewed v2 guest, witness format, and prover
//! routing are untouched — this binds the actual op stream to immutable archived
//! reports on the host so a future candidate guest (v3) can be wired without a
//! journal-format break.
//!
//! Ordering guarantees (durability barriers, in order):
//!   archive record durable  →  state-changing oracle admission
//!   archive-bound journal durable  →  any prove/broadcast side effect
//! Recovery requires every referenced record to exist, decode, and re-normalize
//! to the exact op transcript under the configured policy; any mismatch, missing
//! or corrupt record is a versioned HOLD, never a substitution.
use crate::rollback_journal::{ArchiveEnvelope, ArchiveRef};
use chainlink_oracle::policy::{Normalized, Policy};
use chainlink_streams_client::{
    report_archive::{ArchiveId, ReportArchive},
    report_pair::{policy_binding, PreparedPair},
    UnverifiedReport,
};
use perp_core::engine::BatchOp;
use std::collections::VecDeque;

pub(crate) const MODE_ENV: &str = "DARKPERP_CHAINLINK_ARCHIVE";
pub(crate) const DIR_ENV: &str = "DARKPERP_CHAINLINK_ARCHIVE_DIR";
pub(crate) const POLICY_ENV: &str = "DARKPERP_CHAINLINK_POLICY_JSON";

/// Candidate-mode persistence boundary.
///
/// The archive requirement is a RUNTIME gate (env + in-memory binding), which
/// serde skips everywhere — a gateway that ever settled candidate windows and
/// persisted state must not be able to boot as legacy just because the
/// operator omitted the flag (a restored snapshot, including one with an
/// UNSEALED open window admitted from archived reports, would then keep
/// settling unbound). This sidecar is the durable answer: written ONLY in
/// candidate mode, sealed exactly like the rollback journal, versioned by
/// magic. It never touches the snapshot wire bytes.
const MARKER_MAGIC: &[u8; 8] = b"DPCAM1\0\0";

#[derive(serde::Serialize, serde::Deserialize)]
struct CandidateModeMarkerV1 {
    policy_binding: [u8; 32],
}

/// `<state>.chainlink` (appended, like the `.rollback` sidecar).
pub(crate) fn marker_path(state_path: &std::path::Path) -> std::path::PathBuf {
    let mut os = state_path.as_os_str().to_os_string();
    os.push(".chainlink");
    std::path::PathBuf::from(os)
}

pub(crate) fn write_marker(
    path: &std::path::Path,
    policy_binding: [u8; 32],
    seed: &[u8; 32],
) -> Result<(), String> {
    let body = postcard::to_allocvec(&CandidateModeMarkerV1 { policy_binding })
        .map_err(|e| format!("mode marker encode: {e}"))?;
    let mut plain = Vec::with_capacity(MARKER_MAGIC.len() + body.len());
    plain.extend_from_slice(MARKER_MAGIC);
    plain.extend_from_slice(&body);
    let sealed = crate::snapshot::seal(&plain, seed);
    crate::snapshot::write_atomic(path, &sealed).map_err(|e| format!("mode marker write: {e}"))
}

/// `Ok(None)` = no marker (legacy state, never candidate). `Ok(Some(binding))`
/// = sealed marker. `Err` = a marker EXISTS but is unreadable (wrong seed /
/// tampered / future version): never treated as absent — the caller refuses
/// startup rather than risk a legacy boot of candidate-used state.
pub(crate) fn read_marker(
    path: &std::path::Path,
    seed: &[u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let sealed = match crate::snapshot::read_file(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("mode marker read: {e}")),
    };
    let plain =
        crate::snapshot::open(&sealed, seed).map_err(|e| format!("mode marker open: {e}"))?;
    let body = plain
        .strip_prefix(MARKER_MAGIC.as_slice())
        .ok_or("mode marker magic/version mismatch")?;
    let (CandidateModeMarkerV1 { policy_binding }, rest) =
        postcard::take_from_bytes(body).map_err(|e| format!("mode marker decode: {e}"))?;
    if !rest.is_empty() {
        return Err(format!(
            "mode marker decode: {} trailing bytes after the payload",
            rest.len()
        ));
    }
    Ok(Some(policy_binding))
}

/// Pure boot-gate decision over (persisted marker, configured binding).
/// Testable without env or filesystem; the caller performs the IO.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ModeGate {
    /// Legacy state, legacy config: unchanged behavior.
    Legacy,
    /// Candidate-configured boot must durably write the marker first.
    CandidateWriteMarker,
    /// Candidate-configured boot with a matching persisted marker.
    CandidateContinue,
    /// Refuse startup before ANY recovery mutation, with the reason.
    Refuse(String),
}

pub(crate) fn mode_gate(
    marker: Result<Option<[u8; 32]>, String>,
    configured: Option<[u8; 32]>,
) -> ModeGate {
    match (marker, configured) {
        (Err(e), _) => ModeGate::Refuse(format!(
            "candidate mode marker exists but is unreadable ({e}); refusing to boot rather than guess the mode"
        )),
        (Ok(None), None) => ModeGate::Legacy,
        (Ok(None), Some(_pb)) => ModeGate::CandidateWriteMarker,
        (Ok(Some(_persisted)), None) => ModeGate::Refuse(
            "state was persisted in candidate archive mode (marker present) but \
             DARKPERP_CHAINLINK_ARCHIVE is not configured; refusing to boot as legacy"
                .into(),
        ),
        (Ok(Some(persisted)), Some(pb)) => {
            if persisted == pb {
                ModeGate::CandidateContinue
            } else {
                ModeGate::Refuse(
                    "candidate mode marker policy binding does not match the configured policy"
                        .into(),
                )
            }
        }
    }
}

/// Retained admissions available for op binding at seal time. Bounded: sealing
/// consumes by VALUE match, not by recency alone, so only the window depth
/// matters; the bound is a memory ceiling, never a correctness input.
const MAX_ADMISSIONS: usize = 4096;

pub(crate) struct Admission {
    pub(crate) market_id: u64,
    pub(crate) id: ArchiveId,
    /// The exact normalization admitted at `prepared_at_ms`. Binding keys on
    /// this VALUE (with the market), never on recency: a window may carry both
    /// earlier and later transcripts for the same market, and repeated use of
    /// the same valid archive ID is legitimate.
    transcript: Normalized,
}

pub(crate) struct ArchiveBinding {
    archive: ReportArchive,
    policy: Policy,
    policy_binding: [u8; 32],
    admissions: VecDeque<Admission>,
}

/// Why a binding step refused. Fixed categories only — never credential, path,
/// or report contents in the message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BindError {
    Config,
    Policy,
    Archive,
    NoAdmission,
    Mismatch,
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chainlink archive binding {self:?}")
    }
}

fn config_env(name: &str) -> Result<Option<String>, BindError> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(BindError::Config),
    }
}

/// Classify oracle-bearing ops EXACTLY like the candidate guest
/// (crates/chainlink-oracle/src/binding.rs::used_oracle): a new BatchOp variant
/// must be added here in the same change that adds it there, or seal-time binding
/// fails closed (the op has no archive record → window never seals).
pub(crate) fn used_oracle(
    op: &BatchOp,
) -> Option<(u64, u64, &perp_core::oracle::OracleTranscript)> {
    match op {
        BatchOp::Fill {
            market_id,
            now_ms,
            oracle,
            ..
        }
        | BatchOp::AccrueFunding {
            market_id,
            now_ms,
            oracle,
            ..
        }
        | BatchOp::Liquidate {
            market_id,
            now_ms,
            oracle,
            ..
        }
        | BatchOp::Unbind {
            market_id,
            now_ms,
            oracle,
            ..
        } => Some((*market_id, *now_ms, oracle)),
        BatchOp::Deposit { .. }
        | BatchOp::FundPosition { .. }
        | BatchOp::Withdraw { .. }
        | BatchOp::EnterCloseOnly
        | BatchOp::DeprecatedSeedInsurance { .. }
        | BatchOp::FundInsurance { .. }
        | BatchOp::SettleAll
        | BatchOp::WindDownUnbind { .. }
        | BatchOp::WindDownWithdraw { .. } => None,
    }
}

impl ArchiveBinding {
    /// Opt-in config: absent / "disabled" ⇒ `None` (legacy behavior everywhere);
    /// "candidate" ⇒ an operator-owned archive dir plus an operator-pinned policy
    /// file. Anything else refuses startup.
    pub(crate) fn from_env() -> Result<Option<Self>, BindError> {
        let Some(mode) = config_env(MODE_ENV)? else {
            return Ok(None);
        };
        if mode == "disabled" {
            return Ok(None);
        }
        if mode != "candidate" {
            return Err(BindError::Config);
        }
        let dir = config_env(DIR_ENV)?
            .ok_or(BindError::Config)
            .map(std::path::PathBuf::from)?;
        // Recovery never creates an empty archive in place of a missing backup.
        let archive = ReportArchive::open_existing(&dir).map_err(|_| BindError::Archive)?;
        let policy_path = config_env(POLICY_ENV)?
            .ok_or(BindError::Config)
            .map(std::path::PathBuf::from)?;
        let policy: Policy =
            serde_json::from_slice(&std::fs::read(&policy_path).map_err(|_| BindError::Config)?)
                .map_err(|_| BindError::Config)?;
        Self::new(archive, policy).map(Some)
    }

    #[cfg(test)]
    fn create_in(dir: &std::path::Path, policy: Policy) -> Result<Self, BindError> {
        Self::new(
            ReportArchive::create(&dir.join("store")).map_err(|_| BindError::Archive)?,
            policy,
        )
    }

    fn new(archive: ReportArchive, policy: Policy) -> Result<Self, BindError> {
        // The pinned policy must itself be a valid candidate policy and carry a
        // computable archive binding before any admission is accepted.
        let policy_binding = policy_binding(&policy).map_err(|_| BindError::Policy)?;
        policy.hash().map_err(|_| BindError::Policy)?;
        Ok(Self {
            archive,
            policy,
            policy_binding,
            admissions: VecDeque::new(),
        })
    }

    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(crate) fn policy_binding(&self) -> [u8; 32] {
        self.policy_binding
    }

    /// Durable archive FIRST, admission SECOND. The stored record is immutable
    /// and hash-named; the returned normalization is what the caller signs and
    /// admits. If admission later refuses the transcript, the archived record
    /// simply stays unreferenced — it is never replayed as fresh admission.
    pub(crate) fn admit(
        &mut self,
        market_id: u64,
        base: UnverifiedReport,
        quote: UnverifiedReport,
        now_ms: u64,
    ) -> Result<Normalized, BindError> {
        let pair = PreparedPair::new(&self.policy, market_id, base, quote, now_ms)
            .map_err(|_| BindError::Policy)?;
        let (normalized, _) = pair
            .for_operation(now_ms)
            .map_err(|_| BindError::Mismatch)?;
        // The durability barrier: the record (file + directory fsync) exists
        // before any state-changing admission can cite it.
        let stored = self.archive.store(&pair).map_err(|_| BindError::Archive)?;
        self.admissions.push_back(Admission {
            market_id,
            id: stored.id,
            transcript: normalized,
        });
        if self.admissions.len() > MAX_ADMISSIONS {
            self.admissions.pop_front();
        }
        Ok(normalized)
    }

    /// Bind the ACTUAL op stream — ordered, one ref per oracle-bearing op,
    /// repeated use included — to exact archived records. References are
    /// derived in OP ORDER from an index of retained admissions keyed by exact
    /// (market, transcript) IDENTITY: an op binds iff some admission produced
    /// precisely the transcript the op carries. This is deliberately NOT a
    /// latest-pair-per-market map and NOT recency selection — a window can
    /// contain both an earlier and a later transcript for the same market, and
    /// the same archive ID may be referenced by many ops (duplicate usage is
    /// not invalid; identical report bytes hash to the same record anyway).
    /// No manifest, no reference list, no latest-file fallback: an op whose
    /// exact (market, transcript) identity has no archived admission fails the
    /// seal. (Identity comparison uses the admission-time normalization: price,
    /// publish time, confidence and backup TWAP are all derived from the
    /// immutable report bytes, independent of the op's own clock.)
    pub(crate) fn bind_ops(&self, ops: &[BatchOp]) -> Result<ArchiveEnvelope, BindError> {
        let mut refs = Vec::new();
        for op in ops {
            let Some((market_id, now_ms, oracle)) = used_oracle(op) else {
                continue;
            };
            // Exact (market, transcript) identity — never recency, never a
            // latest-pair-per-market map.
            let want = Normalized {
                price: oracle.price,
                publish_time_ms: oracle.publish_time_ms,
                confidence: oracle.confidence,
                backup_twap: oracle.backup_twap,
            };
            let mut found: Option<ArchiveId> = None;
            for a in &self.admissions {
                if a.market_id == market_id && a.transcript == want {
                    found = Some(a.id);
                    break;
                }
            }
            let Some(id) = found else {
                return Err(
                    if self.admissions.iter().any(|a| a.market_id == market_id) {
                        BindError::Mismatch
                    } else {
                        BindError::NoAdmission
                    },
                );
            };
            refs.push(ArchiveRef {
                market_id,
                now_ms,
                archive_id: id,
            });
        }
        Ok(ArchiveEnvelope {
            policy_binding: self.policy_binding,
            refs,
        })
    }

    /// Recovery/handoff: the sealed envelope must name THIS policy and every
    /// referenced record must still decode and re-normalize to the exact op
    /// transcript. Missing, corrupt, wrong-policy/market/op-time, or transcript
    /// mismatch ⇒ Err ⇒ the caller HOLDs. Never substitute another record.
    pub(crate) fn verify(
        &self,
        ops: &[BatchOp],
        envelope: &ArchiveEnvelope,
    ) -> Result<(), BindError> {
        if envelope.policy_binding != self.policy_binding {
            return Err(BindError::Policy);
        }
        let used: Vec<(u64, u64, &perp_core::oracle::OracleTranscript)> =
            ops.iter().filter_map(used_oracle).collect();
        if used.len() != envelope.refs.len() {
            return Err(BindError::Mismatch);
        }
        for ((market_id, now_ms, oracle), r) in used.iter().zip(&envelope.refs) {
            if r.market_id != *market_id || r.now_ms != *now_ms {
                return Err(BindError::Mismatch);
            }
            let pair = self
                .archive
                .load(r.archive_id, &self.policy, *market_id)
                .map_err(|_| BindError::Archive)?;
            let (normalized, _) = pair
                .for_operation(*now_ms)
                .map_err(|_| BindError::Mismatch)?;
            if !normalized.matches(oracle) {
                return Err(BindError::Mismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "report_archive_binding_tests.rs"]
mod tests;
