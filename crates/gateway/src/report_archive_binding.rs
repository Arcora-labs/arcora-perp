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

/// Retained admissions available for op binding at seal time. Bounded: sealing
/// consumes by VALUE match, not by recency alone, so only the window depth
/// matters; the bound is a memory ceiling, never a correctness input.
const MAX_ADMISSIONS: usize = 4096;

pub(crate) struct Admission {
    pub(crate) market_id: u64,
    pub(crate) prepared_at_ms: u64,
    pub(crate) id: ArchiveId,
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
            prepared_at_ms: now_ms,
            id: stored.id,
        });
        if self.admissions.len() > MAX_ADMISSIONS {
            self.admissions.pop_front();
        }
        Ok(normalized)
    }

    /// Bind the ACTUAL op stream — ordered, one ref per oracle-bearing op,
    /// repeated use included — to exact archived records. Each op is matched by
    /// VALUE: the archived pair re-normalized at the op's own `now_ms` must equal
    /// the transcript the op carries. No manifest, no reference list, no
    /// latest-file fallback: an op with no exact record fails the seal.
    pub(crate) fn bind_ops(&self, ops: &[BatchOp]) -> Result<ArchiveEnvelope, BindError> {
        let mut refs = Vec::new();
        for op in ops {
            let Some((market_id, now_ms, oracle)) = used_oracle(op) else {
                continue;
            };
            refs.push(ArchiveRef {
                market_id,
                now_ms,
                archive_id: self.exact_record(market_id, now_ms, oracle)?,
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

    fn exact_record(
        &self,
        market_id: u64,
        now_ms: u64,
        oracle: &perp_core::oracle::OracleTranscript,
    ) -> Result<ArchiveId, BindError> {
        // Newest-first: an admission can only bind ops at or after its own
        // preparation time, and the first VALUE match is the exact record.
        let candidates: Vec<ArchiveId> = self
            .admissions
            .iter()
            .rev()
            .filter(|a| a.market_id == market_id && a.prepared_at_ms <= now_ms)
            .map(|a| a.id)
            .collect();
        if candidates.is_empty() {
            return Err(BindError::NoAdmission);
        }
        for id in candidates {
            let Ok(pair) = self.archive.load(id, &self.policy, market_id) else {
                // A referenced-but-unreadable admission is corruption, not a
                // signal to try an older record: the op must trace to an intact one.
                continue;
            };
            let Ok((normalized, _)) = pair.for_operation(now_ms) else {
                continue;
            };
            if normalized.matches(oracle) {
                return Ok(id);
            }
        }
        Err(BindError::Mismatch)
    }
}

#[cfg(test)]
#[path = "report_archive_binding_tests.rs"]
mod tests;
