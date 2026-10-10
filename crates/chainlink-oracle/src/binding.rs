//! Candidate proof binds report bodies to actual oracle-bearing operations.
//! Do not substitute manifest.oracle_updates, which v2 does not constrain to ops.
use crate::{
    policy::{hash_words, Policy},
    report::ReportBody,
    Error, Result,
};
use alloc::vec::Vec;
use perp_core::{
    clock::{abi_address, abi_u64, keccak, ClockWitness},
    engine::BatchOp,
    hash::Digest,
    oracle::OracleTranscript,
    DefaultState,
};
use serde::{Deserialize, Serialize};

pub const WIRE_MAGIC: &[u8; 8] = b"DPCLK3\0\0";
pub const EVIDENCE_DOMAIN: &[u8] = b"arcora:chainlink-evidence:v1";
pub const PROOF_DOMAIN: &[u8] = b"arcora:chainlink-bound-proof:v1";
pub const MAX_ENTRIES: usize = 128;
pub const MAX_WITNESS_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairEvidence {
    pub market_id: u64,
    pub now_ms: u64,
    pub base: ReportBody,
    pub quote: ReportBody,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CandidateWitness {
    pub clock: ClockWitness,
    pub policy: Policy,
    /// Exactly one pair per oracle-bearing operation, in operation order.
    pub evidence: Vec<PairEvidence>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateOutput {
    pub commitment: Digest,
    pub clock_commitment: Digest,
    pub policy_hash: Digest,
    pub evidence_hash: Digest,
}
pub fn initial_evidence(policy_hash: Digest, count: usize) -> Result<Digest> {
    if count > MAX_ENTRIES {
        return Err(Error::Bounds);
    }
    Ok(hash_words(&[
        keccak(EVIDENCE_DOMAIN),
        policy_hash,
        abi_u64(count as u64),
    ]))
}
pub fn append_evidence(h: Digest, e: &PairEvidence) -> Digest {
    hash_words(&[
        h,
        abi_u64(e.market_id),
        abi_u64(e.now_ms),
        e.base.hash(),
        e.quote.hash(),
    ])
}
pub fn bind(clock: Digest, policy: &Policy, policy_hash: Digest, evidence_hash: Digest) -> Digest {
    hash_words(&[
        keccak(PROOF_DOMAIN),
        clock,
        abi_address(&policy.oracle_wrapper),
        abi_address(&policy.verifier_proxy),
        policy_hash,
        evidence_hash,
    ])
}
fn used_oracle(op: &BatchOp) -> Option<(u64, u64, &OracleTranscript)> {
    // Exhaustive: a new operation must explicitly classify its oracle use.
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
pub fn check_evidence(
    state: &DefaultState,
    ops: &[BatchOp],
    policy: &Policy,
    entries: &[PairEvidence],
) -> Result<Digest> {
    let policy_hash = policy.hash()?;
    if policy.markets.len() != state.markets.len() {
        return Err(Error::Policy);
    }
    for m in &policy.markets {
        let market = state.markets.get(&m.market_id).ok_or(Error::Policy)?;
        if m.max_report_age_ms > market.max_oracle_staleness_ms {
            return Err(Error::Policy);
        }
    }
    let count = ops.iter().filter(|op| used_oracle(op).is_some()).count();
    if count != entries.len() {
        return Err(Error::Evidence);
    }
    let mut h = initial_evidence(policy_hash, count)?;
    for ((market_id, now_ms, oracle), e) in ops.iter().filter_map(used_oracle).zip(entries) {
        if (market_id, now_ms) != (e.market_id, e.now_ms) {
            return Err(Error::Evidence);
        }
        let normalized =
            policy
                .market(market_id)?
                .normalize(&e.base.decode()?, &e.quote.decode()?, now_ms)?;
        if !normalized.matches(oracle) {
            return Err(Error::Oracle);
        }
        h = append_evidence(h, e);
    }
    Ok(h)
}
pub fn run(mut witness: CandidateWitness) -> Result<CandidateOutput> {
    let (ref mut state, ref ops, ref manifest, ref clock) = witness.clock;
    if clock.chain_id != witness.policy.chain_id {
        return Err(Error::Policy);
    }
    let policy_hash = witness.policy.hash()?;
    let evidence_hash = check_evidence(state, ops, &witness.policy, &witness.evidence)?;
    let roots =
        perp_core::commitment::derive_roots(state, ops, manifest).map_err(|_| Error::Transition)?;
    clock
        .validate(manifest.batch_id, &roots, ops)
        .map_err(|_| Error::Clock)?;
    let clock_commitment = clock.commitment();
    Ok(CandidateOutput {
        commitment: bind(
            clock_commitment,
            &witness.policy,
            policy_hash,
            evidence_hash,
        ),
        clock_commitment,
        policy_hash,
        evidence_hash,
    })
}
pub fn run_encoded(bytes: &[u8]) -> Result<CandidateOutput> {
    if bytes.len() > MAX_WITNESS_BYTES {
        return Err(Error::Bounds);
    }
    let body = bytes.strip_prefix(WIRE_MAGIC).ok_or(Error::Version)?;
    let (witness, rest) = postcard::take_from_bytes(body).map_err(|_| Error::Encoding)?;
    if !rest.is_empty() {
        return Err(Error::Encoding);
    }
    run(witness)
}
