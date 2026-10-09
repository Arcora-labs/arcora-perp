//! Versioned settlement-chain clock binding. Operation times are DERIVED from
//! the immutable log; the chain authenticates registration time and policy.
//! On Base this is L2 time, not an Ethereum L1-origin timestamp.
use crate::commitment::DerivedRoots;
use crate::engine::BatchOp;
use crate::{Digest, EngineError};
use alloc::vec::Vec;
use tiny_keccak::{Hasher as _, Keccak};

pub const WIRE_MAGIC: &[u8; 8] = b"DPCLK2\0\0";
pub const DOMAIN_TEXT: &[u8] = b"arcora:clock-bound-proof:v2";

pub fn keccak(bytes: &[u8]) -> Digest {
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut out = [0; 32];
    h.finalize(&mut out);
    out
}
pub fn abi_u64(n: u64) -> Digest {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}
pub fn abi_address(a: &[u8; 20]) -> Digest {
    let mut w = [0; 32];
    w[12..].copy_from_slice(a);
    w
}
fn hash_words(words: &[Digest]) -> Digest {
    let bytes: Vec<u8> = words.iter().flatten().copied().collect();
    keccak(&bytes)
}
pub fn bind_commitment(base: Digest, receipt: Digest) -> Digest {
    hash_words(&[keccak(DOMAIN_TEXT), base, receipt])
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeBounds {
    pub first_ms: u64,
    pub last_ms: u64,
    pub count: u64,
}
impl TimeBounds {
    /// Exhaustive match: adding a new operation requires classifying its clock.
    pub fn derive(ops: &[BatchOp]) -> Result<Self, EngineError> {
        let mut b = Self::default();
        for op in ops {
            let time = match op {
                BatchOp::Fill { now_ms, .. }
                | BatchOp::AccrueFunding { now_ms, .. }
                | BatchOp::Liquidate { now_ms, .. }
                | BatchOp::Unbind { now_ms, .. } => Some(*now_ms),
                BatchOp::Deposit { .. }
                | BatchOp::FundPosition { .. }
                | BatchOp::Withdraw { .. }
                | BatchOp::EnterCloseOnly
                | BatchOp::DeprecatedSeedInsurance { .. }
                | BatchOp::FundInsurance { .. }
                | BatchOp::SettleAll
                | BatchOp::WindDownUnbind { .. }
                | BatchOp::WindDownWithdraw { .. } => None,
            };
            if let Some(t) = time {
                if b.count == 0 {
                    b.first_ms = t;
                } else if t < b.last_ms {
                    return Err(EngineError::ClockMismatch);
                }
                b.last_ms = t;
                b.count = b.count.checked_add(1).ok_or(EngineError::Overflow)?;
            }
        }
        Ok(b)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClockContext {
    pub chain_id: u64,
    pub verifier: [u8; 20],
    pub settlement: [u8; 20],
    pub batch_id: u64,
    pub previous_root: Digest,
    pub base_commitment: Digest,
    pub phase: u8,
    pub first_ms: u64,
    pub last_ms: u64,
    pub timed_ops: u64,
    pub anchored_at_ms: u64,
    pub max_window_ms: u64,
    pub clock_skew_ms: u64,
}
impl ClockContext {
    /// Solidity abi.encode, NOT the protocol's legacy little-endian helpers.
    pub fn receipt(&self) -> Digest {
        hash_words(&[
            keccak(DOMAIN_TEXT),
            abi_u64(self.chain_id),
            abi_address(&self.verifier),
            abi_address(&self.settlement),
            abi_u64(self.batch_id),
            self.previous_root,
            self.base_commitment,
            abi_u64(self.phase as u64),
            abi_u64(self.first_ms),
            abi_u64(self.last_ms),
            abi_u64(self.timed_ops),
            abi_u64(self.anchored_at_ms),
            abi_u64(self.max_window_ms),
            abi_u64(self.clock_skew_ms),
        ])
    }
    pub fn commitment(&self) -> Digest {
        bind_commitment(self.base_commitment, self.receipt())
    }
    pub fn validate(
        &self,
        batch_id: u64,
        roots: &DerivedRoots,
        ops: &[BatchOp],
    ) -> Result<(), EngineError> {
        let b = TimeBounds::derive(ops)?;
        if self.chain_id == 0
            || self.verifier == [0; 20]
            || self.settlement == [0; 20]
            || self.max_window_ms == 0
            || self.batch_id != batch_id
            || self.previous_root != roots.prev_state_root
            || self.base_commitment != roots.commitment::<crate::hash::Keccak256>()
            || self.phase != roots.wind_down_phase
            || (self.first_ms, self.last_ms, self.timed_ops) != (b.first_ms, b.last_ms, b.count)
            || b.last_ms - b.first_ms > self.max_window_ms
        {
            return Err(EngineError::ClockMismatch);
        }
        if b.count != 0
            && ((b.last_ms as u128 + self.clock_skew_ms as u128) < self.anchored_at_ms as u128
                || b.last_ms as u128 > self.anchored_at_ms as u128 + self.clock_skew_ms as u128)
        {
            return Err(EngineError::ClockMismatch);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
pub type ClockWitness = (
    crate::DefaultState,
    Vec<BatchOp>,
    crate::order::BatchManifest,
    ClockContext,
);

/// Gateway journal transport only; never forwarded to the Solidity verifier.
pub const PROOF_MAGIC: &[u8; 8] = b"DPCLPR2\0";
