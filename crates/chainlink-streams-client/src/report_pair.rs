//! Host-side pairing for archive/witness preparation. Neither a DON attestation nor admission.
use crate::{Network, UnverifiedReport};
use chainlink_oracle::{
    binding::PairEvidence,
    policy::{Normalized, Policy},
};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairError {
    Policy,
    Network,
    Feed,
    Time,
    Report,
}
impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "report pair {self:?}")
    }
}
impl std::error::Error for PairError {}

/// The exact retrieved bytes and their caller-pinned normalization policy.
/// Private fields prevent callers from substituting a normalized price after validation.
/// No oracle-publisher signature is created and no verified-report type is returned.
#[derive(Clone, Debug)]
pub struct PreparedPair {
    pub(crate) policy: Policy,
    pub(crate) market_id: u64,
    pub(crate) prepared_at_ms: u64,
    pub(crate) base: UnverifiedReport,
    pub(crate) quote: UnverifiedReport,
}

/// The reviewed candidate's policy hash plus the wrapper/proxy addresses it omits.
/// The gateway's rollback journal binds archived records to THIS digest, so the
/// policy file alone is not enough to substitute a different binding.
pub fn policy_binding(policy: &Policy) -> Result<[u8; 32], PairError> {
    let policy_hash = policy.hash().map_err(|_| PairError::Policy)?;
    // The candidate policy hash does not include wrapper/proxy addresses. Bind them
    // explicitly here, as the candidate's outer proof commitment also does.
    let mut h = Sha256::new();
    h.update(b"arcora:unverified-report-archive-policy:v1");
    h.update(policy_hash);
    h.update(policy.chain_id.to_be_bytes());
    h.update([policy.network]);
    h.update(policy.oracle_wrapper);
    h.update(policy.verifier_proxy);
    Ok(h.finalize().into())
}

impl PreparedPair {
    pub fn new(
        policy: &Policy,
        market_id: u64,
        base: UnverifiedReport,
        quote: UnverifiedReport,
        now_ms: u64,
    ) -> Result<Self, PairError> {
        policy_binding(policy)?;
        let network = match (policy.chain_id, policy.network) {
            (84532, 0) => Network::Testnet,
            (8453, 1) => Network::Mainnet,
            _ => return Err(PairError::Policy),
        };
        if base.network() != network || quote.network() != network {
            return Err(PairError::Network);
        }
        let market = policy.market(market_id).map_err(|_| PairError::Policy)?;
        if base.decoded().feed_id != market.base_usd_feed
            || quote.decoded().feed_id != market.usdc_usd_feed
        {
            return Err(PairError::Feed);
        }
        for r in [&base, &quote] {
            if r.received_ms() == 0 || now_ms < r.received_ms() {
                return Err(PairError::Time);
            }
            r.check_freshness(r.received_ms(), market.max_report_age_ms)
                .map_err(|_| PairError::Time)?;
        }
        let pair = Self {
            policy: policy.clone(),
            market_id,
            prepared_at_ms: now_ms,
            base,
            quote,
        };
        pair.for_operation(now_ms)?;
        Ok(pair)
    }
    pub fn market_id(&self) -> u64 {
        self.market_id
    }
    pub fn prepared_at_ms(&self) -> u64 {
        self.prepared_at_ms
    }
    pub fn base(&self) -> &UnverifiedReport {
        &self.base
    }
    pub fn quote(&self) -> &UnverifiedReport {
        &self.quote
    }

    /// Call again at the ORIGINAL operation time when assembling its witness.
    /// For a new operation use its current trusted clock. Archive receipt time is
    /// never a substitute for the source observations or the operation clock.
    pub fn for_operation(&self, now_ms: u64) -> Result<(Normalized, PairEvidence), PairError> {
        if now_ms == 0 || now_ms < self.prepared_at_ms {
            return Err(PairError::Time);
        }
        let market = self
            .policy
            .market(self.market_id)
            .map_err(|_| PairError::Policy)?;
        let normalized = market
            .normalize(self.base.decoded(), self.quote.decoded(), now_ms)
            .map_err(|e| match e {
                chainlink_oracle::Error::Time => PairError::Time,
                chainlink_oracle::Error::Feed => PairError::Feed,
                _ => PairError::Report,
            })?;
        let evidence = PairEvidence {
            market_id: self.market_id,
            now_ms,
            base: self.base.body().clone(),
            quote: self.quote.body().clone(),
        };
        Ok((normalized, evidence))
    }
}
