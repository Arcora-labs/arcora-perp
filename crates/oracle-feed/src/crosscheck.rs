//! Host-only two-exchange corroboration, NOT independent publisher consensus.
//! Source labels are transport/parser provenance, not exchange-signed evidence.
use perp_core::{fixed::RATE_SCALE, oracle::OracleTranscript, Market};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpotPair {
    base: String,
    quote: String,
}
impl SpotPair {
    pub fn new(base: &str, quote: &str) -> Result<Self, String> {
        let asset = |s: &str| {
            !s.is_empty()
                && s.len() <= 16
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        };
        if !asset(base) || !asset(quote) || base == quote {
            return Err("invalid explicit spot base/quote".into());
        }
        Ok(Self {
            base: base.into(),
            quote: quote.into(),
        })
    }
    pub fn crypto_instrument(&self) -> String {
        format!("{}_{}", self.base, self.quote)
    }
    pub fn okx_instrument(&self) -> String {
        format!("{}-{}", self.base, self.quote)
    }
    pub fn symbol(&self) -> String {
        format!("{}/{}", self.base, self.quote)
    }
    /// Refuse legacy USDT data for a USDC-labelled market. No peg assumption,
    /// spot/perpetual substitution, or implicit FX conversion is implemented.
    pub fn bind(symbol: &str, crypto_instrument: &str) -> Result<Self, String> {
        let (base, quote) = symbol
            .split_once('/')
            .ok_or("explicit market base/quote required")?;
        let pair = Self::new(base, quote)?;
        if pair.crypto_instrument() != crypto_instrument {
            return Err(
                "oracle spot instrument / market quote mismatch; no implicit conversion".into(),
            );
        }
        Ok(pair)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exchange {
    CryptoCom,
    Okx,
}

/// Opaque source identity assigned only by this crate's fixed-source adapters.
/// Both transcripts use the SAME operator key; this is not a quorum signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTick {
    pub(crate) exchange: Exchange,
    pub(crate) pair: SpotPair,
    pub(crate) transcript: OracleTranscript,
}
impl SourceTick {
    pub fn transcript(&self) -> &OracleTranscript {
        &self.transcript
    }
}

/// Explicit host policy, with NO default or inferred market threshold.
/// Parts-per-million uses the existing RATE_SCALE; zero means exact agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrosscheckPolicy {
    max_deviation_ppm: i128,
}
impl CrosscheckPolicy {
    pub fn new(max_deviation_ppm: i128) -> Result<Self, String> {
        if !(0..=RATE_SCALE).contains(&max_deviation_ppm) {
            return Err("crosscheck deviation must be an explicit 0..1000000 ppm integer".into());
        }
        Ok(Self { max_deviation_ppm })
    }
    /// Pure parser also distinguishes an invalid UTF-8 setting from unset.
    pub fn from_value(value: Result<String, std::env::VarError>) -> Result<Option<Self>, String> {
        match value {
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err("crosscheck policy is not UTF-8".into()),
            Ok(s) => {
                if s.is_empty() || s.len() > 7 || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(
                        "crosscheck deviation requires an explicit integer ppm value".into(),
                    );
                }
                Self::new(s.parse().map_err(|_| "invalid crosscheck deviation")?).map(Some)
            }
        }
    }
    fn agrees(&self, a: i128, b: i128) -> bool {
        if a <= 0 || b <= 0 {
            return false;
        }
        let diff = a.max(b) - a.min(b); // subtraction is safe for positive i128 values
        match (
            diff.checked_mul(RATE_SCALE),
            a.min(b).checked_mul(self.max_deviation_ppm),
        ) {
            (Some(lhs), Some(rhs)) => lhs <= rhs,
            _ => false,
        }
    }
}

/// Per-market runtime high-water marks. Restarts require fresh paired intake;
/// these are not a durable anti-replay journal or a guest commitment.
#[derive(Clone, Debug)]
pub struct CrosscheckGate {
    pair: SpotPair,
    market_id: u64,
    policy: CrosscheckPolicy,
    primary_time: u64,
    secondary_time: u64,
}
impl CrosscheckGate {
    pub fn new(pair: SpotPair, market_id: u64, policy: CrosscheckPolicy) -> Self {
        Self {
            pair,
            market_id,
            policy,
            primary_time: 0,
            secondary_time: 0,
        }
    }
    pub fn pair(&self) -> &SpotPair {
        &self.pair
    }
    /// Mutates watermarks only after ALL checks. The caller must commit this
    /// candidate gate only when downstream admission succeeds as well.
    pub fn accept(
        &mut self,
        primary: &SourceTick,
        secondary: &SourceTick,
        market: &Market,
        received_ms: u64,
    ) -> Result<OracleTranscript, String> {
        if market.id != self.market_id
            || primary.exchange != Exchange::CryptoCom
            || secondary.exchange != Exchange::Okx
            || primary.pair != self.pair
            || secondary.pair != self.pair
        {
            return Err("crosscheck market/source/spot-pair identity mismatch".into());
        }
        let p = primary.transcript;
        let s = secondary.transcript;
        for (t, previous) in [(p, self.primary_time), (s, self.secondary_time)] {
            if t.publish_time_ms == 0
                || t.publish_time_ms <= previous
                || t.confidence < 0
                || t.validate(market, received_ms).is_err()
            {
                return Err("crosscheck source stale, repeated, out of order, or invalid".into());
            }
        }
        // The unchanged guest carries ONLY the primary timestamp. A secondary
        // older than it could expire while that primary still passes the guest's
        // age gate. Refuse instead of laundering the older dependency, rewriting
        // the primary, or inventing a new tolerance. Both use the SAME age limit.
        if s.publish_time_ms < p.publish_time_ms {
            return Err("crosscheck secondary predates the retained primary timestamp".into());
        }
        // Compare both last and book midpoints, symmetrically against the smaller
        // price. No averaging or rewriting of the primary's signed values.
        if !self.policy.agrees(p.price, s.price)
            || !self.policy.agrees(p.backup_twap, s.backup_twap)
        {
            return Err("crosscheck independent source disagreement".into());
        }
        self.primary_time = p.publish_time_ms;
        self.secondary_time = s.publish_time_ms;
        Ok(p)
    }
}

#[cfg(test)]
#[path = "crosscheck_tests.rs"]
mod tests;
