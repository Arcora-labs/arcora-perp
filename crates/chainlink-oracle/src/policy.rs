//! Explicit candidate normalization: asset/USD divided by USDC/USD.
//! Feed IDs, decimals, time limits and recipe are committed policy, never inferred.
use crate::{report::Report, Error, Result};
use alloc::{string::String, vec::Vec};
use perp_core::{
    clock::{abi_u64, keccak},
    fixed::PRICE_SCALE,
    hash::Digest,
    oracle::{OracleSig, OracleTranscript},
};
use serde::{Deserialize, Serialize};

pub const POLICY_DOMAIN: &[u8] = b"arcora:chainlink-usdc-liquidity-envelope-policy:v1";
pub const MAX_MARKETS: usize = 32;

pub fn hash_words(words: &[Digest]) -> Digest {
    keccak(&words.iter().flatten().copied().collect::<Vec<_>>())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketFeed {
    pub market_id: u64,
    pub base_symbol: String,
    pub base_usd_feed: Digest,
    pub base_decimals: u8,
    pub usdc_usd_feed: Digest,
    pub usdc_decimals: u8,
    pub max_report_age_ms: u64,
    pub max_pair_skew_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub chain_id: u64,
    /// 0 = testnet, 1 = mainnet. This candidate supports Base only.
    pub network: u8,
    pub verifier_proxy: [u8; 20],
    pub oracle_wrapper: [u8; 20],
    /// Strictly ascending unique market IDs. Quote denomination is USDC.
    pub markets: Vec<MarketFeed>,
}
impl Policy {
    pub fn hash(&self) -> Result<Digest> {
        if !matches!((self.chain_id, self.network), (84532, 0) | (8453, 1))
            || self.verifier_proxy == [0; 20]
            || self.oracle_wrapper == [0; 20]
            || self.markets.is_empty()
            || self.markets.len() > MAX_MARKETS
        {
            return Err(Error::Policy);
        }
        let mut h = hash_words(&[
            keccak(POLICY_DOMAIN),
            abi_u64(self.chain_id),
            abi_u64(self.network as u64),
            abi_u64(self.markets.len() as u64),
        ]);
        let mut previous = None;
        for m in &self.markets {
            if previous.is_some_and(|id| id >= m.market_id)
                || m.base_symbol.is_empty()
                || m.base_symbol.len() > 16
                || !m
                    .base_symbol
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                || m.base_symbol == "USDC"
                || m.base_usd_feed[..2] != [0, 3]
                || m.usdc_usd_feed[..2] != [0, 3]
                || m.base_usd_feed == m.usdc_usd_feed
                || m.base_decimals > 18
                || m.usdc_decimals > 18
                || m.max_report_age_ms == 0
            {
                return Err(Error::Policy);
            }
            previous = Some(m.market_id);
            h = hash_words(&[
                h,
                abi_u64(m.market_id),
                keccak(m.base_symbol.as_bytes()),
                keccak(b"USDC"),
                m.base_usd_feed,
                abi_u64(m.base_decimals as u64),
                m.usdc_usd_feed,
                abi_u64(m.usdc_decimals as u64),
                abi_u64(m.max_report_age_ms),
                abi_u64(m.max_pair_skew_ms),
            ]);
        }
        Ok(h)
    }
    pub fn market(&self, id: u64) -> Result<&MarketFeed> {
        self.markets
            .iter()
            .find(|m| m.market_id == id)
            .ok_or(Error::Policy)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Normalized {
    pub price: i128,
    pub publish_time_ms: u64,
    pub confidence: i128,
    /// Legacy field: same consensus ratio, NOT an independent TWAP.
    pub backup_twap: i128,
}
impl Normalized {
    pub fn with_signature(self, signature: OracleSig) -> OracleTranscript {
        OracleTranscript {
            price: self.price,
            publish_time_ms: self.publish_time_ms,
            confidence: self.confidence,
            backup_twap: self.backup_twap,
            signature,
        }
    }
    pub fn matches(&self, o: &OracleTranscript) -> bool {
        self.price == o.price
            && self.publish_time_ms == o.publish_time_ms
            && self.confidence == o.confidence
            && self.backup_twap == o.backup_twap
    }
}
fn ratio(a: i128, b: i128, a_dec: u8, b_dec: u8, ceil: bool) -> Result<i128> {
    if a <= 0 || b <= 0 || a_dec > 18 || b_dec > 18 {
        return Err(Error::Price);
    }
    let exponent = 8i32 + b_dec as i32 - a_dec as i32;
    let (numerator, denominator) = if exponent >= 0 {
        (
            a.checked_mul(10i128.checked_pow(exponent as u32).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?,
            b,
        )
    } else {
        (
            a,
            b.checked_mul(
                10i128
                    .checked_pow((-exponent) as u32)
                    .ok_or(Error::Bounds)?,
            )
            .ok_or(Error::Bounds)?,
        )
    };
    let floor = numerator / denominator;
    let answer = floor
        .checked_add(i128::from(ceil && numerator % denominator != 0))
        .ok_or(Error::Bounds)?;
    if answer <= 0 {
        return Err(Error::Price);
    }
    Ok(answer)
}
impl MarketFeed {
    pub fn normalize(&self, base: &Report, quote: &Report, now_ms: u64) -> Result<Normalized> {
        if base.feed_id != self.base_usd_feed
            || quote.feed_id != self.usdc_usd_feed
            || base.feed_id == quote.feed_id
        {
            return Err(Error::Feed);
        }
        base.check_time(now_ms, self.max_report_age_ms)?;
        quote.check_time(now_ms, self.max_report_age_ms)?;
        if u64::from(base.observations.abs_diff(quote.observations)) * 1000 > self.max_pair_skew_ms
        {
            return Err(Error::Time);
        }
        let price = ratio(
            base.price,
            quote.price,
            self.base_decimals,
            self.usdc_decimals,
            false,
        )?;
        let low = ratio(
            base.low(),
            quote.high(),
            self.base_decimals,
            self.usdc_decimals,
            false,
        )?;
        let high = ratio(
            base.high(),
            quote.low(),
            self.base_decimals,
            self.usdc_decimals,
            true,
        )?;
        let confidence = (price - low).max(high - price).max(price / PRICE_SCALE);
        Ok(Normalized {
            price,
            publish_time_ms: u64::from(base.observations.min(quote.observations)) * 1000,
            confidence,
            backup_twap: price,
        })
    }
}
