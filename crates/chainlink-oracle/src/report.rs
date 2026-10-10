//! Fixed-size ABI v3 body. No float, permissive padding, or signature claim.
use crate::{Error, Result};
use alloc::vec::Vec;
use perp_core::hash::Digest;
use serde::{Deserialize, Serialize};

pub const BODY_LEN: usize = 9 * 32;
pub const MAX_FULL_REPORT: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportBody(pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub feed_id: Digest,
    pub valid_from: u32,
    pub observations: u32,
    pub expires_at: u32,
    pub price: i128,
    pub bid: i128,
    pub ask: i128,
}

fn word(bytes: &[u8], index: usize) -> &[u8] {
    &bytes[index * 32..(index + 1) * 32]
}
fn u32_word(w: &[u8]) -> Result<u32> {
    if w[..28].iter().any(|b| *b != 0) {
        return Err(Error::Encoding);
    }
    Ok(u32::from_be_bytes(
        w[28..].try_into().map_err(|_| Error::Encoding)?,
    ))
}
fn positive_i128(w: &[u8]) -> Result<i128> {
    // ABI int192 is canonical, but this candidate deliberately accepts only the
    // positive i128 subset used by the unchanged engine. Wider values fail closed.
    if w[..16].iter().any(|b| *b != 0) {
        return Err(Error::Price);
    }
    let n = i128::from_be_bytes(w[16..].try_into().map_err(|_| Error::Encoding)?);
    if n <= 0 {
        return Err(Error::Price);
    }
    Ok(n)
}
impl ReportBody {
    pub fn decode(&self) -> Result<Report> {
        decode_body(&self.0)
    }
    pub fn hash(&self) -> Digest {
        perp_core::clock::keccak(&self.0)
    }
}
pub fn decode_body(body: &[u8]) -> Result<Report> {
    if body.len() != BODY_LEN {
        return Err(Error::Encoding);
    }
    if body[..2] != [0, 3] {
        return Err(Error::Version);
    }
    for i in [3, 4] {
        if word(body, i)[..8].iter().any(|b| *b != 0) {
            return Err(Error::Encoding);
        }
    }
    let r = Report {
        feed_id: word(body, 0).try_into().map_err(|_| Error::Encoding)?,
        valid_from: u32_word(word(body, 1))?,
        observations: u32_word(word(body, 2))?,
        expires_at: u32_word(word(body, 5))?,
        price: positive_i128(word(body, 6))?,
        bid: positive_i128(word(body, 7))?,
        ask: positive_i128(word(body, 8))?,
    };
    if r.valid_from == 0 || r.valid_from > r.observations || r.expires_at < r.observations {
        return Err(Error::Time);
    }
    Ok(r)
}
impl Report {
    pub fn check_time(&self, now_ms: u64, max_age_ms: u64) -> Result<()> {
        let observed = u64::from(self.observations) * 1000;
        if now_ms == 0
            || observed > now_ms
            || now_ms - observed > max_age_ms
            || now_ms > u64::from(self.expires_at) * 1000
        {
            return Err(Error::Time);
        }
        Ok(())
    }
    /// These are liquidity-impact prices, not a statistical confidence interval
    /// or exchange top-of-book. Enclose all three without assigning their labels
    /// a buy/sell ordering. The policy explicitly commits to this recipe.
    pub fn low(&self) -> i128 {
        self.price.min(self.bid).min(self.ask)
    }
    pub fn high(&self) -> i128 {
        self.price.max(self.bid).max(self.ask)
    }
}

/// Decode the canonical signed ABI container (context[3], body, rs, ss, rawVs).
/// It remains UNVERIFIED: even structurally valid nonzero signatures may be fake.
pub fn body_from_full_report(bytes: &[u8]) -> Result<ReportBody> {
    if bytes.len() < 7 * 32 || bytes.len() > MAX_FULL_REPORT || !bytes.len().is_multiple_of(32) {
        return Err(Error::Encoding);
    }
    let offset = |i: usize| -> Result<usize> { Ok(u32_word(word(bytes, i))? as usize) };
    let body_offset = offset(3)?;
    if body_offset != 224 {
        return Err(Error::Encoding);
    }
    if bytes.len() < body_offset + 32 + BODY_LEN || u32_word(word(bytes, 7))? as usize != BODY_LEN {
        return Err(Error::Encoding);
    }
    let rs = offset(4)?;
    if rs != body_offset + 32 + BODY_LEN || rs + 32 > bytes.len() {
        return Err(Error::Encoding);
    }
    let count = u32_word(&bytes[rs..rs + 32])? as usize;
    if !(1..=31).contains(&count) {
        return Err(Error::Bounds);
    }
    let ss = offset(5)?;
    if ss != rs + 32 + count * 32
        || ss + 32 + count * 32 != bytes.len()
        || u32_word(&bytes[ss..ss + 32])? as usize != count
    {
        return Err(Error::Encoding);
    }
    for i in 0..count {
        if bytes[rs + 32 + i * 32..rs + 64 + i * 32]
            .iter()
            .all(|b| *b == 0)
            || bytes[ss + 32 + i * 32..ss + 64 + i * 32]
                .iter()
                .all(|b| *b == 0)
            || bytes[192 + i] > 1
        {
            return Err(Error::Encoding);
        }
    }
    let body = ReportBody(bytes[body_offset + 32..body_offset + 32 + BODY_LEN].to_vec());
    body.decode()?;
    Ok(body)
}
