//! Canonical snapshots for authoritative L1 reads. A result leaves this module
//! only after every requested word and the final canonical checks have passed.
use super::{parse_bytes32, Digest};
use crate::deposit_rpc::Rpc;
use serde_json::{json, Value};
use sha3::{Digest as _, Keccak256};

#[derive(Clone, Copy)]
pub(super) enum AnchorPolicy {
    Finalized,
    /// Preserve the trading gate's existing confirmation-depth policy.
    Confirmed(u64),
    /// Conservative terminal flag checks must not wait for finality.
    Latest,
}

pub(super) fn quantity(v: &Value) -> Result<u64, String> {
    v.as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 16
                && (s.len() == 1 || !s.starts_with('0'))
                && s.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or_else(|| "settlement observation: invalid RPC quantity".into())
}
pub(super) fn header(v: &Value) -> Result<(u64, Digest), String> {
    Ok((
        quantity(&v["number"])?,
        v["hash"]
            .as_str()
            .and_then(parse_bytes32)
            .ok_or("settlement observation: missing/invalid block hash")?,
    ))
}
/// One header, plus its timestamp when the header fields hash to the reported
/// block hash. Callers that need the time ask for it explicitly.
fn fetch(rpc: &dyn Rpc, tag: Value) -> Result<((u64, Digest), Option<u64>), String> {
    let v = rpc.call("eth_getBlockByNumber", vec![tag.clone(), json!(false)])?;
    let h = header(&v)?;
    if tag != json!("latest") && tag != json!("finalized") && quantity(&tag)? != h.0 {
        return Err(
            "settlement observation: canonical block changed or provider disagrees (height)".into(),
        );
    }
    let time = crate::deposit_rpc::validated_block(&v)
        .ok()
        .filter(|b| (b.number, b.hash) == h)
        .and_then(|b| b.timestamp);
    Ok((h, time))
}
fn block(rpc: &dyn Rpc, tag: Value) -> Result<(u64, Digest), String> {
    Ok(fetch(rpc, tag)?.0)
}
fn chain_agreement(
    primary: &dyn Rpc,
    witness: &dyn Rpc,
    expected: Option<u64>,
) -> Result<(), String> {
    let expected = expected
        .filter(|n| *n > 0)
        .ok_or("settlement observation: missing expected witness chain")?;
    if quantity(&primary.call("eth_chainId", vec![])?)? != expected
        || quantity(&witness.call("eth_chainId", vec![])?)? != expected
    {
        return Err("settlement observation: RPC chain disagrees with startup domain".into());
    }
    Ok(())
}
pub(super) struct CanonicalRead<'a> {
    primary: &'a dyn Rpc,
    witness: Option<&'a dyn Rpc>,
    anchor: (u64, Digest),
    /// The anchor header's timestamp, when its fields hashed to the anchor hash.
    anchor_time: Option<u64>,
}

/// One open inclusion challenge as the settlement stores it. These values do
/// not change while the challenge is open, and a closed hash cannot reopen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenChallenge {
    pub order_hash: Digest,
    pub beneficiary: [u8; 20],
    pub batch_id_hint: u64,
    pub opened_block: u64,
    pub open_batch_count: u64,
    pub stake: u128,
}

/// The settlement's whole open-challenge set at one canonical block, with the
/// stored details of the hashes the caller did not know yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenSetRead {
    pub head: u64,
    pub batch_count: u64,
    pub hashes: Vec<Digest>,
    pub details: Vec<OpenChallenge>,
}

/// `openChallenges(start, max)` clamps `max` to this page size on-chain.
pub(crate) const OPEN_CHALLENGE_PAGE: u64 = 512;
impl<'a> CanonicalRead<'a> {
    pub fn new(
        primary: &'a dyn Rpc,
        witness: Option<&'a dyn Rpc>,
        expected: Option<u64>,
    ) -> Result<Self, String> {
        Self::with_policy(primary, witness, expected, AnchorPolicy::Finalized)
    }
    pub fn with_policy(
        primary: &'a dyn Rpc,
        witness: Option<&'a dyn Rpc>,
        expected: Option<u64>,
        policy: AnchorPolicy,
    ) -> Result<Self, String> {
        if let Some(witness) = witness {
            chain_agreement(primary, witness, expected)?;
        }
        let tag = match policy {
            AnchorPolicy::Finalized => "finalized",
            _ => "latest",
        };
        let (head, head_time) = fetch(primary, json!(tag))?;
        let (anchor, anchor_time) = match policy {
            AnchorPolicy::Confirmed(depth) => {
                let height = head
                    .0
                    .checked_sub(depth)
                    .ok_or("settlement observation: insufficient gate confirmations")?;
                fetch(primary, json!(format!("0x{height:x}")))?
            }
            _ => (head, head_time),
        };
        if let Some(witness) = witness {
            let witness_head = block(witness, json!(tag))?;
            let minimum = match policy {
                AnchorPolicy::Confirmed(depth) => anchor
                    .0
                    .checked_add(depth)
                    .ok_or("settlement observation: confirmation height overflow")?,
                _ => anchor.0,
            };
            if witness_head.0 < minimum {
                return Err("settlement observation: witness has not finalized the anchor or lacks required confirmations".into());
            }
            if (witness_head.0 == anchor.0 && witness_head != anchor)
                || block(witness, json!(format!("0x{:x}", anchor.0)))? != anchor
            {
                return Err("settlement observation: witness finalized anchor disagreement".into());
            }
        }
        Ok(Self {
            primary,
            witness,
            anchor,
            anchor_time,
        })
    }
    pub fn height(&self) -> u64 {
        self.anchor.0
    }
    /// The anchor block's header-bound timestamp (seconds).
    pub fn timestamp(&self) -> Result<u64, String> {
        self.anchor_time
            .ok_or_else(|| "settlement observation: anchor header did not hash to its block hash; no block time".into())
    }
    pub fn word(&self, to: &str, signature: &str, arg: Option<Digest>) -> Result<Digest, String> {
        Ok(self.words(to, signature, arg, 1)?[0])
    }
    pub fn words(
        &self,
        to: &str,
        signature: &str,
        arg: Option<Digest>,
        count: usize,
    ) -> Result<Vec<Digest>, String> {
        self.words_args(to, signature, &arg.into_iter().collect::<Vec<_>>(), count)
    }
    pub fn words_args(
        &self,
        to: &str,
        signature: &str,
        args: &[Digest],
        count: usize,
    ) -> Result<Vec<Digest>, String> {
        let bytes = self.call_bytes(to, signature, args)?;
        if bytes.len() != count * 32 {
            return Err(format!(
                "settlement observation: invalid ABI word for {signature}"
            ));
        }
        // Exact length validation above guarantees no trailing bytes. Fixed-size
        // array chunks avoid fallible slice conversions and preserve word order.
        Ok(bytes.as_chunks::<32>().0.to_vec())
    }
    /// Raw return data of one hash-pinned call; a configured witness must return
    /// the same bytes. The length is checked by the caller's decoder.
    pub fn call_bytes(
        &self,
        to: &str,
        signature: &str,
        args: &[Digest],
    ) -> Result<Vec<u8>, String> {
        let hash = Keccak256::digest(signature.as_bytes());
        let mut calldata = hash[..4].to_vec();
        for arg in args {
            calldata.extend_from_slice(arg);
        }
        let params = vec![
            json!({"to":to,"data":crate::hex0x(&calldata)}),
            json!({"blockHash":crate::hex32(&self.anchor.1),"requireCanonical":true}),
        ];
        let parse = |v: Value| -> Result<Vec<u8>, String> {
            if v.as_str().is_none_or(|s| s.len() % 64 != 2) {
                return Err(format!(
                    "settlement observation: invalid ABI word for {signature}"
                ));
            }
            hex_bytes(&v)
        };
        let bytes = parse(self.primary.call("eth_call", params.clone())?)?;
        if let Some(witness) = self.witness {
            if parse(witness.call("eth_call", params)?)? != bytes {
                return Err(format!(
                    "settlement observation: witness disagrees on {signature}"
                ));
            }
        }
        Ok(bytes)
    }
    /// The account nonce (transaction count, the next unused nonce) of `account`
    /// at the anchor block. A configured witness must report the same value.
    pub fn nonce(&self, account: &[u8; 20]) -> Result<u64, String> {
        let params = vec![
            json!(crate::hex0x(account)),
            json!({"blockHash":crate::hex32(&self.anchor.1),"requireCanonical":true}),
        ];
        let n = quantity(
            &self
                .primary
                .call("eth_getTransactionCount", params.clone())?,
        )?;
        if let Some(witness) = self.witness {
            if quantity(&witness.call("eth_getTransactionCount", params)?)? != n {
                return Err(
                    "settlement observation: witness disagrees on the account nonce".into(),
                );
            }
        }
        Ok(n)
    }
    /// A strictly encoded `bytes32[]` return value holding at most `max` entries.
    pub fn bytes32_array(
        &self,
        to: &str,
        signature: &str,
        args: &[Digest],
        max: u64,
    ) -> Result<Vec<Digest>, String> {
        let bytes = self.call_bytes(to, signature, args)?;
        let words = bytes.as_chunks::<32>().0;
        let malformed = || format!("settlement observation: malformed bytes32[] from {signature}");
        if words.len() < 2 || words.len() * 32 != bytes.len() {
            return Err(malformed());
        }
        if abi_u64(words[0], "array offset").map_err(|_| malformed())? != 32 {
            return Err(malformed());
        }
        let n = abi_u64(words[1], "array length").map_err(|_| malformed())?;
        if n > max || words.len() as u64 != n + 2 {
            return Err(malformed());
        }
        Ok(words[2..].to_vec())
    }
    /// The whole open-challenge set at this anchor: the count, every page of
    /// hashes, and the six stored words of up to `max_details` hashes not in
    /// `known`. A page that disagrees with the count, a duplicate, or a stored
    /// challenge that is not open or cannot exist at this block is an error,
    /// never a shorter set.
    pub fn open_challenges(
        &self,
        settlement: &str,
        known: &std::collections::BTreeSet<Digest>,
        max_details: usize,
    ) -> Result<OpenSetRead, String> {
        let count = abi_u64(
            self.word(settlement, "openChallengeCount()", None)?,
            "openChallengeCount",
        )?;
        let batch_count = abi_u64(self.word(settlement, "batchCount()", None)?, "batchCount")?;
        let mut hashes = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut start = 0u64;
        while start < count {
            let want = (count - start).min(OPEN_CHALLENGE_PAGE);
            let page = self.bytes32_array(
                settlement,
                "openChallenges(uint256,uint256)",
                &[u64_word(start), u64_word(OPEN_CHALLENGE_PAGE)],
                OPEN_CHALLENGE_PAGE,
            )?;
            if page.len() as u64 != want {
                return Err("challenge observation: open-set page disagrees with its count".into());
            }
            for hash in page {
                if !seen.insert(hash) {
                    return Err("challenge observation: duplicate open challenge".into());
                }
                hashes.push(hash);
            }
            start += want;
        }
        let mut details = Vec::new();
        for hash in hashes
            .iter()
            .filter(|h| !known.contains(*h))
            .take(max_details)
        {
            let w = self.words(settlement, "challenges(bytes32)", Some(*hash), 6)?;
            let c = OpenChallenge {
                order_hash: *hash,
                beneficiary: abi_address(w[0], "challenge beneficiary")?,
                batch_id_hint: abi_u64(w[1], "challenge batch hint")?,
                opened_block: abi_u64(w[2], "challenge opened block")?,
                open_batch_count: abi_u64(w[3], "challenge open batch count")?,
                stake: abi_u128(w[4], "challenge stake")?,
            };
            if !abi_bool(w[5], "challenge open")? {
                return Err("challenge observation: listed challenge is not open".into());
            }
            if c.beneficiary == [0; 20]
                || c.opened_block > self.height()
                || c.open_batch_count > batch_count
            {
                return Err("challenge observation: impossible open challenge".into());
            }
            details.push(c);
        }
        Ok(OpenSetRead {
            head: self.height(),
            batch_count,
            hashes,
            details,
        })
    }
    pub fn finish(&self) -> Result<(), String> {
        let height = json!(format!("0x{:x}", self.anchor.0));
        if block(self.primary, height.clone())? != self.anchor {
            return Err(
                "settlement observation: canonical block changed or provider disagrees".into(),
            );
        }
        if let Some(witness) = self.witness {
            if block(witness, height)? != self.anchor {
                return Err("settlement observation: witness canonical block changed".into());
            }
        }
        Ok(())
    }
}
pub(super) fn address_word(a: &[u8; 20]) -> Digest {
    let mut word = [0; 32];
    word[12..].copy_from_slice(a);
    word
}
pub(super) fn abi_address(word: Digest, label: &str) -> Result<[u8; 20], String> {
    if word[..12].iter().any(|b| *b != 0) {
        return Err(format!(
            "settlement observation: {label} is not an address word"
        ));
    }
    let mut a = [0; 20];
    a.copy_from_slice(&word[12..]);
    Ok(a)
}
pub(super) fn u64_word(n: u64) -> Digest {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&n.to_be_bytes());
    word
}
pub(super) fn abi_u64(word: Digest, label: &str) -> Result<u64, String> {
    if word[..24].iter().any(|b| *b != 0) {
        return Err(format!("settlement observation: {label} overflows u64"));
    }
    let bytes: [u8; 8] = word[24..]
        .try_into()
        .map_err(|_| format!("settlement observation: {label} not a u64 word"))?;
    Ok(u64::from_be_bytes(bytes))
}
pub(super) fn abi_u128(word: Digest, label: &str) -> Result<u128, String> {
    if word[..16].iter().any(|b| *b != 0) {
        return Err(format!("settlement observation: {label} overflows u128"));
    }
    let bytes: [u8; 16] = word[16..]
        .try_into()
        .map_err(|_| format!("settlement observation: {label} not a u128 word"))?;
    Ok(u128::from_be_bytes(bytes))
}
pub(super) fn abi_bool(word: Digest, label: &str) -> Result<bool, String> {
    if word[..31].iter().any(|b| *b != 0) || word[31] > 1 {
        return Err(format!(
            "settlement observation: invalid ABI bool for {label}"
        ));
    }
    Ok(word[31] == 1)
}
fn hex_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let data = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or("settlement observation: invalid RPC hex data")?;
    if data.len() % 2 != 0 {
        return Err("settlement observation: invalid RPC hex length".into());
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    for pair in data.as_bytes().as_chunks::<2>().0 {
        let hi =
            crate::hex_nibble(pair[0]).ok_or("settlement observation: invalid RPC hex data")?;
        let lo =
            crate::hex_nibble(pair[1]).ok_or("settlement observation: invalid RPC hex data")?;
        out.push(hi * 16 + lo);
    }
    Ok(out)
}

/// The deposit page validator already binds logs and prefix calls to canonical
/// hashes and rechecks both anchors before crediting. Require the configured
/// witness for each observation here, preserving its existing page-level checks.
pub(super) fn deposit_read(
    primary: &dyn Rpc,
    witness: Option<&dyn Rpc>,
    expected: Option<u64>,
    method: &str,
    params: Vec<Value>,
) -> Result<Value, String> {
    match method {
        "eth_chainId" if params.is_empty() => {}
        "eth_getBlockByNumber"
            if params.len() == 2
                && params[1] == json!(false)
                && (params[0] == json!("finalized") || quantity(&params[0]).is_ok()) => {}
        "eth_call" | "eth_getCode"
            if params.len() == 2
                && params[1]["requireCanonical"] == json!(true)
                && params[1]["blockHash"]
                    .as_str()
                    .and_then(parse_bytes32)
                    .is_some() => {}
        "eth_getLogs"
            if params.len() == 1
                && params[0]["blockHash"]
                    .as_str()
                    .and_then(parse_bytes32)
                    .is_some()
                && params[0].get("fromBlock").is_none()
                && params[0].get("toBlock").is_none() => {}
        _ => return Err("deposit observation: unsupported or unpinned read".into()),
    }
    if let Some(witness) = witness {
        chain_agreement(primary, witness, expected)?;
    }
    let value = primary.call(method, params.clone())?;
    let Some(witness) = witness else {
        return Ok(value);
    };
    let other = witness.call(method, params.clone())?;
    let agrees = match method {
        "eth_chainId" => {
            quantity(&value)? == expected.ok_or("missing startup chain")?
                && quantity(&other)? == quantity(&value)?
        }
        "eth_getBlockByNumber" => {
            let anchor = header(&value)?;
            let peer = header(&other)?;
            if params[0] == json!("finalized") {
                peer.0 >= anchor.0
                    && (peer.0 != anchor.0 || peer == anchor)
                    && block(witness, json!(format!("0x{:x}", anchor.0)))? == anchor
            } else {
                anchor.0 == quantity(&params[0])? && peer == anchor
            }
        }
        "eth_call" | "eth_getCode" => hex_bytes(&value)? == hex_bytes(&other)?,
        "eth_getLogs" => value.is_array() && other.is_array() && value == other,
        _ => unreachable!(),
    };
    if !agrees {
        return Err("deposit observation: witness disagreement".into());
    }
    Ok(value)
}

#[cfg(test)]
mod strict_hex_tests {
    use super::*;

    #[test]
    fn rpc_hex_preserves_byte_order_and_leading_zeroes() {
        assert_eq!(hex_bytes(&json!("0x00ff10Ab")).unwrap(), [0, 255, 16, 171]);
        assert!(hex_bytes(&json!("0x")).unwrap().is_empty());
    }

    #[test]
    fn rpc_hex_rejects_odd_length_instead_of_dropping_the_tail() {
        for value in ["0x0", "0x001", "0x00ff1"] {
            assert!(hex_bytes(&json!(value)).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn rpc_hex_rejects_invalid_prefix_digits_and_non_strings() {
        for value in ["", "00", "0X00", "0x0g", "0xg0", "0xé", "0x 0"] {
            assert!(hex_bytes(&json!(value)).is_err(), "accepted {value}");
        }
        assert!(hex_bytes(&Value::Null).is_err());
        assert!(hex_bytes(&json!(0)).is_err());
    }
}
