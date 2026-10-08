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
fn block(rpc: &dyn Rpc, tag: Value) -> Result<(u64, Digest), String> {
    let h = header(&rpc.call("eth_getBlockByNumber", vec![tag.clone(), json!(false)])?)?;
    if tag != json!("latest") && tag != json!("finalized") && quantity(&tag)? != h.0 {
        return Err(
            "settlement observation: canonical block changed or provider disagrees (height)".into(),
        );
    }
    Ok(h)
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
}
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
        let head = block(primary, json!(tag))?;
        let anchor = match policy {
            AnchorPolicy::Confirmed(depth) => {
                let height = head
                    .0
                    .checked_sub(depth)
                    .ok_or("settlement observation: insufficient gate confirmations")?;
                block(primary, json!(format!("0x{height:x}")))?
            }
            _ => head,
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
        })
    }
    pub fn height(&self) -> u64 {
        self.anchor.0
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
        let hash = Keccak256::digest(signature.as_bytes());
        let mut calldata = hash[..4].to_vec();
        if let Some(arg) = arg {
            calldata.extend(arg);
        }
        let params = vec![
            json!({"to":to,"data":crate::hex0x(&calldata)}),
            json!({"blockHash":crate::hex32(&self.anchor.1),"requireCanonical":true}),
        ];
        let parse = |v: Value| -> Result<Vec<Digest>, String> {
            if v.as_str().is_none_or(|s| s.len() != 2 + count * 64) {
                return Err(format!(
                    "settlement observation: invalid ABI word for {signature}"
                ));
            }
            let bytes = hex_bytes(&v)?;
            if bytes.len() != count * 32 {
                return Err(format!(
                    "settlement observation: invalid ABI word for {signature}"
                ));
            }
            // Length is checked exactly above, so each chunk is a 32-byte word; map the
            // conversion failure to an error instead of unwrapping (clippy-clean).
            bytes
                .chunks_exact(32)
                .map(|w| {
                    w.try_into().map_err(|_| {
                        format!("settlement observation: invalid ABI word for {signature}")
                    })
                })
                .collect()
        };
        let words = parse(self.primary.call("eth_call", params.clone())?)?;
        if let Some(witness) = self.witness {
            if parse(witness.call("eth_call", params)?)? != words {
                return Err(format!(
                    "settlement observation: witness disagrees on {signature}"
                ));
            }
        }
        Ok(words)
    }
    /// Query one bounded challenge page and bind its event metadata to canonical
    /// headers. Disagreement or malformed/omitted events never become an empty page.
    pub fn challenges(
        &self,
        settlement: &str,
        from: u64,
    ) -> Result<(Vec<String>, u64, Option<Digest>), String> {
        const PAGE_BLOCKS: u64 = 1024;
        const MAX_LOGS: usize = 4096;
        if from > self.anchor.0 {
            return Ok((Vec::new(), from, None));
        }
        let end = from.saturating_add(PAGE_BLOCKS - 1).min(self.anchor.0);
        let anchor = self.canonical_height(end)?;
        let page = Self {
            primary: self.primary,
            witness: self.witness,
            anchor,
        };
        let topic = crate::hex0x(&Keccak256::digest(
            b"InclusionChallenged(bytes32,address,uint256)",
        ));
        let params = vec![
            json!({"address":settlement,"topics":[topic],"fromBlock":format!("0x{from:x}"),"toBlock":format!("0x{end:x}")}),
        ];
        let logs = self.primary.call("eth_getLogs", params.clone())?;
        let entries = logs
            .as_array()
            .filter(|a| a.len() <= MAX_LOGS)
            .ok_or("challenge observation: malformed or oversized logs")?;
        if let Some(witness) = self.witness {
            if witness.call("eth_getLogs", params)? != logs {
                return Err("challenge observation: witness log disagreement".into());
            }
        }
        let target = crate::parse_addr20_hex(settlement)
            .ok_or("challenge observation: invalid settlement address")?;
        let mut hashes = Vec::new();
        let mut positions = std::collections::BTreeSet::new();
        let mut headers = std::collections::BTreeMap::new();
        for log in entries {
            let height = quantity(&log["blockNumber"])?;
            let block_hash = log["blockHash"]
                .as_str()
                .and_then(parse_bytes32)
                .ok_or("challenge observation: invalid event block hash")?;
            if log["removed"] != json!(false)
                || !(from..=end).contains(&height)
                || log["address"].as_str().and_then(crate::parse_addr20_hex) != Some(target)
            {
                return Err(
                    "challenge observation: wrong contract, removed or out-of-range event".into(),
                );
            }
            let topics = log["topics"]
                .as_array()
                .filter(|t| t.len() == 3)
                .ok_or("challenge observation: invalid topics")?;
            if topics[0].as_str().and_then(parse_bytes32) != parse_bytes32(&topic) {
                return Err("challenge observation: wrong event signature".into());
            }
            let order = topics[1]
                .as_str()
                .and_then(parse_bytes32)
                .ok_or("challenge observation: invalid order hash")?;
            let challenger = topics[2]
                .as_str()
                .and_then(parse_bytes32)
                .ok_or("challenge observation: invalid challenger")?;
            if challenger[..12].iter().any(|b| *b != 0) {
                return Err("challenge observation: invalid challenger address padding".into());
            }
            let deadline: Digest = hex_bytes(&log["data"])?
                .try_into()
                .map_err(|_| "challenge observation: invalid deadline ABI")?;
            if abi_u64(deadline, "challenge deadline")? <= height {
                return Err("challenge observation: impossible deadline".into());
            }
            quantity(&log["transactionIndex"])?;
            if log["transactionHash"]
                .as_str()
                .and_then(parse_bytes32)
                .is_none()
                || !positions.insert((height, quantity(&log["logIndex"])?))
            {
                return Err(
                    "challenge observation: invalid transaction or duplicate log position".into(),
                );
            }
            let canonical = match headers.get(&height) {
                Some(hash) => *hash,
                None => {
                    let (_, hash) = self.canonical_height(height)?;
                    headers.insert(height, hash);
                    hash
                }
            };
            if canonical != block_hash {
                return Err("challenge observation: event block is not canonical".into());
            }
            hashes.push(crate::hex32(&order));
        }
        page.finish()?;
        Ok((
            hashes,
            end.checked_add(1)
                .ok_or("challenge observation: cursor overflow")?,
            Some(page.anchor.1),
        ))
    }
    pub fn anchor_matches(&self, height: u64, hash: Digest) -> Result<bool, String> {
        if height > self.anchor.0 {
            return Err("challenge observation: latest height behind saved scan anchor".into());
        }
        Ok(self.canonical_height(height)?.1 == hash)
    }
    fn canonical_height(&self, height: u64) -> Result<(u64, Digest), String> {
        let tag = json!(format!("0x{height:x}"));
        let anchor = block(self.primary, tag.clone())?;
        if let Some(witness) = self.witness {
            if block(witness, tag)? != anchor {
                return Err("challenge observation: witness block disagreement".into());
            }
        }
        Ok(anchor)
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
    for pair in data.as_bytes().chunks_exact(2) {
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
