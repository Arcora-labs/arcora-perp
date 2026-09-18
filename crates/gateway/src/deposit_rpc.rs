//! A01: finalized, hash-pinned, prefix-checked, whole-block deposit pages.
//! RPC is still a trust boundary. An inconsistency never becomes an empty page.
use super::{hex0x, parse_addr20_hex, parse_hex32, L1};
use perp_core::merkle::{deposit_chain_fold, deposit_leaf};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const TOPIC: &str = crate::l1::DEPOSIT_TOPIC0;
const MAX_LOGS: usize = 16384;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub number: u64,
    pub hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    pub chain: u64,
    pub vault: [u8; 20],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub domain: Domain,
    pub count: u64,
    pub tip: [u8; 32],
    pub anchor: Option<Block>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    pub from: [u8; 20],
    pub commit: [u8; 32],
    pub amount: u128,
    pub tip: [u8; 32],
    pub tx: [u8; 32],
    pub tx_index: u64,
    pub log_index: u64,
    pub block: Block,
}
#[derive(Clone, Debug)]
pub struct Page {
    pub start: Cursor,
    pub end: Block,
    pub events: Vec<Event>,
}
#[derive(Clone, Debug)]
pub enum Error {
    Retry(String),
    Halt(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry(s) => write!(f, "{s}"),
            Self::Halt(s) => write!(f, "SAFETY HALT: {s}"),
        }
    }
}
impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Retry(s)
    }
}
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::Retry(s.into())
    }
}

pub trait DepositSource: Send + Sync {
    fn fetch(&self, cursor: Cursor) -> Result<Page, Error>;
}
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String>;
}
impl Rpc for L1 {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        self.read_rpc(method, &params)
    }
}
pub struct VaultSource<R> {
    rpc: R,
}
impl<R: Rpc> VaultSource<R> {
    pub fn new(rpc: R) -> Self {
        Self { rpc }
    }
}

fn quantity(v: &Value) -> Result<u64, Error> {
    let s = v.as_str().ok_or("missing RPC quantity")?;
    let s = s.strip_prefix("0x").ok_or("non-hex RPC quantity")?;
    if s.is_empty() || s.len() > 16 {
        return Err("invalid RPC quantity".into());
    }
    u64::from_str_radix(s, 16).map_err(|_| "invalid RPC quantity".into())
}
fn digest(v: &Value) -> Result<[u8; 32], Error> {
    v.as_str()
        .and_then(parse_hex32)
        .ok_or_else(|| "missing/invalid hash".into())
}
fn bytes(v: &Value) -> Result<Vec<u8>, Error> {
    let s = v
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or("non-hex data")?;
    if s.len() % 2 != 0 {
        return Err("odd-length data".into());
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let a = super::hex_nibble(p[0]).ok_or("bad hex data")?;
            let b = super::hex_nibble(p[1]).ok_or("bad hex data")?;
            Ok((a << 4) | b)
        })
        .collect()
}
fn uint64(b: &[u8]) -> Result<u64, Error> {
    if b.len() != 32 || b[..24].iter().any(|x| *x != 0) {
        return Err("uint64 overflow".into());
    }
    Ok(u64::from_be_bytes(b[24..].try_into().unwrap()))
}

impl<R: Rpc> VaultSource<R> {
    fn block(&self, tag: Value) -> Result<Block, Error> {
        let v = self
            .rpc
            .call("eth_getBlockByNumber", vec![tag.clone(), json!(false)])?;
        let block = Block {
            number: quantity(&v["number"])?,
            hash: digest(&v["hash"])?,
        };
        if tag != json!("finalized") && quantity(&tag)? != block.number {
            return Err("RPC returned the wrong block height".into());
        }
        Ok(block)
    }
    fn canonical(&self, b: &Block) -> Result<bool, Error> {
        Ok(self.block(json!(format!("0x{:x}", b.number)))? == *b)
    }
    fn word(
        &self,
        domain: &Domain,
        block: &Block,
        signature: &str,
        arg: Option<u64>,
    ) -> Result<Vec<u8>, Error> {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(signature.as_bytes());
        let mut data = hash[..4].to_vec();
        if let Some(n) = arg {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            data.extend(w);
        }
        let result = self.rpc.call(
            "eth_call",
            vec![
                json!({"to":hex0x(&domain.vault),"data":hex0x(&data)}),
                json!({"blockHash":hex0x(&block.hash),"requireCanonical":true}),
            ],
        )?;
        bytes(&result)
    }
    fn count(&self, domain: &Domain, b: &Block, allow_absent: bool) -> Result<u64, Error> {
        let w = self.word(domain, b, "depositCount()", None)?;
        if w.is_empty() && allow_absent {
            // Only an actually absent historical contract is an empty prefix.
            let code = self.rpc.call(
                "eth_getCode",
                vec![
                    json!(hex0x(&domain.vault)),
                    json!({"blockHash":hex0x(&b.hash),"requireCanonical":true}),
                ],
            )?;
            if code == json!("0x") {
                return Ok(0);
            }
        }
        uint64(&w)
    }
    fn tip(&self, domain: &Domain, b: &Block, n: u64) -> Result<[u8; 32], Error> {
        // The zero prefix is a protocol constant, not an RPC error fallback.
        if n == 0 {
            return Ok([0; 32]);
        }
        self.word(domain, b, "depositTipAt(uint64)", Some(n))?
            .try_into()
            .map_err(|_| "invalid tip word".into())
    }
}

impl<R: Rpc> DepositSource for VaultSource<R> {
    fn fetch(&self, cursor: Cursor) -> Result<Page, Error> {
        let actual = quantity(&self.rpc.call("eth_chainId", vec![])?)?;
        if actual != cursor.domain.chain {
            return Err(Error::Halt(
                "RPC chain does not match deposit domain".into(),
            ));
        }
        // No latest/safe fallback: providers without finalized or EIP-1898 pause intake.
        let head = self.block(json!("finalized"))?;
        if let Some(anchor) = &cursor.anchor {
            if head.number < anchor.number {
                return Err("finalized head regressed; retry another consistent RPC".into());
            }
            if !self.canonical(anchor)? {
                return Err(Error::Halt(
                    "previously credited finalized anchor was reorganized".into(),
                ));
            }
        }
        let total = self.count(&cursor.domain, &head, false)?;
        if total < cursor.count || self.tip(&cursor.domain, &head, cursor.count)? != cursor.tip {
            return Err(Error::Halt(
                "finalized L1 prefix disagrees with persisted engine prefix".into(),
            ));
        }
        if total == cursor.count {
            if !self.canonical(&head)? {
                return Err("finalized head changed while reading".into());
            }
            return Ok(Page {
                start: cursor,
                end: head,
                events: vec![],
            });
        }
        // Find the next deposit-bearing block. This also catches up a legacy snapshot
        // without guessing a deployment/start height and without skipping deposit IDs.
        let mut lo = cursor
            .anchor
            .as_ref()
            .map(|b| b.number.saturating_add(1))
            .unwrap_or(0);
        let mut hi = head.number;
        if lo > hi {
            return Err(Error::Halt("anchor/count inconsistency".into()));
        }
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let b = self.block(json!(format!("0x{mid:x}")))?;
            if self.count(&cursor.domain, &b, true)? > cursor.count {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        let block = self.block(json!(format!("0x{lo:x}")))?;
        let before = if lo == 0 {
            0
        } else {
            let parent = self.block(json!(format!("0x{:x}", lo - 1)))?;
            self.count(&cursor.domain, &parent, true)?
        };
        let after = self.count(&cursor.domain, &block, false)?;
        if before > cursor.count
            || after <= cursor.count
            || after > total
            || after - before > MAX_LOGS as u64
        {
            return Err("invalid or oversized deposit block boundary".into());
        }
        let base_tip = self.tip(&cursor.domain, &block, before)?;
        let end_tip = self.tip(&cursor.domain, &block, after)?;
        let logs = self.rpc.call(
            "eth_getLogs",
            vec![json!({"address":hex0x(&cursor.domain.vault),
            "topics":[TOPIC],"blockHash":hex0x(&block.hash)})],
        )?;
        let events = validate_logs(
            &logs,
            &cursor.domain,
            &block,
            before,
            after,
            base_tip,
            end_tip,
        )?;
        let consumed_tip = if cursor.count == before {
            base_tip
        } else {
            events[(cursor.count - before - 1) as usize].tip
        };
        if consumed_tip != cursor.tip {
            return Err(Error::Halt(
                "block prefix disagrees with consumed deposits".into(),
            ));
        }
        if !self.canonical(&block)? || !self.canonical(&head)? {
            return Err("chain changed during hash-pinned read; retry".into());
        }
        Ok(Page {
            start: cursor.clone(),
            end: block,
            events: events
                .into_iter()
                .filter(|e| e.id >= cursor.count)
                .collect(),
        })
    }
}

/// Reject log omissions/truncation even if eth_getLogs returned HTTP 200. Validate
/// every leaf against the hash-pinned contract prefix and the event's running tip.
#[allow(clippy::too_many_arguments)]
fn validate_logs(
    logs: &Value,
    domain: &Domain,
    block: &Block,
    before: u64,
    after: u64,
    mut tip: [u8; 32],
    end_tip: [u8; 32],
) -> Result<Vec<Event>, Error> {
    let logs = logs.as_array().ok_or("logs response is not an array")?;
    if logs.len() > MAX_LOGS * 2 {
        return Err("oversized log response".into());
    }
    let mut ordered = BTreeMap::new();
    for log in logs {
        if log["removed"] != json!(false) {
            return Err("removed or unqualified log".into());
        }
        if log["address"].as_str().and_then(parse_addr20_hex) != Some(domain.vault)
            || digest(&log["blockHash"])? != block.hash
            || quantity(&log["blockNumber"])? != block.number
        {
            return Err("log from wrong vault or block".into());
        }
        let topics = log["topics"].as_array().ok_or("missing topics")?;
        if topics.len() != 3 || digest(&topics[0])? != parse_hex32(TOPIC).unwrap() {
            return Err("wrong deposit signature".into());
        }
        let fromword = digest(&topics[1])?;
        if fromword[..12].iter().any(|x| *x != 0) {
            return Err("invalid from padding".into());
        }
        let data = bytes(&log["data"])?;
        if data.len() != 96 || data[..16].iter().any(|x| *x != 0) {
            return Err("bad deposit data/amount overflow".into());
        }
        let amount = u128::from_be_bytes(data[16..32].try_into().unwrap());
        if amount == 0 || amount > i128::MAX as u128 {
            return Err("uncreditable deposit amount".into());
        }
        let e = Event {
            id: uint64(&data[32..64])?,
            from: fromword[12..].try_into().unwrap(),
            commit: digest(&topics[2])?,
            amount,
            tip: data[64..96].try_into().unwrap(),
            tx: digest(&log["transactionHash"])?,
            tx_index: quantity(&log["transactionIndex"])?,
            log_index: quantity(&log["logIndex"])?,
            block: block.clone(),
        };
        let identity = (e.tx_index, e.log_index);
        if let Some(previous) = ordered.insert(identity, e.clone()) {
            if previous != e {
                return Err("conflicting duplicate event".into());
            }
        }
    }
    if ordered.len() as u64 != after - before {
        return Err("deposit logs missing or duplicated IDs; prefix not advanced".into());
    }
    let events: Vec<_> = ordered.into_values().collect();
    for (offset, event) in events.iter().enumerate() {
        if event.id != before + offset as u64 {
            return Err("deposit IDs do not follow L1 log order".into());
        }
        tip = deposit_chain_fold(
            &tip,
            &deposit_leaf(&event.from, &event.commit, event.amount, event.id),
        );
        if tip != event.tip {
            return Err("event deposit tip mismatch".into());
        }
    }
    if tip != end_tip {
        return Err("incomplete or forked log page".into());
    }
    Ok(events)
}

#[cfg(test)]
mod tests;
