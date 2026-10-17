//! Bind a block's timestamp to its hash. The block hash is keccak256 of the
//! RLP-encoded header, so recomputing it from the fields an
//! `eth_getBlockByNumber` response carries means a provider cannot report the
//! right hash together with a different time, number or any other header field.
use serde_json::Value;
use sha3::{Digest as _, Keccak256};

#[derive(Clone, Copy)]
enum Kind {
    Hash,
    Address,
    Bloom,
    Nonce,
    Bytes,
    Uint,
}

/// The header fields every Ethereum-family block carries, in RLP order.
const BASE_FIELDS: [(&str, Kind); 15] = [
    ("parentHash", Kind::Hash),
    ("sha3Uncles", Kind::Hash),
    ("miner", Kind::Address),
    ("stateRoot", Kind::Hash),
    ("transactionsRoot", Kind::Hash),
    ("receiptsRoot", Kind::Hash),
    ("logsBloom", Kind::Bloom),
    ("difficulty", Kind::Uint),
    ("number", Kind::Uint),
    ("gasLimit", Kind::Uint),
    ("gasUsed", Kind::Uint),
    ("timestamp", Kind::Uint),
    ("extraData", Kind::Bytes),
    ("mixHash", Kind::Hash),
    ("nonce", Kind::Nonce),
];

/// Fields later forks append, in RLP order (London, Shanghai, Cancun x3, Prague).
/// A field may only be present when every earlier one is.
const FORK_FIELDS: [(&str, Kind); 6] = [
    ("baseFeePerGas", Kind::Uint),
    ("withdrawalsRoot", Kind::Hash),
    ("blobGasUsed", Kind::Uint),
    ("excessBlobGas", Kind::Uint),
    ("parentBeaconBlockRoot", Kind::Hash),
    ("requestsHash", Kind::Hash),
];

/// Generous bound on `extraData`; it only limits allocation from a hostile reply.
const MAX_EXTRA_DATA: usize = 1024;

/// keccak256(rlp(header)) recomputed from a block JSON object. Errors on any
/// missing, non-canonical or wrongly sized field.
pub(crate) fn header_hash(block: &Value) -> Result<[u8; 32], String> {
    let mut payload = Vec::with_capacity(640);
    for (name, kind) in BASE_FIELDS {
        encode_field(&mut payload, &block[name], name, kind)?;
    }
    let mut ended = false;
    for (name, kind) in FORK_FIELDS {
        let field = &block[name];
        if field.is_null() {
            ended = true;
            continue;
        }
        if ended {
            return Err(format!("block header field {name} follows an absent field"));
        }
        encode_field(&mut payload, field, name, kind)?;
    }
    let mut encoded = Vec::with_capacity(payload.len() + 9);
    length_prefix(&mut encoded, payload.len(), 0xc0);
    encoded.extend_from_slice(&payload);
    Ok(Keccak256::digest(&encoded).into())
}

fn encode_field(out: &mut Vec<u8>, v: &Value, name: &str, kind: Kind) -> Result<(), String> {
    let bad = || format!("block header field {name} is missing or malformed");
    let text = v
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(bad)?;
    let bytes = match kind {
        Kind::Uint => {
            // Canonical JSON-RPC quantity: no leading zero nibble except "0x0".
            if text.is_empty()
                || text.len() > 64
                || (text.len() > 1 && text.starts_with('0'))
                || !text.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(bad());
            }
            let padded = if !text.len().is_multiple_of(2) {
                format!("0{text}")
            } else {
                text.to_string()
            };
            let raw = decode(&padded).ok_or_else(bad)?;
            // Minimal big-endian; the integer zero is the empty string.
            let first = raw.iter().position(|b| *b != 0).unwrap_or(raw.len());
            raw[first..].to_vec()
        }
        _ => {
            let raw = decode(text).ok_or_else(bad)?;
            let ok = match kind {
                Kind::Hash => raw.len() == 32,
                Kind::Address => raw.len() == 20,
                Kind::Bloom => raw.len() == 256,
                Kind::Nonce => raw.len() == 8,
                Kind::Bytes => raw.len() <= MAX_EXTRA_DATA,
                Kind::Uint => unreachable!(),
            };
            if !ok {
                return Err(bad());
            }
            raw
        }
    };
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        length_prefix(out, bytes.len(), 0x80);
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

fn length_prefix(out: &mut Vec<u8>, len: usize, offset: u8) {
    if len <= 55 {
        out.push(offset + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap_or(7);
        out.push(offset + 55 + (8 - first) as u8);
        out.extend_from_slice(&be[first..]);
    }
}

fn decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some(crate::hex_nibble(p[0])? << 4 | crate::hex_nibble(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Blocks produced by a local anvil (no network) on three hardforks. The
    // reported hash is the node's own; the encoder must reproduce it exactly.
    fn prague() -> Value {
        fixture("prague")
    }

    fn fixture(name: &str) -> Value {
        let text = match name {
            "london" => include_str!("header_fixtures/london.json"),
            "cancun" => include_str!("header_fixtures/cancun.json"),
            _ => include_str!("header_fixtures/prague.json"),
        };
        serde_json::from_str(text).unwrap()
    }

    fn reported(v: &Value) -> [u8; 32] {
        crate::parse_hex32(v["hash"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn header_hash_matches_node_hashes_across_forks() {
        for name in ["london", "cancun", "prague"] {
            let v = fixture(name);
            assert_eq!(header_hash(&v).unwrap(), reported(&v), "{name}");
        }
    }

    #[test]
    fn header_hash_changes_with_any_bound_field() {
        let p = prague();
        for (field, value) in [
            ("timestamp", json!("0x6553f102")),
            ("number", json!("0x3")),
            ("parentHash", json!(crate::hex32(&[1; 32]))),
            ("extraData", json!("0x01")),
            ("requestsHash", json!(crate::hex32(&[2; 32]))),
        ] {
            let mut v = p.clone();
            v[field] = value;
            assert_ne!(header_hash(&v).unwrap(), reported(&p), "{field}");
        }
    }

    #[test]
    fn header_hash_refuses_malformed_or_gapped_fields() {
        let p = prague();
        for (field, value) in [
            ("timestamp", json!("0x06553f101")),
            ("timestamp", json!("0x")),
            ("timestamp", json!(1_700_000_001)),
            ("number", Value::Null),
            ("miner", json!("0x00")),
            ("logsBloom", json!("0x00")),
            ("nonce", json!("0x00")),
            ("stateRoot", json!("0xzz")),
            (
                "extraData",
                json!(format!("0x{}", "00".repeat(MAX_EXTRA_DATA + 1))),
            ),
        ] {
            let mut v = p.clone();
            v[field] = value;
            assert!(header_hash(&v).is_err(), "{field}");
        }
        // A later fork field without an earlier one is not a valid header.
        let mut gapped = p.clone();
        gapped.as_object_mut().unwrap().remove("withdrawalsRoot");
        assert!(header_hash(&gapped).is_err());
        // Dropping trailing fork fields is a valid (different) header shape.
        let mut london = p;
        for f in [
            "withdrawalsRoot",
            "blobGasUsed",
            "excessBlobGas",
            "parentBeaconBlockRoot",
            "requestsHash",
        ] {
            london.as_object_mut().unwrap().remove(f);
        }
        assert!(header_hash(&london).is_ok());
    }

    #[test]
    fn rlp_length_prefixes_cover_short_and_long_forms() {
        let mut out = vec![];
        length_prefix(&mut out, 55, 0x80);
        assert_eq!(out, [0xb7]);
        out.clear();
        length_prefix(&mut out, 56, 0x80);
        assert_eq!(out, [0xb8, 56]);
        out.clear();
        length_prefix(&mut out, 0x0102, 0xc0);
        assert_eq!(out, [0xf9, 0x01, 0x02]);
    }
}
