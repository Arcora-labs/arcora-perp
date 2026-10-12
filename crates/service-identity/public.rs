//! Public, self-reported build/config checksums. This is never attestation or route approval.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "arcora-public-service-identity/v1";
pub const EVIDENCE_KIND: &str = "self_reported_unattested";

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Sort every object's keys independently of serde_json's map feature flags.
pub fn canonical(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut Vec<u8>) {
        match value {
            Value::Object(fields) => {
                output.push(b'{');
                let mut keys: Vec<_> = fields.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    output.extend(serde_json::to_vec(key).expect("JSON key"));
                    output.push(b':');
                    write(fields.get(*key).expect("existing sorted JSON key"), output);
                }
                output.push(b'}');
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(item, output);
                }
                output.push(b']');
            }
            _ => output.extend(serde_json::to_vec(value).expect("typed JSON value")),
        }
    }
    let mut output = Vec::new();
    write(value, &mut output);
    output
}

pub fn envelope(service: &str, program: Value, public_config: Value) -> Value {
    assert!(matches!(service, "gateway" | "prover"));
    let build: Value = serde_json::from_str(include_str!(concat!(
        env!("OUT_DIR"),
        "/service-build-identity.json"
    )))
    .expect("build identity was validated by the build helper");
    let config_bytes = canonical(&public_config);
    json!({
        "schema": SCHEMA,
        "service": service,
        "evidence_kind": EVIDENCE_KIND,
        "build": build,
        "program": program,
        "public_config": public_config,
        "public_config_sha256": sha256(&config_bytes),
        "capabilities": {
            "candidate_submission_supported": false,
            "candidate_submission_enabled": false
        },
        "scope": {
            "running_services_attested": false,
            "operator_policy_approved": false,
            "proof_generated_by_identity_request": false,
            "release_gate": "HOLD"
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identity_config_hash_is_canonical_and_cannot_approve_a_route() {
        let first = envelope(
            "gateway",
            Value::Null,
            json!({"chain_id":84532,"vault":null}),
        );
        let reordered = envelope(
            "gateway",
            Value::Null,
            json!({"vault":null,"chain_id":84532}),
        );
        assert_eq!(
            first["public_config_sha256"],
            reordered["public_config_sha256"]
        );
        assert_ne!(
            first["public_config_sha256"],
            envelope(
                "gateway",
                Value::Null,
                json!({"chain_id":8453,"vault":null})
            )["public_config_sha256"]
        );
        assert_eq!(first["evidence_kind"], EVIDENCE_KIND);
        assert_eq!(
            first["capabilities"]["candidate_submission_supported"],
            false
        );
        assert_eq!(first["capabilities"]["candidate_submission_enabled"], false);
        assert_eq!(first["scope"]["release_gate"], "HOLD");
        assert_eq!(first["scope"]["running_services_attested"], false);
        assert_eq!(first["scope"]["proof_generated_by_identity_request"], false);
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
