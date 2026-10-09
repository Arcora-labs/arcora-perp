//! Hash-pinned reads and one authorized registration before proving. No
//! "latest" fallback after an anchor is submitted: finality lag means HOLD.
use super::*;
use crate::deposit_rpc::Rpc;
use perp_core::clock::{ClockContext, TimeBounds};

#[derive(Clone, Debug)]
pub(crate) struct ClockConfig {
    pub verifier: [u8; 20],
    pub chain_id: u64,
}
impl ClockConfig {
    pub(crate) fn from_values(
        verifier: Option<&str>,
        chain: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let Some(value) = verifier else {
            return Ok(None);
        };
        let verifier = crate::parse_addr20_hex(value)
            .filter(|a| *a != [0; 20])
            .ok_or("invalid CLOCK_BOUND_VERIFIER")?;
        let chain_id = chain
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .ok_or("clock binding requires a nonzero L1_CHAIN_ID")?;
        Ok(Some(Self { verifier, chain_id }))
    }
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        let v = match std::env::var("CLOCK_BOUND_VERIFIER") {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("invalid CLOCK_BOUND_VERIFIER encoding".into()),
        };
        Self::from_values(v.as_deref(), std::env::var("L1_CHAIN_ID").ok().as_deref())
    }
}
fn address(word: Digest) -> Result<[u8; 20], String> {
    if word[..12] != [0; 12] {
        return Err("invalid clock address word".into());
    }
    word[12..]
        .try_into()
        .map_err(|_| "invalid clock address".into())
}
impl L1 {
    /// The configuration is immutable for this L1 instance. No late env fallback.
    pub(crate) fn clock_enabled(&self) -> bool {
        self.clock.is_some()
    }
    fn clock_read(
        &self,
        batch: u64,
        phase: u8,
        policy: observation::AnchorPolicy,
    ) -> Result<Option<ClockContext>, String> {
        let cfg = self
            .clock
            .as_ref()
            .ok_or("clock binding is not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        let target =
            crate::parse_addr20_hex(&self.settlement).ok_or("invalid settlement address")?;
        let primary = SettlementReader {
            l1: self,
            endpoint: &self.rpc,
            role: "primary",
        };
        if observation::quantity(&primary.call("eth_chainId", vec![])?)? != cfg.chain_id {
            return Err("clock chain mismatch".into());
        }
        self.observe_at(policy, |r| {
            if address(r.word(&self.settlement, "verifier()", None)?)? != cfg.verifier
                || address(r.word(&v, "settlement()", None)?)? != target
                || abi_u64(r.word(&v, "proofVersion()", None)?, "proofVersion")? != 2
            {
                return Err("clock verifier/settlement/version mismatch".into());
            }
            if abi_u64(
                r.word(&self.settlement, "batchCount()", None)?,
                "batchCount",
            )? != batch
            {
                return Err("clock batch is not the canonical batch".into());
            }
            let actual_phase =
                if !abi_bool(r.word(&self.settlement, "closeOnly()", None)?, "closeOnly")? {
                    0
                } else if abi_bool(
                    r.word(&self.settlement, "windDownSettled()", None)?,
                    "windDownSettled",
                )? {
                    2
                } else {
                    1
                };
            if phase != actual_phase {
                return Err("clock wind-down phase mismatch".into());
            }
            let words = r.words_args(
                &v,
                "anchor(uint64,uint8)",
                &[
                    observation::u64_word(batch),
                    observation::u64_word(phase as u64),
                ],
                8,
            )?;
            if !abi_bool(words[7], "anchor exists")? {
                return Ok(None);
            }
            if words[0] != r.word(&self.settlement, "currentStateRoot()", None)? {
                return Err("clock previous root mismatch".into());
            }
            let c = ClockContext {
                chain_id: cfg.chain_id,
                verifier: cfg.verifier,
                settlement: target,
                batch_id: batch,
                previous_root: words[0],
                base_commitment: words[1],
                phase,
                first_ms: abi_u64(words[3], "firstMs")?,
                last_ms: abi_u64(words[4], "lastMs")?,
                timed_ops: abi_u64(words[5], "timedOps")?,
                anchored_at_ms: abi_u64(words[6], "anchoredAtMs")?,
                max_window_ms: abi_u64(r.word(&v, "maxWindowMs()", None)?, "maxWindowMs")?,
                clock_skew_ms: abi_u64(r.word(&v, "clockSkewMs()", None)?, "clockSkewMs")?,
            };
            if words[2] != c.receipt() {
                return Err("clock receipt mismatch".into());
            }
            Ok(Some(c))
        })
    }
    pub(crate) fn register_clock(
        &self,
        w: &sequencer::WindowWitness,
    ) -> Result<ClockContext, String> {
        let mut post = w.pre_state.clone();
        let roots = perp_core::commitment::derive_roots(&mut post, &w.ops, &w.manifest)
            .map_err(|e| format!("clock replay: {e:?}"))?;
        let b = TimeBounds::derive(&w.ops).map_err(|e| format!("clock bounds: {e:?}"))?;
        if let Some(c) = self.clock_read(
            w.batch_id,
            roots.wind_down_phase,
            observation::AnchorPolicy::Latest,
        )? {
            c.validate(w.batch_id, &roots, &w.ops)
                .map_err(|_| "existing clock registration differs")?;
        } else {
            let cfg = self
                .clock
                .as_ref()
                .ok_or("clock binding is not configured")?;
            let values = [
                w.batch_id.to_string(),
                crate::hex32(&roots.prev_state_root),
                crate::hex32(&roots.commitment::<perp_core::hash::Keccak256>()),
                b.first_ms.to_string(),
                b.last_ms.to_string(),
                b.count.to_string(),
                roots.wind_down_phase.to_string(),
            ];
            let args: Vec<&str> = values.iter().map(String::as_str).collect();
            // Errors are ambiguous: caller retains the pre-registration WAL intent.
            self.send(
                &crate::hex0x(&cfg.verifier),
                "register(uint64,bytes32,bytes32,uint64,uint64,uint64,uint8)",
                &args,
            )
            .map_err(|_| "clock registration send unresolved; retain journal".to_string())?;
        }
        let c = self
            .clock_read(
                w.batch_id,
                roots.wind_down_phase,
                observation::AnchorPolicy::Finalized,
            )?
            .ok_or("clock registration is not finalized; retain exact journal and resume later")?;
        c.validate(w.batch_id, &roots, &w.ops)
            .map_err(|_| "finalized clock context differs")?;
        Ok(c)
    }
    /// Recheck the exact receipt before broadcast; strip only the internal envelope.
    pub(crate) fn clock_proof_for_send(
        &self,
        out: &crate::prover_client::ProveOutcome,
    ) -> Result<Vec<u8>, String> {
        let tagged = out.proof.strip_prefix(perp_core::clock::PROOF_MAGIC);
        match (&self.clock, tagged) {
            (None, None) if !out.proof.is_empty() => Ok(out.proof.clone()),
            (Some(_), Some(body)) if body.len() > 32 => {
                let batch = self.batch_count()?;
                let c = self
                    .clock_read(
                        batch,
                        out.wind_down_phase,
                        observation::AnchorPolicy::Finalized,
                    )?
                    .ok_or("finalized clock record missing")?;
                if c.receipt().as_slice() != &body[..32]
                    || c.base_commitment != out.commitment
                    || c.previous_root != out.prev_root
                {
                    return Err("clock receipt changed before broadcast".into());
                }
                Ok(body[32..].to_vec())
            }
            _ => Err("clock proof version/configuration mismatch or empty proof".into()),
        }
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    #[test]
    fn clock_config_is_explicit_and_never_truthy() {
        assert!(ClockConfig::from_values(None, None).unwrap().is_none());
        let v = crate::hex0x(&[1; 20]);
        assert!(ClockConfig::from_values(Some(&v), Some("84532"))
            .unwrap()
            .is_some());
        for chain in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some(" 84532"),
            Some("84532 "),
            Some("18446744073709551616"),
        ] {
            assert!(ClockConfig::from_values(Some(&v), chain).is_err());
        }
        for addr in [
            "",
            "0x00",
            "mock",
            "0x0000000000000000000000000000000000000000",
        ] {
            assert!(ClockConfig::from_values(Some(addr), Some("84532")).is_err());
        }
    }
    #[test]
    fn clock_sender_rejects_tagged_proof_when_binding_disabled() {
        let (w, ww) = crate::prover_client::tests_support::sample_window();
        let mut p = crate::prover_client::prepare_unproved(&w, &ww).unwrap();
        let l1 = L1::test_reader("http://127.0.0.1:9".into());
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
        p.outcome.proof = perp_core::clock::PROOF_MAGIC.to_vec();
        p.outcome.proof.extend([1; 64]);
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
        p.outcome.proof = vec![1; 32];
        assert_eq!(l1.clock_proof_for_send(&p.outcome).unwrap(), vec![1; 32]);
    }
    #[test]
    fn clock_sender_refuses_untagged_or_truncated_v2_proof_without_rpc() {
        let (w, ww) = crate::prover_client::tests_support::sample_window();
        let mut p = crate::prover_client::prepare_unproved(&w, &ww).unwrap();
        let mut l1 = L1::test_reader("http://127.0.0.1:9".into());
        l1.clock = Some(ClockConfig {
            verifier: [1; 20],
            chain_id: 84532,
        });
        p.outcome.proof = vec![1; 32];
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
        p.outcome.proof = perp_core::clock::PROOF_MAGIC.to_vec();
        p.outcome.proof.extend([1; 32]);
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
    }
}
