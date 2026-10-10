//! Optional host-side independent venue guard. No guest or snapshot wire changes.
use super::*;
use oracle_feed::crosscheck::{CrosscheckGate, CrosscheckPolicy, SourceTick, SpotPair};

pub(super) enum FetchedOracle {
    Single(OracleTranscript),
    Pair(Box<(SourceTick, SourceTick)>),
}

impl Gw {
    /// Build the entire binding before installing anything. With today's
    /// USDC-labelled/USDT-fed MARKETS this deliberately REFUSES opt-in startup.
    /// Correct denomination/FX policy must be reviewed separately, not guessed.
    pub(super) fn configure_oracle_crosscheck(
        &mut self,
        policy: Option<CrosscheckPolicy>,
    ) -> Result<(), String> {
        let Some(policy) = policy else {
            return Ok(());
        };
        let mut gates = HashMap::new();
        for m in &self.mkts {
            let feed = m
                .feed
                .ok_or("crosscheck requires a real spot feed for every market")?;
            let pair = SpotPair::bind(m.symbol, feed)?;
            if !self.seq.state.markets.contains_key(&m.id)
                || gates
                    .insert(m.id, CrosscheckGate::new(pair, m.id, policy))
                    .is_some()
            {
                return Err("crosscheck market binding missing or duplicated".into());
            }
        }
        if gates.is_empty() {
            return Err("crosscheck requires configured markets".into());
        }
        self.oracle_crosschecks = gates;
        self.require_fresh_production_oracles();
        Ok(())
    }

    /// Known paired-source failure invalidates admission immediately, not only
    /// after the previous observation expires. Keep the last displayed price and
    /// receipt/source times untouched. This explicit invalid sentinel is NOT a
    /// newly signed price, and the unchanged guest validator always refuses it.
    pub(super) fn halt_crosschecked_oracle(&mut self, market: u64) {
        if !self.oracle_crosschecks.contains_key(&market) {
            return;
        }
        self.seq.set_oracle(
            market,
            OracleTranscript {
                price: 0,
                publish_time_ms: 0,
                confidence: 0,
                backup_twap: 0,
                signature: OracleSig {
                    r: [0; 32],
                    s: [0; 32],
                    v: 0,
                },
            },
        );
        if let Some(m) = self.mkts.iter_mut().find(|m| m.id == market) {
            m.live = false;
        }
    }

    pub(super) fn apply_crosschecked_oracle_at(
        &mut self,
        market: u64,
        primary: SourceTick,
        secondary: SourceTick,
        received_ms: u64,
    ) -> bool {
        let Some(mut candidate) = self.oracle_crosschecks.get(&market).cloned() else {
            return false;
        };
        let accepted = self
            .seq
            .state
            .markets
            .get(&market)
            .ok_or_else(|| "unknown crosscheck market".to_string())
            .and_then(|policy| candidate.accept(&primary, &secondary, policy, received_ms));
        match accepted {
            Ok(transcript)
                if self.apply_validated_real_oracle_at(market, transcript, received_ms) =>
            {
                self.oracle_crosschecks.insert(market, candidate);
                true
            }
            _ => {
                self.halt_crosschecked_oracle(market);
                false
            }
        }
    }
}

#[cfg(test)]
#[path = "oracle_crosscheck_tests.rs"]
mod tests;
