//! Optional L1 settlement bridge (Base Sepolia / Phase 0).
//!
//! When configured, the gateway periodically advances the on-chain
//! `DarkPerpSettlement.currentStateRoot` to mirror the engine's live state root —
//! posting the sequencer bond once, then calling `settleBatch` on a slow timer
//! (NOT every 700ms tick; that would be thousands of L1 txs). The only on-chain
//! constraint with the testnet `MockZkVerifier` is `prevRoot == currentStateRoot`
//! and `proof == publicCommitment`, so the bridge reads the current on-chain root
//! live as `prev`, uses the engine root as `new`, and submits. This makes "the
//! appchain settles on L1" verifiable on Basescan; the real ZK proof replaces
//! MockZkVerifier in a later milestone (see docs/PROVING.md).
//!
//! Transport: shells out to `cast` (Foundry) — pragmatic for a testnet demo and
//! reuses the same signer path as deploy. A production bridge would use a native
//! signer (alloy) instead of a subprocess + key in argv.

use std::process::Command;

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// L1 bridge configuration, read from env. `None` ⇒ L1 mode off (pure in-memory).
#[derive(Clone)]
pub struct L1 {
    pub rpc: String,
    pub settlement: String,
    pub key: String,
}

/// What the bridge last published — surfaced to the UI so on-chain settlement is visible.
#[derive(Clone, Default)]
pub struct L1Status {
    pub settled_root: String,
    pub batch_count: u64,
    pub last_tx: String,
    pub bond_wei: String,
}

impl L1 {
    /// Configure from env. Requires `L1_SETTLEMENT` + `L1_SEQUENCER_KEY`; RPC and
    /// explorer default to Base Sepolia.
    pub fn from_env() -> Option<L1> {
        let settlement = std::env::var("L1_SETTLEMENT").ok()?;
        let key = std::env::var("L1_SEQUENCER_KEY").ok()?;
        Some(L1 {
            rpc: std::env::var("L1_RPC").unwrap_or_else(|_| "https://sepolia.base.org".into()),
            settlement,
            key,
        })
    }

    fn cast(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new("cast")
            .args(args)
            .output()
            .map_err(|e| format!("cast spawn failed (is Foundry installed?): {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// The on-chain `currentStateRoot` (the required `prev` for the next settle).
    pub fn current_root(&self) -> Result<String, String> {
        self.cast(&[
            "call",
            &self.settlement,
            "currentStateRoot()(bytes32)",
            "--rpc-url",
            &self.rpc,
        ])
    }

    fn read_u(&self, sig: &str) -> Result<u128, String> {
        let s = self.cast(&["call", &self.settlement, sig, "--rpc-url", &self.rpc])?;
        // cast may print "0" or "0 [0e0]" — take the leading integer token.
        s.split_whitespace()
            .next()
            .unwrap_or("0")
            .parse::<u128>()
            .map_err(|e| format!("parse {sig}: {e}"))
    }

    pub fn sequencer_bond(&self) -> Result<u128, String> {
        self.read_u("sequencerBond()(uint256)")
    }
    pub fn batch_count(&self) -> Result<u64, String> {
        self.read_u("batchCount()(uint256)").map(|v| v as u64)
    }

    /// Post `wei` of bond from the sequencer key.
    pub fn post_bond(&self, wei: &str) -> Result<String, String> {
        let tx = self.cast(&[
            "send",
            &self.settlement,
            "postBond()",
            "--value",
            wei,
            "--private-key",
            &self.key,
            "--rpc-url",
            &self.rpc,
            "--json",
        ])?;
        Ok(tx_hash(&tx))
    }

    /// Settle: advance the on-chain root from `prev` to `new` with `manifest`.
    /// `ordered`/`withdrawals` are the `0x0` placeholders this build uses. The
    /// proof is the 32-byte public commitment itself (what `MockZkVerifier` checks).
    pub fn settle(&self, prev: &str, manifest: &str, new: &str) -> Result<String, String> {
        let commitment = self.cast(&[
            "call",
            &self.settlement,
            "publicCommitment(bytes32,bytes32,bytes32,bytes32,bytes32)(bytes32)",
            prev,
            manifest,
            new,
            ZERO32,
            ZERO32,
            "--rpc-url",
            &self.rpc,
        ])?;
        let tx = self.cast(&[
            "send",
            &self.settlement,
            "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes)",
            prev,
            manifest,
            new,
            ZERO32,
            ZERO32,
            &commitment,
            "--private-key",
            &self.key,
            "--rpc-url",
            &self.rpc,
            "--json",
        ])?;
        Ok(tx_hash(&tx))
    }
}

/// Pull `transactionHash` out of `cast send --json` output (falls back to raw).
fn tx_hash(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| {
            v.get("transactionHash")
                .and_then(|h| h.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| json.lines().next().unwrap_or("").to_string())
}
