# contracts — L1 settlement (Faz 2)

Foundry project for dark-perp's Ethereum settlement layer (§1, §3, §6). The
contracts hold the trust split that makes the protocol safe even if the sequencer
is compromised: **anchor + accountability here, custody in the vault, no operator
fund authority anywhere** (§0, §10, ADR-0010).

| Contract | Role | Arch ref |
|---|---|---|
| `DarkPerpSettlement` | anchors the state root via verified ZK proofs (SETTLED), liveness→close-only, sequencer bond + inclusion slashing | §2, §3, §6 |
| `CollateralVault` | holds ETH; releases only against a settled withdrawals root | §3, §6 |
| `IZkVerifier` / `MockZkVerifier` | proof verifier interface + test stand-in | §4 |
| `MerkleLib` | sorted-pair keccak membership (inclusion + withdrawals) | §2 |

## Cross-layer binding (locked by tests)

The contract hashing is byte-identical to the Rust producers, so one receipt /
one proof works on both sides:

- `publicCommitment` ↔ `crates/prover::PublicInputs::commitment`
- `receiptDigest` ↔ `perp-core::Receipt::signing_digest`
- a receipt **signed in Rust** (`crates/sequencer`, secp256k1) recovers on-chain
  via `ecrecover` — see `test/CrossLayer.t.sol`. Vectors come from
  `crates/prover/tests/vectors.rs` and `crates/sequencer/tests/fixture.rs`.

## Build & test

Foundry only (no Hardhat). `forge-std` is unavailable in the sandbox (repo-scoped
git proxy), so tests use the vendored `test/utils/MiniTest.sol` harness.

```bash
cd contracts
forge build
forge test
```

## Not production

`MockZkVerifier` is **not sound** — it is the testnet stand-in for the real
SP1/Risc0 Solidity verifier (see `../docs/PROVING.md`). Deploy a real verifier
before mainnet.
