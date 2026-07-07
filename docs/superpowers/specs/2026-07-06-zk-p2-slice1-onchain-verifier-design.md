# ZK Verifier P2 — Slice 1: On-chain SP1 verifier adapter + runbook (Design)

**Date:** 2026-07-06
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2 (real proving + on-chain verifier). This spec is **Slice 1**
only — the on-chain half that is fully buildable and testable in a coding environment,
plus the host fix and the runbook for the infra steps that must run on an SP1-capable
machine. Later slices (the `prover`-crate real SP1 backend, gateway per-engine-batch
settlement, P3 attested prover) get their own specs.

---

## 1. Problem

P1 made the guest DERIVE the six-field commitment, but on-chain it is still checked by
`MockZkVerifier` (`proof == publicCommitment`, unsound). The mainnet gate is a REAL
verifier. SP1 (v6.0.0, already the pinned dep in `crates/sp1-guest`/`sp1-host`) proves the
guest and produces a Groth16 proof verifiable on-chain by Succinct's audited Solidity
verifier. But SP1's verifier interface does not match ours, and the pieces that produce a
real proof need a toolchain + a proving machine + a chain deploy — none of which exist in a
coding session.

## 2. Goal

Deliver the **buildable-and-tested-here** on-chain half: a small adapter contract that makes
SP1's revert-based verifier satisfy the existing `IZkVerifier` bool interface `settleBatch`
already calls, with full `forge` tests against a mock SP1 gateway. Plus the host harness fix
and a precise runbook so the infra steps (build the guest, generate a real proof, deploy,
redeploy the settlement) are ready to execute on an SP1-capable box. **No existing-contract
logic change; no Rust logic change except the host harness.**

## 3. SP1 v6 facts this design rests on (confirmed via SP1 docs, 2026-07-06)

- `ISP1Verifier.verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view` — it is **`view`, returns nothing, and REVERTS on an invalid proof** (it does not return a bool). Adapter must wrap it in try/catch.
- The **first 4 bytes of `proofBytes` select the verifier version** (`VERIFIER_HASH`). The **`SP1VerifierGateway`** routes a proof to the matching version, so the adapter targets the gateway (not a version-pinned verifier), staying valid across SP1 version bumps. Base Sepolia gateway address: look up in `github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments` at deploy time.
- The guest commits exactly the 32-byte keccak digest via `sp1_zkvm::io::commit_slice(&digest)`, so SP1's on-chain `publicValues` **is those 32 bytes** = our `publicCommitment`. The adapter passes `publicValues = abi.encodePacked(publicCommitment)`.
- The **program vkey** is `pk.verifying_key().bytes32()` from `client.setup(ELF)` (a `bytes32`), pinned as the adapter's immutable.
- SP1 v6 host idiom is **`include_elf!("perp-core-guest")`**, not a hardcoded `include_bytes!` path (SP1 targets `riscv32im-succinct-zkvm-elf`; the current host path `riscv64im-…` is wrong).
- `DarkPerpSettlement.verifier` is `immutable`, set in the constructor — swapping it is a **redeploy**, not a setter.

## 4. Design

### 4.1 `contracts/src/interfaces/ISP1Verifier.sol` (new)

The SP1 verifier interface, copied verbatim from `@sp1-contracts/ISP1Verifier.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISP1Verifier {
    /// Reverts if the proof is invalid; returns nothing on success.
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
```

### 4.2 `contracts/src/SP1ZkVerifier.sol` (new) — `is IZkVerifier`

Adapts SP1's revert-on-failure verifier to our bool `IZkVerifier`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "./interfaces/IZkVerifier.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// @title SP1ZkVerifier
/// @notice Real SP1 (Groth16) validity-proof verifier — the mainnet replacement for
/// MockZkVerifier. Adapts SP1's revert-based ISP1Verifier to DarkPerpSettlement's bool
/// IZkVerifier. The guest commits exactly the 32-byte publicCommitment via commit_slice,
/// so SP1's publicValues == abi.encodePacked(publicCommitment). `programVKey` pins THIS
/// guest program (vkey binding); a proof for any other program fails. Targets the
/// SP1VerifierGateway so it stays valid across SP1 verifier versions (proof's 4-byte
/// prefix selects the version).
contract SP1ZkVerifier is IZkVerifier {
    bytes32 public immutable programVKey;
    ISP1Verifier public immutable gateway;

    constructor(ISP1Verifier _gateway, bytes32 _programVKey) {
        gateway = _gateway;
        programVKey = _programVKey;
    }

    /// @inheritdoc IZkVerifier
    /// Returns true iff the SP1 gateway accepts `proof` for `publicCommitment` under the
    /// pinned program vkey. SP1's verifyProof reverts on failure, so we map revert -> false
    /// to satisfy the bool contract settleBatch expects.
    function verify(bytes32 publicCommitment, bytes calldata proof)
        external
        view
        returns (bool)
    {
        try gateway.verifyProof(programVKey, abi.encodePacked(publicCommitment), proof) {
            return true;
        } catch {
            return false;
        }
    }
}
```

Note: `IZkVerifier.verify` is `view` (see `contracts/src/interfaces/IZkVerifier.sol`), and
`settleBatch` calls it in a `view` context — the `try/catch` around a `view` external call is
valid. No change to `IZkVerifier` or `DarkPerpSettlement`.

### 4.3 `contracts/test/SP1ZkVerifier.t.sol` (new) + `MockSP1Verifier`

A `MockSP1Verifier is ISP1Verifier` test double that reverts unless `(programVKey,
publicValues, proofBytes)` equals a preset expected tuple. Tests (all runnable via
`forge test`, the tested de-risk of the on-chain half):

- `verify` returns **true** when the gateway accepts the exact `(vkey, abi.encodePacked(commitment), proof)` — asserts the adapter forwards `publicValues = abi.encodePacked(publicCommitment)` (the load-bearing encoding).
- `verify` returns **false** when the gateway reverts (a bad/foreign proof) — asserts revert→false, so `settleBatch` reverts `BadProof` (not a bubbled revert).
- `verify` returns **false** for a proof produced against a **different vkey** (wrong program) — asserts vkey binding.
- `programVKey`/`gateway` are immutable and set from the constructor.
- (Optional) an integration-style test wiring a `DarkPerpSettlement` with this verifier + the mock gateway, proving `settleBatch` accepts a good proof and reverts `BadProof` on a bad one — confirms the adapter satisfies the settlement's `verifier.verify(...)` call site unchanged.

### 4.4 Host harness fix — `crates/sp1-host/src/main.rs` (+ `crates/sp1-host/build.rs`)

Replace the stale `include_bytes!(concat!(... "riscv64im-succinct-zkvm-elf" ...))` with the
SP1 v6 idiom `const ELF: Elf = include_elf!("perp-core-guest");`, and add a `build.rs` that
uses `sp1-build` to compile the guest at host-build time (so `cargo run` auto-builds it).
The exact `sp1_build` call is confirmed against SP1 v6 docs at implementation (Context7);
if `sp1-build` integration is fiddly, the minimal fallback is the corrected `include_bytes!`
path `target/elf-compilation/riscv32im-succinct-zkvm-elf/release/perp-core-guest` (matching
the guest's actual `riscv32im` target). **Not testable in this environment (no toolchain) —
validated when the runbook's host step runs on an SP1 machine.** `sp1-host` stays excluded
from the workspace.

### 4.5 `docs/PROVING-RUNBOOK.md` (new)

The exact, ordered commands to execute on an SP1-capable box (with the privacy rule stated):

1. **Toolchain:** `curl -L https://sp1up.succinct.xyz | bash && sp1up` (installs `cargo prove`, the `riscv32im-succinct-zkvm-elf` target).
2. **Build the guest:** `cd crates/sp1-guest && cargo prove build` → the guest ELF.
3. **Equivalence gate (validates P1 for real):** `cd crates/sp1-host && cargo run --release` → asserts native `derive_roots(...).commitment` == the guest's committed value. This is the first time the P1 circuit executes in the zkVM.
4. **vkey + real proof:** a documented `sp1-sdk` snippet — `let pk = client.setup(ELF).await?; let vkey = pk.verifying_key().bytes32();` and `let proof = client.prove(&pk, stdin).groth16().await?;` → `proof.bytes()` (proofBytes) + `proof.public_values` (== the 32-byte commitment). **Privacy:** run on the self-hosted **attested** prover only — SP1's public Prover Network would see the plaintext witness (positions/fills); a public network gets `MeasurementMismatch` and cannot open a sealed witness (§10b). Groth16 needs Docker + significant RAM/GPU.
5. **Deploy:** look up the Base Sepolia `SP1VerifierGateway` in `succinctlabs/sp1-contracts/deployments`; deploy `SP1ZkVerifier(gateway, vkey)`.
6. **Redeploy settlement:** deploy `DarkPerpSettlement` with `verifier = SP1ZkVerifier` (verifier is immutable) + rewire the vault/genesis per the existing redeploy flow. MockZkVerifier is retired.
7. **End-to-end:** submit a real `settleBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, proof)` — the on-chain SP1 verifier now enforces the derived commitment.

The runbook also records: proving latency/resources set the settle cadence; a Groth16-capable **attested** VM is required (the current `DC2es_v6` CVM may be too small — an infra decision); and that gateway per-engine-batch settlement (so the published `withdrawalsRoot` matches the per-batch circuit derivation) is Slice 2, not done here.

## 5. Testing

- **`forge test`** on `contracts/test/SP1ZkVerifier.t.sol` — the four+ adapter tests above, all green. This is the merge gate for Slice 1 (the on-chain adapter logic is fully verified here against the mock gateway).
- `forge build` clean (new contracts compile; existing contracts unchanged).
- Host fix + runbook steps are **manual, on an SP1 machine** — documented, not CI-tested. The spec is explicit that these are unvalidated in this environment.

## 6. File map

**Create:**
- `contracts/src/interfaces/ISP1Verifier.sol` — SP1 interface.
- `contracts/src/SP1ZkVerifier.sol` — the `IZkVerifier` adapter.
- `contracts/test/SP1ZkVerifier.t.sol` — forge tests + `MockSP1Verifier`.
- `crates/sp1-host/build.rs` — sp1-build guest compile (or omitted if the fallback path is used).
- `docs/PROVING-RUNBOOK.md` — the infra runbook.

**Modify:**
- `crates/sp1-host/src/main.rs` — `include_elf!("perp-core-guest")` (host harness fix only).
- `crates/sp1-host/Cargo.toml` — add `sp1-build` build-dependency if `build.rs` is used.

**Untouched:** `contracts/src/interfaces/IZkVerifier.sol`, `contracts/src/DarkPerpSettlement.sol`, `contracts/src/CollateralVault.sol`, `contracts/src/mocks/MockZkVerifier.sol` (kept for tests/testnet), all of `crates/perp-core`/`prover`/`gateway`/`sp1-guest` logic.

## 7. Non-goals (Slice 1)

- No `prover`-crate real SP1 backend (Rust proving integration) — needs the toolchain to compile/test; a later slice.
- No gateway per-engine-batch settlement / cumulative→incremental publish / L1-vs-engine granularity reconciliation — Slice 2.
- No `CollateralVault` NatSpec change (still cumulative until Slice 2).
- No actual proof generation, deployment, or `MockZkVerifier` retirement — those are runbook steps executed on an SP1 machine, not in this session.
- No P3 attested-prover (real TDX/Nitro key-release) — separate.
- No change to the 6-field commitment, the guest, or `DarkPerpSettlement`/`IZkVerifier` logic.
