# ZK Verifier P2 — Slice 1: On-chain SP1 verifier adapter Implementation Plan


**Goal:** Add a `SP1ZkVerifier is IZkVerifier` adapter (with forge tests) that makes SP1's revert-based on-chain verifier satisfy the bool `IZkVerifier` interface `DarkPerpSettlement.settleBatch` already calls, plus the SP1 host harness fix and the infra runbook.

**Architecture:** A small Solidity adapter wraps `ISP1Verifier.verifyProof` (which reverts on an invalid proof) in `try/catch` → `bool`. The guest commits exactly the 32-byte publicCommitment via `commit_slice`, so SP1's `publicValues == abi.encodePacked(publicCommitment)`. The guest program vkey is pinned as an immutable (vkey binding); the adapter targets the SP1VerifierGateway (version-robust). Fully unit-tested here against a mock gateway; the host fix + runbook are written here and executed on an SP1-capable machine.

**Tech Stack:** Solidity 0.8.24 (Foundry; **no forge-std** — vendored `test/utils/MiniTest.sol`), SP1 v6.0.0 (`sp1-sdk`/`sp1-zkvm`/`sp1-build`), Rust (host harness).

**Spec:** `docs/superpowers/specs/2026-07-06-zk-p2-slice1-onchain-verifier-design.md`

## Global Constraints

- **SP1 interface (verbatim):** `ISP1Verifier.verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view` — it is `view`, returns NOTHING, and REVERTS on an invalid proof. The adapter maps revert→`false`.
- **Adapter contract:** `verify(bytes32 publicCommitment, bytes calldata proof) external view returns (bool)` = `try gateway.verifyProof(programVKey, abi.encodePacked(publicCommitment), proof) { return true; } catch { return false; }`. `bytes32 public immutable programVKey` (vkey binding), `ISP1Verifier public immutable gateway` (the SP1VerifierGateway).
- **publicValues == `abi.encodePacked(publicCommitment)`** — the guest commits the 32-byte digest via `commit_slice`, so SP1's public values are exactly those 32 bytes. Do NOT wrap/encode differently.
- **Foundry:** solc `0.8.24`, `pragma solidity ^0.8.24;`, SPDX `MIT`. NO `forge-std` — test bases extend `MiniTest` from `./utils/MiniTest.sol` (`assertTrue(bool,string)`, `assertFalse(bool,string)`, `assertEq(uint256|bytes32|address,...,string)`, `vm` cheatcodes). Mocks live in `contracts/src/mocks/`.
- **No logic change to existing contracts:** `IZkVerifier.sol`, `DarkPerpSettlement.sol`, `CollateralVault.sol`, `MockZkVerifier.sol` are untouched. `MockZkVerifier` is KEPT (testnet/tests).
- **Host:** SP1 v6 idiom `include_elf!("perp-core-guest")` (SP1 targets `riscv32im-succinct-zkvm-elf`; the current `riscv64im-…` `include_bytes!` path is the bug). `sp1-host` stays excluded from the workspace.
- **Not testable in this environment (SP1 toolchain absent):** the host fix (Task 2) and the runbook (Task 3) — written here, validated when run on an SP1 machine. The Solidity adapter (Task 1) IS fully testable here via `forge test`.

## File Structure

- `contracts/src/interfaces/ISP1Verifier.sol` **(new)** — the SP1 verifier interface (`verifyProof`, view, reverts).
- `contracts/src/SP1ZkVerifier.sol` **(new)** — the `IZkVerifier` adapter (immutable vkey + gateway; try/catch → bool).
- `contracts/src/mocks/MockSP1Verifier.sol` **(new)** — test double: `verifyProof` reverts unless `(vkey, publicValues, proof)` match a configured expected tuple.
- `contracts/test/SP1ZkVerifier.t.sol` **(new)** — forge tests (MiniTest).
- `crates/sp1-host/src/main.rs` **(modify)** — `include_elf!` host fix.
- `crates/sp1-host/build.rs` **(new)** — sp1-build guest compile.
- `crates/sp1-host/Cargo.toml` **(modify)** — `sp1-build` build-dependency.
- `docs/PROVING-RUNBOOK.md` **(new)** — the infra runbook.

---

### Task 1: SP1ZkVerifier adapter + interface + mock + forge tests

**Files:**
- Create: `contracts/src/interfaces/ISP1Verifier.sol`
- Create: `contracts/src/mocks/MockSP1Verifier.sol`
- Create: `contracts/src/SP1ZkVerifier.sol`
- Create: `contracts/test/SP1ZkVerifier.t.sol`

**Interfaces:**
- Consumes: `contracts/src/interfaces/IZkVerifier.sol` — `interface IZkVerifier { function verify(bytes32 publicCommitment, bytes calldata proof) external view returns (bool ok); }` (unchanged).
- Produces: `SP1ZkVerifier(ISP1Verifier _gateway, bytes32 _programVKey)` with `verify(bytes32,bytes) external view returns (bool)`, `bytes32 public immutable programVKey`, `ISP1Verifier public immutable gateway`.

- [ ] **Step 1: Create the SP1 interface** `contracts/src/interfaces/ISP1Verifier.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISP1Verifier — Succinct SP1 on-chain verifier interface (copied from
/// @sp1-contracts/ISP1Verifier.sol). `verifyProof` is `view`, returns nothing, and
/// REVERTS if the proof is invalid. The first 4 bytes of `proofBytes` select the
/// verifier version (VERIFIER_HASH), which the SP1VerifierGateway routes on.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
```

- [ ] **Step 2: Create the mock gateway** `contracts/src/mocks/MockSP1Verifier.sol` (test-only double mirroring SP1's revert-on-invalid semantics):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1Verifier} from "../interfaces/ISP1Verifier.sol";

/// @title MockSP1Verifier
/// @notice Test/dev double for the SP1VerifierGateway. `verifyProof` reverts unless
/// `(programVKey, publicValues, proofBytes)` equal the configured expected tuple —
/// mirroring SP1's revert-on-invalid-proof behavior. NOT sound; test-only.
contract MockSP1Verifier is ISP1Verifier {
    bytes32 public expectedVKey;
    bytes public expectedPublicValues;
    bytes public expectedProof;

    error MockProofRejected();

    function setExpected(bytes32 vkey, bytes calldata publicValues, bytes calldata proof) external {
        expectedVKey = vkey;
        expectedPublicValues = publicValues;
        expectedProof = proof;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes)
        external
        view
    {
        if (
            programVKey != expectedVKey
                || keccak256(publicValues) != keccak256(expectedPublicValues)
                || keccak256(proofBytes) != keccak256(expectedProof)
        ) {
            revert MockProofRejected();
        }
    }
}
```

- [ ] **Step 3: Write the failing tests** `contracts/test/SP1ZkVerifier.t.sol` (references `SP1ZkVerifier`, which does not exist yet → compile failure = RED):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {MockSP1Verifier} from "../src/mocks/MockSP1Verifier.sol";

contract SP1ZkVerifierTest is MiniTest {
    MockSP1Verifier internal gateway;
    SP1ZkVerifier internal adapter;

    bytes32 internal constant VKEY = bytes32(uint256(0xA11CE));
    bytes32 internal constant COMMIT = bytes32(uint256(0xC0117));
    bytes internal PROOF = hex"11223344deadbeef"; // 4-byte version prefix + body (opaque here)

    function setUp() public {
        gateway = new MockSP1Verifier();
        adapter = new SP1ZkVerifier(ISP1Verifier(address(gateway)), VKEY);
    }

    /// A proof the gateway accepts (exact vkey + abi.encodePacked(commitment) + proof) → true.
    function test_verify_true_on_matching_proof() public {
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertTrue(adapter.verify(COMMIT, PROOF), "matching proof must verify");
    }

    /// Gateway reverts on a different proof → adapter maps revert to false (NOT a bubbled revert).
    function test_verify_false_on_bad_proof() public {
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertFalse(adapter.verify(COMMIT, hex"11223344ffff"), "bad proof must be false");
    }

    /// Proves publicValues == abi.encodePacked(publicCommitment): a different commitment
    /// changes the publicValues the adapter forwards → gateway rejects → false.
    function test_verify_false_on_wrong_commitment() public {
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertFalse(adapter.verify(bytes32(uint256(0xBEEF)), PROOF), "wrong commitment must be false");
    }

    /// vkey binding: an adapter pinned to a different vkey than the gateway expects → false.
    function test_verify_false_on_wrong_vkey() public {
        SP1ZkVerifier wrong = new SP1ZkVerifier(ISP1Verifier(address(gateway)), bytes32(uint256(0xB0B)));
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertFalse(wrong.verify(COMMIT, PROOF), "wrong vkey must be false");
    }

    /// Immutables are pinned from the constructor.
    function test_immutables_pinned() public view {
        assertEq(adapter.programVKey(), VKEY, "vkey pinned");
        assertEq(address(adapter.gateway()), address(gateway), "gateway pinned");
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run (from `contracts/`): `forge test --match-contract SP1ZkVerifierTest`
Expected: FAIL — `SP1ZkVerifier` source not found (compile error).

- [ ] **Step 5: Implement the adapter** `contracts/src/SP1ZkVerifier.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "./interfaces/IZkVerifier.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// @title SP1ZkVerifier
/// @notice Real SP1 (Groth16) validity-proof verifier — the mainnet replacement for
/// MockZkVerifier. Adapts SP1's revert-based `ISP1Verifier` to DarkPerpSettlement's bool
/// `IZkVerifier`. The guest commits exactly the 32-byte publicCommitment via
/// `commit_slice`, so SP1's `publicValues == abi.encodePacked(publicCommitment)`.
/// `programVKey` pins THIS guest program (vkey binding) — a proof for any other program
/// fails. Targets the SP1VerifierGateway so it stays valid across SP1 verifier versions
/// (the proof's 4-byte prefix selects the version). `DarkPerpSettlement.verifier` is
/// immutable, so swapping MockZkVerifier for this is a redeploy.
contract SP1ZkVerifier is IZkVerifier {
    bytes32 public immutable programVKey;
    ISP1Verifier public immutable gateway;

    constructor(ISP1Verifier _gateway, bytes32 _programVKey) {
        gateway = _gateway;
        programVKey = _programVKey;
    }

    /// @inheritdoc IZkVerifier
    /// @dev SP1's `verifyProof` reverts on an invalid proof; map revert → false to satisfy
    /// the bool contract `settleBatch` expects (it reverts `BadProof` when this returns false).
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

- [ ] **Step 6: Run to verify it passes**

Run (from `contracts/`): `forge test --match-contract SP1ZkVerifierTest -vv`
Expected: PASS — all 5 tests green.

- [ ] **Step 7: Confirm the whole contracts suite still builds/passes** (no collateral breakage)

Run (from `contracts/`): `forge build && forge test`
Expected: builds clean; existing suites unaffected (new files only; no existing contract changed).

- [ ] **Step 8: Commit**

```bash
git add contracts/src/interfaces/ISP1Verifier.sol contracts/src/mocks/MockSP1Verifier.sol contracts/src/SP1ZkVerifier.sol contracts/test/SP1ZkVerifier.t.sol
git commit -m "feat(contracts): SP1ZkVerifier adapter — SP1 verifyProof -> IZkVerifier bool + vkey binding"
```

---

### Task 2: SP1 host harness fix (`include_elf`)

**Files:**
- Modify: `crates/sp1-host/src/main.rs` (the `ELF` constant + import)
- Create: `crates/sp1-host/build.rs`
- Modify: `crates/sp1-host/Cargo.toml` (add `sp1-build` build-dependency)

**Interfaces:** none consumed by later tasks. This fixes the host so `cargo run` finds the guest ELF under SP1 v6.

**NOTE — not buildable/testable in this environment** (SP1 toolchain absent; `sp1-host` is excluded from the workspace and depends on `sp1-sdk`). Write the correct code; it is validated by Task 3's runbook step on an SP1 machine. Do NOT attempt `cargo build`/`cargo run` here.

- [ ] **Step 1: Switch the ELF constant to `include_elf!`** in `crates/sp1-host/src/main.rs`. Replace the stale hardcoded path:

```rust
// BEFORE (stale — SP1 targets riscv32im, not riscv64im; version-fragile path):
// const ELF: &[u8] = include_bytes!(concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/../sp1-guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/perp-core-guest"
// ));

// AFTER (SP1 v6 idiom — resolves the ELF that build.rs compiled, version-robust):
use sp1_sdk::{include_elf, Elf};
const ELF: Elf = include_elf!("perp-core-guest");
```

Adjust the existing `use sp1_sdk::{...}` line to include `include_elf` and `Elf` (keep the other imports the file already uses: `ProverClient`, `SP1Stdin`, etc.). Everything else in `main` (feeding the witness into `SP1Stdin`, executing, comparing to `native_commit`) is unchanged.

- [ ] **Step 2: Add the build script** `crates/sp1-host/build.rs` that compiles the guest at host-build time so `include_elf!("perp-core-guest")` resolves:

```rust
//! Compiles the SP1 guest (`crates/sp1-guest`, package `perp-core-guest`) so the host's
//! `include_elf!("perp-core-guest")` can embed it. Requires the SP1 toolchain (`cargo prove`).
fn main() {
    sp1_build::build_program("../sp1-guest");
}
```

Confirm the exact `sp1-build` v6 API against the current SP1 docs at implementation (Context7: SP1 `sp1-build` `build_program` / `build_program_with_args`); if it differs, use the documented v6 form. **Fallback** if `sp1-build` integration is problematic: skip `build.rs`, keep `include_bytes!` but correct the path to the real `riscv32im` target: `"/../sp1-guest/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/perp-core-guest"` — and document in Task 3 that the guest must be `cargo prove build`-ed before running the host.

- [ ] **Step 3: Add the build-dependency** to `crates/sp1-host/Cargo.toml`:

```toml
[build-dependencies]
sp1-build = "6.0.0"
```

(Pin the same major as `sp1-sdk = "6.0.0"` already in the file.)

- [ ] **Step 4: Static self-check (no build here)**

Run: `git diff --stat crates/sp1-host` — confirm only `main.rs`, `build.rs`, `Cargo.toml` changed, and that `main.rs`'s witness/equivalence logic (the `(DefaultState, Vec<BatchOp>, BatchManifest)` witness + `derive_roots` native reference + `assert_eq!(native_commit, zk_commit, ...)`) is otherwise intact. The real build/run is the runbook's host step (Task 3).

- [ ] **Step 5: Commit**

```bash
git add crates/sp1-host/src/main.rs crates/sp1-host/build.rs crates/sp1-host/Cargo.toml
git commit -m "fix(sp1-host): include_elf!(perp-core-guest) + sp1-build build.rs (was stale riscv64im path)"
```

---

### Task 3: `docs/PROVING-RUNBOOK.md`

**Files:**
- Create: `docs/PROVING-RUNBOOK.md`

**Interfaces:** none. Operator documentation for the infra steps that run on an SP1-capable machine.

- [ ] **Step 1: Write the runbook** `docs/PROVING-RUNBOOK.md` with the exact, ordered steps (the content below is the deliverable — write it as-is, adjusting only if a referenced path/name is wrong):

````markdown
# Proving Runbook — real SP1 verification (P2 Slice 1)

Run these on an **SP1-capable machine** (Linux, Docker for Groth16, ample RAM/GPU).
The coding repo ships only the on-chain adapter + host fix; proof generation and
deployment happen here.

## 0. Privacy rule (read first)
The batch witness contains plaintext positions/fills. **Do NOT use Succinct's public
Prover Network** for real batches — it would see the witness. Proving must run on the
**self-hosted, attested prover** (§10b): a public network gets `MeasurementMismatch`
and cannot open a sealed witness. A Groth16-capable **attested** VM is required (the
current `DC2es_v6` CVM may be too small — size up as an infra decision).

## 1. Install the SP1 toolchain
```bash
curl -L https://sp1up.succinct.xyz | bash
sp1up          # installs `cargo prove` + the riscv32im-succinct-zkvm-elf target
cargo prove --version
```

## 2. Build the guest
```bash
cd crates/sp1-guest && cargo prove build
```
Produces the `perp-core-guest` ELF.

## 3. Equivalence gate (validates P1 in the real zkVM)
```bash
cd crates/sp1-host && cargo run --release
```
Asserts `native derive_roots(...).commitment == the guest's committed value`. This is
the first execution of the P1 circuit in the SP1 zkVM. Must print the equality/success
before proceeding. (If the ELF isn't found, see Task 2's fallback path note.)

## 4. Get the vkey + a real Groth16 proof
In an `sp1-sdk` script (or extend `sp1-host` with a `--prove` mode on your machine):
```rust
use sp1_sdk::{include_elf, Elf, HashableKey, ProverClient, SP1Stdin};
const ELF: Elf = include_elf!("perp-core-guest");

let client = ProverClient::from_env().await;      // MUST resolve to the local/attested prover, NOT the network
let pk = client.setup(ELF).await.unwrap();
let vkey: String = pk.verifying_key().bytes32();  // <-- the bytes32 for the SP1ZkVerifier constructor
let mut stdin = SP1Stdin::new();
stdin.write_vec(witness_bytes);                    // postcard (DefaultState, Vec<BatchOp>, BatchManifest)
let proof = client.prove(&pk, stdin).groth16().await.unwrap();
let proof_bytes = proof.bytes();                   // <-- settleBatch `proof` arg
let public_values = proof.public_values.as_slice();// == the 32-byte publicCommitment
```
Record `vkey` (bytes32) and `proof_bytes`.

## 5. Deploy the on-chain verifier
- Find the Base Sepolia **SP1VerifierGateway** address in
  `github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments`.
- Deploy `SP1ZkVerifier(gateway, vkey)` (from this repo's `contracts/src/SP1ZkVerifier.sol`).

## 6. Redeploy the settlement pointing at it
`DarkPerpSettlement.verifier` is immutable, so swapping MockZkVerifier is a redeploy:
```
new DarkPerpSettlement(sequencer, enclaveSigner, SP1ZkVerifier_addr, genesisRoot,
                       livenessTimeoutBlocks, challengeWindowBlocks, challengeBond)
```
Then rewire the CollateralVault + repost the sequencer bond per the existing redeploy
flow. MockZkVerifier is retired for this deployment.

## 7. End-to-end
Submit a real settlement:
```
settleBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, proof_bytes)
```
`publicCommitment = publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot,
withdrawalsRoot, rejectedRoot)` must equal the 32-byte `public_values` from step 4, and
the SP1 gateway must accept `proof_bytes` under the pinned `vkey`. On success the derived
commitment is now enforced on-chain by real ZK.

## Notes / gotchas
- Proving latency + resources set the L1 settle cadence.
- **Slice 2 (not done):** the gateway still publishes the CUMULATIVE `withdrawalsRoot`
  over `pending_withdrawals` and aggregates multiple engine batches per L1 settle, while
  the circuit derives a PER-ENGINE-BATCH incremental root. For the on-chain
  `withdrawalsRoot` to match the proof, the gateway must switch to per-engine-batch
  settlement (Slice 2) — until then, a real proof only matches if you settle one engine
  batch at a time with its own incremental root.
````

- [ ] **Step 2: Sanity-check the doc** — confirm the referenced names match the repo: the guest package is `perp-core-guest` (`crates/sp1-guest/Cargo.toml`), `SP1ZkVerifier` constructor is `(ISP1Verifier gateway, bytes32 programVKey)` (Task 1), the `settleBatch` signature is `(bytes32 prevRoot, bytes32 manifestHash, bytes32 newRoot, bytes32 orderedRoot, bytes32 withdrawalsRoot, bytes32 rejectedRoot, bytes proof)` (`DarkPerpSettlement.sol`). Fix any drift.

- [ ] **Step 3: Commit**

```bash
git add docs/PROVING-RUNBOOK.md
git commit -m "docs(zk-p2): PROVING-RUNBOOK — toolchain, equivalence gate, proof, deploy, redeploy"
```

---

## Final verification (after all tasks)

- [ ] `cd contracts && forge test --match-contract SP1ZkVerifierTest -vv` — 5 adapter tests green.
- [ ] `cd contracts && forge build && forge test` — whole contracts suite green (nothing else touched).
- [ ] `git diff --stat main..HEAD` — only the 8 files in the File Structure changed; no existing-contract/`perp-core`/`prover`/`gateway`/`sp1-guest` logic touched.
- [ ] Host (Task 2) + runbook (Task 3) are documented-for-SP1-machine, NOT built here — confirm the plan/spec say so and no CI step tries to build `sp1-host`.
```
