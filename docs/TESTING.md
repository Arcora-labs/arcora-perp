# Building & testing

The repo is a Cargo workspace (Rust core), a Foundry project (L1 contracts), and a
Vite app (frontend). Each layer is independently buildable; the cross-layer bond
between Rust and Solidity is enforced by shared test vectors.

## Rust workspace

```bash
cargo test            # all crates: 95 tests
cargo clippy --workspace --all-targets   # clean
# prove the settlement core compiles as a zkVM guest (no_std, no float/clock/IO):
cargo build -p perp-core --no-default-features
cargo build -p matcher --no-default-features
cargo build -p note-archive --no-default-features
cargo build -p bridge --no-default-features
```

Crate map:

| Crate | What | Tests |
|---|---|---|
| `perp-core` | deterministic state transition, risk, invariants | unit + `tests/lifecycle.rs` |
| `matcher` | price-time CLOB | unit |
| `sequencer` | receipts/manifests/finality/inclusion/maintenance | `tests/spine.rs`, `tests/fixture.rs` |
| `prover` | proving harness + §10b boundary | unit + `tests/vectors.rs` |
| `note-archive` | view-key recovery | unit |
| `committee` | Shamir t-of-n + quorum | unit |
| `bridge` | amount-bucket + mixing | unit |
| `e2e` | full-flow integration | `tests/full_flow.rs` |

## Contracts (Foundry)

`forge-std` is unavailable in the sandbox (the git proxy is repo-scoped), so the
suite uses the vendored `contracts/test/utils/MiniTest.sol` harness.

```bash
cd contracts
forge build
forge test            # 16 tests
```

## Frontend (Vite + React + TS)

```bash
cd frontend
pnpm install
pnpm dev              # http://localhost:5173
pnpm build            # strict tsc + production build
```

## Cross-layer vectors (the important part)

The Rust producers and Solidity consumers are pinned to the same bytes:

- `crates/prover/tests/vectors.rs` emits the receipt-signing digest and the proof
  public-input commitment; `contracts/test/CrossLayer.t.sol` asserts the contract
  recomputes the identical values.
- `crates/sequencer/tests/fixture.rs` emits a real secp256k1 receipt signature;
  `CrossLayer.t.sol::test_real_rust_receipt_passes_ecrecover` recovers it on-chain.

If either side changes its hashing or signing, one of these tests fails on both
sides — that is the guard that keeps the off-chain and on-chain layers in lockstep.

## What's modelled vs production

Documented stand-ins (clearly labelled in code, swap points specified):

- **Proving** — `CommitmentProver` / `MockZkVerifier` stand in for SP1/Risc0; see
  [`PROVING.md`](PROVING.md).
- **TEE attestation** — enclave keys/measurements are values; real TDX/Nitro
  attestation is production.
- **Sealing / note encryption / committee DKG / bridge mixing seed** — keystream /
  seed-derived stand-ins for real ECIES / enclave key-release / CSPRNG / VRF.

None of these stand-ins affect the accounting, the cross-layer binding, or the
protocol logic — they are the leaves the production deployment swaps.
