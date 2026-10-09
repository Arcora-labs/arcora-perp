> PR #30 now also contains a clock-bound integration candidate under
> `contracts/src/ClockBoundVerifier.sol`. This original experimental contract
> remains isolated and is not used by that candidate. See
> [integration scope and release blockers](../../../docs/audits/2026-10-09-clock-integration.md).

# Batch clock anchoring: isolated prototype

**Status: experimental, not wired into production settlement or the SP1 guest.**
No deployment script imports this contract. It handles no collateral and does
not verify a proof. Passing these tests does not close the oracle freshness gap.

The prototype registers an immutable batch context against settlement-chain
block time *before* expensive proving. It records the original min/max operation
times, a manifest hash, batch ID, previous root, chain and contract domain.
Exact retries retain the original receipt. Modified registrations, timestamps
outside the configured clock skew, and overlong windows are rejected. Reading
an already registered receipt does not expire it merely because proving took
longer. The test configuration (10-second window, 2-second skew) is illustrative,
not an approved production policy.

## Required before production integration

1. Have the guest derive min/max from every original price-bearing operation and
   validate all oracle freshness checks at those original times. Bind this exact
   anchor receipt into versioned public inputs; do not trust caller-supplied bounds.
2. Have settlement enforce current batch/root continuity, anchor consumption,
   monotonicity, and a safe rule for retries after rollback. This isolated registry
   deliberately does not know the canonical settlement state.
3. Specify recovery for finalized/reorganized anchors, bounded windows during
   downtime, empty/price-free batches, forced exits and proof queue backlogs.
4. Pin the clock source. On Base, `block.timestamp` is Base L2 block time, not a
   direct Ethereum L1-origin timestamp. L1-origin selection and finality policy
   must be reviewed rather than mislabeled as already solved.
5. Produce Rust/Solidity encoding vectors, real SP1 proofs, verifier-key binding
   and reviewed migration/deployment evidence. No existing public-input format
   or live contract is modified by this prototype.

Run: `forge test --root contracts/experimental/batch-clock -vv`.
Reference: Solidity 0.8.24 documentation, Units and Globally Available Variables
(`block.timestamp` is seconds; the protocol operation clocks are milliseconds).


## Encoding regression

`test_fixed_encoding_vector_matches_rust` and
`crates/perp-core/tests/clock_anchor_vectors.rs` check the same fixed ABI/Keccak
vector. The Rust fixture uses standard 32-byte ABI big-endian numeric words and
left-padded addresses, not the protocol's legacy little-endian word helpers.
This test does not integrate the anchor with the SP1 guest or public inputs.
