# Threat model

> **Audit status (internal adversarial review).** The Rust core had two
> review→fix passes (collateral conservation, margin/flip handling, self-trade,
> funding-sign, maker-drift manifest honesty, receipt-seq). The Solidity contracts
> had a security review that confirmed the vault `claim` CEI/anti-reentrancy, leaf
> collisions, Merkle-forgery resistance, `_leWord`, and access control are sound,
> and found three issues — all fixed with dedicated tests: **F2** (withdrawals/
> ordered roots not bound by the proof → fund theft), **F1** (forge-proof slashing
> escape via unconstrained batchId + raw Merkle leaf), **F3** (challenge griefing +
> signature malleability). The roots are now in the public commitment, inclusion
> answers use a domain-separated batch-bound leaf and must reference a batch
> settled before the challenge, and challenges require a refundable bond + a
> canonical-signature check. A fifth pass audited the redundancy/privacy crates
> (`committee`, `bridge`, `note-archive`): it confirmed the Shamir GF(256)
> reconstruction, distinct-signer quorum, and commitment-consistency trial
> decryption are sound, and fixed a conservation bug in `bridge::decompose` — a
> negative or `u32`-overflowing amount silently lost value instead of surfacing as
> remainder (a negative would even wrap the `as u32` cast). It also added a
> duplicate-member guard to `Committee::new` and documented two production-misuse
> footguns: the Shamir seed must be secret and fresh (seed + one share recovers the
> secret), and bridge buckets need independent per-bucket randomness.


Synthesizes the architecture's honest failure analysis (§0, §10, §10b, §11) into
one place: for each component that can be compromised, **what breaks** and **what
contains the damage**. The guiding principle (§0): three separate trust roots, so
no single failure is catastrophic.

## Trust roots

| Root | Secures | Does NOT secure |
|---|---|---|
| **TEE** (matcher + prover enclave) | order/position confidentiality, low-latency matching | liveness, fairness, recovery, fund validity |
| **Protocol** (order log + slashing + forced exit) | sequencing accountability, liveness, fair access | confidentiality, fund validity |
| **ZK** (validity proof on L1) | fund safety, valid state transitions | inclusion, ordering, censorship |

## Compromise → impact → containment

| If compromised | What breaks | What contains it |
|---|---|---|
| **TEE confidentiality** (side-channel, §10) | order/position privacy leaks; MM gets a latency edge | committee-of-enclaves t-of-n (§11, `committee`) — needs t-1 enclaves to leak; funds still safe (ZK) |
| **TEE integrity** (bad matching, preconf lies) | wrong fills, unreliable MATCHED preconfs, market-integrity abuse | quorum preconf (`committee`), Proof-v2 matching determinism (future); MATCHED is non-binding (§3) |
| **Sequencer liveness** (halts) | no new batches | anyone triggers close-only after the timeout; users force-exit against the last settled root (§6, `DarkPerpSettlement.triggerCloseOnly`) |
| **Sequencer censors an order** | a user's order is withheld | signed receipt + inclusion timeout → on-chain challenge → bond slashed, close-only (§2, `challengeInclusion`/`slashUnanswered`) |
| **Sequencer tries to steal funds** | — | it can't: the vault releases only against a SETTLED withdrawals root; the settlement contract holds no funds (§0, ADR-0010) |
| **Prover sees the witness** (bare prover farm, §10b) | positions/fills/margins leak to the prover | sealed witness opens only at the attested measurement, zeroized after the job (`prover::AttestedProver`); public proving networks can't open it |
| **Oracle manipulation** (§8) | bad liquidations / funding | transcript sanity gates (staleness, confidence, backup-deviation) re-proven in ZK; anomaly → close-only breaker (`oracle.rs`, `Market` bounds) |
| **Invalid state transition** (any of the above) | — | ZK validity proof: the L1 verifier rejects it, the root never advances (§3, `IZkVerifier`) |
| **User loses device** | — | seed → view-key → scan the encrypted note archive → recover notes/positions (§7, `note-archive`) |

## What an attacker can NEVER do (given the ZK root holds)

- **Steal funds from the vault.** Withdrawals require a Merkle proof against a
  withdrawals root published only by a *settled* batch; the settlement contract has
  no fund-movement authority. A broken sequencer can stall or censor, never steal.
- **Advance the state root without a valid proof.** `settleBatch` checks the proof
  against the public-input commitment binding `(prevRoot, manifestHash, newRoot)`.
- **Mint value.** Collateral conservation is an exact integer identity re-proven in
  ZK (Proof-v1): `Σ notes + Σ collateral + insurance + vault_pool == external_in −
  external_out`.

## Residual / honestly-acknowledged leakage

- **Market-level liquidation pressure is visible** (§9): per-position liquidations
  are private, but aggregate funding/OI/insurance movement is irreducibly
  observable. We prefer batching/aggregation over dummy-event padding.
- **Sub-unit bridge remainders leak** (§13): amounts below the smallest
  denomination can't be bucketed and are reported explicitly (`bridge`).
- **Confidentiality depends on hardware** until the committee/MPC hardening lands;
  a single compromised enclave (pre-committee) leaks confidentiality (but not
  funds).

## Production prerequisites (not yet real in this repo)

The stand-ins below must be replaced before mainnet; none affect the accounting or
the containment structure above:

- real SP1/Risc0 verifier (replaces `MockZkVerifier`) — see `PROVING.md`;
- real TDX/Nitro attestation (enclave measurement is currently a value);
- real enclave sealing / note encryption / committee DKG / bridge VRF seed.
