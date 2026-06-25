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
> answers use a domain-separated batch-bound leaf, and challenges require a
> refundable bond + a canonical-signature check. (F1 also added a "batch must
> predate the challenge" rule, later **superseded by P2** below.) A fifth pass audited the redundancy/privacy crates
> (`committee`, `bridge`, `note-archive`): it confirmed the Shamir GF(256)
> reconstruction, distinct-signer quorum, and commitment-consistency trial
> decryption are sound, and fixed a conservation bug in `bridge::decompose` — a
> negative or `u32`-overflowing amount silently lost value instead of surfacing as
> remainder (a negative would even wrap the `as u32` cast). It also added a
> duplicate-member guard to `Committee::new` and documented two production-misuse
> footguns: the Shamir seed must be secret and fresh (seed + one share recovers the
> secret), and bridge buckets need independent per-bucket randomness. A sixth pass
> audited the matcher CLOB hot path (`book.rs`): it confirmed the FOK pre-check,
> self-trade prevention, and time-in-force handling keep the full-fill invariant
> (`crossable_liquidity` and the match loop both exclude self-orders), and pinned
> the deliberate post-only-vs-own-order semantics (reject as maker-or-nothing
> rather than silently STP-cancelling the owner's existing maker) with a test. A
> seventh pass audited the prover boundary (`prover`): it confirmed the public-input
> commitment binds all five roots and the measurement-gated witness open/zeroize,
> and fixed a **two-time-pad** in the sealing stand-in — the keystream was derived
> from the (constant) prover measurement alone, so every batch's witness reused one
> pad and XOR-ing two sealed witnesses leaked the XOR of two private ledgers. Sealing
> now binds a per-seal nonce (the batch public commitment); regression test added.
> An eighth pass (second Solidity) re-audited the inclusion-challenge game and found
> **P2**, a serious griefing bug introduced by F1's own fix: requiring the answering
> batch to be *settled before the challenge opened* is incompatible with async
> settlement (ACCEPTED→SETTLED spans blocks, and resting orders settle in a later
> batch than their receipt's). Anyone holding a fresh enclave-signed receipt could
> challenge before the order settled; the only valid inclusion proof would then be
> in a batch settled *after* the challenge, which the rule rejected — so the honest
> sequencer was un-answerably slashed (bond refunded to the griefer, making it free).
> Fix: `answerChallenge` now accepts any **genuinely settled** batch (before the
> deadline). Forgery stays impossible via the batch-bound `inclusionLeaf`, and a
> never-settled order can't be proven and is independently caught by the liveness
> timeout. Two tests pin it: late-but-genuine inclusion answers; a settled batch
> lacking the order still reverts `NotIncluded`.


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
