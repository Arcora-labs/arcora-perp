# Threat model for SEC-022 … SEC-025 — canonical statement

**Purpose.** SEC-022, SEC-023, SEC-024 and SEC-025 each originally stated their own threat model, and three of them stated it wrongly — claiming "exploitable by whoever produces the witness" without checking who that is or what they already control. This document is the single canonical statement those specs reference. Correct the severities here; do not restate them per-spec.

## The parties

| Party | Runs where | What it holds |
|---|---|---|
| **User / API client** | anywhere | an API key; optionally a caller-signed secp256k1 key |
| **Gateway / sequencer** | Azure TDX CVM (attested) | the enclave seed, the **oracle publisher key**, the L1 sequencer key, the witness it seals |
| **Prover** | a separate box (GB10) | a **sealed** witness (AEAD) it cannot read or alter, and the SP1 proving key |
| **L1 contracts** | Base Sepolia | the verifying key, the vault, the settled root |

## What each party can actually do

**A user** can only reach the system through the `/v1` HTTP surface. Everything it does is mediated by the gateway.

**The prover cannot forge anything.** It receives a sealed witness — `SealedWitness` is AEAD-authenticated, so it cannot change `now_ms`, swap an `OracleTranscript`, reorder ops, or alter the state. It can only refuse to prove, or prove what it was given. **This is the key correction:** SEC-023 and SEC-024 originally claimed prover exploitability. They have none.

**The gateway is the trusted computing base, and it is trusted deliberately.** It holds the oracle publisher key (`gateway/main.rs:1164`), pins every `Market.oracle_pubkey` to that key's own address at boot (`:1508`), and re-signs live feed data after remapping `publish_time_ms` (`:3112-3127`). So against a compromised gateway the oracle signature constrains nothing — it can mint a signature over any price at any timestamp.

**This is not an oversight.** ZK-001 chose it explicitly (`specs/2026-07-21-zk001-signed-oracle-design.md:5`):

> Chosen trust model: **self-signing** (an operator-held publisher key) … removing operator trust from the price itself (e.g. Pyth/Wormhole attestations) is a larger, separate epic (Phase 2).

and left the seam for Phase 2 (`:15`): *"The `Market.oracle_pubkey` + `validate()` signature-check interface is kept stable so a different signature source can drop in later."* `docs/SECURITY.md:122` correspondingly claims only *sanity gates* — staleness, confidence, backup-deviation — and no publisher-independence property. The documentation never over-promised; the SEC-02x specs did.

## Consequence for each finding

| Finding | Original claim | Correct statement |
|---|---|---|
| **SEC-022** — fill-price band + closed-position debt | critical, protocol-soundness | **Unchanged: critical.** Exploitable by any user with two funded accounts, through the ordinary order API. No credential compromise, no operator involvement. This is the only one of the four a user can reach. |
| **SEC-023** — no clock in the proven transition | "critical, proof-soundness … exploitable by the sequencer/prover" | **Defence-in-depth under Phase 1.** The prover cannot alter `now_ms`; the gateway can, but a compromised gateway can forge the price outright, making the replay redundant. **It becomes load-bearing the moment a Phase-2 independent anchor lands** — at that point a signed price the operator cannot forge is still replayable without an anchored clock, which is exactly the "operator picks which real past price" attack. Ship it with, or before, any independent anchor. |
| **SEC-024** — `SeedInsurance` fabricates external collateral | "critical, proof-soundness" | **Defence-in-depth under Phase 1**, same reasoning. Still worth doing: it is cheap, and it removes the only *unbounded* external-value assertion in the circuit, which is a property worth having independent of who can currently reach it. |
| **SEC-025** — honest genesis + SEC-019 ABI | critical, deployment-blocking | **Unchanged.** Threat-model independent: the repo does not currently settle end-to-end, and genesis carries $20.04M of fabricated deposits that wedge batch one against a SEC-019 contract. |

## The Phase-1 guarantee, stated honestly

Under the current architecture the proof guarantees that **the state transition is internally consistent and follows the rules** — conservation, margin, matching, the deposit chain, the withdrawal tree. It does **not** guarantee the price was real, because the price is signed by the operator. Price integrity currently rests on the TDX attestation of the gateway, not on the proof.

Anything that claims otherwise — in a spec, in the docs, or to a user — is overstating it.

## What would change this

The Phase-2 epic ZK-001 deferred: pin `Market.oracle_pubkey` to a publisher the operator does not control, verified either in-circuit (Pyth/Wormhole guardian quorum — a 13-of-19 multi-ECDSA verification inside the zkVM) or through an adapter that re-signs into `oracle_digest` form (which re-introduces a trusted party, but a different and auditable one). Its real obstacles are the digest tuple no publisher signs natively, third-party cadence (Chainlink heartbeats run minutes-to-hours against a 10 s staleness budget), and the absence of any honest third-party analogue for `confidence` and `backup_twap`. Not scheduled.
