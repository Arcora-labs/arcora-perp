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
> A ninth pass (second sequencer) found **P3**: `accept_order` issues an ACCEPTED
> receipt (and an inclusion record) unconditionally, but an order later rejected for
> cause at seal (insufficient margin, post-only-would-take, FOK-unfillable, all
> fills failed) lands in `manifest.rejected`, never in `ordered`, so its record's
> `seen_in_batch` stayed `None` forever — `inclusion_violations` then mistook a
> justified rejection for censorship and would trigger a wrongful slash. Fix:
> `seal_batch` now clears the still-unseen inclusion record of any order it commits
> to `manifest.rejected` (a drifted resting maker already `seen` in an earlier batch
> is left intact). Regression test added.
> An eleventh pass audited the oracle sanity gates (`oracle.rs`, the §8 manipulation
> defense that runs inside the zkVM guest) and found **P4**: the confidence and
> backup-deviation checks multiplied attacker-influenced values (`price`,
> `confidence`) with raw `i128` `*`. An extreme price overflows — wrapping in release
> (so a manipulated price could slip past the gate) and panicking in the guest (an
> unprovable batch). Fixed to `checked_mul` with overflow treated as out-of-bounds
> (reject), matching the "never wrap" rule the rest of the risk math already follows;
> regression test feeds `i128::MAX` and asserts clean rejection in debug and release.
> A twelfth pass audited the note commitment tree (`merkle.rs`) and found **P5**: a
> classic RFC-6962 second-preimage gap — leaves were placed at level 0 *raw*, so
> `MerkleTree::verify` accepted an inner node value (hashed under `MerkleNode`) as a
> leaf and reconstructed the root, a proof-forgery primitive. Not yet reachable for
> theft (spending uses the note-domain commitment map, and `verify` had no consumer),
> but it is exactly the membership check the Proof-v1 circuit will rely on. Fixed by
> hashing every level-0 entry under a new `Domain::MerkleLeaf` tag (appended last so
> all existing committed hashes are unchanged), so an inner node can never be a leaf.
> The cross-layer vectors use synthetic roots and no test pins an absolute root, so
> the blast radius was contained; regression test offers a real inner node as a leaf
> and asserts rejection.
> A continuation pass swept every crate again and fixed nine more issues, each
> failing-test-first (full detail in `HARDENING.md`). Settlement-spine correctness:
> `sequencer::mark_settled(N)` pruned the rollback snapshots for batch N *and every
> earlier batch* (hardening them) but advanced finality for only N, so finalizing a
> height directly left earlier batches "hard yet MATCHED" — un-withdrawable forever
> (§3); now every pending batch ≤ N settles (200-seed fuzzer added). The matcher
> enforced order expiry only at submit, so a good-till-time *resting maker* could
> still trade past its expiry and, unreaped, anchor the funding mark (§1/§8); both
> the match loop and the FOK pre-check now exclude expired makers and
> `reap_expired` clears them before the mark is read (300-seed fuzzer added). The
> live oracle adapter read an empty bid/ask string as a literal 0, so a one-sided
> book outage produced a giant spurious spread that the §8 gate rejected — a healthy
> `last` would stall; a digit-less string is now absent, falling back to `last`.
> **Domain-hygiene sweep:** the one-domain-one-purpose rule had three more
> cross-purpose reuses — the §7 wallet KDF (owner/view/**spend**) hashed under
> `StateRoot`, the bridge mix commitment under `NoteCommitment` (collidable with a
> spendable note commitment), and the committee Shamir coefficients under
> `Nullifier` — each given a dedicated tag (`KeyDerivation`/`BridgeCommitment`/
> `ShamirShare`, plus `WitnessCommitment` for the prover stand-in); the
> pairwise-distinct test now spans 16 tags. The only multi-use tag left is
> `StateRoot` for the cross-layer public commitment, which is deliberate (the
> Solidity verifier and sp1 guest recompute it byte-for-byte — locked by the KAT).


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
- **Insurance fund is a one-way penalty sink** (Phase 0): liquidation penalties flow
  *into* it, but it is not yet drawn on to socialize bad debt. A gap-down past the
  maintenance buffer parks the shortfall as negative collateral, absorbed by the
  vault clearing pool — so conservation and vault solvency hold (a 10th review pass
  verified and pinned this with `bad_debt_liquidation_conserves_and_cannot_be_escaped`),
  but a production system needs the insurance back-stop + auto-deleverage cascade.

## Known design limitations (flagged for input, not yet fixed)

- **On-chain inclusion challenge has no rejection-proof path (P3b).** P3 fixed the
  *off-chain* monitor so a justly-rejected order is not self-reported as censorship.
  The *on-chain* `challengeInclusion` is the mirror image and still open: a user
  holding an enclave-signed receipt for an order that was legitimately rejected
  (insufficient margin, post-only-would-take, FOK-unfillable) can open a challenge,
  and the sequencer cannot answer because the order is in `manifest.rejected`, not
  the on-chain `orderedRoot` — so an honest sequencer is slashable. Two candidate
  fixes, both touching the cross-layer trust anchor (hence deferred for design
  input rather than changed unilaterally):
  1. **Commit a `rejectedRoot`** alongside `orderedRoot` (the same pattern as the F2
     fix that added `orderedRoot`/`withdrawalsRoot`), and add an
     `answerByRejection(orderHash, batchId, proof)` path. Proving rejection
     membership in a settled batch demonstrates the order was handled. Cost: a
     6th field in `publicCommitment` / `PublicInputs`, re-locked byte-exact vectors.
  2. **Tier receipts**: make the on-chain-challengeable commitment cover only orders
     the enclave commits to *ordering*, with `accept_order`'s instant ACK as a
     distinct non-slashable acknowledgement. Cost: refines the §2 receipt semantics.
- **Vault `withdrawalsRoot` must be cumulative (P6) — NOW WIRED.** `CollateralVault.publishWithdrawals`
  *overwrites* the root each settled batch, so the published root must be the
  cumulative set of all authorized-but-unclaimed withdrawals — not just the new ones
  — or a user who hasn't yet `claim`ed an older withdrawal is stranded when the next
  batch publishes. The mechanism is sound (claims are gated on the proven root, never
  the operator; double-claim is blocked by `claimed[leaf]`), and the cumulative
  invariant is a *prover obligation* not enforceable on-chain. **As of 2026-06-28 this
  is implemented** in the gateway bridge (`crates/gateway/src/withdrawals.rs` +
  `main.rs`): each settle it reads `vault.claimed(leaf)` for every pending withdrawal,
  drops the claimed ones, and rebuilds the root over **every still-unclaimed leaf**,
  honoring the invariant (the real ZK prover must reproduce exactly this transition).
  The full deposit → withdraw → cumulative-root → `vault.claim` (USDC) flow is verified
  live on Base Sepolia. An on-chain alternative (accept claims against any historical
  root via a stored accumulator) would remove the prover obligation at the cost of
  vault state; not needed while the bridge maintains the cumulative set.
  - **Leaf format must match exactly — DONE.** `claim` derives the leaf as
    `keccak256(abi.encodePacked(to, amount, nonce))` (address‖uint256‖uint256, all
    fixed-width so `encodePacked` is unambiguous). The off-chain withdrawals tree
    builds leaves byte-for-byte identically (`withdrawals::withdrawal_leaf` — 20-byte
    address ‖ 32-byte BE amount ‖ 32-byte BE nonce, *unprefixed* keccak, sorted-pair
    nodes matching `MerkleLib`), **byte-locked to Solidity by `cast`-derived test
    vectors** in `crates/gateway/src/withdrawals.rs`. (The withdrawals leaf is *not*
    `MerkleLeaf`-domain tagged: second-preimage safety here comes from hashing the
    claimed fields, the same way `inclusionLeaf` does — so the off-chain side likewise
    does NOT domain-tag it.)

## Production prerequisites (not yet real in this repo)

The stand-ins below must be replaced before mainnet; none affect the accounting or
the containment structure above:

- real SP1/Risc0 verifier (replaces `MockZkVerifier`) — see `PROVING.md`;
- real TDX/Nitro attestation (enclave measurement is currently a value);
- real enclave sealing / note encryption / committee DKG / bridge VRF seed;
- **spend-key ↔ owner binding — DONE (audit DP-003).** `consume_note` now rejects a
  spend unless `owner_from_spend_key(spend_key) == note.owner`, and `Wallet::from_seed`
  derives `owner = H(spend_key)`, so a note can be consumed only by presenting its
  owner's spend key — the authorization no longer rests on the enclave.

## Post-audit remediation residuals (2026-07)

All 13 Codex audit findings (DP-001..013) plus two adversarial-review rounds and a
workflow code review are fixed on `feat/real-tee`. The DP-004 off-chain answering
half is now also wired (the gateway publishes real ordered/rejected roots per settle
and a background loop watches `InclusionChallenged` and calls
`answerChallenge`/`answerByRejection` with a Merkle proof), so the wrongful-slash
vector is closed end to end. One perf item is intentionally deferred:

- **`state_root` cost grows with history (perf).** Binding the nullifier-set contents and
  the unspent-note set (audit DP-002) makes `state_root()` re-hash the whole append-only
  nullifier set and the full note set on every call — O(N) in chain history, twice per
  batch. Correct and fine at Phase-0 volumes, but settlement latency climbs unbounded as
  the chain ages. The fix is an incrementally-maintained set digest, but it MUST stay
  collision-resistant AND order-independent (a state's root must depend on the *set*, not
  insertion order). A naive commutative accumulator (XOR/sum of per-element hashes) is O(1)
  but reintroduces a collision weakness — undoing DP-002 — so it is NOT acceptable. The
  correct options are a sparse Merkle nullifier accumulator (O(log N) insert, O(1) root, and
  the "non-membership proof" the nullifier module already anticipates) or a proven
  incremental multiset hash (e.g. LtHASH/MuHASH). Deferred as a dedicated, carefully-tested
  data-structure change rather than a hasty rewrite of the just-hardened root computation.
