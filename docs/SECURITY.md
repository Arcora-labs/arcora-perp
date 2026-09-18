# Threat model

> **A10 trust-boundary correction (2026-09-18).** The public testnet alpha is a
> **trusted-gateway / custodial** system at the authorization and oracle boundaries.
> The gateway currently holds server-custody account spend keys in live process memory
> and controls the oracle publisher key accepted by the engine. The zk proof establishes
> that a settled transition satisfies the guest program and its committed inputs. It does
> **not** independently establish user intent for operations authorized with a key the
> gateway itself holds, nor external price truth for a transcript signed by the
> gateway-controlled oracle publisher. A prover that only receives the sealed witness
> does not gain these gateway authorities. Claims such as "TEE compromise can only leak
> confidentiality" or "ZK alone makes the operator unable to steal funds" are therefore
> outside the alpha's stated guarantee. Stronger claims require separated oracle trust
> and user-controlled/proof-bound authorization, followed by independent review.


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
| **Sequencer tries to steal funds** | — | it can't: the vault releases only against a SETTLED withdrawals root; the settlement contract has no authority over the vault's collateral — it custodies only its own sequencer bond + challenge stakes (§0, ADR-0010) |
| **Prover sees the witness** (bare prover farm, §10b) | positions/fills/margins leak to the prover | sealed witness opens only at the attested measurement, zeroized after the job (`prover::AttestedProver`); public proving networks can't open it |
| **Oracle manipulation** (§8) | bad liquidations / funding | transcript sanity gates (staleness, confidence, backup-deviation) re-proven in ZK; anomaly → close-only breaker (`oracle.rs`, `Market` bounds) |
| **Invalid state transition** (any of the above) | — | ZK validity proof: the L1 verifier rejects it, the root never advances (§3, `IZkVerifier`) |
| **User loses device** | — | seed → view-key → scan the encrypted note archive → recover notes/positions (§7, `note-archive`) |

## What an attacker can NEVER do (given the ZK root holds)

- **Steal user funds from the vault.** Withdrawals require a Merkle proof against a
  withdrawals root published only by a *settled* batch; the settlement contract has
  no authority over the vault's collateral (it custodies only its own sequencer bond
  and challenge stakes, moved via pull-payment). A broken sequencer can stall or
  censor, never steal user funds.
- **Advance the state root without a valid proof.** `settleBatch` checks the proof
  against the public-input commitment binding `(prevRoot, manifestHash, newRoot)`.
- **Mint value.** Collateral conservation is an exact integer identity re-proven in
  ZK (Proof-v1): `Σ notes + Σ collateral + insurance + vault_pool + treasury ==
  external_in − external_out`. *(Residual: this binds `external_in` internally but
  not yet to real L1 deposit events — a compromised enclave can inflate `external_in`
  via a fabricated `op_deposit` and mint against it; deposit-event-root binding is a
  tracked P3 item, SEC-019.)*

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

## Public-testnet posture (Base Sepolia, 2026-07) — what the ZK caveat means

A single-enclave public testnet is live (gateway inside a real Azure TDX CVM,
settling to Base Sepolia). The threat model above assumes **all three trust roots
hold**. On the testnet the **ZK root is now REAL**: a full SP1 zkVM re-execution of
the engine is proven to Groth16 and verified on-chain by `SP1ZkVerifier`
(`0x8012F3b3…`, live on Base Sepolia since 2026-07-09, replacing the earlier
`MockZkVerifier`). So on the testnet specifically:

- The "advance the state root without a valid proof / steal from a settled
  withdrawals root" guarantees ARE now enforced on-chain — an invalid state or
  withdrawals root fails `settleBatch` at the real verifier. Funds remain **test
  USDC only** while the remaining stand-ins below are in place.
- Remaining ZK-adjacent stand-ins (why the mint/steal guarantees are not yet *fully*
  airtight): **(a)** the **attested-proving boundary is a stub** — the prover runs
  with a fixed `0xAB` measurement and a public `0x5E` seal-root, not a real
  DCAP-attested key-release, so "the witness opens only at the attested measurement"
  is not yet enforced (SEC-020 / P3); **(b)** **deposit integrity is enclave-rooted,
  not ZK-bound** — `external_in` is not tied to real L1 deposit events, so a
  compromised enclave can mint via a fabricated deposit (SEC-019 / P3); **(c)**
  **gateway key-custody is Phase-0** — wallet spend keys are generated server-side
  and held in plaintext process memory (sealed at rest under `ENCLAVE_SEED`, not yet
  a vTPM-released key), so a live-process compromise is a fund-loss path until
  `TeeSealProvider` (#5d).
- What **is** genuinely exercised end to end: the real ZK verifier + Groth16 proving,
  the TEE attestation (real live TDX + vTPM quote, wrong-measurement boots refuse),
  the settlement/vault/withdrawal plumbing, sequencing accountability (rate limits,
  caller-signed orders, inclusion challenge answering), and sealed state persistence
  with an on-chain-continuity boot gate.
- Order bodies reach the gateway over TLS but are **not yet encrypted to the
  enclave epoch key** (Milestone C #2/#3), and sealing uses the software
  `SealKeyProvider` stand-in (#5d) — so "operator-blind" is partially, not fully,
  realized on the testnet.

Mainnet flips every stand-in below to real; the accounting and containment
structure do not change.

## Production prerequisites (not yet real in this repo)

The stand-ins below must be replaced before mainnet; none affect the accounting or
the containment structure above:

- real SP1/Risc0 verifier — **DONE (live)**: the real `SP1ZkVerifier` (`0x8012F3b3`)
  verifies Groth16 on Base Sepolia (replaced `MockZkVerifier`, 2026-07-09); the
  remaining prover item is the **attested-proving boundary** — real DCAP attestation
  replacing the `0xAB`/`0x5E` stub (SEC-020) — see `PROVING.md`;
- real TDX/Nitro attestation — **live-boot DONE on the testnet** (the gateway
  verifies its own Azure TDX + vTPM quote, `docs/ATTESTATION.md` #5c); real
  vTPM-backed key-release (`TeeSealProvider`, #5d) is the remaining TEE item;
- real enclave sealing / note encryption / committee DKG / bridge VRF seed;
- **spend-key ↔ owner binding — DONE at the engine layer (audit DP-003).** `consume_note`
  now rejects a spend unless `owner_from_spend_key(spend_key) == note.owner`, and
  `Wallet::from_seed` derives `owner = H(spend_key)`, so a note can be consumed only by
  presenting its owner's spend key — the *engine-layer* authorization no longer rests on
  the enclave. (Caveat: the **gateway still custodies** each account's spend key
  server-side in plaintext process memory — Phase-0 custody, see the testnet posture
  above — so end-to-end non-custodial key handling awaits `TeeSealProvider` #5d.)

## Post-audit remediation residuals (2026-07)

All 13 Codex audit findings (DP-001..013), two adversarial-review rounds, and a
workflow code review are fixed on `feat/real-tee`, and both deferred residuals are now
also closed:

- **DP-004 off-chain answering — DONE.** The gateway publishes real ordered/rejected roots
  per settle and a background loop watches `InclusionChallenged` and calls
  `answerChallenge`/`answerByRejection` with a Merkle proof, so the wrongful-slash vector is
  closed end to end.

- **`state_root` unbounded cost — DONE.** The nullifier digest (the only set that grows without
  bound — it is append-only) is now an O(1) running hash-chain advanced on each insert, instead
  of an O(N)-in-history re-hash (audit DP-002 perf follow-up, `crates/perp-core/src/nullifier.rs`).
  A naive commutative accumulator (XOR/sum) was rejected — it would have reintroduced a collision
  weakness, undoing DP-002. The chain is order-dependent, which is SOUND here because the sole
  insert path is `consume_note` in deterministic transition order (identical native + zkVM guest)
  and the field is serialized into the witness (never rebuilt by re-insert). The unspent-note
  digest stays O(M) but M is bounded by *current* unspent notes (removed on spend), not chain
  history, so it does not grow without bound.

## SEC-021 / SEC-021b — withdrawal authorization (2026-07, FIXED)

Two findings from the withdrawal-authorization review, both fixed (gateway +
frontend; no contract change):

- **SEC-021 — withdrawals were authorized by the bearer API key alone.**
  `POST /v1/accounts/withdraw` (and the LP variant `POST /v1/lp/withdraw`) moved
  funds to an arbitrary `to` on the strength of the `X-Api-Key` header, so a
  leaked API key was full fund loss — defeating both caller-signed mode and the
  ownership-proven deposit binding. **Fixed:** every withdrawal now requires a
  strictly-increasing per-account nonce plus a 65-byte secp256k1 signature over a
  deployment-bound digest — `keccak256("dark-perp:withdraw:" ‖ chain_id ‖ vault ‖
  owner ‖ market_id ‖ amount ‖ to ‖ nonce)` for account withdrawals,
  `keccak256("dark-perp:lp-withdraw:" ‖ chain_id ‖ vault ‖ owner ‖ shares ‖
  nonce)` for LP — recovering to the account's **authorizing address**: the
  registered caller-signed `signer` if there is one, else the bound deposit
  address (an account with neither cannot withdraw). Server-custody accounts are
  additionally pinned to `to` = the bound deposit address. The nonce commits only
  after the withdrawal fully succeeds, so a rejected request never burns it.
  (`Gw::account_withdraw`, `Gw::account_lp_withdraw`, `Gw::authorizing_address`,
  `withdraw_auth_digest`, `lp_withdraw_auth_digest` in `crates/gateway/src/main.rs`;
  the digest layouts are user-facing API — documented byte-for-byte in
  `docs/API.md` and frozen by `auth_digests_match_known_answer_vectors`.)

- **SEC-021b — the deposit-address REBIND only proved control of the NEW
  address** (found reviewing the SEC-021 fix itself). Proving control of an
  address the attacker owns is free, so an API-key-only attacker could re-point
  the binding at their own EOA — and, under SEC-021's own `to` pin, direct every
  future withdrawal there. The rebind path was exactly the hole the withdrawal
  signature was meant to close. **Fixed:** moving an existing binding now also
  requires `currentSignature` — the CURRENTLY bound address's signature over
  `keccak256("dark-perp:rebind-deposit:" ‖ chain_id ‖ vault ‖ owner ‖
  rebind_counter ‖ old_addr ‖ new_addr)`. The per-account `rebind_counter`
  (`+1` per accepted rebind, served as `rebindCounter` on `GET /v1/accounts/me`)
  makes each rebind signature single-use, so an old rotation signature cannot be
  replayed after the binding has moved again — the replay matters most when
  rotating away from a *compromised* address whose old signatures the attacker
  holds. (`Gw::account_set_deposit_address`, `rebind_auth_digest`.)

Both digests bind `chain_id` + the vault address (a signature for one deployment
is not portable onto another restored from a copied snapshot), and both are
accepted over the raw 32-byte digest or either EIP-191 `personal_sign` shape
(over the 32 bytes, or over their lowercase `0x…` hex string) — all three are
deterministic transforms of the same digest (`eip191_prehash_candidates`), so
signer ergonomics widen while authorization does not. Caller-signed **order**
signatures remain raw-digest-only.

### User-visible consequences — deliberate, carry into the alpha release notes

These follow from decisions taken on purpose (no operator override was the
point), and users must learn them here rather than live:

1. **No recovery path for a lost bound-address key.** The binding moves only
   with a signature from the address currently bound — no timelock, no operator
   unbind. Combined with the server-custody `to` pin, losing that key makes the
   account's funds **permanently unwithdrawable**. "Keep the key you deposited
   from" is the whole mitigation.
2. **First bind wins, permanently.** An attacker holding only a leaked API key
   can bind their own address to an account that never bound one, and the victim
   cannot overwrite it. The account holds no funds in that state (crediting
   requires `from` == bound address), so this is griefing, not theft — but the
   failure mode is inverted relative to the old behavior, where the victim could
   simply rebind. Mitigation: bind immediately after registering.
3. **Registering a caller-signed `signer` narrows withdrawal authorization to
   that one key.** `authorizing_address` gives `signer` precedence over a bound
   deposit address, deliberately. Losing the signer key strands the funds even
   though the deposit-address key is safe.

### Residual — what a leaked API key can STILL do (pre-existing, outside SEC-021's reach)

SEC-021 closed the withdrawal surface, but it does not make a leaked API key
harmless — one value-extraction route survives it, by construction:

- **Order placement remains bearer-authorized for server-custody accounts** —
  the per-order signature branch in `account_place_order` runs only when a
  registered `signer` is `Some`. Combined with the absence of any
  oracle-relative fill-price band in the real matcher, a leaked key can still
  move value out of the victim account through an off-market self-cross into an
  attacker-controlled account, which then withdraws with its *own* perfectly
  valid signature — fully satisfying SEC-021. The house-MM off-market guard
  covers only the `Ioc`/`Fok` taker path; a `Gtc` order rests in the real
  matcher book at the caller's own price. This is pre-existing and lives in
  `perp-core`/`matcher`/`sequencer`, which SEC-021 could not modify — they
  compile into the SP1 guest, and changing them would invalidate the deployed
  verifying key. Closing it (an oracle-relative price band on resting orders,
  or per-order signatures for server-custody accounts) needs its own
  guest-affecting design cycle.
- **`POST /v1/lp/deposit` remains API-key-only.** A leaked key can push a
  victim's free balance into the counterparty pool; pulling it back out is a
  *signed* LP withdrawal the attacker cannot produce — so the funds are
  strandable, not stealable, through this route (griefing, not theft, matching
  consequence 2 above).
