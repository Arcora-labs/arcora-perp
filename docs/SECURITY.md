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
| **Protocol** (order log + capped fines + close-only with refunds) | sequencing accountability, liveness, fair access | confidentiality, fund validity |
| **ZK** (validity proof on L1) | fund safety, valid state transitions | inclusion, ordering, censorship |

## Compromise → impact → containment

| If compromised | What breaks | What contains it |
|---|---|---|
| **TEE confidentiality** (side-channel, §10) | order/position privacy leaks; MM gets a latency edge | committee-of-enclaves t-of-n (§11, `committee`) — needs t-1 enclaves to leak; funds still safe (ZK) |
| **TEE integrity** (bad matching, preconf lies) | wrong fills, unreliable MATCHED preconfs, market-integrity abuse | quorum preconf (`committee`), Proof-v2 matching determinism (future); MATCHED is non-binding (§3) |
| **Sequencer liveness** (halts) | no new batches | anyone can trigger close-only after the timeout; deposits no settled batch consumed become refundable at principal from the vault; existing published withdrawal claims remain available with Merkle data; new exits still require operator/prover and final wind-down governance |
| **Sequencer withholds a landed deposit** (keeps settling without consuming it) | the deposit is never credited | anyone can trigger close-only once the oldest unconsumed deposit is older than `livenessTimeoutBlocks`; that deposit and every later one then become refundable from the vault |
| **Sequencer censors an order** | a user's order is withheld | each receipt carries an enclave-signed L1 challenge authorization; an unanswered challenge pays a capped fine from the bond to the account's beneficiary once later batches settle, and settlement continues. Rejected-root membership does not prove a truthful rejection reason; fairness remains an explicit limitation |
| **Gateway custody-key compromise** | unauthorized guest-valid operations can affect funds | vault roots constrain direct payout; guest validity alone does not authenticate user intent independently of server-held keys |
| **Prover sees the witness** (bare prover farm, §10b) | positions/fills/margins leak to the prover | the intended boundary is attestation-gated key release; the development prover is inside the current privacy trust boundary. Hardware deployment and full witness-copy cleanup remain unverified |
| **Oracle manipulation** (§8) | bad liquidations / funding / wind-down settlement price | signature, freshness, confidence and backup-deviation checks run in-guest, but one publisher signs both price and backup and can lie consistently; external price truth is still trusted. `SettleAll` closes open positions at the last price recorded in the settled state, which that same key signed |
| **Invalid state transition** (any of the above) | — | ZK validity proof: the L1 verifier rejects it, the root never advances (§3, `IZkVerifier`) |
| **User loses device** | — | seed → view-key → scan the encrypted note archive → recover notes/positions (§7, `note-archive`) |

## Current alpha proof and custody boundary (2026-10-09)

The gateway holds user spending keys and price-publisher authority. A gateway
compromise can authorize guest-valid operations or sign false prices; a validity
proof alone does not independently establish user intent or external market truth.

- The vault requires a Merkle claim against a published withdrawal root and binds
  its destination, amount and nonce. This prevents arbitrary direct vault claims,
  but does not eliminate upstream custody-key risk. New exits require the
  operator/prover and governance during final wind-down.
- Settlement checks the guest public-input commitment and previous-state-root
  continuity. The deployed verifier/program key must match the reviewed source.
- Conservation is enforced by the engine. SEC-019 additionally binds deposits to
  the vault's ordered count/tip prefix; fabricated native deposits cannot be
  treated as confirmed L1 deposits. The full normal-wallet flow with a real clock
  proof remains a distinct release acceptance test.
- The settlement records the consumed deposit count on every settle. Deposits
  above it are refundable from the vault once close-only begins, and claims cannot
  consume their principal (§ Settlement ABI version 3).
- Rejection membership and order hashes are committed, but truthful rejection
  reasons and matching fairness are not proven. See
  [the current rejection review](audits/2026-10-09-rejection-boundary.md).
- The wind-down settlement price is the last validated price recorded in the
  settled state. The operator's own oracle key signs it, and the operator chooses
  which signed transcript, within the staleness window, each op carries.
  Governance chooses when close-only starts; in the shipped flow governance is the
  hot sequencer key (§ Funding, wind-down settlement and witness binding).
- The guest bounds funding (rate clamp, mark band, one-hour cap per gap, exact
  carry), but the sequencer chooses the funding mark and the timing of ops.

The older phase notes below describe historical design work, not fresh deployment
or release acceptance. Current task state is in
[the follow-up report](audits/2026-10-09-remaining-work/README.md).

## Settlement ABI version 3 — deposit boundary, refunds, capacity and bounded challenges (2026-10)

`DarkPerpSettlement.ABI_VERSION()` is `3` for the settlement, vault and clock
verifier in this source. The July Base Sepolia stack predates these rules; they
take effect only on a fresh deployment (`docs/REDEPLOY-CC-RUNBOOK.md`).

**Deposits and close-only.**

- Every settle path pins its proven deposit root to the vault's chain prefix and
  records the count as `consumedDepositCount`. The count cannot exceed the vault's
  head or decrease.
- Close-only is irreversible and has three entries. Anyone may trigger it on a
  stalled root (once the stack holds a batch, a deposit or an open challenge) or
  on a deposit left unconsumed for `livenessTimeoutBlocks`. Governance may enter it
  directly.
- In close-only the count is frozen: wind-down settles must keep it. Anyone can
  refund a deposit above it to its payer (`refundDeposit`); only the payer may
  redirect the refund.
- Vault claims cannot consume the principal of deposits the settled state has not
  credited (`ReservedForUncredited`).
- Deposit permits carry a deadline (`validUntil`), and each owner commitment enters
  the deposit chain once. Amounts must be between 1 and `int128` max.
- Deposits close at bond capacity: a deposit that would lift 5% of the vault's TVL
  above the posted bond is refused. Settlement never checks the bond.

**Inclusion challenges.**

- A challenge needs an enclave-signed authorization bound to the chain id, the
  settlement and a beneficiary: the account's bound deposit address. The perp-core
  receipt signature alone does not open a challenge. Each order hash can be
  challenged once.
- Answers are permissionless, can be batched per settled batch, and stay valid until
  a slash or release lands. Open challenges are enumerable on-chain.
- A slash needs `progressBatches` ordinary batches settled after the challenge
  opened, plus `challengeGraceBlocks`. It pays at most `slashPayoutCap` to the
  beneficiary, returns the stake, and leaves settlement running. Close-only never
  slashes; a challenge that cannot reach the gate is released with its stake.
- Credits can be claimed to another address (`claimEthTo`, `claimUsdcTo`).

**Clock and wiring.**

- `ClockBoundVerifier.cancel` lets the role that registers a phase remove an anchor
  that is at least `anchorTimeoutMs` old (1 h by default). A cancelled receipt never
  verifies again. Cancelling stays an operator action: the gateway never cancels an
  anchor by itself.
- The settle loop resolves a clock window that can never settle, without a restart,
  and only when nothing of it can still land on L1: our anchor is cancelled or absent,
  and either the finalized, header-bound block time is past the window's last
  operation time plus the immutable `clockSkewMs` (block times never decrease, so a
  later registration reverts), or every recorded sequencer-key nonce is final and
  no sequencer-key transaction is pending on any configured RPC. A phase-0 window
  with timed operations is then voided off-chain (fills undone, deposits credited
  again, withdrawals removed and re-requested with a new signature); an untimed
  window returns to the open window and registers again. On the nonce basis alone
  the gateway may send up to three 0-value self-transfers per window at an unused
  sequencer nonce; they touch no contract and are not a cancel. Repeated voids stop
  the settle loop until a restart
  (`docs/PROVING-RUNBOOK.md`, § Dead clock window).
- The settlement constructor refuses a verifier that is not a fresh clock verifier
  (proof version 2, unbound). `setVault` requires the vault to name this settlement.
- `Deploy.s.sol` is a testnet harness over the mock verifier only. Release stacks
  are deployed with `deploy_clock_stack.py` and checked with `release_manifest.py
  observe-target`.

**Gateway posture.**

- At boot, in L1 mode, the gateway refuses to start unless all of these hold:
  - `ABI_VERSION() == 3`;
  - the verifier reports proof version 2 and `CLOCK_BOUND_VERIFIER` is set;
  - the vault names the settlement;
  - `anchorTimeoutMs()` covers its own finality and proving budgets;
  - `DEPOSIT_PERMIT_TTL_SECS` is at most one eighth of the liveness window;
  - where the local settled root equals `currentStateRoot()`, the local consumed
    count equals `consumedDepositCount()`.
- The settle tick refuses to seal when that tick's open-challenge read failed.
- While idle, the gateway settles an empty keepalive batch every
  `livenessTimeoutBlocks / 4`.
- Automatic bond top-up pauses after a slash until the operator acknowledges it.
- Never roll the gateway binary back across this change.

### User-visible consequences

1. **Opening a challenge is public.** The beneficiary is an indexed event topic, so
   a challenge links that deposit address to the order hash.
2. **Only settled state carries into close-only.** A deposit credited off-chain but
   never consumed by a settled batch is refunded at principal. Trades and withdrawal
   requests that were only in windows that never settled are discarded.
3. **A permit is not a reservation.** When the bond's capacity is full, deposits are
   refused until the operator posts more bond, first come first served.
4. **Permits expire.** A permit cannot be used after `validUntil`; authorize again.
5. **No bound address, no L1 challenge authorization.** Receipts for an account
   without a bound deposit address carry `l1Challenge: null`.

## Funding, wind-down settlement and witness binding (2026-10-18)

These rules are part of the zkVM guest program in this source. They take effect only
with a newly built guest, a new program key and a fresh deployment.

**Witness framing.** The guest accepts exactly one input:
`b"DPCLK4\0\0" ‖ postcard(state, ops, manifest, clock context)`, with no trailing
bytes, and always binds the commitment to the L1 clock receipt
(`perp_core::clock::bind_transition`). Input without that prefix is refused before
any decode. The native replay and the prover service accept the same framing only,
and the gateway's HTTP prover client sends nothing for an unbound witness. `DPCLK3`
remains the separate Chainlink candidate framing. On L1, `ClockBoundVerifier` passes
the inner `SP1ZkVerifier` the bound commitment
`keccak256(abi.encode(DOMAIN, baseCommitment, receipt))`, which is exactly the 32 bytes
the guest commits. The `SP1ZkVerifier` NatSpec that equates the public values with the
settlement's `publicCommitment` predates clock binding; the contracts stay
byte-identical, so the correction lives here.

**Every serialized field is bound.** Each field of the decoded pre-state is either
bound into the anchored state root, derived on decode, or validated on decode:

- the note-commitment tree is encoded as its depth and leaves; the empty-subtree
  roots are derived, the depth must be 1 to 64, the leaves must fit the capacity and
  must be distinct;
- the nullifier set is encoded as its insertion-order log (§ Post-audit remediation
  residuals);
- each market's funding state is range-checked (rate within the clamp, carry
  strictly inside its divisor, a non-negative recorded price, no recorded time
  without a price), and the funding and market keys must match;
- each position's stored owner and market must equal its key.

The state root and every state sub-digest start with a distinct role-tag word, so no
two of them share a preimage format. A mutated field therefore gives a decode error,
a shape error or a different root.

**Withdrawal leaf nonces are bound to state.** The state root records the nonce of
the last real L1 withdrawal (`last_withdrawal_nonce`). A real withdrawal, ordinary or
wind-down, must carry a strictly greater nonce, by at most `2^32`, and becomes the new
last one. An internal burn must carry nonce 0. Every settle path on L1 requires the
proven previous root to equal `currentStateRoot()`, so every published withdrawal leaf
carries a distinct nonce across all batches and phases, and `claimed[leaf]` on the
vault makes each one single-use. The gateway assigns leaf nonces above the last
recorded one; on boot and restore it moves a lagging counter forward and raises an
alert.

**Funding.** Each span is charged at the rate stored at its start, to the positions
that existed during it, for at most one hour per gap, with an exact carry
(`docs/ECONOMIC_SECURITY.md`, Q8). The guest proves those bounds, the rate clamp and
the mark band. The funding mark and the op timing are the sequencer's choice, so
time-correctness assumes an honest sequencer.

**Wind-down settlement.** `SettleAll` closes open positions at each market's last
recorded validated price (entry price for a market that never recorded one), covers
deficits from the clearing pool, insurance and the treasury, applies a global
pro-rata haircut only to what remains, and pays the reserves left over as one
withdrawal leaf to the wind-down recipient. The recipient is an L1 address bound into
the state root at genesis and immutable afterwards. `darkperp-gateway
--print-genesis-root` prints the root together with the recipient and the oracle
signer it binds, and the release manifest carries those three values from that run.
`observe-target` checks that the deployed `currentStateRoot()` equals the declared
root while no batch has settled, `validate --check-process-env` ties the gateway's
`WIND_DOWN_RECIPIENT` to the declared recipient, and at boot the gateway checks that
its state root, on a fresh genesis the one it computes from its own configuration,
continues the settlement's. Given the release's gateway binary (`--gateway-bin`),
`release_manifest.py` `create`, `validate` and `observe-target` and
`deploy_clock_stack.py` also recompute the root from the declared recipient and
oracle signer and refuse unless it is the declared root; without it, the root is
not recomputed and those two addresses rest on the output that listed them with it.
On a chain id other than a local test chain (31337 or 1337), neither address may be
one of the published default development accounts. See
`docs/FINAL_SETTLE_RUNBOOK.md`.

**Deposits after an engine trip.** Once the engine is close-only, the guest refuses
`Deposit`, and the gateway stops permits and crediting. Such deposits stay
unconsumed on L1 and are refunded at principal after L1 close-only. The gateway
records each one that landed under its permits, and the account view lists it as
refundable once L1 close-only is observed.

**Fresh stack.** Off-chain byte formats from before this change (witnesses, gateway
snapshots and rollback journals) are refused by their format magic, not migrated.

## Residual / honestly-acknowledged leakage

- **Market-level liquidation pressure is visible** (§9): per-position liquidations
  are private, but aggregate funding/OI/insurance movement is irreducibly
  observable. We prefer batching/aggregation over dummy-event padding.
- **Sub-unit bridge remainders leak** (§13): amounts below the smallest
  denomination can't be bucketed and are reported explicitly (`bridge`).
- **Confidentiality depends on hardware** until the committee/MPC hardening lands;
  a compromised gateway also retains the custody and oracle risks described above.
- **Bad debt has a fixed live waterfall.** A liquidation's shortfall is covered by
  the insurance fund, then the treasury, then auto-deleverage of the market's
  winners, each capped so that it keeps collateral at or above zero and equity at or
  above maintenance margin. Whatever is still uncovered stays parked on the closed
  position, inside the conservation identity, and trips the system to close-only.
  From then on the guest refuses new deposits, so they cannot absorb the earlier
  shortfall (`docs/ECONOMIC_SECURITY.md`, Q3/Q7). What reaches users through ADL or
  the wind-down haircut is attributable, never silent.

## Known design limitations (flagged for input, not yet fixed)

- **Rejection membership answers are implemented; rejection legitimacy remains
  open.** `DarkPerpSettlement` commits `rejectedRoot` and implements
  `answerByRejection(orderHash, batchId, proof)`. Anyone can answer an open
  challenge, until a slash or release lands, by proving declared rejection
  membership in a genuinely settled batch. The gateway builds ordered or rejected
  membership proofs from retained batch data and its challenge worker selects the
  corresponding answer path. Stake routing compares the answering batch with the
  challenge's captured batch count (`openBatchCount`), including same-block
  publication order.
  This proves membership in the committed list; it does not prove that the
  rejection reason was legitimate or that matching was fair. The guest lacks
  authenticated order bodies and a committed book/lifecycle needed to replay
  those decisions. A dishonest matcher can declare a valid order rejected and
  answer by membership. Closing that gap requires a separate witness/guest
  protocol change and release verification. The
  [rejection-boundary evidence](audits/2026-10-09-rejection-boundary.md) records
  local characterization and refund tests, with their scope limits. Current
  source and local evidence do not establish a live deployment or independent
  proof/custody acceptance.
- **Vault `withdrawalsRoot` must be cumulative (P6) — NOW WIRED, later relaxed.**
  `CollateralVault.publishWithdrawals` overwrites `withdrawalsRoot` each settled batch,
  but it also records every published non-zero root (`rootPublished`), and `claim`
  accepts a proof against any of them (audit DP-012). A later root that omits a leaf
  therefore no longer strands it. The NatSpec on `publishWithdrawals` that still
  calls the cumulative root a MUST predates that change; the contract source is kept
  byte-identical, so the correction lives here. The guest commits each batch's own
  withdrawal leaves; the phase-1 wind-down root holds at most the one reserve-payout
  leaf, claimable with an empty proof. The historical rationale follows: a single
  overwritten root had to be the cumulative set of all authorized-but-unclaimed
  withdrawals, or a user who hadn't yet `claim`ed an older withdrawal would be
  stranded when the next batch published. The mechanism is sound (claims are gated on the proven root, never
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
  per settle. Its challenge worker reads the settlement's on-chain open-challenge set
  (`openChallengeCount`, `openChallenges`, `challenges`) each tick and answers with
  Merkle proofs, batched per settled batch through `answerChallenges`. The settlement
  ABI version 3 replaced the earlier `InclusionChallenged` log scan. The
  membership-answer path is wired in source; rejection legitimacy and guest matching
  remain open as described above. This does not establish live release acceptance.

- **`state_root` unbounded cost — DONE.** The nullifier digest (the only set that grows without
  bound — it is append-only) is now an O(1) running hash-chain advanced on each insert, instead
  of an O(N)-in-history re-hash (audit DP-002 perf follow-up, `crates/perp-core/src/nullifier.rs`).
  A naive commutative accumulator (XOR/sum) was rejected — it would have reintroduced a collision
  weakness, undoing DP-002. The chain is order-dependent, and the set is serialized as its
  insertion-order log and nothing else: decode rebuilds the membership index and the chain by
  inserting the log in order, and a repeated entry fails the decode. Two sets therefore have
  equal digests exactly when they hold the same nullifiers inserted in the same order (barring a
  hash collision), so the state root binds every encoded byte of the set. The sole insert path is
  `consume_note`, in deterministic transition order (identical native + zkVM guest). The
  unspent-note digest stays O(M) but M is bounded by *current* unspent notes (removed on spend),
  not chain history, so it does not grow without bound.

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
