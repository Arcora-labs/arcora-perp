# SEC-028 — a replayed deposit authorization permanently wedges the deposit stream

**Status:** finding, verified at source. Not yet designed. Found while adversarially
reviewing the 025-A spec; **independent of 025-A and present on `main` today.**

**Severity:** High. Permanent, unrecoverable denial of the deposit path for the cost of a
few base units of USDC. No fund loss for existing users — they can still withdraw — and
settlement keeps running.

## The claimed invariant

`CollateralVault.deposit` takes a gateway signature, and the contract's own documentation
states the reason (`contracts/src/CollateralVault.sol`, above `deposit`):

> the vault accepts a deposit ONLY if the gateway pre-authorized this exact
> (from, ownerCommit, amount) tuple for THIS vault on THIS chain, so **every leaf that can
> enter the chain is creditable off-chain by construction (no uncreditable leaf can
> head-of-line-block the contiguous deposit queue — spec §1b)**.

That invariant does not hold.

## Why it fails

The signature is verified and **discarded** — the contract says so explicitly: *"It is
verified then DISCARDED — it does NOT enter the leaf or the chain."* It binds chain, vault,
payer, `ownerCommit` and `amount`, and deliberately **not** `depositCount`/`id`, because the
gateway cannot predict the landing index at signing time.

So the tuple carries **no nonce and no id**, and nothing on-chain marks it consumed. The same
signature can be submitted any number of times, each call producing a fresh leaf at a fresh
id.

Off-chain, the gateway consumes the authorization after the first credit
(`crates/gateway/src/main.rs:2135`), and its comment states the intent:

> One-shot: consume the authorization so a second event for the same ownerCommit can't
> double-credit (the tx-hash dedup already guards replays; this is defense in depth and keeps
> the SECRET blind from lingering past its single use).

Both halves are individually reasonable. Together they are the bug: the contract permits a
second leaf, and the gateway destroys the only thing that could credit it.

The second leaf then hits the SEC-019 misattribution guard (`main.rs:2036-2048`), which is
fail-closed and refuses an absent record:

> An ABSENT record (a deposit whose commit we never authorized) or a stored blind that fails
> to reproduce the commit is refused.

Because deposits must be credited in strict contiguous order — enforced at the host
(`main.rs:2061-2066`), in the engine (`crates/perp-core/src/engine.rs:375-377`), and
ultimately by `_requireDepositPrefix`, which would break **every** future settle on a wrong
fold — that uncreditable leaf blocks every deposit behind it, forever.

## Why it is unrecoverable

Re-authorizing does not help. `account_authorize_deposit` generates a **fresh CSPRNG blind**
per call (`main.rs:1977-1983`), so a new authorization produces a *different* `ownerCommit`
and cannot credit the stuck leaf. The original blind was deleted, and `owner_commit` is
`keccak(owner ‖ blind)` over 32 random bytes — not recoverable by search.

There is no operator path to credit a deposit on a user's behalf, and no path to supply a
blind out of band.

## Attack

1. Register; bind a deposit address.
2. `POST /v1/accounts/deposit/authorize` for `amount = 1` base unit. Receive the signature.
3. Call `CollateralVault.deposit(1, ownerCommit, sig)` **twice**.
4. Confirm the first. The gateway credits it and deletes the authorization.
5. The second leaf is now permanently uncreditable, and the deposit stream is wedged.

Cost: 2 base units of USDC plus gas.

**Step 4 is required.** An earlier draft of this spec said the attacker "need not even confirm
the first". That is wrong: until a credit succeeds, the authorization is still there, so both
leaves remain creditable and the block is the ordinary **voluntary, recoverable** kind — the
depositor can confirm whenever they choose. It is the *first successful credit* that deletes
the blind and converts the second leaf into a permanent one. One unconfirmed leaf is enough to
stall the queue; it is not enough to wedge it.

## Blast radius

- **Deposits:** permanently dead for every user.
- **Settlement:** unaffected. The uncredited leaves sit above the gateway's consumed prefix;
  `newDepositCount` is the gateway's own count and `depositTipAt(n)` is written for every
  `n ≤ depositCount`, so batches keep settling. `deposit_posture` explicitly accepts a
  gateway behind the vault (`main.rs:8709-8715`).
- **Withdrawals:** unaffected.
- **The attacker's own funds:** the replayed deposit's tokens are in the vault, never
  credited, and therefore never claimable. The attacker burns them.

## Directions (not yet a design)

**Preferred: consume the digest on-chain.** Add a `usedDepositAuthorization[digest]` mapping to
`CollateralVault` and mark it inside `deposit`, **before** `transferFrom` so a revert rolls the
mark back with the rest of the call. This fixes the root cause — the signature stops being
replayable at all — rather than teaching the gateway to tolerate replays. It preserves the
existing signature ABI (no new parameter, no re-signing scheme), needs no gateway state growth,
and does not keep a secret blind alive past its single use.

Store the **digest**, not the signature bytes. Keying on signature bytes would tie replay
protection to an encoding rather than to the authorization itself. *(The malleability argument
is weaker here than it first appears: `_recover` already rejects high-`s` signatures
(`contracts/src/CollateralVault.sol:138`), so the obvious mutated variant is refused anyway.
Digest keying is still the right design — it is the authorization that should be one-shot, not
one particular serialization of it.)*

Cost: a contract change, so a fresh `CollateralVault` deploy. Acceptable — this workstream's
cutover already requires fresh contracts.

Alternatives considered:

1. **Do not delete the authorization** — retain `ownerCommit → blind` so every replayed leaf
   stays creditable. Gateway-only, no contract change, and SEC-026-safe (verified below). But
   it *accommodates* the replay rather than preventing it, retains a secret past its single
   use, and grows gateway state without a safe eviction policy (see below). Viable fallback if
   a contract deploy is off the table; not the first choice.
2. **Bind an id or nonce into the signature.** The contract deliberately does not bind
   `depositCount`, because the gateway cannot predict the landing index at signing time. A
   gateway-chosen nonce avoids that, but changes the signature ABI and the gateway's signing
   path for no benefit over consuming the digest.
3. **An operator path to credit a stuck leaf** with a re-supplied blind. Re-opens exactly the
   confiscation surface 025-A had to design around. Least attractive.

*(Note for whichever option is chosen: `processed_deposit_txs` is not the only double-credit
protection. The contiguous-id check independently rejects replaying an already-consumed leaf,
so the tx-hash dedup is defence in depth on that axis too.)*

### The SEC-026 interaction — verified, and option 1 survives it

Option 1's risk was that crediting two leaves for the same `(owner, amount)` would produce the
same note commitment and be rejected by historical uniqueness — trading one wedge for another.
**It does not.** Verified at source:

- The note blind is 32 bytes of `0xB0` with the first eight overwritten by the account's
  `deposit_counter` in little-endian (`crates/gateway/src/main.rs:2067-2069`).
- The counter is **per account, monotonic, and bumped only on success** (`:2134`).
- `mint_note` rejects a commitment already in the tree (`crates/perp-core/src/engine.rs:427-435`).

So the first credit uses `0xB0 ‖ N` and the second `0xB0 ‖ N+1` — different blinds, different
commitments, no `DuplicateCommitment`. The tree already reasons about exactly this: the comment
at `main.rs:2064-2066` cites "SEC-026 review F2" and states the property directly.

Crediting both is also the *correct* outcome: the user really did pay twice, so they should be
credited twice. Today's behaviour strands the second payment **and** wedges the queue.

### What option 1 still has to solve

Retaining authorizations indefinitely grows state without bound, and keeps a secret blind alive
past its single use — which is the stated reason the deletion exists. Neither is fatal, but a
naive fix trades a wedge for a leak and a leak for an unbounded map.

**An expiry policy would reintroduce the bug**: any authorization that expires while an
un-landed leaf can still reference it recreates the uncreditable leaf, and the gateway cannot
know whether such a leaf exists. So the retention must be bounded by *refusing new
authorizations at a per-account cap* rather than by evicting old ones — never drop a blind that
some leaf might still need.

## A second, independent cause of the same wedge — authorization durability

Found in the same review, and **not fixed by any of the options above.**

`account_authorize_deposit` inserts the blind into memory only (`main.rs:1977-1983`), and the
handler returns the signature immediately. Snapshots are periodic — every `SNAPSHOT_SECS`,
default 30 (`main.rs:357`, `:7043`). So:

1. The user calls `/authorize` and receives a signed tuple.
2. The gateway crashes before the next snapshot.
3. The user's deposit lands on L1 (or already had).
4. The restored gateway has **no record of the blind**, and the leaf is uncreditable —
   permanently, by the same mechanism as the replay case.

This needs no attacker and no replay: an ordinary user and an ordinary crash suffice. The
window is up to `SNAPSHOT_SECS` wide on every authorization the gateway issues.

**Fix direction:** make the authorization durable *before* the signature leaves the process —
either a synchronous snapshot barrier on that path, or a small append-only authorization log
that boot replays. Returning a signature for a deposit the gateway cannot later credit is the
defect; the signature is a promise the gateway has not yet made durable.

This matters acutely at cutover: the operator's own bootstrap deposit runs through exactly this
path, so a crash in that window strands the capitalization *and* wedges the queue on the very
first deposit. 025-A's cutover must force a durable authorization before the L1 deposit is sent.

## Relationship to 025-A

025-A's "pre-bootstrap deposit-ordering restriction" was designed against a *voluntary*
head-of-line block (a user deposits and declines to confirm, recoverable the moment they
act). This is the same shape but **involuntary and permanent**, and it is strictly worse.
Any 025-A gate must be designed knowing this exists; and 025-A's gate does not fix it,
because the wedge can be created after the gate opens.
