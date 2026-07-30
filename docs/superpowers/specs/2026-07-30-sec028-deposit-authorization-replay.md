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

Cost: 2 base units of USDC plus gas. The attacker need not even confirm the first — leaving
both uncredited wedges the stream just as effectively and costs the same.

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

Roughly in increasing order of intrusiveness:

1. **Do not delete the authorization** — retain `ownerCommit → blind` and rely on the
   existing tx-hash dedup (`processed_deposit_txs`) to stop double-crediting, which is what
   actually prevents it. The deleted-blind comment calls itself "defense in depth"; it is
   the load-bearing cause here. Cheapest, and it makes every replayed leaf creditable, which
   is exactly the contract's stated invariant. Needs care: retaining blinds grows state and
   keeps a secret alive longer than one use.
2. **Bind the id or a nonce into the signature.** Contract change; the contract explicitly
   rejected binding `depositCount` because the gateway cannot predict the landing index — but
   a gateway-chosen *nonce* consumed in a mapping has no such problem.
3. **An operator path to credit a stuck leaf** with a re-supplied blind. Re-opens exactly the
   confiscation surface 025-A had to design around, so this is the least attractive.

Option 1 looks correct and small, but the interaction with SEC-026 historical commitment
uniqueness needs checking before it is chosen: two identical `(owner, asset, amount, blind)`
notes produce the same commitment, and `mint_note` rejects any historically used commitment
(`engine.rs:427-435`). The note blind is `0xB0 ‖ deposit_counter` and the counter bumps per
successful credit, so two credits get different note blinds — but that must be verified, not
assumed, because it is the difference between option 1 working and option 1 wedging
differently.

## Relationship to 025-A

025-A's "pre-bootstrap deposit-ordering restriction" was designed against a *voluntary*
head-of-line block (a user deposits and declines to confirm, recoverable the moment they
act). This is the same shape but **involuntary and permanent**, and it is strictly worse.
Any 025-A gate must be designed knowing this exists; and 025-A's gate does not fix it,
because the wedge can be created after the gate opens.
