# SEC-021 Remediation — Withdrawal Authorization (signed withdrawals + rebind lock) — Design

**Finding:** SEC-021 [high, broken-authz] — the gateway's withdrawal path skips the signature check the account explicitly bought. An account registers **caller-signed** mode by POSTing `{"signer":"0x…"}` to `/v1/accounts` (`main.rs:4296-4319`), whose stated purpose is that *a leaked API key alone cannot act*. The order path honours that: `account_place_order` requires a secp256k1 signature recovering to the registered `signer` plus a strictly-increasing nonce on **every** order (`main.rs:2268-2333`), commented *"A caller-signed account requires the caller's own secp256k1 signature on every order, so a leaked API key alone cannot trade."*

The withdrawal path carries no such guarantee. `WithdrawReq` has no signature field at all — only `{ marketId, amount, to }` (`main.rs:3889-3894`); `post_v1_withdraw` authorizes on `X-Api-Key` alone (`main.rs:4470-4486`); and `account_withdraw` never reads `acct.signer` before recording the withdrawal leaf (`main.rs:1875-1934`). The destination `to` is fully attacker-chosen — `parse_addr20_hex` validates only the format (`main.rs:4478-4481`).

So **the lowest-value operation (an order) is signature-protected while the highest-value one (moving money out) is bearer-token-only** — the protection the account specifically opted into is absent on exactly the path where funds leave.

**Exploit:** a leaked API key for a caller-signed account (the precise scenario the feature exists to survive: a relayer, a logged `X-Api-Key` header, compromised browser storage). The attacker cannot trade — no signing key — but `POST /v1/accounts/withdraw {marketId, amount, to: <attacker>}` succeeds with no signature, records a withdrawal leaf bound to the attacker's address, and after the next L1 settle the attacker collects USDC via `CollateralVault.claim`.

**SEC-021b (found while designing this fix, adversarial review):** the deposit-address binding is **mutable by the API key alone**, which defeats any defence built on it. `account_set_deposit_address` proves control only of the *new* address and overwrites an existing binding unconditionally (`main.rs:1710`); the only other check is cross-account uniqueness (`main.rs:1703-1709`). Since `GET /v1/accounts/me` returns the account `owner` (`main.rs:2471`), an attacker holding just the API key can compute `deposit_bind_digest(owner, attackerEOA)`, sign it with their **own** key (trivial — it is their address), rebind the victim account, and then withdraw to it. The `Account` comment claiming the address is *"Bound once"* (`main.rs:958`) is false. This must be fixed in the same change; a `to` pin alone is worthless without it.

A secondary consequence: an API-key attacker can rebind between deposit authorization and confirmation, making a legitimate on-chain deposit fail the bound-address check (`main.rs:1791`) and potentially head-of-line-block contiguous deposit consumption.

## Scope

- **`crates/gateway` only.** No `perp-core`, no `sequencer`, no Solidity, no circuit change.
- **`Gw::account_withdraw`** (`:1875`) — require a signature before any state mutation.
- **New `Gw::account_lp_withdraw`** — the account-scoped, authorized entry point; `Gw::lp_withdraw` (`:2808`) stays the raw engine primitive (see §6).
- **`Gw::account_set_deposit_address`** (`:1676`) — a rebind must also be authorized by the **currently bound** address.
- **New gateway-local digest helpers** + one shared EIP-191 prehash helper generalized from the existing deposit-bind code.
- **`Account`** gains `last_withdraw_nonce: u64`.
- **`v1_account`** (`:2467`) — expose `depositAddress`, `callerSigned`, `nextWithdrawNonce` (the frontend cannot implement the new flow without them).
- **Frontend** (`AccountPanel.tsx`, `realClient.ts` + tests) — withdrawal becomes a wallet-signed action.
- **Docs** — `docs/API.md`, the in-`main.rs` OpenAPI blob, `docs/public-site/{api,trading}.html`, `docs/SECURITY.md`.

**Non-goals / deferred:**

- **`deposit_authorize` hardening** — separate, lower severity. Note the correct rationale: a leaked key there does **not** move value (the call transfers nothing); the real defect is that every request inserts an entry into the unbounded, persisted `deposit_authorizations` map (`main.rs:1752`) with no per-account cap or rate limit (`main.rs:4420`) — a durable memory/snapshot-growth vector. Track as its own issue.
- **EIP-712 typed data** — better wallet UX (the wallet renders "withdraw 2000 USDC to 0x…" instead of a hex blob to blind-sign), but introduces typehash/`chainId`/`verifyingContract` machinery with no precedent here. Revisit once the signed-withdrawal flow is live.
- **Timelocked rebind** — considered and rejected for now; requires a delayed-state machine plus a notification surface. The current-address signature requirement is the proportionate fix.
- The report's other two items (AttestationRegistry not wired to the settlement contract; the live prover running `DEV_INSECURE`) are separate workstreams, already tracked.

## Current state (grounding)

- **`Account`** (`main.rs:949-989`): `signer: Option<[u8;20]>`, `last_signed_nonce` (orders), `last_sealed_nonce` (sealed-order replay), `deposit_address: Option<[u8;20]>`, `deposit_authorizations`.
- **Order signature verification** (`main.rs:2320-2334`): `parse_hex65` → `recover_eth_address(&order_hash, &sig)` against the registered signer → commit `last_signed_nonce`. **Raw digest only, one prehash candidate, no EIP-191.**
- **Deposit-address bind** (`main.rs:1688-1702`): the one place that accepts EIP-191. `deposit_bind_digest(owner, addr) = keccak256("dark-perp:bind-deposit:" ‖ owner ‖ addr)` (`main.rs:4073-4080`); `deposit_bind_prehash_candidates(digest) -> [[u8;32];3]` (`main.rs:4088-4124`) returns (a) the raw digest, (b) EIP-191 over the 32 raw bytes, (c) EIP-191 over the `"0x…"` hex string. The frontend signs via `personal_sign` (`frontend/src/api/wallet.ts:248-251`).
- **Deposit crediting requires a bound address** (`main.rs:1791-1803`) — an unbound account is refused with *"Bind a deposit address first"*.
- **In-memory mint is disabled in production** (`main.rs:2101-2111`, audit DP-001), and production mode is automatic for an L1-enabled deployment (`main.rs:5168`).
- **Legacy `/api/*` mutation routes are omitted in production** (`main.rs:5334-5349`, audit DP-010).
- **No account-to-account transfer exists** — `pool_transfer` (`main.rs:2739`) is LP-internal only; LP shares are obtainable only by first debiting the account's own market-0 balance (`main.rs:2776`, `:2806`); MM/insurance wallets are not registered `Account`s (`main.rs:1480`, `:1503`, `:1536`); opening an order requires existing free margin (`main.rs:2230`).

  **Therefore, in production, every funded account already has a bound deposit address.** Verified independently and confirmed by adversarial review — no hidden credit path bypasses the gate. **This does not hold in dev/demo**, where `account_deposit` credits unbound accounts (see "Dev/test impact").

- **No caller-signed client exists in the wild.** The frontend registers with a bodyless POST (`frontend/src/api/realClient.ts:503`) → every live account is server-custody. Caller-signed mode is reachable only via raw API + docs (`docs/API.md:134-152`) and two Rust unit tests (`main.rs:7739`, `:8178`). **The source cannot prove this of live state — see "Pre-rollout verification".**
- **`/v1/lp/withdraw` has no client** — the frontend LP UI calls the legacy `/api/lp/withdraw` (`frontend/src/components/LpVault.tsx:66`), whose handler passes `share_key = gw.user.owner`, **not an entry in `accounts`** (`main.rs:5034-5046`).
- **`Domain` enum** (`perp-core/src/hash.rs:34-172`) is dense `1..=32`, next free 33, with a density + pairwise-distinctness test at `hash.rs:225-283`.

## Design

### 1. One rule: every withdrawal is signed

A withdrawal requires a secp256k1 signature recovering to the account's **authorizing address**:

```
authorizing_address(acct) =
      acct.signer          if Some   // caller-signed: the explicit opt-in wins
    | acct.deposit_address if Some   // server-custody: the EOA it proved control of at bind
    | reject                          // neither ⇒ no withdrawal is possible
```

This collapses the two account types into a single code path. Server-custody accounts are not left bearer-token-only: the system **already proved that EOA holds a usable signing key** — it signed the bind — so requiring it again at withdrawal costs the user nothing new and is UX-consistent (the frontend already signs during deposit, via an existing `personalSign` helper).

Additionally, for server-custody accounts **`to` MUST equal the bound `deposit_address`.** This is defence in depth, deliberately kept even though the signature already binds `to`: the rebind path is exactly where this design's first version failed, so a second, independent constraint on the destination is justified. Caller-signed accounts keep a free `to` — they are the explicit advanced mode and have cryptographically consented to the destination (deposit from a hot wallet, withdraw to a cold one).

`lp_withdraw` moves value to the account's **own** internal balance, not to an L1 address — there is no `to`. Only the signature dimension applies.

### 2. Rebind lock (SEC-021b)

`account_set_deposit_address` gains a rule: **if the account is already bound, the request must also carry a signature from the currently bound address** over a rebind digest. Both signatures are required — the new address proves control (unchanged), the old address authorizes the transfer of the binding.

```
rebind_auth_digest(owner, old_addr, new_addr)
    = keccak256( "dark-perp:rebind-deposit:" ‖ owner(32) ‖ old(20) ‖ new(20) )
```

Binding both addresses stops a signature authorizing a move to *one* destination being reused to authorize a move to another. First-time binding (`deposit_address == None`) is unchanged — one signature from the address being bound.

This also closes the authorize/confirm griefing window noted above.

Fix the now-false comment at `main.rs:958` (*"Bound once"*) to describe the real rule.

### 3. Digest construction

New gateway-local helpers, placed beside `deposit_bind_digest` and following it exactly:

```
withdraw_auth_digest(chain_id, vault, owner, market_id, amount, to, nonce)
    = keccak256( "dark-perp:withdraw:" ‖ chain_id(u64 BE, 8) ‖ vault(20)
                 ‖ owner(32) ‖ market_id(u64 BE, 8) ‖ amount(i128 BE, 16)
                 ‖ to(20) ‖ nonce(u64 BE, 8) )

lp_withdraw_auth_digest(chain_id, vault, owner, shares, nonce)
    = keccak256( "dark-perp:lp-withdraw:" ‖ chain_id(u64 BE, 8) ‖ vault(20)
                 ‖ owner(32) ‖ shares(u128 BE, 16) ‖ nonce(u64 BE, 8) )
```

**Why gateway-local ASCII prefixes rather than a new `Domain` variant.** This is a gateway authorization decision — it never enters the proven state, so it has no reason to live in `perp-core`. More decisively, `perp-core` compiles into the SP1 guest: touching it risks changing the guest ELF, hence the vkey, hence a verifier redeploy. That failure mode is on record — GATE-1 caught a guest-ELF drift against verifier `0xCbdD`'s vkey `0x00f4a710` and forced a fresh deploy. `deposit_bind_digest` uses an ASCII prefix for exactly this reason; we follow it.

**Why `chain_id` + `vault` are in the preimage (deployment separator).** The snapshot serializes whole `Account`s including `owner`, `signer` and `last_withdraw_nonce` (`main.rs:1568`). Without a deployment separator, a snapshot restored or copied to another deployment would accept the *same* signature — and because the signed authorization nonce is **not** the withdrawal-leaf nonce (that comes from the gateway-global `next_withdraw_nonce`, `main.rs:1894`), one signed authorization could become different claim leaves on different deployments. `chain_id` and the vault address are already held by `GatewaySigner` (`main.rs:3966-3980`). **The plan must specify the value used when no L1 is configured (dev/demo) and make it explicit, not incidental.**

**Why `owner` is in the digest.** Without it, a signature is replayable across two accounts registered to the same address. Binding `owner` makes each signature usable by exactly one account.

**Why no length prefixes.** Every field is fixed-width, so the concatenation is unambiguous by construction — no variable-length field can create a canonicalization collision. The distinct ASCII prefixes additionally make each digest unusable against the other flows.

Adversarial review found **no** practical replay from these digests into an order hash, a deposit bind, the gateway's deposit authorization, or a raw Ethereum transaction — those preimages are structurally different, so reuse would require a Keccak collision.

### 4. Signature verification

Rename `deposit_bind_prehash_candidates` → **`eip191_prehash_candidates(digest) -> [[u8;32];3]`** and share it. The body is already generic; only the name is bind-specific. Update the existing call site (`main.rs:1695`) and its tests.

```
sig = parse_hex65(req.signature)                          // else reject
ok  = eip191_prehash_candidates(digest).iter()
          .any(|p| recover_eth_address(p, &sig) == Some(authorizing_address))
```

**Security invariant (restate in the code comment):** all three candidates are deterministic transforms of the *same* digest, so no attacker-chosen preimage ever enters the hash. Accepting any of them widens signer ergonomics, never authorization.

**Why three candidates when the order path accepts only the raw digest.** Order signing targets bots and CLI clients, which sign raw digests happily. A withdrawal is confirmed by a human in a browser wallet, and MetaMask refuses to sign a raw digest — `personal_sign` always prepends the EIP-191 prefix. The deposit-bind path already accepts all three for this reason.

Malleability, as verified: high-`s` is rejected inside `k256`'s verification primitive, so `recover_eth_address` is safe. Note however that it accepts `v` in `0..3` **and** `27..30`, whereas the Solidity paths accept only `27/28` (`CollateralVault.sol:138`, `DarkPerpSettlement.sol:468`) — not an authorization issue (these signatures stay gateway-local), but the comment at `main.rs:3940` claiming it behaves "exactly as the contract's `ecrecover`" is inaccurate and should be corrected.

### 5. Replay protection

`Account` gains one field:

```rust
/// Strictly-increasing nonce of the last SUCCESSFULLY COMPLETED signed
/// withdrawal (account or LP). Separate from `last_signed_nonce` (orders) so a
/// high-frequency order stream cannot invalidate a signed withdrawal in flight.
#[serde(default)]
last_withdraw_nonce: u64,
```

- **Separate from the order nonce.** Orders are high-frequency; a shared counter would let orders racing past nonce *N* invalidate an already-signed withdrawal.
- **Shared between the two withdrawal flows.** The digests are domain-separated, so cross-replay is impossible regardless; a second counter would be redundant state.

**Commit point — commit the nonce only after the entire withdrawal succeeds.** Verifying the signature at the top but committing the nonce there would let a validly signed request consume its nonce and *then* fail on insufficient settled balance (`main.rs:1888`) or insufficient shares/pool liquidity (`main.rs:2814`); the user's retry of the unchanged signed request would then be rejected as a replay. Verify early, mutate the nonce last.

Confirmed sound by review: the global gateway lock serializes both HTTP flows; a recorded-but-unsettled withdrawal must consume its nonce; and settlement rollback must **not** roll it back — rollback requeues the original ops and withdrawals rather than undoing them (`main.rs:2029`, `sequencer/src/lib.rs:1121`).

### 6. Enforcement point

Checks belong in the engine methods, not the HTTP handlers — every existing unit test calls `gw.account_withdraw(...)` directly, so a handler-only fix would leave the regression tests unable to observe the hole, and the invariant should bind to the method rather than to one call path.

But `lp_withdraw` **cannot** simply gain a top-level `accounts.get(share_key)` check: the legacy demo handler calls it with `share_key = gw.user.owner`, which is not an entry in `accounts` (`main.rs:5044`), and that would break the demo LP UI. Silently skipping authorization for non-account keys would hollow out the invariant.

Therefore:

- `Gw::lp_withdraw` stays the **raw engine primitive** (unauthenticated by contract, legacy/demo keeps calling it — and legacy routes are prod-disabled anyway).
- New **`Gw::account_lp_withdraw(key, shares, nonce, sig)`** performs authorization, then delegates. `post_v1_lp_withdraw` calls this.
- `account_lp_withdraw` **derives** the withdrawer wallet from the account rather than accepting it as a parameter, removing the dual-identity hazard in `lp_withdraw(share_key, withdrawer, …)` where a caller could pair them incorrectly.

`account_withdraw` is already account-scoped, so it gains its checks in place.

Confirmed by review: the only runtime `BatchOp::Withdraw { to: Some(..) }` — i.e. the only producer of an L1-claimable leaf — is inside `account_withdraw` (`main.rs:1911`); LP and legacy burns use `to: None`.

### 7. Request schema

Mirrors `OrderReq`'s shape:

```rust
struct WithdrawReq   { market_id, amount, to,
                       #[serde(default)] nonce: Option<u64>,
                       #[serde(default)] signature: Option<String> }
struct LpWithdrawReq { shares,
                       #[serde(default)] nonce: Option<u64>,
                       #[serde(default)] signature: Option<String> }
```

Both are now **required at runtime for every account**; the fields stay `Option` at the type level only so a missing one produces a clean domain error in the existing wording style rather than a serde rejection. Note `LpWithdrawReq` is shared with the legacy demo handler (`main.rs:5029`), which ignores the new fields.

### 8. Error handling

All authorization checks run **before the first `seq.apply(...)`**. Every rejection returns `Err` with no state mutation and no nonce advance. Messages follow the existing style: specific enough to debug, leaking no account state.

## State / snapshot impact

`Account` is serialized into the postcard snapshot, and postcard is positional — a trailing field added with `#[serde(default)]` may still fail to load an older snapshot with an EOF error, despite the claim at `main.rs:976` that this keeps pre-upgrade snapshots loadable. **The plan must test this rather than assume it**, and record the true answer.

In practice this is unlikely to bite: the forge-audit remediation (`a413750`) is merged but not yet deployed and already requires fresh `Settlement`/`Vault`/`USDC` contracts (3 new constructor params) plus a snapshot wipe. This fix rides that same redeploy.

## Pre-rollout verification

The source establishes that the *bundled frontend* registers server-custody accounts; it cannot establish what the *live snapshot* contains. Before deploying, inspect live state for:

- accounts with `signer: Some(..)` (caller-signed accounts in the wild),
- funded accounts with `deposit_address: None` — these become non-withdrawable under the new rule and need an operator path.

## Dev/test impact

`account_deposit` credits unbound accounts outside production (`main.rs:2101-2111`), and existing tests withdraw from such accounts (e.g. `main.rs:8870`). Those accounts have no authorizing address and would become non-withdrawable. The plan must choose and justify a single approach — bind an address in the test/dev fixtures, or provide an explicit non-production exemption — and apply it consistently.

## Testing

**The regression test that would have caught the original bug** — a caller-signed account calling `account_withdraw` with no signature must return `Err`, with balance, state root **and `last_withdraw_nonce`** unchanged.

**The regression test for SEC-021b** — an attacker holding only the API key must not be able to rebind a bound account to an address they control, then withdraw to it. This is the full exploit chain and it must be expressed as one test.

| Case | Expected |
|---|---|
| Server-custody, valid signature from bound address, `to` == bound address | accepted |
| Server-custody, valid signature, `to` != bound address | rejected |
| Server-custody, no signature | rejected |
| Server-custody, signature from a non-bound address | rejected |
| Server-custody, no bound address and no signer | rejected |
| Caller-signed, valid signature, arbitrary `to` | accepted |
| Caller-signed, no signature | rejected |
| Caller-signed, signature by the wrong key | rejected |
| Both `signer` and `deposit_address` set | `signer` authorizes; a `deposit_address` signature is rejected |
| Valid signature, tampered `amount`/`to`/`marketId` in the body | rejected |
| Same `(nonce, signature)` replayed | rejected |
| Nonce not strictly increasing | rejected |
| Valid signature that then fails on insufficient balance, retried unchanged | **accepted on retry** (nonce was not burned) |
| `withdraw` signature replayed against `lp_withdraw` | rejected (domain separation) |
| Signature from account A replayed on account B, same signer | rejected (`owner` binding) |
| Signature valid for another `chain_id`/`vault` | rejected (deployment separator) |
| Rebind with only the new address's signature | rejected |
| Rebind with both signatures | accepted |
| First-time bind with one signature | accepted (unchanged) |
| All three EIP-191 prehash shapes | each accepted |
| Every rejection above | state root **and** `last_withdraw_nonce` unchanged |

The last row matters: `last_withdraw_nonce` lives in `Account`, **outside** `seq.state.state_root()`, so a state-root assertion alone cannot detect a wrongly-burned nonce. Assert the account nonce explicitly.

The three-shape test mirrors the existing deposit-bind test at `main.rs:7935-8007`. Existing deposit-bind tests must still pass after the helper rename.

## Frontend

Withdrawal becomes a wallet-signed action, mirroring the existing deposit-bind flow:

- **`v1_account`** (`main.rs:2467-2475`) must return `depositAddress`, `callerSigned` and `nextWithdrawNonce` — the client currently persists only `{apiKey, owner}` (`realClient.ts:495`) and cannot otherwise tell bound from unbound after a reload, nor pick a valid nonce.
- **`AccountPanel.tsx`** — replace the free-text destination input (`:126`) with the bound address shown read-only; build the digest, obtain a signature via the existing `personalSign` helper, and submit it with the withdrawal. If no address is bound, guide the user to bind one first.
- **`realClient.requestWithdrawal`** (`:722-734`) — send `nonce` + `signature`.
- **`realClient.test.ts`** — update request-body expectations at `:423`, `:428`, `:446`, `:543`.

This also closes the adjacent wrong-address-withdrawal class: users can no longer mistype a destination.

## Documentation

- **`docs/API.md`** — withdrawal section: the signature/nonce requirement for **both** account types, the `to` rule, and the rebind rule.
- **`main.rs` OpenAPI blob** (~`:4844`) — new `nonce`/`signature` fields on the withdrawal endpoints; `depositAddress`/`callerSigned`/`nextWithdrawNonce` on `/v1/accounts/me`.
- **`docs/public-site/api.html`, `docs/public-site/trading.html`** — same, user-facing.
- **`docs/SECURITY.md`** — record SEC-021 and SEC-021b with their resolutions.
- **Comment corrections:** `main.rs:958` (*"Bound once"* — false), `main.rs:3940` (*"exactly as the contract's `ecrecover`"* — inaccurate on `v`).
- **Pre-existing doc gap, fixed here:** `docs/API.md:134-152` never states that the caller-signed *order* signature is over the **raw digest** (no EIP-191 prefix). Document it, and document that withdrawal signatures accept all three EIP-191 shapes.
