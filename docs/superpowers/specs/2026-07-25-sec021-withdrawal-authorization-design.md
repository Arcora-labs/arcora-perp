# SEC-021 Remediation — Withdrawal Authorization (caller signature + `to` binding) — Design

**Finding:** SEC-021 [high, broken-authz] — the gateway's withdrawal path skips the signature check the account explicitly bought. An account registers **caller-signed** mode by POSTing `{"signer":"0x…"}` to `/v1/accounts` (`main.rs:4296-4319`), whose stated purpose is that *a leaked API key alone cannot act*. The order path honours that: `account_place_order` requires a secp256k1 signature recovering to the registered `signer` plus a strictly-increasing nonce on **every** order (`main.rs:2268-2333`), commented *"A caller-signed account requires the caller's own secp256k1 signature on every order, so a leaked API key alone cannot trade."*

The withdrawal path carries no such guarantee. `WithdrawReq` has no signature field at all — only `{ marketId, amount, to }` (`main.rs:3889-3894`); `post_v1_withdraw` authorizes on `X-Api-Key` alone (`main.rs:4470-4486`); and `account_withdraw` never reads `acct.signer` before recording the withdrawal leaf (`main.rs:1875-1934`). The destination `to` is fully attacker-chosen — `parse_addr20_hex` validates only the format, with no requirement that it match the account's bound deposit address (`main.rs:4478-4481`).

So **the lowest-value operation (an order) is signature-protected while the highest-value one (moving money out) is bearer-token-only** — the protection the account specifically opted into is absent on exactly the path where funds leave.

**Exploit:** a leaked API key for a caller-signed account (the precise scenario the feature exists to survive: a relayer, a logged `X-Api-Key` header, compromised browser storage). The attacker cannot trade — no signing key — but `POST /v1/accounts/withdraw {marketId, amount, to: <attacker>}` succeeds with no signature, records a withdrawal leaf bound to the attacker's address, and after the next L1 settle the attacker collects USDC via `CollateralVault.claim`.

## Scope

- **`crates/gateway` only.** No `perp-core`, no `sequencer`, no Solidity, no circuit change.
- **`Gw::account_withdraw`** — enforce the authorization rules below before any state mutation.
- **`Gw::lp_withdraw`** — same enforcement, symmetric (signature dimension only; see §1).
- **New gateway-local digest helpers** + one shared EIP-191 prehash helper generalized from the existing deposit-bind code.
- **`Account`** gains one field: `last_withdraw_nonce: u64`.
- **Frontend** (`AccountPanel.tsx`, `realClient.ts` + tests) — the withdrawal destination becomes the bound deposit address rather than free text.
- **Docs** — `docs/API.md`, the in-`main.rs` OpenAPI blob, `docs/public-site/{api,trading}.html`, `docs/SECURITY.md`.

**Non-goals / deferred:**

- **`deposit_authorize` signature** — deliberately out of scope. A leaked key there lets an attacker authorize a deposit *into the victim's account*: giving money away, not taking it. The security report grouped it with the withdrawal finding as "same pattern, same risk"; that is an overstatement. Tracked separately, low priority.
- **EIP-712 typed data** for the withdrawal signature — genuinely better wallet UX (the wallet renders "withdraw 2000 USDC to 0x…" instead of a hex blob to blind-sign), but it introduces typehash/`chainId`/`verifyingContract` machinery with no precedent in this repo, and no caller-signed frontend exists yet to benefit. Revisit when one does.
- **Signature mode for server-custody accounts** — Phase-0 custody is the documented design; unchanged.
- The report's other two items (AttestationRegistry not wired to the settlement contract; the live prover running `DEV_INSECURE`) are separate workstreams, already tracked.

## Current state (grounding)

- **`Account`** (`main.rs:949-989`): `signer: Option<[u8;20]>`, `last_signed_nonce` (orders), `last_sealed_nonce` (sealed-order replay), `deposit_address: Option<[u8;20]>`, `deposit_authorizations`.
- **Order signature verification** (`main.rs:2320-2334`): `parse_hex65` → `recover_eth_address(&order_hash, &sig)` against the registered signer → commit `last_signed_nonce`. **Raw digest only, one prehash candidate, no EIP-191.**
- **Deposit-address bind** (`main.rs:1688-1702`): the one place that accepts EIP-191. `deposit_bind_digest(owner, addr) = keccak256("dark-perp:bind-deposit:" ‖ owner ‖ addr)` (`main.rs:4073-4080`); `deposit_bind_prehash_candidates(digest) -> [[u8;32];3]` (`main.rs:4088-4124`) returns (a) the raw digest, (b) EIP-191 over the 32 raw bytes, (c) EIP-191 over the `"0x…"` hex string. The frontend signs via `personal_sign` (`frontend/src/api/wallet.ts:248-251`).
- **Deposit crediting already requires a bound address** (`main.rs:1791-1803`): an unbound account is refused with *"Bind a deposit address first"*. **Consequence: in production every account holding on-chain-deposited funds already has `deposit_address == Some(...)`.**
- **Legacy `/api/*` mutation routes are omitted in production** (`main.rs:5334-5349`, audit DP-010), so they are not an alternate path to this bug.
- **No caller-signed client exists in the wild.** The frontend registers with a bodyless POST (`frontend/src/api/realClient.ts:503`) → every live account is server-custody. Caller-signed mode is reachable only via raw API + docs (`docs/API.md:134-152`) and two Rust unit tests (`main.rs:7739`, `:8178`).
- **`/v1/lp/withdraw` has no client at all** — the frontend LP UI calls the legacy `/api/lp/withdraw` (`frontend/src/components/LpVault.tsx:66`).
- **`Domain` enum** (`perp-core/src/hash.rs:34-172`) is dense `1..=32`, next free discriminant 33, with a density + pairwise-distinctness test at `hash.rs:225-283`.

**What this means for priority:** the `to` binding is what protects today's live users (all server-custody); the signature enforcement fulfils the documented promise of a mode currently only reachable through the raw API. Both ship together.

## Design

### 1. Authorization rules

| Account type | Signature | `to` constraint |
|---|---|---|
| Server-custody (`signer: None`) | none (Phase-0 custody, unchanged) | **`to` MUST equal the bound `deposit_address`.** No bound address ⇒ withdrawal refused |
| Caller-signed (`signer: Some`) | **required** — secp256k1 over the withdrawal digest, recovering to `signer` | free — the signature already binds `to` |

Rationale for the asymmetry: each mode gets the strongest guarantee it can offer. A server-custody account has no signing key, so pinning the destination is its only defence against a leaked API key — and it costs nothing operationally, since funds can only enter through a bound address anyway. A caller-signed account has cryptographically consented to the exact destination, so restricting it further would break a legitimate flow (deposit from a hot wallet, withdraw to a cold one) while adding no security.

`lp_withdraw` moves value to the account's **own** internal balance, not to an L1 address — there is no `to`. Only the signature dimension applies there.

### 2. Digest construction

New gateway-local helpers, placed beside `deposit_bind_digest` and following it exactly:

```
withdraw_auth_digest(owner, market_id, amount, to, nonce)
    = keccak256( "dark-perp:withdraw:" ‖ owner(32) ‖ market_id(u64 BE, 8)
                 ‖ amount(i128 BE, 16) ‖ to(20) ‖ nonce(u64 BE, 8) )

lp_withdraw_auth_digest(owner, shares, nonce)
    = keccak256( "dark-perp:lp-withdraw:" ‖ owner(32) ‖ shares(u128 BE, 16) ‖ nonce(u64 BE, 8) )
```

**Why gateway-local ASCII prefixes rather than a new `Domain` variant.** This is a gateway authorization decision — it never enters the proven state, so it has no reason to live in `perp-core`. More decisively, `perp-core` compiles into the SP1 guest: touching it risks changing the guest ELF, hence the vkey, hence a verifier redeploy. That failure mode is on record — GATE-1 caught a guest-ELF drift against verifier `0xCbdD`'s vkey `0x00f4a710` and forced a fresh deploy. `deposit_bind_digest` uses an ASCII prefix for exactly this reason; we follow it.

**Why `owner` is in the digest.** Without it, a signature is replayable across two accounts registered to the same signer address — a user may hold several. Binding `owner` makes each signature usable by exactly one account. (Same rationale as `deposit_bind_digest`, whose comment records it.)

**Why no length prefixes.** Every field is fixed-width (32/8/16/20/8), so the concatenation is unambiguous by construction — there is no variable-length field that could create a canonicalization collision. The two distinct ASCII prefixes additionally make a `withdraw` signature unusable against `lp_withdraw`.

### 3. Signature verification

Rename `deposit_bind_prehash_candidates` → **`eip191_prehash_candidates(digest) -> [[u8;32];3]`** and share it. The body is already fully generic; only the name is bind-specific. Update the existing call site (`main.rs:1695`) and its tests.

Verification mirrors the order path:

```
sig   = parse_hex65(req.signature)                         // else reject
ok    = eip191_prehash_candidates(digest).iter()
            .any(|p| recover_eth_address(p, &sig) == Some(registered_signer))
```

**Security invariant (must be restated in the code comment):** all three candidates are deterministic transforms of the *same* digest, so no attacker-chosen preimage ever enters the hash. Accepting any of them widens signer ergonomics, never authorization.

**Why three candidates here when the order path accepts only the raw digest.** Order signing targets bots and CLI clients, which sign raw digests happily. A withdrawal is the operation a human confirms in a browser wallet, and MetaMask refuses to sign a raw digest — `personal_sign` always prepends the EIP-191 prefix. The deposit-bind path already accepts all three for precisely this reason, and the frontend already has a working `personalSign` helper.

### 4. Replay protection

`Account` gains one field:

```rust
/// Strictly-increasing nonce of the last accepted caller-signed WITHDRAWAL
/// (account or LP). Separate from `last_signed_nonce` (orders) so a
/// high-frequency order stream cannot invalidate a signed withdrawal in flight.
#[serde(default)]
last_withdraw_nonce: u64,
```

- **Separate from the order nonce.** Orders are high-frequency; sharing one counter would let orders racing past nonce *N* invalidate an already-signed withdrawal.
- **Shared between the two withdrawal flows.** The digests are domain-separated, so cross-replay is impossible regardless; a second counter would be redundant state. One client, one counter.

Rule, identical to the order path: reject if `n <= acct.last_withdraw_nonce`; on acceptance set `acct.last_withdraw_nonce = n` — **only after verification passes**.

### 5. Enforcement point

Checks go at the **top of `Gw::account_withdraw` and `Gw::lp_withdraw`**, not in the HTTP handlers.

The security report recommends fixing the handlers. Enforcing in the engine methods is strictly stronger:

- Every existing unit test calls `gw.account_withdraw(...)` directly, bypassing HTTP. A handler-only fix would leave the regression tests unable to observe the hole.
- The invariant then belongs to the method rather than to one call path, so any future caller inherits it.

Handlers only parse the new optional fields and pass them down.

### 6. Request schema

Mirrors `OrderReq`'s shape; both fields optional at the type level, required at runtime for caller-signed accounts:

```rust
struct WithdrawReq   { market_id, amount, to,
                       #[serde(default)] nonce: Option<u64>,
                       #[serde(default)] signature: Option<String> }
struct LpWithdrawReq { shares,
                       #[serde(default)] nonce: Option<u64>,
                       #[serde(default)] signature: Option<String> }
```

Server-custody accounts omit both (ignored if sent). Caller-signed accounts must supply both; a missing field is rejected in the same wording style as the order path (*"caller-signed account: `signature` is required"*).

### 7. Error handling

All authorization checks run **before the first `seq.apply(...)`**. Every rejection returns `Err` with no state mutation — verified by test (§8) asserting the state root is unchanged after each rejected call. Messages follow the existing style: specific enough to debug, leaking no account state.

## State / snapshot impact

`Account` is serialized into the postcard snapshot, and postcard is positional — a trailing field added with `#[serde(default)]` may still fail to load an older snapshot with an EOF error, despite the claim at `main.rs:976` that this keeps pre-upgrade snapshots loadable. **The plan must test this rather than assume it**, and record the true answer.

In practice this is unlikely to bite: the forge-audit remediation (`a413750`) is merged but not yet deployed and already requires fresh `Settlement`/`Vault`/`USDC` contracts (3 new constructor params) plus a snapshot wipe. This fix rides that same redeploy.

## Testing

**The regression test that would have caught this bug** — a caller-signed account calling `account_withdraw` with no signature must return `Err`, with balance and state root unchanged. No such test exists today.

Full matrix:

| Case | Expected |
|---|---|
| Server-custody, `to` == bound address | accepted |
| Server-custody, `to` != bound address | rejected |
| Server-custody, no bound address | rejected |
| Caller-signed, valid signature, arbitrary `to` | accepted |
| Caller-signed, no signature | rejected |
| Caller-signed, signature by the wrong key | rejected |
| Caller-signed, valid signature but tampered `amount`/`to` in the body | rejected |
| Same `(nonce, signature)` replayed | rejected |
| Nonce not strictly increasing | rejected |
| `withdraw` signature replayed against `lp_withdraw` | rejected (domain separation) |
| Signature from account A replayed on account B, same signer | rejected (`owner` binding) |
| All three EIP-191 prehash shapes | each accepted |
| Every rejection above | state root unchanged |

The three-shape test mirrors the existing deposit-bind test at `main.rs:7935-8007`. Existing deposit-bind tests must still pass after the helper rename.

## Frontend

- **`AccountPanel.tsx`** — replace the free-text destination input (`:126`, currently a user-typed `dest`) with a read-only display of the bound deposit address, sent as `to`. If no address is bound, guide the user to bind one first instead of offering a withdrawal that will be refused.
- **`realClient.requestWithdrawal`** (`:722-734`) — send the bound address.
- **`realClient.test.ts`** — update the request-body expectations at `:423`, `:428`, `:446`, `:543`.

This also closes the adjacent wrong-address-withdrawal class: users can no longer mistype a destination.

## Documentation

- **`docs/API.md`** — withdrawal section: the new `to` rule and the caller-signed signature/nonce requirement.
- **`main.rs` OpenAPI blob** (~`:4844`) — new `nonce`/`signature` fields on the withdrawal endpoints.
- **`docs/public-site/api.html`, `docs/public-site/trading.html`** — same, user-facing.
- **`docs/SECURITY.md`** — record SEC-021 and its resolution.
- **Pre-existing doc gap, fixed here:** `docs/API.md:134-152` never states that the caller-signed *order* signature is over the **raw digest** (no EIP-191 prefix). Document it, and document that the withdrawal signature accepts all three EIP-191 shapes.
