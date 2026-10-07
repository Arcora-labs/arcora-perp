# SEC-028 Deposit Authorization Replay — Implementation Plan


**Goal:** Make a gateway deposit authorization one-shot on-chain, so a replayed signature can no longer mint a second, permanently uncreditable leaf that wedges the deposit queue forever.

**Architecture:** One `mapping(bytes32 => bool)` on `CollateralVault`, marked inside `deposit` **after** signature recovery and **before** `transferFrom`. The signature ABI, the leaf, the fold and every cross-layer KAT are untouched.

**Tech Stack:** Solidity (Foundry). No Rust change, no gateway change.

## Global Constraints

- **`crates/perp-core` is NOT touched, and neither is any Rust crate.** This is a contract-only change. No vkey, no root, no snapshot or journal magic moves. If a task seems to need a Rust change, stop and report.
- **The signature ABI does not change.** No new parameter, no re-signing scheme, no change to what the gateway signs. The whole point of keying on the digest is that the existing scheme stays.
- **Never deploy. Never push.** Commit on the branch only.
- Baselines to preserve: `cd contracts && forge test` = **85 passed**; `cargo test --workspace` = **593 / 50 suites** (must be untouched — if it moves, something Rust-side changed and that is a defect); `cargo fmt --all --check` and `cargo clippy --workspace --all-targets` clean.
- Comments explain **why**. A claim in a comment must be one the code can actually perform — every must-fix in the last two branch reviews was prose that broke this rule.

## Background the implementer needs

`deposit` takes a gateway signature over `keccak256(chainid ‖ vault ‖ from ‖ ownerCommit ‖ amount)` and the contract's own doc says why: *"every leaf that can enter the chain is creditable off-chain by construction (no uncreditable leaf can head-of-line-block the contiguous deposit queue)."*

**That invariant does not hold.** The signature is verified and discarded, binds no nonce and no id (deliberately — the gateway cannot predict the landing index at signing time), and nothing marks it consumed. So the same tuple can be submitted repeatedly, each call minting a fresh leaf. Off-chain, the gateway deletes the authorization after the first credit, so the second leaf hits the fail-closed SEC-019 misattribution guard and can never be credited — and because deposits are credited in strict contiguous order, it blocks every deposit behind it forever. Re-authorizing mints a fresh blind and a different `ownerCommit`, so it cannot rescue the stuck leaf.

Cost to an attacker: two base units of USDC plus gas. Blast radius: deposits die for everyone; settlement and withdrawals keep working.

---

### Task 1: Consume the authorization on-chain

**Files:**
- Modify: `contracts/src/CollateralVault.sol`
- Test: `contracts/test/CollateralVault.t.sol`

**Interfaces:**
- Produces: `mapping(bytes32 => bool) public usedDepositAuthorization;` and `error AuthorizationAlreadyUsed();`

- [ ] **Step 1: Write the failing tests**

Add to `contracts/test/CollateralVault.t.sol`. **Read the file first** — it already has a gateway-signing helper and a deposit helper; reuse them rather than adding siblings, and match its existing naming. The shape of the signing helper in this repo is:

```solidity
    function _gwSig(address from, uint256 amount, bytes32 commit) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(vault), from, commit, amount));
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(GW_PK, digest);
        return abi.encodePacked(r, sg, v);
    }
```

```solidity
    /// SEC-028: the same signed tuple must not mint a second leaf. Before this, a
    /// depositor could replay their own authorization, and because the gateway consumes
    /// its stored blind on the FIRST credit, the second leaf became permanently
    /// uncreditable and head-of-line-blocked the contiguous deposit queue for EVERYONE.
    function test_replayed_authorization_is_refused() public {
        uint256 amount = 1_000 * USD;
        bytes memory sig = _gwSig(alice, amount, TEST_OWNER_COMMIT);
        usdc.mint(alice, amount * 2);
        vm.startPrank(alice);
        usdc.approve(address(vault), amount * 2);
        vault.deposit(amount, TEST_OWNER_COMMIT, sig);

        // The leaf state BEFORE the replay — read into locals, because expectRevert
        // binds to the very next external call.
        uint64 countBefore = vault.depositCount();
        bytes32 tipBefore = vault.depositChainTip();

        vm.expectRevert(CollateralVault.AuthorizationAlreadyUsed.selector);
        vault.deposit(amount, TEST_OWNER_COMMIT, sig);
        vm.stopPrank();

        // The wedge came from a LEAF EXISTING AT ALL, not from the call succeeding — so
        // proving no leaf was minted is the point, not merely that it reverted.
        assertEq(vault.depositCount(), countBefore, "no leaf may be minted by a replay");
        assertEq(vault.depositChainTip(), tipBefore, "the chain tip must not move");
    }

    /// A failed transfer must roll the mark back with the rest of the call, or a
    /// legitimate depositor whose approval was short is stranded permanently.
    function test_a_failed_transfer_leaves_the_authorization_usable() public {
        uint256 amount = 1_000 * USD;
        bytes memory sig = _gwSig(alice, amount, TEST_OWNER_COMMIT);
        usdc.mint(alice, amount);
        vm.startPrank(alice);
        // No approval yet: transferFrom fails, so the whole call must revert.
        vm.expectRevert();
        vault.deposit(amount, TEST_OWNER_COMMIT, sig);

        // …and the SAME signature still works once the approval is there.
        usdc.approve(address(vault), amount);
        vault.deposit(amount, TEST_OWNER_COMMIT, sig);
        vm.stopPrank();
        assertEq(vault.depositCount(), 1, "the retry must be creditable");
    }

    /// The mapping must not be over-broad: a different authorization is unaffected.
    function test_a_distinct_authorization_still_deposits() public {
        uint256 a1 = 1_000 * USD;
        uint256 a2 = 2_000 * USD;
        usdc.mint(alice, a1 + a2);
        vm.startPrank(alice);
        usdc.approve(address(vault), a1 + a2);
        vault.deposit(a1, TEST_OWNER_COMMIT, _gwSig(alice, a1, TEST_OWNER_COMMIT));
        vault.deposit(a2, TEST_OWNER_COMMIT, _gwSig(alice, a2, TEST_OWNER_COMMIT));
        vm.stopPrank();
        assertEq(vault.depositCount(), 2, "a different digest must be independent");
    }

    /// An unsigned or wrongly-signed call must burn nothing: the digest it presented
    /// stays usable by its legitimate holder afterwards.
    function test_a_bad_signature_does_not_consume_the_authorization() public {
        uint256 amount = 1_000 * USD;
        bytes memory good = _gwSig(alice, amount, TEST_OWNER_COMMIT);
        bytes memory bad = _badSig(alice, amount, TEST_OWNER_COMMIT);
        usdc.mint(alice, amount);
        vm.startPrank(alice);
        usdc.approve(address(vault), amount);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount, TEST_OWNER_COMMIT, bad);
        vault.deposit(amount, TEST_OWNER_COMMIT, good);
        vm.stopPrank();
        assertEq(vault.depositCount(), 1, "a rejected signature must not burn the digest");
    }
```

**Implementer note:** `_badSig` signs with a key that is not `GW_PK`. If the test file already has such a helper, use it; otherwise add one beside `_gwSig` in the same style. `alice`, `USD` and `TEST_OWNER_COMMIT` are existing fixtures in this file — **verify their names before use** and report if they differ.

- [ ] **Step 2: Run to confirm they fail**

Run: `cd contracts && forge test --match-test test_replayed_authorization_is_refused -vv`
Expected: FAIL — the error type does not exist yet, so the file will not compile. Once you add the error but not the check, expect the assertion to fail because the replay succeeds and `depositCount` is 2. **Report which of the two you observed** — a compile failure is not evidence that the behaviour is wrong, only that the test is new.

- [ ] **Step 3: Implement**

Add the error beside the others (~`:103-116`):

```solidity
    error AuthorizationAlreadyUsed();
```

Add the mapping beside `claimed` and `rootPublished`, which are the file's existing one-shot idiom, with the rationale:

```solidity
    /// SEC-028: gateway authorizations already consumed. `deposit`'s signature binds
    /// (chainid, vault, from, ownerCommit, amount) and deliberately NOT `depositCount` —
    /// the gateway cannot predict the landing index at signing time. Without this mapping
    /// the same tuple mints a fresh leaf on every submission, and since the gateway
    /// consumes its stored blind on the FIRST credit, every later identical leaf is
    /// permanently uncreditable and head-of-line-blocks the contiguous deposit queue.
    /// That is exactly the property `deposit`'s own doc claims the signature establishes;
    /// this mapping is what actually establishes it.
    ///
    /// Keyed on the DIGEST, not the signature bytes: replay protection should bind the
    /// authorization, not one serialization of it.
    mapping(bytes32 => bool) public usedDepositAuthorization;
```

In `deposit`, after the `_recover` check and **before** `transferFrom`:

```solidity
        // Placement is load-bearing in BOTH directions. After `_recover`, so an unsigned
        // or wrongly-signed call cannot burn a digest it never had the right to spend.
        // Before `transferFrom`, so a failed transfer reverts the whole call and rolls
        // this mark back with it — leaving no state in which an authorization is consumed
        // but no leaf exists.
        if (usedDepositAuthorization[digest]) revert AuthorizationAlreadyUsed();
        usedDepositAuthorization[digest] = true;
```

- [ ] **Step 4: Run the new tests**

Run: `cd contracts && forge test --match-path test/CollateralVault.t.sol -vv`
Expected: PASS, including all four new tests.

- [ ] **Step 5: Run the WHOLE forge suite and expect breakage**

Run: `cd contracts && forge test`

**This is the step that matters.** The change makes a previously-legal pattern revert: any test that deposits **twice with the same `(from, ownerCommit, amount)`** now fails. `Integration.t.sol`'s `_deposit` helper passes a shared `TEST_OWNER_COMMIT` for every call, so this is likely, not hypothetical.

For each failure, decide and **report which**, per test:

- **The test was exercising two genuinely distinct deposits** and only happened to reuse the tuple. Vary the amount or the commit. This is the common case and it is a fixture fix, not a behaviour change.
- **The test was actually relying on replay being possible.** That is a finding, not a fixture problem — **stop and report it** rather than editing the test to match the new behaviour. A test that asserted the old, broken property is evidence about the system, and silently rewriting it would erase exactly the signal this task exists to produce.

- [ ] **Step 6: Confirm nothing Rust-side moved**

Run: `cargo test --workspace`
Expected: **593 passed / 50 suites**, unchanged. This is a contract-only change; any movement here means something else was touched and is a defect to report, not to accommodate.

- [ ] **Step 7: Commit**

```bash
git add contracts/src/CollateralVault.sol contracts/test/CollateralVault.t.sol
git commit -m "fix(vault): consume the deposit authorization on-chain (SEC-028)"
```

---

### Task 2: Correct the claims this change makes true — and the one it does not

The vault's `deposit` doc already asserts the invariant as though it held. Now it does, for the replay cause. It still does **not** hold for the second cause, and the tree must not imply otherwise.

**Files:**
- Modify: `contracts/src/CollateralVault.sol` (the `deposit` doc), `docs/superpowers/specs/2026-07-30-sec028-deposit-authorization-replay.md` (status)

- [ ] **Step 1: Make the contract's own claim precise**

The `deposit` doc says the signature ensures "every leaf that can enter the chain is creditable off-chain by construction". Amend it to say what now establishes that — the digest mapping, not the signature alone — and to name the limit: an authorization whose blind was never made durable off-chain still yields an uncreditable leaf, because the gateway stores it in memory and snapshots periodically. That is SEC-028's **second cause** and it is **not fixed here**.

- [ ] **Step 2: Update the spec's status**

Change the spec's status line from "designed" to record that the replay cause is implemented and the durability cause remains open, with the branch name. Do **not** write that SEC-028 is closed.

- [ ] **Step 3: Verify and commit**

Run: `cd contracts && forge test` and `cargo test --workspace`

```bash
git add contracts/src/CollateralVault.sol docs/superpowers/specs/2026-07-30-sec028-deposit-authorization-replay.md
git commit -m "docs(sec028): what the mapping establishes, and what it does not"
```

---

## Branch completion

- [ ] `forge test` green; `cargo test --workspace` **unchanged at 593 / 50**; fmt and clippy clean.
- [ ] Report every pre-existing forge test you had to adjust, and confirm none was relying on replay being possible.
- [ ] Request an independent review of the branch. Codex independently verified this finding and proposed this remedy over the gateway-side alternative; ask it to check the placement and the storage-write cost.
- [ ] **Do not deploy.** This is a contract change, so it needs a fresh `CollateralVault`. The cutover already deploys fresh contracts, so it costs nothing extra — but it does mean the wedge stays reachable on the currently deployed stack until then.
- [ ] **SEC-028's second cause remains open.** Authorizations live in memory until the next periodic snapshot, so a crash between issuing a signature and snapshotting still leaves an uncreditable leaf, with no attacker and no replay. 025-A works around it for its own cutover step only; ordinary users have no barrier.
