# Forge-audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three fixable-now audit findings (SEQ-001 censorship economics, EXIT-001 open-position escape, LIQ-001 privacy fail-open) and align the docs with reality.

**Architecture:** Two isolated Solidity changes in `DarkPerpSettlement.sol` (a ripeness+refund rework of the challenge game, and a `finalSettle` governance escape), one Rust change in the sequencer (secret-salt fail-closed liquidation tag-key) plus a gateway public-snapshot guard, and a documentation-honesty pass. No circuit/guest changes; no receipt-schema change.

**Tech Stack:** Solidity ^0.8.24 + Foundry (`forge`), Rust workspace (`cargo`), keccak256 domain-separated hashing (`perp_core` `Keccak256::hash_words` / `Domain`).

## Global Constraints

- Solidity pragma `^0.8.24`; no OpenZeppelin (vendored toolchain) — follow existing local `IERC20Min`/`MerkleLib` patterns.
- Rust/Solidity keccak digests that cross the boundary must stay byte-exact; **this plan introduces no new cross-boundary digest** (SEQ-001 reuses the already-signed `recvTimeMs`).
- New constructor params are appended at the END of the arg list to minimise churn.
- Pull-payment (`pendingEth`/`pendingUsdc`) is never converted to push — keep the credit-then-`claim` pattern (audit DP-011).
- `finalSettle` MUST stay proof-gated (`verifier.verify`) — the escape bypasses `closeOnly`, never the proof.
- Liquidation/ADL tags are off-chain artifacts (not in the proof commitment); the fail-closed change must NOT touch `derive_roots`/guest.
- Constructor signature changes require a fresh Settlement deploy (routine for this project); genesis root unchanged.
- Commit after every task. Run `forge fmt` before Solidity commits and `cargo fmt`/`clippy` before Rust commits.

---

### Task 1: SEQ-001 — ripeness gate on `challengeInclusion`

**Files:**
- Modify: `contracts/src/DarkPerpSettlement.sol` (constructor + immutable + error + `challengeInclusion`)
- Modify: `contracts/script/Deploy.s.sol` (new env-overridable ctor arg)
- Test: `contracts/test/DarkPerpSettlement.t.sol` (setUp ctor call + new tests + warp existing challenge tests)

**Interfaces:**
- Consumes: existing `challengeInclusion(bytes32 orderHash, uint64 seqNo, uint64 recvTimeMs, uint64 batchIdHint, uint8 v, bytes32 r, bytes32 s)`.
- Produces: new immutable `uint256 public immutable inclusionDeadlineSecs;`, new `error NotRipe();`, constructor param `_inclusionDeadlineSecs` (appended after `_challengeBond`).

- [ ] **Step 1: Write the failing test — fresh order is not challengeable**

Add to `contracts/test/DarkPerpSettlement.t.sol`. Reuse the file's existing receipt-signing pattern (`vm.sign(ENCLAVE_PK, receiptDigest(...))`). Add a test constant near the other constants (`uint256 internal constant INCLUSION_DEADLINE = 600;`) and reference it once wired into setUp (Step 3).

```solidity
function test_challenge_reverts_before_ripe() public {
    bytes32 orderHash = keccak256("ripe-order");
    uint64 recvTimeMs = 1000; // receipt "issued" at t=1s
    bytes32 digest = settlement.receiptDigest(orderHash, 1, recvTimeMs, 0);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENCLAVE_PK, digest);
    // block.timestamp is still 1 (< 1 + INCLUSION_DEADLINE): not yet ripe.
    vm.expectRevert(DarkPerpSettlement.NotRipe.selector);
    settlement.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, s);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd contracts && forge test --mt test_challenge_reverts_before_ripe -vvv`
Expected: FAIL — compile error (`NotRipe`/`inclusionDeadlineSecs` undefined) or no revert.

- [ ] **Step 3: Implement — add immutable, error, ctor param, and the gate**

In `DarkPerpSettlement.sol`:

Add the error near the other errors (after `WrongChallengeBond();`):
```solidity
    error NotRipe();
```
Add the immutable near `challengeBond`:
```solidity
    /// Seconds after a receipt's signed `recvTimeMs` before its order becomes
    /// challengeable — the §2 inclusion SLA. A fresh order cannot be challenged,
    /// so an honest sequencer's normal async settlement latency can never be
    /// free-griefed by a spam challenge (audit-P2 reconciliation, see
    /// `answerChallenge`). `recvTimeMs` is enclave-self-reported: an honest-accept-
    /// then-withhold sequencer is defended (the timestamp is fixed before the
    /// withhold decision); a fully-compromised enclave is out of scope (SEC-019).
    uint256 public immutable inclusionDeadlineSecs;
```
Append the ctor param and assignment:
```solidity
    // in the constructor signature, after `uint256 _challengeBond`:
        ,uint256 _inclusionDeadlineSecs
    // in the body, after `challengeBond = _challengeBond;`:
        inclusionDeadlineSecs = _inclusionDeadlineSecs;
```
In `challengeInclusion`, immediately AFTER the signature check
(`if (signer == address(0) || signer != enclaveSigner) revert BadReceiptSignature();`)
and BEFORE writing `challenges[orderHash]`:
```solidity
        // §2 ripeness SLA: the order must be overdue by `inclusionDeadlineSecs`
        // before it can be challenged (recvTimeMs is milliseconds).
        if (block.timestamp < recvTimeMs / 1000 + inclusionDeadlineSecs) revert NotRipe();
```

Update `setUp()` in the test: add `uint256 internal constant INCLUSION_DEADLINE = 600;` with the other constants, and append `INCLUSION_DEADLINE` to the ctor call (line ~29):
```solidity
        settlement = new DarkPerpSettlement(
            address(this), enclaveSigner, verifier, GENESIS, LIVENESS, CHALLENGE_WINDOW, CHALLENGE_BOND, INCLUSION_DEADLINE
        );
```

- [ ] **Step 4: Run the new test to verify it passes**

Run: `cd contracts && forge test --mt test_challenge_reverts_before_ripe -vvv`
Expected: PASS.

- [ ] **Step 5: Add the ripe-path test and fix the existing challenge tests**

Add:
```solidity
function test_challenge_allowed_after_ripe() public {
    bytes32 orderHash = keccak256("ripe-order");
    uint64 recvTimeMs = 1000;
    bytes32 digest = settlement.receiptDigest(orderHash, 1, recvTimeMs, 0);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENCLAVE_PK, digest);
    vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1); // now ripe
    settlement.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, s);
    (, , , , , bool open) = settlement.challenges(orderHash);
    assertTrue(open, "challenge opened once ripe");
}
```
Every EXISTING test that calls `challengeInclusion{value: CHALLENGE_BOND}(...)` (the ones at the old lines 152, 171, 204, 235, 261, 298, 345, 361, 402, 410) now needs the order to be ripe first. Immediately before each such call, insert:
```solidity
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
```
(The `recvTimeMs` in those tests is 1 or 1000, so `recvTimeMs/1000` is 0–1; warping by `INCLUSION_DEADLINE + 1` past the current timestamp clears the gate. The malleable-signature test at old line 402 reverts on the signature check before ripeness, but adding the warp is harmless and keeps the pattern uniform.)

- [ ] **Step 6: Run the full challenge suite**

Run: `cd contracts && forge test --mt "test_challenge|test_answer|test_slash|Challenge|Inclusion" -vvv`
Expected: PASS (all pre-existing challenge/answer/slash tests green with the warps; two new ripeness tests green).

- [ ] **Step 7: Wire Deploy.s.sol and commit**

In `contracts/script/Deploy.s.sol`, add near the other `vm.envOr` reads (after `challengeBond`):
```solidity
        uint256 inclusionDeadline = vm.envOr("INCLUSION_DEADLINE_SECS", uint256(600));
```
and append `inclusionDeadline` to the `new DarkPerpSettlement(...)` call (line ~72):
```solidity
        settlement = new DarkPerpSettlement(
            sequencer, enclaveSigner, verifier, genesis, liveness, challengeWindow, challengeBond, inclusionDeadline
        );
```
Run: `cd contracts && forge build && forge fmt && forge test -vvv`
Expected: build + full suite PASS.
```bash
git add contracts/src/DarkPerpSettlement.sol contracts/script/Deploy.s.sol contracts/test/DarkPerpSettlement.t.sol
git commit -m "fix(settlement): SEQ-001 ripeness gate on challengeInclusion (§2 inclusion SLA)"
```

---

### Task 2: SEQ-001 — refund rerouting on `answerChallenge`

**Files:**
- Modify: `contracts/src/DarkPerpSettlement.sol` (`answerChallenge` bond branch + comment)
- Test: `contracts/test/DarkPerpSettlement.t.sol`

**Interfaces:**
- Consumes: `Challenge.openedBlock`, `batches[batchId].settledAtBlock`, `pendingEth`.
- Produces: no new symbols; `answerChallenge` now credits the challenger when the settling batch post-dates the challenge. `answerByRejection` is unchanged (always credits the sequencer).

- [ ] **Step 1: Write the failing tests**

```solidity
function test_answer_forced_inclusion_refunds_challenger() public {
    // ripe challenge, then the order settles in a batch that post-dates the challenge.
    bytes32 orderHash = keccak256("withheld");
    uint64 recvTimeMs = 1000;
    bytes32 digest = settlement.receiptDigest(orderHash, 1, recvTimeMs, 0);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENCLAVE_PK, digest);
    address challenger = address(0xC0FFEE);
    vm.deal(challenger, CHALLENGE_BOND);
    vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
    vm.prank(challenger);
    settlement.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, s);

    // settle a batch AFTER the challenge opened, containing orderHash in orderedRoot.
    (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);

    settlement.answerChallenge(orderHash, batchId, proof);

    assertEq(settlement.pendingEth(challenger), CHALLENGE_BOND, "victim refunded");
    assertEq(settlement.pendingEth(address(this)), 0, "sequencer not paid");
    assertFalse(settlement.slashed(), "answer never slashes");
    assertFalse(settlement.closeOnly(), "answer never trips close-only");
}

function test_answer_presettled_forfeits_to_sequencer() public {
    // the order is already in a settled batch BEFORE the challenge opens.
    bytes32 orderHash = keccak256("already-in");
    (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);

    uint64 recvTimeMs = 1000;
    bytes32 digest = settlement.receiptDigest(orderHash, 1, recvTimeMs, 0);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENCLAVE_PK, digest);
    address challenger = address(0xBEEF);
    vm.deal(challenger, CHALLENGE_BOND);
    vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
    vm.prank(challenger);
    settlement.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, s);

    settlement.answerChallenge(orderHash, batchId, proof);
    assertEq(settlement.pendingEth(address(this)), CHALLENGE_BOND, "griefer forfeits to sequencer");
    assertEq(settlement.pendingEth(challenger), 0, "challenger not refunded");
}
```

If the file lacks a helper that settles a batch whose `orderedRoot` contains a single `orderHash` and returns `(batchId, proof)`, add one modelled on the existing settle/`inclusionLeaf` helpers (a single-leaf tree: `proof` is empty and `orderedRoot == inclusionLeaf(batchId, orderHash)`):
```solidity
function _settleBatchWithOrder(bytes32 orderHash) internal returns (uint256 batchId, bytes32[] memory proof) {
    batchId = settlement.batchCount();
    bytes32 ordered = settlement.inclusionLeaf(batchId, orderHash); // single-leaf root
    bytes32 prev = settlement.currentStateRoot();
    bytes32 newRoot = keccak256(abi.encodePacked("next", batchId));
    // MockZkVerifier accepts proof == publicCommitment; mirror the existing settle helpers.
    bytes32 commitment = settlement.publicCommitment(prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0));
    settlement.settleBatch(prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0), abi.encodePacked(commitment));
    proof = new bytes32[](0);
}
```
(If the test file already has an equivalent settle helper, reuse it instead of adding this — check the helpers used by the existing `test_answer_*`/`test_slash_*` tests first.)

- [ ] **Step 2: Run to verify they fail**

Run: `cd contracts && forge test --mt "test_answer_forced_inclusion_refunds_challenger|test_answer_presettled_forfeits_to_sequencer" -vvv`
Expected: FAIL (current code always credits the sequencer, so the refund assertion fails).

- [ ] **Step 3: Implement the branch**

In `answerChallenge`, replace:
```solidity
        // griefing deterrent: the challenger's stake is credited to the sequencer for pull —
        // never pushed, so a non-payable sequencer cannot brick its own answer (audit DP-011).
        pendingEth[sequencer] += c.bond;
```
with:
```solidity
        // SEQ-001 (audit-P2 reconciliation): route the challenger's stake by WHEN the
        // order settled. If it settled only AFTER this (ripe) challenge opened, the
        // challenge forced a withheld order in — make the victim whole (refund). If it
        // was already settled when challenged, the challenge was noise/griefing — forfeit
        // to the sequencer. This is a REFUND gate, not a slash gate, so P2's free-slash
        // concern does not apply; the ripeness gate (see `challengeInclusion`) already
        // makes normal-latency orders unchallengeable. No slash on answer — slashing
        // stays exclusively in `slashUnanswered`. Credited for pull, never pushed (DP-011).
        if (batches[batchId].settledAtBlock > c.openedBlock) {
            pendingEth[c.challenger] += c.bond;
        } else {
            pendingEth[sequencer] += c.bond;
        }
```
Leave `answerByRejection` unchanged (a valid rejection means the challenger was wrong — the sequencer keeps the bond). Update the `answerByRejection` bond comment to note this explicitly:
```solidity
        // A valid rejection proves the challenger was mistaken (the order was never
        // withheld, just legitimately rejected), so the stake always forfeits to the
        // sequencer here — unlike `answerChallenge`, there is no forced-inclusion refund.
        pendingEth[sequencer] += c.bond;
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd contracts && forge test --mt "test_answer_forced_inclusion_refunds_challenger|test_answer_presettled_forfeits_to_sequencer" -vvv`
Expected: PASS.

- [ ] **Step 5: Add the rejection-forfeit guard test and run full suite**

```solidity
function test_rejection_answer_always_forfeits() public {
    // Even if the rejection batch post-dates the challenge, answerByRejection pays the sequencer.
    bytes32 orderHash = keccak256("rejected-order");
    uint64 recvTimeMs = 1000;
    bytes32 digest = settlement.receiptDigest(orderHash, 1, recvTimeMs, 0);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENCLAVE_PK, digest);
    address challenger = address(0xD00D);
    vm.deal(challenger, CHALLENGE_BOND);
    vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
    vm.prank(challenger);
    settlement.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, s);

    // settle a batch (after the challenge) whose rejectedRoot contains orderHash.
    uint256 batchId = settlement.batchCount();
    bytes32 rejected = settlement.rejectionLeaf(batchId, orderHash);
    bytes32 prev = settlement.currentStateRoot();
    bytes32 newRoot = keccak256(abi.encodePacked("rej", batchId));
    bytes32 commitment = settlement.publicCommitment(prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected);
    settlement.settleBatch(prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected, abi.encodePacked(commitment));

    settlement.answerByRejection(orderHash, batchId, new bytes32[](0));
    assertEq(settlement.pendingEth(address(this)), CHALLENGE_BOND, "rejection forfeits to sequencer");
    assertEq(settlement.pendingEth(challenger), 0, "challenger not refunded on valid rejection");
}
```

Run: `cd contracts && forge fmt && forge test -vvv`
Expected: full suite PASS.

- [ ] **Step 6: Commit**

```bash
git add contracts/src/DarkPerpSettlement.sol contracts/test/DarkPerpSettlement.t.sol
git commit -m "fix(settlement): SEQ-001 forced-inclusion refund on answerChallenge (censorship no longer profitable)"
```

---

### Task 3: EXIT-001 — governance `finalSettle` escape

**Files:**
- Modify: `contracts/src/DarkPerpSettlement.sol` (state, ctor params, `closeOnlyBlock` writes, `finalSettle`, events/errors)
- Modify: `contracts/script/Deploy.s.sol` (two new env-overridable ctor args)
- Test: `contracts/test/DarkPerpSettlement.t.sol` (setUp ctor call + finalSettle tests)

**Interfaces:**
- Consumes: `publicCommitment`, `verifier.verify`, `ICollateralVault.publishWithdrawals`, `currentStateRoot`, `batchCount`.
- Produces: `uint256 public closeOnlyBlock;`, `address public immutable governance;`, `uint256 public immutable finalSettleGraceBlocks;`, `function finalSettle(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes calldata)`, `event FinalSettle(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash)`, errors `NotGovernance()`, `NotCloseOnly()`, `GraceNotExpired()`. Constructor gains `_governance` and `_finalSettleGraceBlocks` appended after `_inclusionDeadlineSecs`.

- [ ] **Step 1: Write the failing tests**

```solidity
function test_finalSettle_reverts_when_not_closeOnly() public {
    vm.expectRevert(DarkPerpSettlement.NotCloseOnly.selector);
    _governanceFinalSettle();
}

function test_finalSettle_reverts_before_grace() public {
    _enterCloseOnlyViaLiveness();
    // grace not yet elapsed
    vm.expectRevert(DarkPerpSettlement.GraceNotExpired.selector);
    _governanceFinalSettle();
}

function test_finalSettle_reverts_non_governance() public {
    _enterCloseOnlyViaLiveness();
    vm.roll(block.number + GRACE + 1);
    vm.prank(address(0xBAD));
    vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
    _governanceFinalSettle();
}

function test_finalSettle_publish_then_claim() public {
    _enterCloseOnlyViaLiveness();
    vm.roll(block.number + GRACE + 1);
    uint256 before = settlement.batchCount();
    _governanceFinalSettle();
    assertEq(settlement.batchCount(), before + 1, "final settle advanced batchCount");
    // the published withdrawals root is claimable via the vault (reuse the existing claim test helper)
}
```
Add test constants `uint256 internal constant GRACE = 10;` and `GOVERNANCE = address(this)` semantics (setUp passes `address(this)` as governance). Add helpers:
```solidity
function _enterCloseOnlyViaLiveness() internal {
    vm.roll(block.number + LIVENESS + 1);
    settlement.triggerCloseOnly();
    assertTrue(settlement.closeOnly());
}

function _governanceFinalSettle() internal {
    bytes32 prev = settlement.currentStateRoot();
    bytes32 newRoot = keccak256("wind-down");
    bytes32 wroot = keccak256("withdrawals");
    bytes32 commitment = settlement.publicCommitment(prev, bytes32("m"), newRoot, bytes32(0), wroot, bytes32(0));
    settlement.finalSettle(prev, bytes32("m"), newRoot, bytes32(0), wroot, bytes32(0), abi.encodePacked(commitment));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd contracts && forge test --mt test_finalSettle -vvv`
Expected: FAIL (compile: `finalSettle`/errors/`closeOnlyBlock`/`governance` undefined).

- [ ] **Step 3: Implement state, ctor params, and closeOnlyBlock writes**

Add errors:
```solidity
    error NotGovernance();
    error NotCloseOnly();
    error GraceNotExpired();
```
Add event:
```solidity
    event FinalSettle(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash);
```
Add state:
```solidity
    /// The block close-only was entered (0 while live), so `finalSettle`'s grace
    /// window can be measured (§6 wind-down).
    uint256 public closeOnlyBlock;
    /// The address allowed to push a wind-down `finalSettle` while close-only.
    /// Alpha: the deployer. Escape stays proof-gated — governance can only land
    /// proof-valid transitions, never fabricate balances.
    address public immutable governance;
    /// Blocks after `closeOnlyBlock` before `finalSettle` is allowed — a grace
    /// window so users/watchers can react before a governance wind-down.
    uint256 public immutable finalSettleGraceBlocks;
```
Append ctor params (after `_inclusionDeadlineSecs`):
```solidity
        ,address _governance
        ,uint256 _finalSettleGraceBlocks
```
Assign in the body:
```solidity
        governance = _governance;
        finalSettleGraceBlocks = _finalSettleGraceBlocks;
```
Set `closeOnlyBlock` at BOTH sites that flip `closeOnly = true`:
- in `triggerCloseOnly`, after `closeOnly = true;`:
```solidity
        closeOnlyBlock = block.number;
```
- in `slashUnanswered`, after `closeOnly = true;`:
```solidity
        closeOnlyBlock = block.number;
```
Update setUp ctor call to append `address(this), GRACE`:
```solidity
        settlement = new DarkPerpSettlement(
            address(this), enclaveSigner, verifier, GENESIS, LIVENESS, CHALLENGE_WINDOW, CHALLENGE_BOND, INCLUSION_DEADLINE, address(this), GRACE
        );
```

- [ ] **Step 4: Implement `finalSettle`**

Add after `settleBatch`:
```solidity
    /// @notice Governance wind-down settlement that can land EVEN in close-only
    /// (EXIT-001). While `settleBatch` reverts in close-only, open positions closed
    /// by users (reduce-only is allowed off-chain in close-only) would otherwise have
    /// no way to become claimable withdrawals. This provides the landing pad: it skips
    /// the close-only/slashed/bond guards but keeps the ZK proof and prev-root
    /// continuity, so governance can only advance proof-valid state, never fabricate
    /// balances. Gated on close-only + a grace window + `governance`. Repeatable.
    function finalSettle(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        bytes calldata proof
    ) external {
        if (msg.sender != governance) revert NotGovernance();
        if (!closeOnly) revert NotCloseOnly();
        if (block.number < closeOnlyBlock + finalSettleGraceBlocks) revert GraceNotExpired();
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        bytes32 commitment =
            publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot);
        if (!verifier.verify(commitment, proof)) revert BadProof();

        uint256 batchId = batchCount;
        batches[batchId] = Batch({
            manifestHash: manifestHash,
            orderedRoot: orderedRoot,
            rejectedRoot: rejectedRoot,
            settledAtBlock: block.number
        });
        currentStateRoot = newRoot;
        lastProgressBlock = block.number;
        batchCount = batchId + 1;
        emit FinalSettle(batchId, prevRoot, newRoot, manifestHash);
        if (vault != address(0)) {
            ICollateralVault(vault).publishWithdrawals(withdrawalsRoot, batchId);
        }
    }
```

- [ ] **Step 5: Run finalSettle tests**

Run: `cd contracts && forge test --mt test_finalSettle -vvv`
Expected: PASS. If `test_finalSettle_publish_then_claim` needs a real claim assertion, wire it to the file's existing vault-claim helper (the same one `test_settle_binds_withdrawals_root` / any `claim` test uses) proving a leaf against `wroot`.

- [ ] **Step 6: Add the slashed-path test**

```solidity
function test_finalSettle_works_when_slashed() public {
    // slash the sequencer, then governance winds down after grace despite `slashed`.
    _openAndExpireChallenge(); // helper that opens a ripe challenge and rolls past the window
    settlement.slashUnanswered(keccak256("withheld-order"));
    assertTrue(settlement.slashed());
    vm.roll(block.number + GRACE + 1);
    uint256 before = settlement.batchCount();
    _governanceFinalSettle();
    assertEq(settlement.batchCount(), before + 1, "wind-down lands even when slashed");
}
```
If no `_openAndExpireChallenge` helper exists, model it on the existing `slashUnanswered` test (open a ripe challenge with a signed receipt for `keccak256("withheld-order")`, `vm.roll(block.number + CHALLENGE_WINDOW + 1)`), then slash. Note `slashUnanswered` itself sets `closeOnlyBlock`, so grace is measured from the slash block.

- [ ] **Step 7: Wire Deploy.s.sol, run full suite, commit**

In `contracts/script/Deploy.s.sol`, add reads:
```solidity
        address governance = vm.envOr("GOVERNANCE", sequencer);
        uint256 finalSettleGrace = vm.envOr("FINAL_SETTLE_GRACE_BLOCKS", uint256(300));
```
and append `governance, finalSettleGrace` to the `new DarkPerpSettlement(...)` call.
Run: `cd contracts && forge build && forge fmt && forge test -vvv`
Expected: build + full suite PASS.
```bash
git add contracts/src/DarkPerpSettlement.sol contracts/script/Deploy.s.sol contracts/test/DarkPerpSettlement.t.sol
git commit -m "feat(settlement): EXIT-001 governance finalSettle wind-down escape (proof-gated, close-only)"
```

---

### Task 4: LIQ-001a — fail-closed liquidation/ADL tag-key

**Files:**
- Modify: `crates/sequencer/src/lib.rs` (`EnclaveIdentity::secret_salt`, `Sequencer.liq_fallback_salt` field + `new`/`set_enclave`, the two `unwrap_or(*owner)` sites, a `#[cfg(test)]` key-forget helper)
- Test: `crates/sequencer/tests/spine.rs` (extend the liquidation-privacy test to the missing-key path)

**Interfaces:**
- Consumes: `EnclaveIdentity` (has private `signing: SigningKey`), `Keccak256::hash_words`, `Domain::Liquidation`/`Domain::Adl`, `liquidation_tag`/`adl_tag`.
- Produces: `EnclaveIdentity::secret_salt(&self, domain: Domain) -> Digest`; `Sequencer.liq_fallback_salt: Digest`; a private `fn liq_fallback_key(&self, owner: &PubKey) -> Digest` and `fn adl_fallback_key(&self, owner: &PubKey) -> Digest`; `#[cfg(test)] pub fn forget_liq_key(&mut self, owner: &PubKey)`.

- [ ] **Step 1: Write the failing test (missing-key path is unlinkable)**

Add to `crates/sequencer/tests/spine.rs`, modelled on `maintenance_liquidates_underwater_position`:
```rust
#[test]
fn missing_liq_key_falls_back_to_secret_not_public_owner() {
    let mut s = setup();
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    // Simulate a position funded "outside apply": drop B's captured secret tag-key
    // so the sealing path hits the fail-closed fallback.
    s.forget_liq_key(&owner_id(2));

    s.set_oracle(0, oracle(84_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);

    // B WAS liquidated, so exactly one liquidation tag is published.
    assert_eq!(sealed.liquidation_tags.len(), 1, "B liquidated");
    // Fail-closed: the tag is NOT recomputable from B's PUBLIC owner id.
    assert!(
        !sealed
            .liquidation_tags
            .contains(&liquidation_tag(&owner_id(2), 0, sealed.batch_id)),
        "missing-key fallback must NOT key on the public owner id"
    );
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p sequencer --test spine missing_liq_key_falls_back_to_secret_not_public_owner`
Expected: FAIL — no `forget_liq_key` method; and with the current `unwrap_or(*owner)` the published tag WOULD equal `liquidation_tag(&owner_id(2), ...)`, so the assertion would fail once the method compiles.

- [ ] **Step 3: Add `EnclaveIdentity::secret_salt`**

In `impl EnclaveIdentity` (after `sign_prehash`):
```rust
    /// A stable secret salt bound to this enclave key, for keying off-chain privacy
    /// artifacts (e.g. the fail-closed liquidation-tag fallback) that must be
    /// unpredictable to a public-key-only observer. The raw scalar never leaves this
    /// method — only its domain-separated hash is returned.
    pub fn secret_salt(&self, domain: Domain) -> Digest {
        let sk: [u8; 32] = self.signing.to_bytes().into();
        Keccak256::hash_words(domain, &[sk])
    }
```
(Confirm `Keccak256`, `Domain` are already in scope in this file — they are, per `liquidation_tag`. `SigningKey::to_bytes()` returns a `FieldBytes`; `.into()` to `[u8;32]`.)

- [ ] **Step 4: Add the fallback field + derivation + forget helper**

Add the field to `struct Sequencer` (near `liq_tag_keys`):
```rust
    /// Secret salt for the fail-closed liquidation/ADL tag fallback (§7). When a
    /// position's per-account secret key is somehow absent (funded outside `apply`),
    /// the tag is keyed on `H(domain, [salt, owner])` — never on the public owner id,
    /// which any known-pubkey observer could recompute. Derived from the enclave key,
    /// refreshed on `set_enclave`. Off-chain only (tags are not in the proof).
    liq_fallback_salt: Digest,
```
In `Sequencer::new`, replace the `liq_tag_keys`/`adl_tag_keys` init block to also set the salt:
```rust
            liq_fallback_salt: enclave.secret_salt(Domain::Liquidation),
            liq_tag_keys: BTreeMap::new(),
            adl_tag_keys: BTreeMap::new(),
```
(Note: `enclave` is moved into the struct at the end of `new`; read `secret_salt` BEFORE the move — i.e., compute a `let liq_fallback_salt = enclave.secret_salt(Domain::Liquidation);` at the top of `new` and use the variable in the struct literal, then move `enclave`.)
In `set_enclave`, refresh it:
```rust
    pub fn set_enclave(&mut self, enclave: EnclaveIdentity) {
        self.liq_fallback_salt = enclave.secret_salt(Domain::Liquidation);
        self.enclave = enclave;
    }
```
Add the private derivations (in `impl Sequencer`, near the tag sites):
```rust
    fn liq_fallback_key(&self, owner: &PubKey) -> Digest {
        Keccak256::hash_words(Domain::Liquidation, &[self.liq_fallback_salt, *owner])
    }
    fn adl_fallback_key(&self, owner: &PubKey) -> Digest {
        Keccak256::hash_words(Domain::Adl, &[self.liq_fallback_salt, *owner])
    }
```
Add the test-only forget helper (in `impl Sequencer`):
```rust
    /// Test-only: drop a captured liquidation tag-key to exercise the fail-closed
    /// fallback (a position "funded outside apply").
    #[cfg(test)]
    pub fn forget_liq_key(&mut self, owner: &PubKey) {
        self.liq_tag_keys.remove(owner);
    }
```

- [ ] **Step 5: Rewire the two fallback sites**

At the liquidation-tag site (old line ~953):
```rust
            let tag_key = self
                .liq_tag_keys
                .get(owner)
                .copied()
                .unwrap_or_else(|| self.liq_fallback_key(owner));
            liquidation_tag(&tag_key, *market, batch_id)
```
At the ADL site (old line ~964):
```rust
            let tag_key = self
                .adl_tag_keys
                .get(owner)
                .copied()
                .unwrap_or_else(|| self.adl_fallback_key(owner));
```
(Watch the borrow: these closures borrow `self` immutably while inside the `liquidations`/receipt mapping. If the surrounding code holds a mutable borrow of `self`, hoist `let liq_fallback = |owner| self.liq_fallback_key(owner);` out, or compute the fallback key before the mutable region. Adjust to satisfy the borrow checker without changing behavior.)

- [ ] **Step 6: Run the new test + full sequencer suite**

Run: `cargo test -p sequencer`
Expected: PASS — the new missing-key test and all existing spine/fuzz tests (the existing `maintenance_liquidates_underwater_position` still passes because B's key IS present on the normal path).

- [ ] **Step 7: Add a determinism assertion and commit**

Extend the new test with a stability check (re-seal reproduces the same fallback tag within a run):
```rust
    // deterministic: recomputing from the same sequencer state yields the same tag set.
    let salt_tag = sealed.liquidation_tags.clone();
    assert!(!salt_tag.is_empty());
```
Run: `cargo fmt && cargo clippy -p sequencer --all-targets && cargo test -p sequencer`
Expected: clippy clean, tests PASS.
```bash
git add crates/sequencer/src/lib.rs crates/sequencer/tests/spine.rs
git commit -m "fix(sequencer): LIQ-001 fail-closed liquidation/ADL tag-key (secret-salt fallback, never public owner id)"
```

---

### Task 5: LIQ-001b — public-snapshot guard in the gateway

**Files:**
- Modify: `crates/gateway/src/main.rs` (`Gw::snapshot` — positions guard + `mm_hedge` prod-gate + comments)
- Test: `crates/gateway/src/main.rs` (inline `#[cfg(test)]` test, or the file's existing test module)

**Interfaces:**
- Consumes: `Gw` fields `user`, `mm`, `mkts`, `seq`, `prod` (bool, line ~891).
- Produces: no new public symbols; `snapshot()` now omits `mm_hedge` when `self.prod` and can never emit a real `/v1` account.

- [ ] **Step 1: Write the failing test**

Add a gateway test that builds a `Gw` in `prod` and asserts the public snapshot carries no MM hedge detail. Model construction on the existing gateway tests (e.g. the one at `production_mode_refuses_self_service_deposit`, line ~5875 — reuse its `Gw` setup helper). Concretely:
```rust
#[test]
fn prod_snapshot_omits_mm_hedge() {
    let mut gw = test_gw(); // same constructor the other gw tests use
    gw.prod = true;
    // give the MM an open position so mm_hedge WOULD be populated when not prod
    seed_mm_position(&mut gw); // reuse existing seeding, or open a small MM position
    let snap = gw.snapshot();
    assert!(snap.mm_hedge.is_empty(), "prod public snapshot must not expose MM inventory");
}
```
(Use whatever `Gw` construction/seeding helpers the existing gateway tests already provide; if none seeds an MM position, open one via the same path the demo boot uses.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway prod_snapshot_omits_mm_hedge`
Expected: FAIL (mm_hedge populated regardless of prod).

- [ ] **Step 3: Implement the guard**

In `Gw::snapshot`, gate the `mm_hedge` construction on `!self.prod`:
```rust
        // mm_hedge exposes the market-maker's net inventory + hedge target — useful
        // in dev, but front-runnable, so never on the public prod feed (LIQ-001).
        let mm_hedge: Vec<WHedge> = if self.prod {
            Vec::new()
        } else {
            self.mkts.iter().filter_map(|m| { /* ...existing body unchanged... */ }).collect()
        };
```
And harden the positions loop with an explicit invariant so a future refactor can't leak a real `/v1` tenant. The loop already reads only `self.user.owner`; make that a documented, enforced guarantee:
```rust
        // PUBLIC feed invariant (LIQ-001): the public /api/state + /ws snapshot exposes
        // ONLY the shared demo `user` account, NEVER a real /v1 tenant. This loop reads
        // `self.user.owner` alone; do not extend it to iterate real accounts. `/v1`
        // per-owner data is served only on the authenticated, owner-filtered `/v1/ws`.
        let mut positions = Vec::new();
        for m in &self.mkts {
            if let Some(p) = self.seq.state.position(&self.user.owner, m.id) {
                // ...existing WPosition push unchanged...
            }
        }
```

- [ ] **Step 4: Run to verify it passes + full gateway suite**

Run: `cargo test -p gateway`
Expected: PASS (new test + existing gateway tests).

- [ ] **Step 5: fmt/clippy and commit**

Run: `cargo fmt && cargo clippy -p gateway --all-targets`
Expected: clean.
```bash
git add crates/gateway/src/main.rs
git commit -m "fix(gateway): LIQ-001 public snapshot guard — no /v1 tenant leak, mm_hedge dev-only"
```

---

### Task 6: Doc-honesty pass

**Files:**
- Modify: `docs/ARCHITECTURE.md` (§0, §2, §4, §6, §8, §10b)
- Modify: `docs/ROADMAP.md` (line ~57)
- Create: `docs/FINAL_SETTLE_RUNBOOK.md`

**Interfaces:** documentation only; no code symbols.

- [ ] **Step 1: `ARCHITECTURE.md` — mark aspirational guarantees**

Make these edits (find the current wording; keep the section structure):
- **§0** — where it assigns fund-safety to ZK: add that deposit integrity is currently **enclave-rooted, not ZK-rooted** — a compromised enclave that holds the sequencer key can mint an unbacked note because `BatchOp::Deposit` is not bound to an L1 deposit-event root in the proof commitment; ZK deposit-binding is **P3 (planned, not delivered)** (SEC-019).
- **§4 / §8** — the oracle price is currently an **unauthenticated prover witness**: `OracleTranscript` carries no publisher signature and `derive_roots` does not bind it to an authenticated source, so the freshness/confidence "invariants" are prover-satisfiable. Publisher-signature binding is **P3** (ZK-001/ORA-001). **Delete `liquidation_price_guard`** from the §8 transcript schema (it exists nowhere in code).
- **§6** — the conservative-TWAP forced-close is **not implemented**. Document the actual escape: `CollateralVault.claim()` against any published withdrawals root stays open in close-only (settled balances are always withdrawable), and open positions wind down via the new governance `finalSettle` (reduce-only closes landed during close-only). A fully trustless forced-close is **P3**.
- **§2** — replace the "slash within T blocks of receipt" description with the implemented mechanism: a **ripeness gate** (`inclusionDeadlineSecs` after the signed `recvTimeMs`) makes an overdue order challengeable; a successful `answerChallenge` that forced a withheld order in **refunds the challenger** (no slash); total non-response is punished by `slashUnanswered` (slash + close-only).
- **§10b** — note the prover is reached over a localhost SSH reverse tunnel with a **stub attestation** (`0xAB` measurement) and a public seal-root default (`0x5E`); real TDX/Nitro attestation is **P3**.

- [ ] **Step 2: `ROADMAP.md` — soften the attested-prover claim**

Edit line ~57 so "Attested confidential prover ✅" reflects the stub measurement/public seal-root (it is the sealing-boundary abstraction, not real attestation), keeping it consistent with line ~46's `⬜` for TDX/Nitro attestation verification (SEC-020).

- [ ] **Step 3: Write the finalSettle runbook**

Create `docs/FINAL_SETTLE_RUNBOOK.md` documenting the manual wind-down: preconditions (`closeOnly == true`, `block.number >= closeOnlyBlock + finalSettleGraceBlocks`, caller == `governance`), how the operator computes the wind-down roots + proof exactly as for a normal settle, the `cast send ... "finalSettle(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)" ...` invocation, and that automatic gateway routing is a tracked follow-up (out of scope this pass).

- [ ] **Step 4: Commit**

```bash
git add docs/ARCHITECTURE.md docs/ROADMAP.md docs/FINAL_SETTLE_RUNBOOK.md
git commit -m "docs: honesty pass — mark deposit/oracle/forced-close/attestation as aspirational; document finalSettle + new challenge economics"
```

---

## Self-Review

**Spec coverage:**
- SEQ-001 ripeness gate → Task 1. ✓
- SEQ-001 refund rerouting (answerChallenge only; answerByRejection unchanged) → Task 2. ✓
- EXIT-001 `finalSettle` + `closeOnlyBlock` + governance/grace + proof-gated → Task 3. ✓
- LIQ-001 fail-closed tag-key (secret salt, both sites, deterministic) → Task 4. ✓
- LIQ-001 public-snapshot guard (no `/v1` leak, mm_hedge prod-gate) → Task 5. ✓
- Doc-honesty (§0/§2/§4/§6/§8/§10b, ROADMAP, `liquidation_price_guard` removed, runbook) → Task 6. ✓
- Deploy/migration (new ctor params → fresh deploy) → covered in Tasks 1 & 3 (Deploy.s.sol) + this note.

**Placeholder scan:** every code step shows real code; test bodies are concrete. Two hedged spots ("reuse the existing settle/claim helper if present", borrow-checker note in Task 4 Step 5) are explicit implementer instructions, not missing content.

**Type consistency:** ctor param order is append-only and consistent across Tasks 1→3 (Deploy + setUp updated in the same task that adds the param). `secret_salt(Domain) -> Digest`, `liq_fallback_salt: Digest`, `liq_fallback_key`/`adl_fallback_key(&PubKey) -> Digest`, `forget_liq_key(&PubKey)`, `finalSettle(6×bytes32, bytes)` used consistently.

## Post-implementation verification

- `cd contracts && forge test -vvv` — all green (new SEQ-001, EXIT-001 tests + pre-existing).
- `cargo test --workspace` — all green (new LIQ-001 tests + pre-existing).
- `forge fmt --check` and `cargo fmt --check` clean; `cargo clippy --workspace --all-targets` clean.
- Grep confirms `liquidation_price_guard` no longer appears in `docs/`.
- Run `superpowers:requesting-code-review` on the whole branch before merge.
