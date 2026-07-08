# Live Migration Cutover — Implementation Plan (Runbook)

> **For agentic workers:** Task 0 (code tooling) uses superpowers:subagent-driven-development. Phases 0–5 are a LIVE-OPS runbook — executed interactively with the user (SSH/cast/systemctl), NOT via SDD. Steps use checkbox (`- [ ]`) tracking.

**Goal:** Flip the public testnet (perp.arcoralabs.xyz, Base Sepolia) from the legacy MockZkVerifier path to the new window-settle path with real Groth16 proofs from GB10, settled against a fresh DarkPerpSettlement bound to SP1ZkVerifier `0xCbdD…`.

**Architecture:** Two tiny code tooling changes land on `main` first (Task 0). Then a 6-phase live cutover: prover up (GB10/Tailscale) → compute genesis root → deploy fresh contract stack → cutover the CVM gateway env + fresh snapshot → verify a real proof settles. Rollback = restore the CVM backups (old stack stays valid on-chain).

**Tech Stack:** Rust (gateway), Solidity/Foundry (contracts + `cast`/`forge`), systemd, Tailscale, Azure CVM.

## Global Constraints

- **Hosts:** CVM `azureuser@104.42.53.250` (`ssh -i ~/.ssh/id_ed25519`); GB10 `huseyinarslan@192.168.1.108` (`ssh -i ~/.ssh/id_ed25519`); local Mac = repo `/Users/huseyinarslan/Desktop/dark-perp`; Base Sepolia RPC `https://sepolia.base.org`.
- **Live contracts (current):** Settlement `0x27Fc1bDa0B04163ABDf310ABC1391AD9778cfA82` (batchCount 1, root `0x4d1ae1d2…`), Vault `0x71a19b16F400752a1c0761dEF7bBA208eDFf37EA`, MockUSDC `0x5DCd457B723F81531753fE92B82696e771671557`.
- **Reusable:** SP1ZkVerifier `0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF` (programVKey `0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024`).
- **Identities that STAY:** enclaveSigner `0x92173839C6B3b717179ba5505CCE31bD2131EbA0`; sequencer/deployer `0xed37B7fc534Cc93D4195b4F11ADc5C14237cd287` (its key = the CVM gateway.env `L1_SEQUENCER_KEY`).
- **Settlement constructor params (unchanged except verifier + genesis):** `livenessBlocks=7200`, `challengeBlocks=300`, `challengeBond=10000000000000000` (0.01 ETH).
- **SECRETS: never write key values in this plan, in git, or echo them.** The deployer key is referenced as `$DEPLOYER_KEY` (source from a file in a subshell); `ENCLAVE_SEED` lives in `/etc/darkperp/enclave.seed` on the CVM and is untouched. Set `export FOUNDRY_DISABLE_NIGHTLY_WARNING=1` for clean `cast` output.
- **Runtime-captured values** (marked `⟨…⟩`) are read during execution and carried forward: `⟨GB10_TS_IP⟩`, `⟨GENESIS_ROOT⟩`, `⟨NEW_SETTLEMENT⟩`, `⟨NEW_VAULT⟩`.
- **GATE = a red check stops the phase.** Do not advance on a failed gate; go to Rollback if already cut over.

---

## Task 0: Migration tooling (code — SDD)

**Files:**
- Modify: `contracts/script/Deploy.s.sol` (add a `VERIFIER` env override so a fresh Settlement can bind a real verifier).
- Create/Modify: `contracts/test/DeployVerifierEnv.t.sol` (forge test for the override).
- Modify: `crates/gateway/src/main.rs` (`Gw::boot`, ~line 1060 — log the genesis engine root).

**Interfaces:**
- Produces: `Deploy.s.sol` honoring `VERIFIER` (address) → binds it as the Settlement's `IZkVerifier` when set, else deploys `MockZkVerifier`; a boot log line `[state] genesis engine root 0x…`.

- [ ] **Step 1: Deploy.s.sol — VERIFIER env override**

In `contracts/script/Deploy.s.sol`, the current broadcast block deploys `verifier = new MockZkVerifier();` unconditionally. Replace the verifier selection so a set `VERIFIER` env binds a real verifier, and gate the Mock-only guard on actually using Mock. First ensure `import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";` is present (add if missing). Change the `verifier` local's type to `IZkVerifier` and select it:

```solidity
        // Verifier selection: a set VERIFIER binds a real (e.g. SP1) verifier; else Mock (dev/testnet).
        address verifierEnv = vm.envOr("VERIFIER", address(0));
        if (verifierEnv == address(0)) {
            // Only the unsound Mock needs the testnet/override guard.
            require(
                DeployGuard.isTestnet(block.chainid) || vm.envOr("ALLOW_MOCK_VERIFIER", uint256(0)) == 1,
                "Deploy: MockZkVerifier is unsound; refusing on a non-testnet chain (set ALLOW_MOCK_VERIFIER=1 to force)"
            );
        }

        vm.startBroadcast(pk);

        IZkVerifier verifier = verifierEnv == address(0)
            ? IZkVerifier(address(new MockZkVerifier()))
            : IZkVerifier(verifierEnv);
        settlement = new DarkPerpSettlement(
            sequencer, enclaveSigner, verifier, genesis, liveness, challengeWindow, challengeBond
        );
```

(Adapt to the file's actual `verifier`/`settlement` declarations — if `verifier` was declared `MockZkVerifier verifier;` at contract scope, retype it `IZkVerifier verifier;`. Keep the rest of the broadcast block — `usdc`, `vault`, `setVault`, `mint` — unchanged. The `require` moves from its old unconditional spot into the `verifierEnv == address(0)` branch; delete the old unconditional copy.)

- [ ] **Step 2: forge test for the override**

Create `contracts/test/DeployVerifierEnv.t.sol`. Assert both branches select the right verifier via the Settlement's `verifier()` getter (the field is `IZkVerifier public immutable verifier`). Use `vm.setEnv` + the script's `run()` (mirror how other `*.t.sol` tests exercise scripts; if the script has no test-friendly entry, factor the verifier-selection into an `internal` helper the test can call directly):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";

contract DeployVerifierEnvTest is Test {
    function test_verifier_env_binds_real_verifier() public {
        address fake = address(0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF);
        vm.setEnv("VERIFIER", vm.toString(fake));
        Deploy d = new Deploy();
        d.run();
        // d exposes the deployed `settlement` (make it public if not already).
        assertEq(address(d.settlement().verifier()), fake, "VERIFIER env must bind the given verifier");
    }

    function test_unset_verifier_deploys_mock() public {
        vm.setEnv("VERIFIER", "");
        Deploy d = new Deploy();
        d.run();
        assertTrue(address(d.settlement().verifier()) != address(0), "Mock verifier deployed when VERIFIER unset");
    }
}
```

(Adapt to the real `Deploy` script API: if `settlement` is not externally readable, either add a `public` getter or read it from the script's return/state. If `run()` broadcasts, use `vm.envOr`/a no-broadcast test entry. The intent that must hold: `VERIFIER` set → `settlement.verifier() == VERIFIER`; unset → a fresh non-zero Mock.)

- [ ] **Step 3: Run the forge tests**

Run: `cd /Users/huseyinarslan/Desktop/dark-perp/contracts && FOUNDRY_DISABLE_NIGHTLY_WARNING=1 forge test --match-contract DeployVerifierEnvTest -vvv`
Expected: both tests PASS. Also `forge test` (whole suite) stays green.

- [ ] **Step 4: Gateway — log the genesis engine root at boot**

In `crates/gateway/src/main.rs`, `Gw::boot` computes `let genesis_root = seq.state.state_root();` (~line 1060). Immediately after it, add:

```rust
        println!("[state] genesis engine root {}", hex32(&genesis_root));
```

(Confirm `hex32(&Digest) -> String` is in scope — it is used elsewhere in `main.rs`; `genesis_root` is a `Digest`. This is a log-only side effect: no behavior change. If `boot` runs before the logger/stdout is configured, plain `println!` is fine — the existing boot lines use it.)

- [ ] **Step 5: Build the gateway + run the boot test locally**

Run: `cargo build -p gateway` (compiles) then `cargo test -p gateway` (unchanged suite green — the log line is inert). Optionally, a quick manual confirm: `cargo run -p gateway 2>&1 | grep "genesis engine root"` (Ctrl-C after the line prints) shows `[state] genesis engine root 0x…`.

- [ ] **Step 6: Commit**

```bash
git add contracts/script/Deploy.s.sol contracts/test/DeployVerifierEnv.t.sol crates/gateway/src/main.rs
git commit -m "feat(migration): Deploy.s.sol VERIFIER env override + gateway boot genesis-root log"
```

Task 0 lands via SDD (implement → task review → whole-branch review) and merges to `main` BEFORE the runbook (the CVM rebuild in Phase 2 needs the boot log; the deploy in Phase 3 needs the VERIFIER env).

---

## RUNBOOK — Phases 0–5 (LIVE OPS, executed with the user)

> Each step is tagged `[Mac]` (local, Claude can run read-only), `[CVM]` (`ssh azureuser@104.42.53.250`), `[GB10]` (`ssh huseyinarslan@192.168.1.108`), or `[cast]` (Base Sepolia, read-only ok by Claude; writes by the user with `$DEPLOYER_KEY`). Live writes (deploys, service restart) are run by the user.

### Phase 0 — Pre-flight (read-only + backups)

- [ ] **0.1 `[Mac]` Confirm `main` is green** (Task 0 merged): `git -C /Users/huseyinarslan/Desktop/dark-perp log --oneline -1 main`; `cargo test --workspace` green; `cd contracts && forge test` green.
- [ ] **0.2 `[cast]` Confirm the reusable verifier + deployer funds.**
```bash
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1; RPC=https://sepolia.base.org
cast call 0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF "programVKey()(bytes32)" --rpc-url $RPC
# expect 0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024
cast balance 0xed37B7fc534Cc93D4195b4F11ADc5C14237cd287 --rpc-url $RPC   # ETH for gas (> ~0.01 ETH)
cast call 0x5DCd457B723F81531753fE92B82696e771671557 "balanceOf(address)(uint256)" 0xed37B7fc534Cc93D4195b4F11ADc5C14237cd287 --rpc-url $RPC  # USDC for the bond
```
- [ ] **0.3 `[CVM]` Back up the live gateway (binary, env, snapshot).**
```bash
TS=$(date +%Y%m%d-%H%M%S)
sudo cp /usr/local/bin/darkperp-gateway /usr/local/bin/darkperp-gateway.bak-$TS
sudo cp /etc/darkperp/gateway.env       /etc/darkperp/gateway.env.bak-$TS
sudo cp /var/lib/darkperp/state.snap    /var/lib/darkperp/state.snap.bak-$TS 2>/dev/null || echo "(no state.snap yet)"
ls -la /usr/local/bin/darkperp-gateway.bak-$TS /etc/darkperp/gateway.env.bak-$TS
```
- **GATE 0:** vkey == `0x00f4a71…`; deployer has ETH + USDC; three `.bak-$TS` files exist. Record `$TS`.

### Phase 1 — Prover up on GB10 + reachable over Tailscale

- [ ] **1.1 `[GB10]` + `[CVM]` Join both boxes to one tailnet.** On each: install tailscale, `sudo tailscale up`; on GB10 read its tailnet IP: `tailscale ip -4` → record `⟨GB10_TS_IP⟩`.
- [ ] **1.2 `[GB10]` One-time: register the amd64 emulator** (GB10 is arm64; the gnark image is amd64-only): `docker run --privileged --rm tonistiigi/binfmt --install amd64`.
- [ ] **1.3 `[GB10]` Start the prover-service bound to the tailnet** (nohup — first `client.setup(ELF)` is slow):
```bash
cd ~/dark-perp/crates/prover-service   # (sync main HEAD here first if stale)
nohup env DOCKER_DEFAULT_PLATFORM=linux/amd64 PROVER_BIND=⟨GB10_TS_IP⟩:8091 cargo run --release \
  > ~/prover.log 2>&1 &
# poll: tail -f ~/prover.log  until  "prover-service on ⟨GB10_TS_IP⟩:8091"
```
(Leave `PROVER_SEAL_ROOT` at its default `0x5E…` on BOTH sides, or set the same custom value here and in the gateway env at 4.1.)
- [ ] **1.4 `[CVM]` Verify reachability + vkey match from the CVM:**
```bash
curl -s http://⟨GB10_TS_IP⟩:8091/vkey    # -> {"vkey":"0x00f4a710..."}
```
Compare to the on-chain `programVKey()` from 0.2 — they MUST be equal.
- **GATE 1:** the CVM `curl …/vkey` returns exactly `0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024`. **If it differs** → the guest ELF drifted: redeploy `SP1ZkVerifier(SP1VerifierGateway, ⟨new vkey⟩)` (look up the Base Sepolia SP1VerifierGateway in `github.com/succinctlabs/sp1-contracts/.../deployments`; `forge create src/SP1ZkVerifier.sol:SP1ZkVerifier --constructor-args ⟨gateway⟩ ⟨vkey⟩ --private-key $DEPLOYER_KEY --rpc-url $RPC`), and use the NEW address everywhere `0xCbdD…` appears below.

### Phase 2 — Compute the fresh gateway genesis root

- [ ] **2.1 `[CVM]` Sync `main` HEAD + rebuild the gateway** (mirrors the 2026-07-05 cutover):
```bash
# from the Mac: rsync the repo to the CVM (exclude target/.git), then on the CVM:
cd ~/dark-perp && cargo build --release -p gateway   # ~1-2 min, no OOM on DC2es_v6
sudo cp target/release/gateway /usr/local/bin/darkperp-gateway.new   # stage, don't swap yet
```
- [ ] **2.2 `[CVM]` Read the genesis root from a throwaway boot** (no L1, exact prod market config). Run the NEW binary with the prod market/env EXCEPT `L1_SETTLEMENT` unset (so no bridge, no settle), capture the log line, Ctrl-C:
```bash
sudo env $(grep -v '^L1_SETTLEMENT=' /etc/darkperp/gateway.env | grep -v '^PROVER_URL=' | xargs) \
  /usr/local/bin/darkperp-gateway.new 2>&1 | grep -m1 "genesis engine root"
# -> [state] genesis engine root 0x????????...   ->  record ⟨GENESIS_ROOT⟩
```
(The genesis root is deterministic in the boot config — same binary + same market/fee/insurance/funding config → same root. This MUST be the same binary + env that Phase 4 runs, so Phase 4 reuses `/usr/local/bin/darkperp-gateway.new`.)
- **GATE 2:** a stable 32-byte `⟨GENESIS_ROOT⟩` captured (re-run 2.2 once to confirm it's identical).

### Phase 3 — Deploy the fresh contract stack (verifier = SP1ZkVerifier)

- [ ] **3.1 `[cast]` (user, with `$DEPLOYER_KEY`) Deploy via the Task-0 script.**
```bash
cd /Users/huseyinarslan/Desktop/dark-perp/contracts
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
( set +o history; export DEPLOYER_KEY=$(cat ~/path/to/deployer.key)   # never echoed
  VERIFIER=0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF \
  PRIVATE_KEY=$DEPLOYER_KEY \
  ENCLAVE_SIGNER=0x92173839C6B3b717179ba5505CCE31bD2131EbA0 \
  GENESIS_ROOT=⟨GENESIS_ROOT⟩ \
  LIVENESS_BLOCKS=7200 CHALLENGE_BLOCKS=300 CHALLENGE_BOND=10000000000000000 \
  forge script script/Deploy.s.sol --rpc-url https://sepolia.base.org --broadcast )
# from broadcast/Deploy.s.sol/84532/run-latest.json: record ⟨NEW_SETTLEMENT⟩, ⟨NEW_VAULT⟩ (and MockUSDC — reuse 0x5DCd457B… or the fresh one).
```
- [ ] **3.2 `[cast]` (user) Post the sequencer bond** (USDC-denominated; `requiredBond = vault.tvl()*500/1e4`). Approve + `postBond`:
```bash
cast send 0x5DCd457B723F81531753fE92B82696e771671557 "approve(address,uint256)" ⟨NEW_SETTLEMENT⟩ <amount> --private-key $DEPLOYER_KEY --rpc-url https://sepolia.base.org
cast send ⟨NEW_SETTLEMENT⟩ "postBond(uint256)" <amount> --private-key $DEPLOYER_KEY --rpc-url https://sepolia.base.org
```
- [ ] **3.3 `[cast]` Verify the fresh stack on-chain:**
```bash
cast call ⟨NEW_SETTLEMENT⟩ "verifier()(address)" --rpc-url $RPC          # == 0xCbdD7381...
cast call ⟨NEW_SETTLEMENT⟩ "enclaveSigner()(address)" --rpc-url $RPC     # == 0x92173839...
cast call ⟨NEW_SETTLEMENT⟩ "currentStateRoot()(bytes32)" --rpc-url $RPC  # == ⟨GENESIS_ROOT⟩
cast call ⟨NEW_SETTLEMENT⟩ "batchCount()(uint256)" --rpc-url $RPC        # == 0
```
- [ ] **3.4 `[Mac]` Record the deploy** in `contracts/deployments/base-sepolia.json` (new stack in `contracts`, move `0x27Fc1bDa…` into `supersededDeploys`, note "real SP1ZkVerifier `0xCbdD…`, window-settle path"). Commit on `main`.
- **GATE 3:** `verifier==0xCbdD…`, `enclaveSigner==0x92173839…`, `currentStateRoot==⟨GENESIS_ROOT⟩`, `batchCount==0`, bond posted.

### Phase 4 — Cutover the CVM gateway

- [ ] **4.1 `[CVM]` Rewrite `/etc/darkperp/gateway.env`** (edit in place; keep secrets):
```
L1_SETTLEMENT=⟨NEW_SETTLEMENT⟩
L1_VAULT=⟨NEW_VAULT⟩
L1_USDC=0x5DCd457B723F81531753fE92B82696e771671557   # or the fresh USDC
PROVER_URL=http://⟨GB10_TS_IP⟩:8091
PROVER_TIMEOUT_SECS=1200
# PROVER_SEAL_ROOT=... only if you set a custom one on GB10 (must match)
# UNCHANGED: L1_SEQUENCER_KEY, ENCLAVE_SEED path, ATTESTATION_*, DARKPERP_STATE, PORT
```
- [ ] **4.2 `[CVM]` Swap in the new binary + wipe the snapshot** (postcard positional → old snap fail-closes; fresh boot recomputes genesis, `l1_status:None` skips the continuity check):
```bash
sudo mv /usr/local/bin/darkperp-gateway.new /usr/local/bin/darkperp-gateway
sudo rm -f /var/lib/darkperp/state.snap          # backup already at .bak-$TS from 0.3
sudo systemctl restart darkperp-gateway
```
- [ ] **4.3 `[CVM]` Watch the boot log:**
```bash
sudo journalctl -u darkperp-gateway -n 60 -f
# expect, in order:
#   [attest] enclave bound to verified measurement 0x422890f6..faf55bd (TCB ...)
#   [state] genesis engine root ⟨GENESIS_ROOT⟩          <- MUST equal Phase-2
#   [state] sealed persistence ON -> ...
#   NO "REFUSING to start"
```
- **GATE 4:** attestation bound; `[state] genesis engine root` == `⟨GENESIS_ROOT⟩` == on-chain `currentStateRoot`; no `REFUSING to start`; gateway serving (`curl -s https://perp.arcoralabs.xyz/v1/system/status` → 200 with `openWindowId`).

### Phase 5 — Verify the new path LIVE

- [ ] **5.1 First real window settle.** After a window accrues + its ~13-min GB10 proof completes, the gateway submits `settleBatch` to `⟨NEW_SETTLEMENT⟩`. Watch: `[l1] window settled root … batch 1 tx 0x… (withdrawals root …)` on the CVM, and on-chain `batchCount 0→1`, `currentStateRoot` advanced. `cast tx <hash>` status == 1 (verified against `0xCbdD…`).
- [ ] **5.2 Confirm the settle loop serializes** (proof ≫ window): `journalctl` shows one window sealed→proved→settled at a time; no `batch_id desync` storm; soft-finality (MATCHED) stays instant for orders.
- [ ] **5.3 Full e2e** (mirror the 2026-07-05 verification): register → USDC deposit + attribution → order fills at oracle mark → withdraw → cumulative root published on the real settle → `vault.claim` pays USDC → re-claim reverts `AlreadyClaimed`.
- [ ] **5.4 3b-4 reconciliation live:** a POST `/v1/orders` receipt carries `windowId`; `GET /v1/batch/<counterA>` returns `{windowId, settled}`; `/v1/system/status` `openWindowId` tracks `l1.batchCount`.
- [ ] **5.5 Fold the fault-path runbook items:** add an ops alert on the gateway `HOLDING` log lines (extend `darkperp-health`/ntfy `darkperp-ops-perpseq`); do ONE deliberate wedged-RPC forced-failure probe (temporarily point `L1_RPC` at a dead endpoint for one settle) to observe roll-forward/rollback recovery, then restore. Update the TestnetNotice copy: "real Groth16 proofs (dev prover); SETTLED finality lags ~a proof interval."
- **GATE 5:** a real proof settled on-chain (status 1) + e2e green + reconciliation endpoints correct.

---

## Rollback (any red gate after Phase 4)

The old stack (`0x27Fc1bDa…` + the pre-3b binary) is untouched on-chain. Revert:
```bash
# [CVM]
sudo cp /etc/darkperp/gateway.env.bak-$TS /etc/darkperp/gateway.env
sudo cp /usr/local/bin/darkperp-gateway.bak-$TS /usr/local/bin/darkperp-gateway
sudo cp /var/lib/darkperp/state.snap.bak-$TS /var/lib/darkperp/state.snap   # if it existed
sudo systemctl restart darkperp-gateway
sudo journalctl -u darkperp-gateway -n 40    # expect "[state] on-chain continuity OK" against 0x27Fc1bDa…'s root
```
No on-chain action needed. Stop the GB10 prover (`kill` the cargo process) + `tailscale down` if abandoning. The fresh contracts simply sit unused (can be reused on a retry).

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-09-zk-p2-live-migration-cutover-design.md`):
- §4 tooling (Deploy.s.sol VERIFIER + gateway genesis log) → Task 0. ✅
- §5 Phase 0 (pre-flight/backups) → Phase 0; Phase 1 (prover+Tailscale+vkey gate) → Phase 1; Phase 2 (genesis root) → Phase 2; Phase 3 (fresh stack) → Phase 3; Phase 4 (cutover+snapshot) → Phase 4; Phase 5 (verify+fault-path) → Phase 5. ✅
- §3 decisions (GB10 dev prover, Tailscale, reuse 0xCbdD iff vkey, enclaveSigner/deployer stay, no DNS) → Global Constraints + Phase 1 gate + Phase 3 args. ✅
- §6 risks (vkey drift → GATE 1 branch; genesis lockstep → GATE 2/3/4 cross-checks; 13-min cadence → 5.2; snapshot fail-closed → 4.2; bond → 0.2/3.2; prover downtime → 5.5) → covered. ✅
- §7 rollback → Rollback section. ✅

**2. Placeholder scan:** the `⟨…⟩` tokens are runtime-captured values (explicitly read in a prior step), NOT unfilled plan gaps; every code step (Task 0) shows complete code. No TBD/TODO.

**3. Consistency:** contract addresses, keys-by-reference, `⟨GENESIS_ROOT⟩` threaded (read in 2.2 → deployed in 3.1 → cross-checked in 3.3/4.3), `⟨GB10_TS_IP⟩` (read 1.1 → used 1.3/1.4/4.1), verifier `0xCbdD…` consistent throughout; the vkey-drift branch (GATE 1) redirects every later `0xCbdD…` use. No secret values inlined.
