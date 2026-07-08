# ZK Verifier P2 — Live Migration Cutover — Design (Deployment Runbook)

**Date:** 2026-07-09
**Status:** Approved (brainstorming) → ready for the step-by-step plan
**Type:** DEPLOYMENT RUNBOOK, not a protocol change. All code slices (3b-1..3b-4) are merged + CI-green + GB10 e2e-validated. This slice takes the new (window-settle + real-Groth16) path LIVE on the public testnet.

---

## 1. Current live state (verified 2026-07-09)

- **Gateway host:** Azure TDX CVM `perp-seq` (DC2es_v6, westus, `104.42.53.250`), ssh `azureuser@` + `~/.ssh/id_ed25519`. systemd `darkperp-gateway.service`, env `/etc/darkperp/gateway.env`, snapshot `/var/lib/darkperp/state.snap`, enclave seed `/etc/darkperp/enclave.seed`, attestation `/var/lib/darkperp/attestation/`, gateway on `:8080` behind Caddy at **perp.arcoralabs.xyz** (+ sslip.io fallback).
- **Live contracts (Base Sepolia, on-chain-verified):** DarkPerpSettlement `0x27Fc1bDa0B04163ABDf310ABC1391AD9778cfA82` — `batchCount = 1`, `currentStateRoot = 0x4d1ae1d2…`, `enclaveSigner = 0x92173839C6B3b717179ba5505CCE31bD2131EbA0`, verifier = MockZkVerifier `0xC0a6F6E5…`, genesisRoot `0x0`. Vault `0x71a19b16…`, MockUSDC `0x5DCd457B…`. sequencer/deployer `0xed37B7fc534Cc93D4195b4F11ADc5C14237cd287` (key = gateway.env `L1_SEQUENCER_KEY`, memory tag `0xd82263…`).
- **Gateway build:** currently a pre-3b-1 build on the **legacy path** (`PROVER_URL` unset → MockZkVerifier, no real proofs).
- **Already deployed (reusable):** the Slice-1 **SP1ZkVerifier `0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF`** (immutable `programVKey = 0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024`, wired to Succinct's SP1VerifierGateway). GB10 e2e (3b-2b) verified real Groth16 against it.

## 2. Target state

The CVM gateway runs the **new window-settle path** (`PROVER_URL` set), producing real Groth16 proofs from **GB10** (the dev/test prover), settled on-chain against a **fresh DarkPerpSettlement bound to SP1ZkVerifier `0xCbdD…`**, with the fresh contract's `genesisRoot` in lockstep with the fresh gateway's boot engine root. perp.arcoralabs.xyz is unchanged (same box, same domain).

## 3. Key decisions (locked in brainstorming)

- **Prover = GB10** (`ssh -i ~/.ssh/id_ed25519 huseyinarslan@192.168.1.108`, arm64, runs the amd64-only sp1-gnark image under qemu, ~13 min/proof). It is the **dev/test prover**: proofs are real and verify on-chain, but the prover is not a real TEE (measurement is the fixed `0xAB…` stub; production-attested x86_64 is P3). Legitimate for a public testnet — the on-chain verification is real; the prover-attestation gap is the honest P3 remainder, reflected in the TestnetNotice.
- **CVM→GB10 reachability = Tailscale.** Both boxes join one tailnet; `PROVER_URL = http://<gb10-tailscale-ip>:8091`, `PROVER_BIND` on GB10 set to its tailscale interface (or `0.0.0.0:8091` within the tailnet). Private + authenticated; the prover is never publicly exposed (it sees plaintext positions after unsealing — must stay non-public per the PROVING-RUNBOOK privacy caveat). GB10 must stay awake/online while live.
- **Reuse SP1ZkVerifier `0xCbdD…`** iff its `programVKey()` still equals the live prover's `/vkey` (Phase-0 gate). The circuit/guest ELF was untouched by 3b-3/3b-3.1/3b-4 (they are gateway/sequencer/perp-core-Receipt only; the witness is `(DefaultState, Vec<BatchOp>, BatchManifest)` — no `Receipt`), so the vkey should still match; **verify live**. Only if it drifted do we redeploy `SP1ZkVerifier(gateway, newVkey)` — which needs the Base Sepolia **SP1VerifierGateway** address (look up in `github.com/succinctlabs/sp1-contracts/.../deployments` at deploy time; not recorded in-repo).
- **enclaveSigner stays `0x92173839…`** (the real CVM enclave). The fresh Settlement binds it unchanged so receipts/settles verify; `ENCLAVE_SEED` on the CVM is untouched.
- **No DNS/Caddy repoint** — the gateway stays on the CVM at perp.arcoralabs.xyz; only its config/binary/snapshot change.

## 4. Migration tooling (small, safe code — protocol untouched)

Two minor additions land on `main` first (their own tiny commits), because the runbook needs them:

1. **`contracts/script/Deploy.s.sol` — a `VERIFIER` env override.** Currently the script always `new MockZkVerifier()`. Add: `address verifierEnv = vm.envOr("VERIFIER", address(0)); IZkVerifier verifier = verifierEnv == address(0) ? new MockZkVerifier() : IZkVerifier(verifierEnv);`. So `VERIFIER=0xCbdD… forge script … --broadcast` deploys a fresh Settlement bound to the real verifier (Mock stays the default for local/dev). Repeatable + auditable + broadcast-recorded.
2. **Gateway boot genesis-root log.** `Gw::boot` computes `genesis_root = seq.state.state_root()` but never logs it. Add one line — `println!("[state] genesis engine root {}", hex32(&genesis_root));` — so Phase 2 reads the exact `genesisRoot` to deploy the Settlement with (and it's a permanent ops aid). Harmless, no behavior change.

These two are a pre-migration code slice (brainstorm→plan→SDD, tiny) OR folded into this runbook's plan as Task 0. Everything else is `cast`/`ssh`/`systemctl` ops.

## 5. The cutover — 6 phases

Each phase ends with a **verification gate**; do not advance on a red gate.

- **Phase 0 — Pre-flight (read-only, local):** confirm `main` builds + CI green; back up on the CVM (`darkperp-gateway` binary, `gateway.env`, `state.snap`, timestamped `.bak`); confirm the deployer/sequencer `0xed37B7fc…` holds enough Base Sepolia ETH (gas) + USDC (bond = `vault.tvl()*500/1e4`, ≥ the deposits it will back); Tailscale installed on both boxes. **Gate:** backups exist; funds present.
- **Phase 1 — Prover up + reachable (GB10):** on GB10, register the amd64 binfmt emulator, `cd crates/prover-service && DOCKER_DEFAULT_PLATFORM=linux/amd64 PROVER_BIND=<tailscale>:8091 PROVER_SEAL_ROOT=<root> cargo run --release` (nohup + poll — the first `client.setup(ELF)` is slow); join both boxes to the tailnet. **Gate:** from the CVM, `curl http://<gb10-tailscale-ip>:8091/vkey` returns a vkey; it **equals** `cast call 0xCbdD… "programVKey()(bytes32)"` (else → the SP1ZkVerifier-redeploy sub-branch).
- **Phase 2 — Compute the genesis root:** rsync `main` HEAD to the CVM, `cargo build --release -p gateway`, install to `/usr/local/bin/darkperp-gateway`. Boot it once **without the L1 bridge** (or read the boot log before it settles) with the exact 3-market prod config; read `[state] genesis engine root 0x…` from the log. **Gate:** a stable 32-byte genesis root captured.
- **Phase 3 — Deploy the fresh contract stack:** `VERIFIER=0xCbdD… PRIVATE_KEY=<0xd82263…> ENCLAVE_SIGNER=0x92173839… GENESIS_ROOT=<Phase-2> LIVENESS_BLOCKS=7200 CHALLENGE_BLOCKS=300 CHALLENGE_BOND=10000000000000000 forge script script/Deploy.s.sol --rpc-url https://sepolia.base.org --broadcast` → fresh DarkPerpSettlement + CollateralVault + (fresh or reused MockUSDC) + `setVault`. Then `postBond` the USDC bond. Update `contracts/deployments/base-sepolia.json` (move the old stack to `supersededDeploys`). **Gate:** on-chain `zkVerifier == 0xCbdD…`, `enclaveSigner == 0x92173839…`, `currentStateRoot == genesisRoot (Phase-2)`, `batchCount == 0`; bond posted.
- **Phase 4 — Cutover the gateway:** edit `/etc/darkperp/gateway.env` — `L1_SETTLEMENT`/`L1_VAULT`(/`L1_USDC`) → new addresses; `PROVER_URL=http://<gb10-tailscale-ip>:8091`; `PROVER_SEAL_ROOT` == GB10's; `PROVER_TIMEOUT_SECS=1200` (> the ~13-min proof); keep `L1_SEQUENCER_KEY`, `ENCLAVE_SEED`, `ATTESTATION_*`, `DARKPERP_STATE`. **Delete `/var/lib/darkperp/state.snap`** (postcard positional → the 3b-4 field additions make the old snapshot fail-closed; a fresh boot recomputes genesis + starts `l1_status: None`, skipping the continuity check). `systemctl restart darkperp-gateway`. **Gate:** boot log shows attestation bound (measurement `0x422890f6…`), `[state] genesis engine root` == Phase-2, persistence ON, no `REFUSING to start`.
- **Phase 5 — Verify live:** watch the first real window settle — after a window's ~13-min proof, `settleBatch` lands (status 1) against `0xCbdD…`, `batchCount 0→1`, `currentStateRoot` advances. Run the full e2e (register → USDC deposit → order fills at oracle mark → withdraw → root published → `vault.claim`). Check 3b-4: a receipt carries `windowId`, `GET /v1/batch/:id` reconciles, `openWindowId`≈`l1.batchCount`. Confirm the settle loop **serializes** (at most one window sealed-but-unsettled; the `begin_window_settle` desync guard blocks a second settle until the first lands — so ~13-min proofs stretch the effective window, they do NOT wedge). **Gate:** a real proof settled on-chain + e2e green.

## 6. Risks + mitigations

- **vkey drift** (guest ELF changed since Slice-1 → `0xCbdD…` rejects). Mitigation: the Phase-1 gate compares `/vkey` to `programVKey()`; on mismatch, redeploy `SP1ZkVerifier(SP1VerifierGateway, newVkey)` (look up the gateway address) and use it in Phase 3.
- **Genesis lockstep** (fresh Settlement `genesisRoot` ≠ gateway boot root → first `settleBatch` reverts `BadPrevRoot`). Mitigation: Phase 2 reads the exact boot root from the new log line and Phase 3 deploys with it; Phase-3 + Phase-4 gates cross-check `currentStateRoot == genesisRoot == boot root`. The boot config (3 markets, fees, insurance seed, funding) MUST be byte-identical between the Phase-2 read and the Phase-4 run (same binary, same env) — it is deterministic.
- **~13-min proof cadence** (proof ≫ the ~30s design window). Mitigation: the window-settle loop serializes via the desync guard (one window in flight; the effective on-chain cadence is ~1 settle per proof, ~13 min). Verify in Phase 5. Soft-finality (MATCHED) stays instant for users; only SETTLED lags — note it in the TestnetNotice.
- **Prover downtime** (GB10 asleep/offline → settles stall). Mitigation: the new-path settle failure heals (3b-3 rollback re-seals; 3b-3.1 recovers a landed tx); a stalled prover just means no new settles until GB10 is back (soft-finality unaffected). Keep GB10 awake; alert on settle-stuck (existing `darkperp-health` ntfy). Fold the 3b-3.1 runbook items (alert on "HOLDING" log lines; a one-time wedged-RPC forced-failure probe) into Phase 5.
- **Snapshot mis-restore** (fail-closed exit(1)). Mitigation: Phase 4 deletes the snapshot deliberately (fresh boot); the fail-closed behavior is the safety net, not a bug.
- **Bond shortfall** (deployer USDC < required bond → `settleBatch` reverts `UnderBonded`). Mitigation: Phase-0 funds check + Phase-3 `postBond`.

## 7. Rollback

The old stack stays fully valid on-chain (contracts + the pre-3b build). To revert at any red gate: restore `/etc/darkperp/gateway.env.bak-<ts>`, `/usr/local/bin/darkperp-gateway.bak-<ts>`, and `/var/lib/darkperp/state.snap.bak-<ts>`; `systemctl restart darkperp-gateway`. The gateway rejoins the legacy path on `0x27Fc1bDa…` at its last-good root (its boot continuity check confirms `currentStateRoot` matches the restored snapshot). No on-chain action needed to roll back. Stop the GB10 prover + leave the tailnet if abandoning.

## 8. Non-goals

- Not P3 (real TDX/Nitro attested x86_64 prover + secret-keyed nonce) — GB10 is the dev prover; the prover-attestation gap is documented, not closed here.
- No protocol/contract logic change (only the `Deploy.s.sol` VERIFIER env + the gateway genesis log — both non-behavioral).
- No DNS/Caddy/domain change; no market-set change; no new frontend.
- Not a mainnet deploy (chain guard refuses `8453`/`1`; MockUSDC faucet + testnet posture stay).
