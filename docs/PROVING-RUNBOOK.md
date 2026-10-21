# Proving Runbook — real SP1 verification (P2 Slice 1)

Run these on an **SP1-capable machine** (Linux, Docker for Groth16, ample RAM/GPU).
The coding repo ships only the on-chain adapter + host fix; proof generation and
deployment happen here.

## 0. Privacy rule (read first)
The batch witness contains plaintext positions/fills. **Do NOT use Succinct's public
Prover Network** for real batches — it would see the witness. Proving must run on the
**self-hosted, attested prover** (§10b): a public network gets `MeasurementMismatch`
and cannot open a sealed witness. A Groth16-capable **attested** VM is required (the
current `DC2es_v6` CVM may be too small — size up as an infra decision).

## 1. Install the SP1 toolchain
```bash
curl -L https://sp1up.succinct.xyz | bash
sp1up          # installs `cargo prove` + the riscv32im-succinct-zkvm-elf target
cargo prove --version
```

## 2. Build the guest (optional — verification only)
```bash
cd crates/sp1-guest && cargo prove build
```
Produces the `perp-core-guest` ELF. This step is now optional: `crates/sp1-host/build.rs`
(`sp1_build::build_program("../sp1-guest")`) auto-builds the guest whenever you `cargo run`
the host in step 3. Run this step standalone only if you want to sanity-check the guest
builds in isolation before invoking the host.

## 3. Equivalence gate (validates P1 in the real zkVM)
```bash
cd crates/sp1-host && cargo run --release --bin sp1-host
```
(`--bin sp1-host` is required: the crate has several bin targets and no `default-run`,
so a bare `cargo run` errors with "could not determine which binary to run". Run with
`SP1_SKIP_PROGRAM_BUILD` **unset** — CI's typecheck job sets it, and with it set the
guest ELF this gate executes is never built.)
Asserts that the native `perp_core::clock::bind_transition(...).commitment` equals the
guest's committed value for the same clock-bound witness bytes. This is
the first execution of the P1 circuit in the SP1 zkVM. Must print the equality/success
before proceeding. (If include_elf! can't find the guest ELF, run the standalone build
first — `cd crates/sp1-guest && cargo prove build` — and if it still isn't found, as a
last resort edit `crates/sp1-host/src/main.rs` to embed it directly with `include_bytes!`
of `target/elf-compilation/riscv32im-succinct-zkvm-elf/release/perp-core-guest`, the
guest's real SP1 target path.)

## 4. Get the vkey + a real Groth16 proof
In an `sp1-sdk` script (or extend `sp1-host` with a `--prove` mode on your machine):
```rust
use sp1_sdk::{include_elf, Elf, HashableKey, ProverClient, SP1Stdin};
const ELF: Elf = include_elf!("perp-core-guest");

let client = ProverClient::from_env().await;      // MUST resolve to the local/attested prover, NOT the network
let pk = client.setup(ELF).await.unwrap();
let vkey: String = pk.verifying_key().bytes32();  // <-- the bytes32 for the SP1ZkVerifier constructor
let mut stdin = SP1Stdin::new();
stdin.write_vec(witness_bytes);                    // b"DPCLK4\0\0" ‖ postcard((DefaultState, Vec<BatchOp>, BatchManifest, ClockContext))
let proof = client.prove(&pk, stdin).groth16().await.unwrap();
let proof_bytes = proof.bytes();                   // <-- settleBatch `proof` arg
let public_values = proof.public_values.as_slice();// == the 32-byte clock-bound commitment
```
Record `vkey` (bytes32) and `proof_bytes`.

The guest accepts only that framing, with no trailing bytes; an unframed tuple or any
other magic is refused before decode. The committed value is
`keccak256(abi.encode(keccak256("arcora:clock-bound-proof:v2"), publicCommitment, receipt))`,
the commitment bound to the window's L1 clock receipt; `ClockBoundVerifier` recomputes it
and passes it to `SP1ZkVerifier`. For the reviewed fixture, `clock-proof` in
`crates/sp1-host` builds the witness and runs this flow.

## 5. Deploy the on-chain verifier
- Find the Base Sepolia **SP1VerifierGateway** address in
  `github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments`.
- Deploy `SP1ZkVerifier(gateway, vkey)` (from this repo's `contracts/src/SP1ZkVerifier.sol`).

## 6. Redeploy the settlement pointing at it
`DarkPerpSettlement.verifier` is immutable, so swapping the verifier is a redeploy. The
settlement no longer accepts `SP1ZkVerifier` directly: its constructor refuses any
verifier that is not a fresh, unbound clock verifier (`proofVersion() == 2`,
`settlement() == 0`). The chain is:
```
SP1ZkVerifier(gateway, vkey)
  → ClockBoundVerifier(SP1ZkVerifier, maxWindowMs, clockSkewMs, anchorTimeoutMs)
  → DarkPerpSettlement(Config{ sequencer, enclaveSigner, verifier = clock, genesisRoot,
        livenessTimeoutBlocks, challengeGraceBlocks, challengeBond, inclusionDeadlineSecs,
        governance, finalSettleGraceBlocks, progressBatches, slashPayoutCap })
  → CollateralVault(settlement, token, gatewaySigner) → setVault → bindSettlement
```
Deploy it with `scripts/local-verification/deploy_clock_stack.py` (see
`docs/REDEPLOY-CC-RUNBOOK.md`), never with `Deploy.s.sol`, which wires only the mock.
The gateway posts the sequencer bond before deposits open.

## 7. End-to-end
Submit a real settlement (SEC-025-B: `settleBatch` takes NINE parameters — seven
roots including the SEC-019 `depositsRoot`, the cumulative `uint64 newDepositCount`,
and the proof). The window must have been registered with the clock first; the
settlement records `newDepositCount` as `consumedDepositCount()`, and it must lie
between the previous value and the vault's `depositCount()`:
```
settleBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot,
            depositsRoot, newDepositCount, proof_bytes)
```
`publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot,
rejectedRoot, depositsRoot)` is the base commitment. `ClockBoundVerifier` binds it to the
receipt registered for the window, and that bound value must equal the 32-byte
`public_values` from step 4; the SP1 gateway must accept `proof_bytes` under the pinned
`vkey`. On success the derived commitment is now enforced on-chain by real ZK.

## Notes / gotchas
- Proving latency + resources set the L1 settle cadence.
- **Slice 2 (not done):** the gateway still publishes the CUMULATIVE `withdrawalsRoot`
  over `pending_withdrawals` and aggregates multiple engine batches per L1 settle, while
  the circuit derives a PER-ENGINE-BATCH incremental root. For the on-chain
  `withdrawalsRoot` to match the proof, the gateway must switch to per-engine-batch
  settlement (Slice 2) — until then, a real proof only matches if you settle one engine
  batch at a time with its own incremental root.

## Prover service (Slice 2) — real proofs on demand

On the SP1 machine (GB10), the prover service (`crates/prover-service`, excluded from
the workspace) turns a sealed witness into a real Groth16 proof the on-chain
`SP1ZkVerifier` accepts.

### Build + run
```bash
# one-time on an arm64 host: register the amd64 emulator for the gnark (amd64-only) image
docker run --privileged --rm tonistiigi/binfmt --install amd64

cd crates/prover-service
DOCKER_DEFAULT_PLATFORM=linux/amd64 cargo run --release   # amd64 gnark under qemu (arm64 host)
# serves on 127.0.0.1:8091 by default (override with PROVER_BIND=host:port)
curl -s localhost:8091/vkey          # -> {"vkey":"0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024"}
curl -s localhost:8091/measurement   # -> {"measurement":"0xabab…"}  (SoftwareSeal stand-in, all-0xAB)
```
`vkey` is the `programVKey` the service's SP1 setup derives for the guest ELF — it must
match the deployed `SP1ZkVerifier`'s immutable `programVKey`
(`0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024` for the Slice-1
Base Sepolia deploy below). The seal root the service opens sealed witnesses against is
`PROVER_SEAL_ROOT` (env, hex; defaults to all-`0x5E` if unset) — must match whatever the
caller sealed the witness to.

### Prove a batch
A client seals the witness to the service's `/measurement` (SoftwareSeal stand-in) and
POSTs it:
`POST /prove {"sealed":"0x<hex postcard-encoded SealedWitness>"}` →
`{prev_root, manifest_hash, new_root, ordered_root, withdrawals_root, rejected_root,
commitment, proof}` (all hex-prefixed).

### Seal + POST (client side)
The service opens a witness sealed to its measurement (`0xAB…AB`, the stand-in) with the
seal root (`PROVER_SEAL_ROOT`, default `0x5E…5E`). A client builds the batch witness, seals it,
and POSTs the hex:
```rust
// (in a small client bin or extend sp1-host) — build the (state, ops, manifest) witness bytes,
// then:
let m = [0xABu8; 32];
let sealed = prover::SealedWitness::seal(
    &witness_bytes,
    &prover::SoftwareSealProvider::new([0x5Eu8; 32], m),  // must match the service's root+measurement
    m,
    nonce,
).unwrap();
let hex = format!("0x{}", hex::encode(postcard::to_allocvec(&sealed).unwrap()));
// curl -s localhost:8091/prove -H 'content-type: application/json' -d "{\"sealed\":\"$hex\"}"
```
SEC-025-B: take ONLY the `proof` bytes from the response. The service's itemised
roots are DIAGNOSTIC — the response carries no `depositsRoot` at all, and the roots
submitted on-chain come from the gateway's own LOCAL replay of the witness
(`perp_core::commitment::derive_roots`, exactly what `prove_and_prepare` in
`crates/gateway/src/prover_client.rs` does). Derive all seven roots + the post-replay
`consumed_deposit_count` locally, check the service's `commitment` equals the keccak
commitment over YOUR seven derived roots, then pair your roots with its `proof`.

(If `PROVER_SEAL_ROOT` is unset the service uses `0x5E…`; if set, the client must use the same value.)

### e2e verify on-chain (the merge gate)
Submit your seven locally derived roots, the cumulative `newDepositCount`, and the
service's proof to a fresh `DarkPerpSettlement` wired to the Slice-1 `SP1ZkVerifier`
(`0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF` on Base Sepolia), genesis = `prev_root`.
(Historical: this direct wiring predates the clock verifier. A settlement built from
current source refuses a direct `SP1ZkVerifier`; wrap it in a `ClockBoundVerifier`
and register the window before settling.)
`newDepositCount` is the **cumulative** post-state `consumed_deposit_count`, not a
per-window count (a zero-deposit window over a pre-state that already consumed five
deposits submits **5**); `_requireDepositPrefix` pins `depositsRoot` to the vault's
deposit-chain tip at exactly that count, before the proof is even verified:
```bash
cast send <SETTLEMENT> \
  "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)" \
  <prev_root> <manifest_hash> <new_root> <ordered_root> <withdrawals_root> <rejected_root> \
  <deposits_root> <new_deposit_count> <proof> \
  --rpc-url https://sepolia.base.org --private-key $KEY
```
`$KEY` must be the deployed settlement's `sequencer` (`settleBatch` is `onlySequencer`).
Status 1 = the service's real proof was verified on-chain by `SP1ZkVerifier`. (Privacy:
for real batches the service must run on a self-hosted **ATTESTED** x86_64 prover — the
gnark image is amd64-only, so the arm64 GB10 is a dev/test prover, not a production
attested one; P3 adds real TDX/Nitro key-release.)

## Clock registration preflight

Before the gateway registers a window with the clock it checks:

- the sealed body fits within 512 MiB and the prover's advertised limit;
- no phase-0 window is registered while the settlement is in close-only;
- under `DARKPERP_PROD=1` with the HTTP prover, the clock's inner verifier chain
  leads to an SP1 adapter whose `programVKey()`, and the route's ELF hash, match the
  release or candidate manifest in use. Mock and Chainlink-candidate stacks, whose
  inner verifier has no `programVKey`, skip only this identity check;
- under `DARKPERP_PROD=1`, the HTTP prover's `GET /identity` was read: when it times
  out, fails or lacks a field, the window is rolled back unregistered like any
  refused preflight and the settle loop retries, so no window registers without the
  prover's identity in hand. Outside production a failed identity read only means
  the body-size check uses the 512 MiB transport limit.

A timed window must register within `clockSkewMs` of its last operation, and
operations are admitted until the settle tick pauses admission. So everything that
does not depend on the window is read before the pause: the bond top-up, the
stake-refund sweep, the batch count, the clock binding, the settlement's batch
count and phase, the prover's identity and, in production, the adapter's
`programVKey()` (read once; the route is immutable). Between the seal and the
register only local work remains: the body-size check against the limit read
before the pause, and the sealed window's batch and phase against the settlement's.
The register's own read and send are the only L1 round trips left in that budget.

## Stale clock anchor: cancel

Every settle path needs a clock anchor for the current batch and phase before its
proof can verify. Before `anchorTimeoutMs` an anchor cannot be replaced
(`ReplacementForbidden`). An anchor whose proof can never land would therefore hold
the batch, so the clock lets the registrant role remove it once it is old enough:

| Phase | Who may cancel | When |
|---|---|---|
| 0 (ordinary) | `sequencer` | while the settlement is live, after `anchorTimeoutMs` |
| 1 (SettleAll) / 2 (exits) | `governance` | in close-only, after `anchorTimeoutMs` |

`anchorTimeoutMs` is 1 h at launch. The gateway refuses to boot unless it covers two
finality budgets plus the prover timeout plus a margin, so an anchor whose honest
proof is still on its way is never old enough to cancel. The gateway raises a
stale-anchor alert once an anchor is older than `anchorTimeoutMs`.

**Procedure.**

1. Make sure the anchor is dead, not slow. No local settle for that receipt may be
   in flight, and the prover must not still be working on it.
2. Read the anchor from one deployment. `clock.phase()` gives the phase,
   `settlement.batchCount()` the batch id, and `clock.anchor(batchId, phase)` the
   `receipt` and `anchoredAtMs`.
3. Cancel through the gateway with
   `POST /v1/admin/settlement/cancel-anchor { "batchId", "phase", "receipt" }`
   (`FIN_ADMIN_KEY`; see `docs/API.md`). Without the gateway, the registrant key can
   send it directly:

   ```bash
   cast send $CLOCK "cancel(uint64,uint8,bytes32)" <batchId> <phase> <receipt> \
     --rpc-url $RPC <registrant signer flags>
   ```

   The call reverts `Unauthorized` (wrong role), `BadContext` (not the current batch
   or phase), `MissingAnchor` (no anchor, or another receipt) or `InvalidTime` (not
   old enough).
4. Check that `cancelledReceipt(receipt)` is true and `ClockCancelled` was emitted.

**Effects.** The anchor is deleted and `lastTimedMs` is not rolled back. A proof
bound to the cancelled receipt can never verify again. A re-registration is stamped
later, so it gets a new receipt. The gateway treats a cancelled receipt as the end
of that window's settle wait. The settle loop then classifies the window at a
finalized block and resolves it (§ Dead clock window); a restart is not needed, and
`POST /v1/admin/settlement/resume` makes the loop poll at once. If the loop holds
instead, reconcile through the rollback journal and restart before repeating a
wind-down step. Never edit the state by hand.

## Dead clock window

Once a window's clock intent is journaled, a failed registration, proof or settle
no longer stops the settle loop. The window stays sealed and clock admission stays
closed, so no orders, fills, liquidations or funding ticks run; the settlement's
liveness and deposit-inclusion clocks keep running. Each poll reads the durable
journal again and the settlement, the anchor slot, the sequencer nonce and the
block time at one finalized block, then:

- commits our settle if it landed;
- settles the exact journal again if our own anchor is registered, with the settle
  backoff and a check at the latest block that the anchor is still ours; after
  three failures the proof is made once more and `clock_recovery_blocked` is raised;
- resolves the window if it can never settle (below);
- otherwise waits.

`GET /api/state` shows the pending recovery as `clockRecovery` (`docs/API.md`).

**When a window can never settle.** Our anchor is not in the slot (it was
cancelled, or none exists), and no transaction of ours can still put it there.
One of these shows it:

| Basis | Applies to | Rule at the finalized block |
|---|---|---|
| chain clock | a window with timed operations | the header-bound block time is past the window's last operation time plus `clockSkewMs`. Block times never decrease, so a registration mined later reverts `InvalidTime`. This is the usual case: a registration sent after `clockSkewMs` is refused by its gas estimate and never broadcast |
| quiet nonce fence | every window; the only basis for an untimed window or one whose operation times are not monotonic | the sequencer's finalized nonce is past every nonce recorded for the window's sends, and on every configured RPC (`L1_RPC`, `L1_RPC_WITNESS`) its latest and pending nonces equal the finalized nonce |

The chain clock basis relies on header-bound, non-decreasing block times of a
finalized, witness-agreed block, which Base and other EVM chains provide. The
gateway also refuses to send a timed registration once its own clock is within a
small margin of the window's last operation time plus `clockSkewMs`; nothing is
sent and no nonce is recorded.

**What happens to it.**

| Window | Result |
|---|---|
| phase 0 with timed operations | voided (below) |
| phase 0 whose operation times are not monotonic | voided on the fence basis; the log line says to check the gateway clock (NTP) |
| untimed (any phase) | returned to the open window; it registers again under a new receipt |
| phase 0 while the settlement is in close-only | returned to the open window; the close-only rebase drops it in the wind-down (`docs/FINAL_SETTLE_RUNBOOK.md`) |
| another anchor holds the batch and phase | waits with `clock_recovery_blocked`: cancel that anchor once it is older than `anchorTimeoutMs`, after which the window is resolved as above |
| an anchor of a journaled receipt is gone without a cancellation | holds: the settle loop stops |

The gateway never cancels an anchor by itself; cancelling stays the operator's
`POST /v1/admin/settlement/cancel-anchor`. After such a cancel a timed phase-0
window is voided once the cancel is final: the anchor was at least
`anchorTimeoutMs` old (1 h at launch), so its last operation time plus
`clockSkewMs` has passed, or passes at most `clockSkewMs` later with a shorter
timeout. An untimed window needs the fence; the cancel is itself a sequencer-key
send.
Close-only is still available through governance, but a dead phase-0 window no
longer needs it.

**Bounded nonce burn.** On the fence basis a recorded nonce that no transaction
used (a send refused before broadcast) would keep the fence from passing. After two
consecutive polls with quiet nonces and the finalized nonce at or below the
window's recorded ceiling, the loop sends a 0-value transfer from the sequencer key
to itself at exactly that nonce, with gas limit 21000 and no estimate, at most three
times per window. Under the sequencer key's nonce lock it reads the latest and
pending nonces again on every configured RPC and sends nothing unless they are all
that nonce, so it never replaces a sequencer-key transaction still in a mempool.
Configure `L1_ANSWER_KEYSTORE`, so challenge answers never use the sequencer key's
nonces. It touches no contract and cancels nothing. A window with timed
operations waits for the chain clock instead, unless the block time could not be
read.

**What a void does.** Everything the window did off-chain is discarded; nothing of
it ever landed on L1.

- The engine returns to the window's pre-state. Every fill of the window is undone.
  Each order the window sequenced, rejected or filled, including resting orders its
  fills touched, ends cancelled with the execution reason `WindowVoided`, and is
  published as `Cancelled` in the replacement window, which settles under the same
  batch id.
- Each deposit the window credited is credited again with new notes; the user does
  nothing. Until then `POST /v1/accounts/deposit/onchain` answers 202.
- Each withdrawal requested in the window is removed and can never be claimed; its
  amount is back in the position. The user requests it again with a new signature.
  No nonce moves back.
- An insurance bootstrap the window applied returns to `NotStarted`.
- Display-only figures (candles, ADL totals, house market-maker counters) are not
  reverted.

Affected accounts get `execution`, `withdrawalVoided` and `depositRestored` events
once the void is durable, `GET /v1/accounts/withdrawals` lists the removed
withdrawals as `voided`, and `/api/state` shows `settlementVoid`. The void is
persisted before the journal is deleted and before admission reopens.

**Operator steps.**

1. While a recovery is pending, read `clockRecovery` in `/api/state` and the
   `[recovery]` log lines. `clock_recovery_blocked` is raised when only the
   operator can act, and `clockRecovery.operatorAction` says what to do:

   | Reason | Action |
   |---|---|
   | another anchor holds the batch | cancel it once it is older than `anchorTimeoutMs` |
   | the settle keeps failing against our anchor | fix the prover or RPC, or cancel the anchor once it is older than `anchorTimeoutMs` |
   | a deposit halt blocks the settle | clear the halt, or cancel the anchor |
   | the nonce burns are used up | let the pending sequencer-key transaction be mined, or mine one from the sequencer key |
   | less than half of the close-only budget is left | resolve the window before anyone can trigger close-only |
   | the recovery has been pending for many polls | read the `[recovery]` log lines |
   | repeated live voids | see the void breaker below |

2. After a void, `window_voided` stays raised until the replacement window
   settles. Tell the users whose withdrawals were removed to request them again.
   The `settlementVoid` notice, the `voided` lists and `window_voided` are not
   persisted: a restart forgets them, so send the notice before restarting.
3. **Void breaker.** Two voids without a settled timed window between them, or
   three within an hour (a void at boot counts), stop the settle loop: the last
   void is durable and its journal deleted, but admission stays closed and
   `clock_recovery_blocked` is raised. A systematic delay between a window's last
   operation and its registration causes this; each failure logs
   `[recovery] window <n>: clock failed <ms> ms after its last timed op`. Fix the
   cause (gateway clock, RPC latency, disk), then restart. The restart is the
   acknowledgment; the next start is a normal boot.
4. The nonce fence file `<state>.l1-nonce` is part of the state. Never restore an
   older copy of it, and run only one gateway instance with the sequencer key.
5. With clock mode, configure `L1_ANSWER_KEYSTORE`, so challenge answers do not
   share the sequencer key's nonces.

**A restart while a window is undecided.** Boot classifies the journal with the
same rules, at one finalized block and with every recorded sequencer-key send as
the ceiling, but it cannot wait and does not burn. The evidence is read up to
three times; if every read fails, startup is refused and nothing is resumed. A
window with timed
operations is decided by the chain clock at boot, and one that may still settle is
resumed only against its existing anchor. An untimed window, or one whose
operation times are not monotonic, needs the fence: if boot refuses startup
because the sequencer nonce has not passed every recorded send, check that no
sequencer-key transaction is pending. If none is, mine any transaction from the
sequencer key at the finalized nonce, wait until it is finalized, and restart:

```bash
NONCE=$(cast nonce <SEQUENCER> --block finalized --rpc-url $RPC)
cast send <SEQUENCER> --value 0 --nonce $NONCE --gas-limit 21000 \
  --rpc-url $RPC <sequencer signer flags>
```
