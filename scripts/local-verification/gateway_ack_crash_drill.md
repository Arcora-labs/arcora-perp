# Gateway HTTP acknowledgement crash drill

Build the normal gateway executable and install the frontend's locked dependencies
before running the drill. The signing helper uses the existing `@noble/curves` and
`@noble/hashes` packages; it does not add a new dependency.

```sh
cargo build --locked -p gateway
pnpm --dir frontend install --frozen-lockfile
python3 scripts/local-verification/gateway_ack_crash_drill.py \
  --gateway-bin target/debug/gateway \
  --output-dir /tmp/arcora-gateway-ack-crash-FRESH
```

The output directory must not already exist. Keep the build's source fingerprint
with `result.json`: the runner records the exact binary and script hashes, but
cannot infer which source files produced a binary supplied by its caller.

The runner executes nine cases against actual gateway processes, using a fresh
encrypted snapshot, generated wallet/enclave keys and dynamic loopback ports for
each case. It sends no L1 transaction and never requests a proof.

| Operation | Before request body | Completed response lost | Complete ACK received |
|---|---|---|---|
| Deposit authorization | Admit headers with HTTP 100 Continue, withhold body, kill; baseline account and permit remain valid | Proxy receives real response but sends zero bytes to client; kill; same permit still routes after restart | Client reads full response, then kill; same permit still routes after restart |
| Credential recovery | Original credential and nonce survive; fresh challenge resolves the interrupted attempt | Old credential revoked and nonce advanced; client signs current public nonce, without using the lost key | Received replacement key remains valid after restart |
| Order cancellation | The unfilled order survives; cancellation resolves after restart | Cancellation survives; retry returns the same historical receipt | Cancellation survives; retry returns the same historical receipt |

Every case checks owner, balance, positions, order nonce, withdrawal nonce and
address binding. Recovery checks reject the original nonce replay. Cancellation
checks preserve the original acceptance receipt, a single order row, zero filled
and remaining quantity, and unchanged execution metadata after repeated retries.
`cancelledSize` is the historical cancellation result: a successful retry repeats
that amount instead of reporting a newly applied quantity. Each resolution is
followed by another SIGKILL and restart to verify its durable state, then the last
owned process is killed for cleanup: 27 SIGKILL exits in total.
Snapshot hashes are recorded but do not have to remain byte-identical while the
gateway runs: a legitimate periodic save uses a fresh seal nonce. Assertions
check the restored operation and account state instead.

The lost-response proxy can privately observe a completed response to check server
state, but that observation is not client knowledge. A lost recovery key is never
used to resolve the recovery. For a lost deposit authorization, the current API
does not offer an idempotency token or a permit lookup that recreates the lost
signature. The runner therefore records this outcome as unknown to the client,
does not issue another permit, and performs no on-chain send. The retained permit
is checked through the existing route handler, which issues no new signature and
credits no funds. This is preservation and honest uncertainty, not a claim that
the lost authorization became usable by the client.

This matrix exercises the production executable's HTTP and persistence paths in
demo mode. It uses demo collateral and an unsealed test order; public oracle and
candle reads remain enabled. It is not a production deployment, power-failure
simulation, internal fsync barrier matrix, complete funds-flow test, or completion
of the original S6-02 release gate. No production crash hooks are introduced.
