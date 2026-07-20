# FIN-001 Remediation — Settlement Circuit-Breaker (bounded retry + HELD) — Design

**Finding:** FIN-001 [med] — the L1 settle loop retries a failed prove **forever**. On
`SettleAttempt::ProveFailed` (`crates/gateway/src/main.rs:5674-5685`) the window is rolled
back (`seq.rollback_window`, which **prepends** the failed ops ahead of newer ones) and
retried on the next `L1_SETTLE_SECS` tick — with **no failure counter, no backoff, and no
circuit breaker**. A single window that never proves (almost always a prover/infra outage;
in the worst case a genuine host↔guest divergence "poison pill") is re-sealed at the head of
every subsequent window and blocks every order behind it from ever reaching L1 finality,
indefinitely and invisibly.

The dangerous parts of the original audit finding are already fixed by prior work: rollback
is real (`sequencer/src/lib.rs:1120-1136` restores `next_batch_id`/`window_start_state`),
and finality is real, not simulated (`window_settle_mode = prover.is_some()` disables the
demo auto-advance; `Finality::Settled` is only reached after a real on-chain
`l1c.settle_proved(...)` tx). **This design closes the one residual gap: the unbounded,
silent retry.**

## Scope

Turn the unbounded retry into a **bounded-retry → backoff → HELD circuit-breaker** with
operator visibility, chosen posture **halt-and-alert** (never auto-reject a valid order):

- Count consecutive `ProveFailed`s; apply exponential backoff so transient prover outages are
  ridden out without hammering.
- After a threshold `N`, enter a **HELD** state: loud alert + a `settlement_health` field
  exposed on the status/WS surface; settle attempts continue only at the backoff cap.
- **Self-heal:** any successful settle clears HELD → HEALTHY. A genuine poison-pill stays
  HELD + alerting forever (correct — it needs a human), but **no valid order is ever
  rejected and settlement never wedges silently.**
- **Admin force:** a gated endpoint lets the operator trigger an immediate attempt (skip the
  current backoff), for when they have fixed the prover and don't want to wait for the cap.

**Non-goals / explicitly NOT done (halt-and-alert was chosen over auto-quarantine):**

- No op rejection / quarantine. We do **not** split a "poison" op out or mark it
  `Finality::Rejected`. That means **no `perp-core` change, no `rejected_root`/manifest
  change, no circuit/guest change** — this fix is pure gateway host-side control flow.
- No change to `rollback_window` semantics (prepend-and-retry stays; we only gate the
  cadence and add the HELD stop).
- No change to order intake, matching, or the trading hot-path. Only **L1 settlement** is
  held — users keep trading; they only wait longer for L1 finality while HELD.
- No new alerting infrastructure required (ntfy is optional, see §4).

## Current state (grounding)

- `crates/gateway/src/main.rs`:
  - Settle loop: `tokio::time::interval_at(now + L1_SETTLE_SECS, L1_SETTLE_SECS)`
    (`~5509`), `loop { iv.tick().await; ... }`; `L1_SETTLE_SECS = 30` (`:292`).
  - `enum SettleAttempt { Ok{...}, ProveFailed(String), SettleFailed{...} }` (`:5595`).
    Any error from `prove_and_prepare` becomes `ProveFailed(e)` (`:5617`) — **infra failures
    (prover down / 401 after re-handshake / timeout) and a hypothetical deterministic
    invalid-witness are NOT distinguished today.**
  - `ProveFailed` arm (`:5674-5685`): `eprintln!` + `seq.rollback_window(&witness_rb)` +
    `rollback_window_withdrawals(ww_rb)` + keep journal + `snapshot_notify`. No counter.
  - `SettleFailed` (ambiguous cast-send) already has explicit on-chain reconcile
    (`:5686-5779`) — **out of scope; left unchanged.**
  - Auth: an `ApiKey` security scheme (`let auth = json!({"security":[{"ApiKey":[]}]})`,
    `:4260`) already guards privileged endpoints (e.g. withdraw). The admin resume endpoint
    reuses it. No `/admin` route exists yet.
  - The gateway `snapshot()` / status surface is what the status API + WS broadcast serialize.

## Design

### 1. `SettleHealth` — pure state machine (testable core)

A small, clock-free struct (new module `crates/gateway/src/settle_health.rs`) holding the
policy; the loop supplies timing.

```rust
pub enum Health { Healthy, Degraded, Held }

pub enum NextAction {
    /// Retry after this delay (0 ⇒ attempt on the next tick).
    Retry(Duration),
    /// HELD: keep probing, but only at the cap interval.
    Hold(Duration),
}

pub struct SettleHealth {
    consecutive_failures: u32,
    threshold: u32,        // N — HELD at/after this many consecutive failures
    base: Duration,        // backoff base (= L1_SETTLE_SECS)
    cap: Duration,         // backoff / probe ceiling
    last_error: Option<String>,
    // `held_since` / a monotonic timestamp is threaded by the loop, not stored here,
    // to keep this struct clock-free and deterministic under test.
}

impl SettleHealth {
    pub fn on_success(&mut self) { self.consecutive_failures = 0; self.last_error = None; }

    pub fn on_failure(&mut self, err: String) -> NextAction {
        self.consecutive_failures += 1;
        self.last_error = Some(err);
        let n = self.consecutive_failures;
        if n >= self.threshold {
            NextAction::Hold(self.cap)                    // HELD — probe at cap
        } else {
            // exponential: base * 2^(n-1), capped
            let d = self.base.saturating_mul(1u32 << (n - 1)).min(self.cap);
            NextAction::Retry(d)
        }
    }

    pub fn health(&self) -> Health {
        match self.consecutive_failures {
            0 => Health::Healthy,
            n if n >= self.threshold => Health::Held,
            _ => Health::Degraded,
        }
    }
    pub fn consecutive_failures(&self) -> u32 { self.consecutive_failures }
    pub fn last_error(&self) -> Option<&str> { self.last_error.as_deref() }
}
```

### 2. Settle-loop wiring

The loop keeps ticking every `L1_SETTLE_SECS`, but gates each attempt on a `next_attempt`
deadline (a `tokio::time::Instant`):

- On each tick: if `now < next_attempt`, skip (still cheap; no prove attempted).
- On `SettleAttempt::Ok`: `health.on_success()`; `next_attempt = now` (normal cadence);
  if we were HELD, log the recovery.
- On `SettleAttempt::ProveFailed(e)`: the existing rollback runs unchanged, then
  `match health.on_failure(e) { Retry(d) | Hold(d) => next_attempt = now + d }`. On the
  transition **into** HELD (crossing the threshold) emit the distinctive alert (§4) exactly
  once, not every probe.
- `SettleFailed` is unchanged and does **not** feed `SettleHealth` (it has its own reconcile;
  a settle-send ambiguity is not a prove failure).
- Admin force sets `next_attempt = now` so the next tick attempts immediately.

### 3. Status surface

Add to the gateway snapshot / status payload (and thus the status API + WS `State`):

```
settlement_health: "HEALTHY" | "DEGRADED" | "HELD"
settlement_consecutive_failures: u32
settlement_last_error: string | null
settlement_held_since_ms: u64 | null   // set when entering HELD, cleared on recovery
```

`DEGRADED` = ≥1 consecutive failure but below threshold (backing off); `HELD` = at/over
threshold. This is the operator's and any monitor's signal.

### 4. Alert on entering HELD

On the HEALTHY/DEGRADED→HELD transition, emit one distinctive, greppable line
(`eprintln!("[l1][HELD] settlement halted after {N} consecutive prove failures: {last_error} — trading continues, L1 finality paused; fix prover or POST /v1/admin/settlement/resume")`).
If `FIN_ALERT_NTFY_TOPIC` is set, also POST a one-line alert there (best-effort, non-fatal);
unset ⇒ log-only. No new required dependency.

### 5. Admin resume endpoint

`POST /v1/admin/settlement/resume`, gated by the existing `ApiKey` auth scheme (`:4260`) —
the same guard privileged endpoints already use; unauthenticated ⇒ 401. Effect: set a shared
**force signal** the settle loop owns (an `AtomicBool` / `Notify` shared between the endpoint
task and the loop task — `SettleHealth` stays clock-free and holds no force state); on the
next tick the loop treats the signal as `next_attempt = now`, attempts a settle, and clears
the signal. It does **not** fake HEALTHY — health clears only when a real settle succeeds.
Response reports the current `settlement_health` so the operator sees whether the forced
attempt cleared it. Idempotent; safe to call when already HEALTHY (no-op).

### Configuration (env, with defaults)

| Env | Default | Meaning |
|---|---|---|
| `FIN_HELD_THRESHOLD` | `3` | `N` consecutive `ProveFailed`s before HELD |
| `FIN_BACKOFF_CAP_SECS` | `300` | backoff / HELD-probe ceiling |
| `FIN_ALERT_NTFY_TOPIC` | unset | optional ntfy topic for the HELD alert |

Backoff base is `L1_SETTLE_SECS`. Values are read once at boot; invalid ⇒ default + WARN.

## Behavior matrix

| Consecutive ProveFailed | Health | Next attempt | Order rejected? | Trading? |
|---|---|---|---|---|
| 0 | HEALTHY | next tick (`L1_SETTLE_SECS`) | no | yes |
| 1..N-1 | DEGRADED | `base·2^(n-1)` capped | no | yes |
| ≥ N | HELD | every `cap` (self-heal probe) | **no** | yes |
| any → success | HEALTHY | normal cadence | no | yes |
| HELD + admin resume | HELD until a probe succeeds | immediate | no | yes |

Settlement never wedges silently and never auto-rejects a valid order; a persistent failure
becomes a loud, visible, self-healing HELD.

## Components & interfaces (files)

- `crates/gateway/src/settle_health.rs` (new) — `SettleHealth`, `Health`, `NextAction`; pure,
  unit-tested.
- `crates/gateway/src/main.rs` — `mod settle_health; use`; instantiate `SettleHealth` for the
  settle loop; gate attempts on `next_attempt`; feed `on_success`/`on_failure`; HELD alert;
  add `settlement_*` to the snapshot/status; add the `POST /v1/admin/settlement/resume` route
  behind `ApiKey` auth.
- No change to `crates/perp-core`, `crates/sequencer` (`rollback_window` untouched), the SP1
  guest, or the L1 contracts.

## Testing (TDD, per repo methodology)

Pure `SettleHealth` (fully local, `cargo test -p gateway`):
1. `on_failure` below threshold ⇒ `Retry` with exponential-then-capped delay; `health()`
   is `Degraded`.
2. `on_failure` reaching `threshold` ⇒ `Hold(cap)`; `health()` is `Held`.
3. `on_success` at any point ⇒ counter 0, `Healthy`, `last_error` cleared (self-heal).
4. Backoff schedule is exponential and never exceeds `cap`; deterministic (no clock).
5. `force_retry_now` does not reset health (still `Held` until a success).

Loop/endpoint (gateway builds+tests here):
6. The settle loop skips attempts while `now < next_attempt` and attempts once it passes
   (driven with an injected/short interval or by unit-testing the gate helper).
7. `POST /v1/admin/settlement/resume` without the API key ⇒ 401; with it ⇒ 200 and the
   next attempt is un-gated (assert `next_attempt` moved to now / a "force" flag set).
8. Status snapshot serializes `settlement_health`/`consecutive_failures`/`last_error`.

## Out of scope / deferred

- Auto-quarantining a genuine poison-pill op (would need the `rejected_root` path + a way to
  attribute which op is at fault — bisection). Deliberately not done; HELD + alert surfaces it
  for a human instead. If poison-pills prove common in practice, a follow-up can add operator-
  driven op quarantine on top of this HELD state without reworking it.
- Classifying `ProveFailed` into infra-vs-invalid subtypes. Not needed for halt-and-alert
  (both paths lead to the same bounded-retry→HELD); a future refinement could shorten the
  path to HELD for a clearly-deterministic failure.
