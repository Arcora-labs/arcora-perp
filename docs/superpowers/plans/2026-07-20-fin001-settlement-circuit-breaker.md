# FIN-001 Settlement Circuit-Breaker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the L1 settle loop's unbounded, silent prove-retry with a bounded-retry → backoff → HELD circuit-breaker (halt-and-alert), so a persistent prove failure becomes a loud, self-healing, operator-visible HELD state instead of wedging settlement forever — without ever auto-rejecting a valid order.

**Architecture:** A pure, clock-free `SettleHealth` state machine (new `crates/gateway/src/settle_health.rs`) holds the policy (consecutive-failure counter, HEALTHY/DEGRADED/HELD, exponential-capped backoff). The settle loop owns timing (a `next_attempt` deadline) and feeds outcomes into it; a shared `Arc<AtomicBool>` force flag lets an operator-gated endpoint un-gate the next tick. Status is surfaced on the gateway snapshot. Pure gateway host-side — no `perp-core`/`sequencer`/circuit change.

**Tech Stack:** Rust, tokio, axum, the existing `crates/gateway`. Fully local: `cargo test -p gateway` (no SP1 toolchain).

## Global Constraints

- **Halt-and-alert only — NEVER auto-reject/quarantine an op.** No `perp-core`, `sequencer`, `rejected_root`/manifest, or SP1-guest change. Pure gateway host-side control flow.
- **Never wedge silently and never fake health:** a persistent failure must become a visible HELD; health (`HEALTHY`/`DEGRADED`/`HELD`) clears to HEALTHY ONLY on a real settle success, never by an admin action.
- **Fail-closed admin:** the resume endpoint is operator-only via a dedicated `FIN_ADMIN_KEY` (0x+64hex, `X-Admin-Key` header, constant-time compare). Unset ⇒ endpoint disabled (503). The per-user `X-Api-Key`/`api_key_from` scheme MUST NOT gate it.
- **Scope = L1 settlement only.** Order intake, matching, and the trading hot-path are untouched.
- **Defaults (env-overridable, read once at boot, invalid ⇒ default + WARN):** `FIN_HELD_THRESHOLD=3`, `FIN_BACKOFF_CAP_SECS=300`; backoff base = `L1_SETTLE_SECS` (30, `crates/gateway/src/main.rs:292`). Optional `FIN_ALERT_NTFY_TOPIC`, `FIN_ADMIN_KEY`.
- **fmt discipline:** the repo is not `rustfmt`-clean at HEAD; scope `cargo fmt` to touched hunks. `cargo clippy -p gateway --all-targets` must be clean.

---

### Task 1: `SettleHealth` pure state machine

**Files:**
- Create: `crates/gateway/src/settle_health.rs`
- Modify: `crates/gateway/src/main.rs` (add `mod settle_health;` near the other `mod`/`use` declarations at the top)
- Test: `crates/gateway/src/settle_health.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
```rust
pub enum Health { Healthy, Degraded, Held }          // Health::as_str() -> "HEALTHY"|"DEGRADED"|"HELD"
pub enum NextAction { Retry(std::time::Duration), Hold(std::time::Duration) } // NextAction::delay() -> Duration
pub struct SettleHealth { /* private */ }
impl SettleHealth {
    pub fn new(threshold: u32, base: Duration, cap: Duration) -> Self;
    pub fn from_env(base: Duration) -> Self;
    pub fn on_success(&mut self);
    pub fn on_failure(&mut self, err: String) -> (NextAction, bool); // bool = just entered HELD (alert once)
    pub fn health(&self) -> Health;
    pub fn consecutive_failures(&self) -> u32;
    pub fn last_error(&self) -> Option<&str>;
}
```

- [ ] **Step 1: Write the failing tests**

Create `crates/gateway/src/settle_health.rs` with only the test module first (types referenced don't exist yet ⇒ it won't compile ⇒ RED):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sh() -> SettleHealth { SettleHealth::new(3, Duration::from_secs(30), Duration::from_secs(300)) }

    #[test]
    fn healthy_initially() {
        let h = sh();
        assert_eq!(h.health(), Health::Healthy);
        assert_eq!(h.consecutive_failures(), 0);
        assert_eq!(h.last_error(), None);
    }

    #[test]
    fn first_failure_degraded_base_backoff() {
        let mut h = sh();
        let (a, just_held) = h.on_failure("boom".into());
        assert_eq!(a, NextAction::Retry(Duration::from_secs(30))); // base * 2^0
        assert!(!just_held);
        assert_eq!(h.health(), Health::Degraded);
        assert_eq!(h.last_error(), Some("boom"));
    }

    #[test]
    fn second_failure_exponential() {
        let mut h = sh();
        h.on_failure("a".into());
        let (a, _) = h.on_failure("b".into());
        assert_eq!(a, NextAction::Retry(Duration::from_secs(60))); // base * 2^1
        assert_eq!(h.health(), Health::Degraded);
    }

    #[test]
    fn third_failure_enters_held_alerts_once() {
        let mut h = sh();
        h.on_failure("a".into());
        h.on_failure("b".into());
        let (a, just_held) = h.on_failure("c".into());
        assert_eq!(a, NextAction::Hold(Duration::from_secs(300))); // cap
        assert!(just_held);                     // THIS failure crossed into HELD
        assert_eq!(h.health(), Health::Held);
        let (a2, just_held2) = h.on_failure("d".into());
        assert_eq!(a2, NextAction::Hold(Duration::from_secs(300)));
        assert!(!just_held2);                   // already HELD ⇒ no repeat alert
    }

    #[test]
    fn backoff_never_exceeds_cap() {
        // small cap forces the exponential to clamp
        let mut h = SettleHealth::new(10, Duration::from_secs(30), Duration::from_secs(45));
        h.on_failure("a".into());               // 30
        let (a, _) = h.on_failure("b".into());  // 60 -> clamp 45
        assert_eq!(a, NextAction::Retry(Duration::from_secs(45)));
    }

    #[test]
    fn success_resets_and_rearms_alert() {
        let mut h = sh();
        h.on_failure("a".into()); h.on_failure("b".into()); h.on_failure("c".into());
        assert_eq!(h.health(), Health::Held);
        h.on_success();
        assert_eq!(h.health(), Health::Healthy);
        assert_eq!(h.consecutive_failures(), 0);
        assert_eq!(h.last_error(), None);
        // after recovery a fresh HELD episode alerts again
        h.on_failure("x".into()); h.on_failure("y".into());
        let (_, just_held) = h.on_failure("z".into());
        assert!(just_held);
    }

    #[test]
    fn threshold_floor_is_one() {
        let mut h = SettleHealth::new(0, Duration::from_secs(30), Duration::from_secs(300));
        let (a, just_held) = h.on_failure("a".into()); // threshold coerced to 1 ⇒ immediate HELD
        assert_eq!(a, NextAction::Hold(Duration::from_secs(300)));
        assert!(just_held);
        assert_eq!(h.health(), Health::Held);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway settle_health`
Expected: FAIL — compile error, `SettleHealth`/`Health`/`NextAction` undefined.

- [ ] **Step 3: Implement the state machine**

Prepend to `crates/gateway/src/settle_health.rs` (above the test module):
```rust
//! FIN-001: bounded-retry + HELD circuit-breaker policy for the L1 settle loop.
//! Pure and clock-free — the settle loop owns all timing and feeds outcomes in.
use std::time::Duration;

pub const DEFAULT_HELD_THRESHOLD: u32 = 3;
pub const DEFAULT_BACKOFF_CAP_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health { Healthy, Degraded, Held }
impl Health {
    pub fn as_str(&self) -> &'static str {
        match self { Health::Healthy => "HEALTHY", Health::Degraded => "DEGRADED", Health::Held => "HELD" }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextAction { Retry(Duration), Hold(Duration) }
impl NextAction {
    pub fn delay(&self) -> Duration { match self { NextAction::Retry(d) | NextAction::Hold(d) => *d } }
}

#[derive(Debug, Clone)]
pub struct SettleHealth {
    consecutive_failures: u32,
    threshold: u32,
    base: Duration,
    cap: Duration,
    last_error: Option<String>,
    alerted: bool,
}

impl SettleHealth {
    pub fn new(threshold: u32, base: Duration, cap: Duration) -> Self {
        Self { consecutive_failures: 0, threshold: threshold.max(1), base, cap, last_error: None, alerted: false }
    }

    /// FIN_HELD_THRESHOLD (default 3), FIN_BACKOFF_CAP_SECS (default 300). base = L1_SETTLE_SECS.
    pub fn from_env(base: Duration) -> Self {
        let threshold = parse_env_u32("FIN_HELD_THRESHOLD", DEFAULT_HELD_THRESHOLD);
        let cap = Duration::from_secs(parse_env_u64("FIN_BACKOFF_CAP_SECS", DEFAULT_BACKOFF_CAP_SECS));
        Self::new(threshold, base, cap)
    }

    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_error = None;
        self.alerted = false;
    }

    pub fn on_failure(&mut self, err: String) -> (NextAction, bool) {
        self.consecutive_failures += 1;
        self.last_error = Some(err);
        let n = self.consecutive_failures;
        if n >= self.threshold {
            let just_entered = !self.alerted;
            self.alerted = true;
            (NextAction::Hold(self.cap), just_entered)
        } else {
            // exponential base * 2^(n-1), clamped to cap; guard the shift against overflow
            let mult = 1u64.checked_shl(n - 1).unwrap_or(u64::MAX).min(u32::MAX as u64) as u32;
            let d = self.base.saturating_mul(mult).min(self.cap);
            (NextAction::Retry(d), false)
        }
    }

    pub fn health(&self) -> Health {
        if self.consecutive_failures == 0 { Health::Healthy }
        else if self.consecutive_failures >= self.threshold { Health::Held }
        else { Health::Degraded }
    }
    pub fn consecutive_failures(&self) -> u32 { self.consecutive_failures }
    pub fn last_error(&self) -> Option<&str> { self.last_error.as_deref() }
}

fn parse_env_u32(key: &str, default: u32) -> u32 {
    match std::env::var(key) {
        Ok(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("[fin-001] WARN {key}={v:?} invalid — using default {default}");
            default
        }),
        Err(_) => default,
    }
}
fn parse_env_u64(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("[fin-001] WARN {key}={v:?} invalid — using default {default}");
            default
        }),
        Err(_) => default,
    }
}
```
Then add `mod settle_health;` to `crates/gateway/src/main.rs` alongside its other module declarations (grep `^mod ` / `^use crate::` at the top of that file to place it consistently).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p gateway settle_health`
Expected: PASS (7 tests). Also `cargo clippy -p gateway --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/settle_health.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): FIN-001 SettleHealth state machine (bounded retry + HELD, clock-free)"
```

---

### Task 2: `settlement_*` status fields on the snapshot

**Files:**
- Modify: `crates/gateway/src/main.rs` — `struct Gw` (`:963`), the `WState` snapshot struct, `fn snapshot(&self)` (`:3285`), and `Gw`'s constructor
- Test: `crates/gateway/src/main.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `settle_health::{SettleHealth, Health}` (Task 1).
- Produces: `Gw.settle_health: SettleHealth`, `Gw.settlement_held_since_ms: Option<u64>`; four new `WState` fields serialized by `snapshot()`.

- [ ] **Step 1: Write the failing test**

Add to the gateway test module (find an existing `#[cfg(test)]` that builds a `Gw`/app — grep `fn app_with_token|fn test_gw|Gw {` in `crates/gateway/src/main.rs` — and reuse that constructor). If a bare `Gw` is buildable in tests, prefer that; otherwise use the existing app builder and reach its `gw`.
```rust
#[test]
fn snapshot_exposes_settlement_health() {
    let mut gw = /* reuse existing test Gw/app builder */;
    // healthy by default
    let s = gw.snapshot();
    assert_eq!(s.settlement_health, "HEALTHY");
    assert_eq!(s.settlement_consecutive_failures, 0);
    assert_eq!(s.settlement_last_error, None);
    assert_eq!(s.settlement_held_since_ms, None);
    // drive to HELD (default threshold 3)
    gw.settle_health.on_failure("e1".into());
    gw.settle_health.on_failure("e2".into());
    let (_, just_held) = gw.settle_health.on_failure("e3".into());
    if just_held { gw.settlement_held_since_ms = Some(1_700_000_000_000); }
    let s2 = gw.snapshot();
    assert_eq!(s2.settlement_health, "HELD");
    assert_eq!(s2.settlement_consecutive_failures, 3);
    assert_eq!(s2.settlement_last_error.as_deref(), Some("e3"));
    assert_eq!(s2.settlement_held_since_ms, Some(1_700_000_000_000));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway snapshot_exposes_settlement_health`
Expected: FAIL — fields `settle_health`/`settlement_*` don't exist yet.

- [ ] **Step 3: Add the fields + serialize them**

In `struct Gw` (`:963`) add:
```rust
    settle_health: crate::settle_health::SettleHealth,
    settlement_held_since_ms: Option<u64>,
```
In `Gw`'s constructor (grep where `Gw {` is built with its field list — likely a `fn new`/`Default`-like site) initialize:
```rust
    settle_health: crate::settle_health::SettleHealth::from_env(std::time::Duration::from_secs(L1_SETTLE_SECS)),
    settlement_held_since_ms: None,
```
In the `WState` struct (the type `snapshot()` returns — grep `struct WState`) add, mirroring the existing `serde` derive/attributes on its siblings:
```rust
    settlement_health: String,
    settlement_consecutive_failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_held_since_ms: Option<u64>,
```
In `fn snapshot(&self)` (`:3285`) populate them:
```rust
    settlement_health: self.settle_health.health().as_str().to_string(),
    settlement_consecutive_failures: self.settle_health.consecutive_failures(),
    settlement_last_error: self.settle_health.last_error().map(|s| s.to_string()),
    settlement_held_since_ms: self.settlement_held_since_ms,
```
(Match the surrounding field style; if `WState` uses `#[serde(rename_all=...)]` keep these names consistent with it.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p gateway snapshot_exposes_settlement_health && cargo test -p gateway`
Expected: PASS (new test + all pre-existing gateway tests). `cargo clippy -p gateway --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): FIN-001 expose settlement_health on the status snapshot"
```

---

### Task 3: Settle-loop wiring (backoff gate + feed outcomes + HELD alert)

**Files:**
- Modify: `crates/gateway/src/main.rs` — the settle loop (`interval_at` at `~:5509`; `Ok` arm `~:5646`; `ProveFailed` arm `:5674-5685`); add a small `held_alert_message` + `maybe_ntfy` in `settle_health.rs`
- Test: `crates/gateway/src/settle_health.rs` (`#[cfg(test)]` — message helper)

**Interfaces:**
- Consumes: `SettleHealth`/`NextAction` (Task 1), `Gw.settle_health`/`Gw.settlement_held_since_ms` (Task 2), `now_ms()` (`:349`).
- Produces: the loop maintains a `next_attempt: tokio::time::Instant` gate; `held_alert_message(consecutive: u32, last_error: &str) -> String`.

- [ ] **Step 1: Write the failing test (alert message helper)**

Add to `settle_health.rs` tests:
```rust
    #[test]
    fn alert_message_names_count_error_and_remedy() {
        let m = held_alert_message(3, "prover 503");
        assert!(m.contains("[l1][HELD]"));
        assert!(m.contains('3'));
        assert!(m.contains("prover 503"));
        assert!(m.contains("/v1/admin/settlement/resume"));
        assert!(m.contains("trading continues"));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway alert_message_names_count_error_and_remedy`
Expected: FAIL — `held_alert_message` undefined.

- [ ] **Step 3: Implement the helper + wire the loop**

Add to `settle_health.rs` (above the tests):
```rust
/// The single greppable HELD alert line.
pub fn held_alert_message(consecutive: u32, last_error: &str) -> String {
    format!(
        "[l1][HELD] settlement halted after {consecutive} consecutive prove failures: {last_error} \
         — trading continues, L1 finality paused; fix the prover or POST /v1/admin/settlement/resume"
    )
}

/// Best-effort HELD alert to an optional ntfy topic (FIN_ALERT_NTFY_TOPIC). Never blocks the
/// caller and never fails the loop: detached `curl`, errors ignored.
pub fn maybe_ntfy(msg: &str) {
    if let Ok(topic) = std::env::var("FIN_ALERT_NTFY_TOPIC") {
        if topic.is_empty() { return; }
        let msg = msg.to_string();
        std::thread::spawn(move || {
            let _ = std::process::Command::new("curl")
                .args(["-s", "-m", "5", "-d", &msg, &format!("https://ntfy.sh/{topic}")])
                .status();
        });
    }
}
```
In `main.rs`, just before the settle `loop {` (right after the `interval_at` at `~:5509`), add the gate state:
```rust
            let settle_base = Duration::from_secs(L1_SETTLE_SECS);
            let mut next_attempt = tokio::time::Instant::now();
```
Immediately after `iv.tick().await;` inside the loop, gate the attempt:
```rust
                if tokio::time::Instant::now() < next_attempt { continue; }
```
In the `Ok(SettleAttempt::Ok { .. })` arm (`~:5646`), after the existing commit block, record success + resume normal cadence:
```rust
                            {
                                let mut gw = app.gw.lock().await;
                                let was_held = matches!(gw.settle_health.health(), crate::settle_health::Health::Held);
                                gw.settle_health.on_success();
                                gw.settlement_held_since_ms = None;
                                if was_held { println!("[l1] settlement recovered → HEALTHY"); }
                            }
                            next_attempt = tokio::time::Instant::now();
```
Replace the `ProveFailed` arm body (`:5674-5685`) — keep the existing rollback, add the health feed + backoff + alert:
```rust
                        Ok(SettleAttempt::ProveFailed(e)) => {
                            eprintln!("[l1] prove failed: {e} — rolling back (no tx was broadcast)");
                            let (action, just_held, n, last) = {
                                let mut gw = app.gw.lock().await;
                                gw.seq.rollback_window(&witness_rb);
                                gw.rollback_window_withdrawals(ww_rb);
                                let (action, just_held) = gw.settle_health.on_failure(e.clone());
                                if just_held { gw.settlement_held_since_ms = Some(now_ms()); }
                                (action, just_held,
                                 gw.settle_health.consecutive_failures(),
                                 gw.settle_health.last_error().unwrap_or("").to_string())
                            };
                            next_attempt = tokio::time::Instant::now() + action.delay();
                            if just_held {
                                let msg = crate::settle_health::held_alert_message(n, &last);
                                eprintln!("{msg}");
                                crate::settle_health::maybe_ntfy(&msg);
                            }
                            snapshot_notify.notify_one();
                        }
```
(Leave `SettleFailed` untouched.)

- [ ] **Step 4: Run to verify it passes + full crate suite**

Run: `cargo test -p gateway`
Expected: PASS (message-helper test + all pre-existing). `cargo clippy -p gateway --all-targets` clean, `cargo check -p gateway` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs crates/gateway/src/settle_health.rs
git commit -m "feat(gateway): FIN-001 wire settle loop to SettleHealth (backoff gate + HELD alert once)"
```

---

### Task 4: Operator-gated `POST /v1/admin/settlement/resume` + force flag

**Files:**
- Modify: `crates/gateway/src/main.rs` — shared force flag on the app state, the settle loop's force check, the route (`Router` at `:4745`), and a new handler
- Test: `crates/gateway/src/main.rs` (`#[cfg(test)]` — auth matrix + force-flag effect)

**Interfaces:**
- Consumes: the app `Shared` state, `HeaderMap`, `now_ms`; the settle loop's `next_attempt` (Task 3).
- Produces: `force_settle: Arc<AtomicBool>` on the app state; `async fn post_v1_admin_resume(...)`; route `/v1/admin/settlement/resume`.

- [ ] **Step 1: Write the failing tests**

Add to the gateway test module. Reuse the existing app/`Shared` test builder (grep `Shared`/`AppState`/`app_with_token`); the constant-time compare + gating logic can also be unit-tested directly via a small helper.
```rust
    #[test]
    fn admin_key_check_is_fail_closed_and_constant_shape() {
        // unset ⇒ disabled
        assert_eq!(admin_resume_authz(None, None), AdminAuthz::Disabled);
        // set but missing header ⇒ unauthorized
        assert_eq!(admin_resume_authz(Some("0xAA..").map(str::to_string).as_deref(), None), AdminAuthz::Unauthorized);
        // wrong ⇒ unauthorized
        assert_eq!(
            admin_resume_authz(Some("0x".to_string() + &"aa".repeat(32)).as_deref(),
                               Some(&("0x".to_string() + &"bb".repeat(32)))),
            AdminAuthz::Unauthorized
        );
        // exact match ⇒ ok
        let k = "0x".to_string() + &"aa".repeat(32);
        assert_eq!(admin_resume_authz(Some(&k), Some(&k)), AdminAuthz::Ok);
    }

    #[tokio::test]
    async fn resume_sets_force_flag_when_authorized() {
        let app = /* existing app builder */;
        std::env::set_var("FIN_ADMIN_KEY", "0x".to_string() + &"aa".repeat(32));
        app.force_settle.store(false, std::sync::atomic::Ordering::SeqCst);
        // with the right header, the handler flips the flag and returns 200
        let resp = post_v1_admin_resume(
            axum::extract::State(app.clone()),
            header_map_with("x-admin-key", &("0x".to_string() + &"aa".repeat(32))),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(app.force_settle.load(std::sync::atomic::Ordering::SeqCst));
        std::env::remove_var("FIN_ADMIN_KEY");
    }
```
(If the file has no `header_map_with` helper, build a `HeaderMap` inline. Model the async handler test on the file's existing handler tests — reuse their `State`/app construction verbatim.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway admin_key_check_is_fail_closed_and_constant_shape resume_sets_force_flag_when_authorized`
Expected: FAIL — `admin_resume_authz`/`post_v1_admin_resume`/`force_settle` undefined.

- [ ] **Step 3: Implement the auth helper, force flag, handler, route, loop check**

Add the authz decision as a pure, testable helper (near `api_key_from`, `:3722`):
```rust
#[derive(Debug, PartialEq, Eq)]
enum AdminAuthz { Ok, Unauthorized, Disabled }

/// Constant-time compare of the presented X-Admin-Key against the configured FIN_ADMIN_KEY.
/// `configured` = env value (None ⇒ endpoint disabled); `presented` = header value.
fn admin_resume_authz(configured: Option<&str>, presented: Option<&str>) -> AdminAuthz {
    let Some(cfg) = configured else { return AdminAuthz::Disabled; };
    let Some(got) = presented else { return AdminAuthz::Unauthorized; };
    let (a, b) = (cfg.as_bytes(), got.as_bytes());
    // length-independent, constant-time-ish fold (avoids early-exit on first mismatch)
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    if diff == 0 { AdminAuthz::Ok } else { AdminAuthz::Unauthorized }
}
```
Add the force flag to the app state struct (grep the `Shared`/`AppState`/`App` that handlers receive via `State`):
```rust
    force_settle: std::sync::Arc<std::sync::atomic::AtomicBool>,
```
initialize it `std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))` where the app state is built, and make sure the settle-loop task has a clone (it captures `app`, so `app.force_settle` is reachable).

Add the handler (near the other `post_v1_*` handlers):
```rust
async fn post_v1_admin_resume(
    State(app): State<Shared>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let configured = std::env::var("FIN_ADMIN_KEY").ok();
    let presented = headers.get("x-admin-key").and_then(|v| v.to_str().ok());
    match admin_resume_authz(configured.as_deref(), presented) {
        AdminAuthz::Disabled => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "settlement resume disabled — set FIN_ADMIN_KEY" })),
        ).into_response(),
        AdminAuthz::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid X-Admin-Key" })),
        ).into_response(),
        AdminAuthz::Ok => {
            app.force_settle.store(true, std::sync::atomic::Ordering::SeqCst);
            let health = { app.gw.lock().await.settle_health.health().as_str().to_string() };
            (StatusCode::OK, Json(serde_json::json!({
                "status": "settlement retry forced on next tick",
                "settlement_health": health
            }))).into_response()
        }
    }
}
```
Register the route (in the `Router` chain, `~:4795` alongside `/v1/system/status`):
```rust
        .route("/v1/admin/settlement/resume", post(post_v1_admin_resume))
```
In the settle loop, consume the force flag at the very top of each tick — BEFORE the `next_attempt` gate from Task 3:
```rust
                if app.force_settle.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    next_attempt = tokio::time::Instant::now();
                }
                if tokio::time::Instant::now() < next_attempt { continue; }
```

- [ ] **Step 4: Run to verify it passes + full suite**

Run: `cargo test -p gateway`
Expected: PASS (auth-matrix + force-flag tests + all pre-existing). `cargo clippy -p gateway --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "fix(gateway): FIN-001 operator-gated /v1/admin/settlement/resume + force-settle flag"
```

---

## Self-Review

**Spec coverage:**
- §1 SettleHealth pure state machine → Task 1. ✓
- §2 settle-loop wiring (next_attempt gate, on_success/on_failure, alert once) → Task 3. ✓
- §3 status surface (`settlement_health`/count/last_error/held_since) → Task 2. ✓
- §4 HELD alert (log + optional ntfy) → Task 3 (`held_alert_message`/`maybe_ntfy`). ✓
- §5 admin resume endpoint (operator `FIN_ADMIN_KEY`, `X-Admin-Key`, constant-time, fail-closed 503/401) + shared force flag + loop force-check → Task 4. ✓
- Config (`FIN_HELD_THRESHOLD`/`FIN_BACKOFF_CAP_SECS`/`FIN_ALERT_NTFY_TOPIC`/`FIN_ADMIN_KEY`) → Task 1 `from_env` + Task 3 `maybe_ntfy` + Task 4 handler. ✓
- Behavior matrix (HEALTHY/DEGRADED/HELD, self-heal, no order rejection) → Tasks 1+3. ✓
- Non-goals (no perp-core/sequencer/circuit/rejected_root change) → respected; only `crates/gateway` touched. ✓

**Placeholder scan:** every code step carries real code. The only "grep to locate" instructions are for real existing symbols the implementer must match to (`Gw` constructor site, `WState` struct, the app `Shared`/`AppState` builder, an existing handler-test template) — not invented content.

**Type consistency:** `SettleHealth`/`Health`/`NextAction`, `on_failure -> (NextAction, bool)`, `health().as_str()`, `Gw.settle_health`/`Gw.settlement_held_since_ms`, `WState.settlement_*`, `force_settle: Arc<AtomicBool>`, `admin_resume_authz`/`AdminAuthz`/`post_v1_admin_resume` are used consistently across Tasks 1→4. Task 3's loop `continue` gate and Task 4's force `swap` are ordered so force wins (force sets `next_attempt=now`, then the gate passes).
