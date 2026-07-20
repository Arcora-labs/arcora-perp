//! FIN-001: bounded-retry + HELD circuit-breaker policy for the L1 settle loop.
//! Pure and clock-free — the settle loop owns all timing and feeds outcomes in.
// Part of this module's public surface (from_env, NextAction::delay, Health::as_str,
// the DEFAULT_* constants, and the env parse helpers) is exercised only once the
// settle loop is wired up in the following FIN-001 tasks. Allow dead_code for now so
// the state machine can land clippy-clean ahead of that wiring.
#![allow(dead_code)]
use std::time::Duration;

pub const DEFAULT_HELD_THRESHOLD: u32 = 3;
pub const DEFAULT_BACKOFF_CAP_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Degraded,
    Held,
}
impl Health {
    pub fn as_str(&self) -> &'static str {
        match self {
            Health::Healthy => "HEALTHY",
            Health::Degraded => "DEGRADED",
            Health::Held => "HELD",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextAction {
    Retry(Duration),
    Hold(Duration),
}
impl NextAction {
    pub fn delay(&self) -> Duration {
        match self {
            NextAction::Retry(d) | NextAction::Hold(d) => *d,
        }
    }
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
        Self {
            consecutive_failures: 0,
            threshold: threshold.max(1),
            base,
            cap,
            last_error: None,
            alerted: false,
        }
    }

    /// FIN_HELD_THRESHOLD (default 3), FIN_BACKOFF_CAP_SECS (default 300). base = L1_SETTLE_SECS.
    pub fn from_env(base: Duration) -> Self {
        let threshold = parse_env_u32("FIN_HELD_THRESHOLD", DEFAULT_HELD_THRESHOLD);
        let cap = Duration::from_secs(parse_env_u64(
            "FIN_BACKOFF_CAP_SECS",
            DEFAULT_BACKOFF_CAP_SECS,
        ));
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
            let mult = 1u64
                .checked_shl(n - 1)
                .unwrap_or(u64::MAX)
                .min(u32::MAX as u64) as u32;
            let d = self.base.saturating_mul(mult).min(self.cap);
            (NextAction::Retry(d), false)
        }
    }

    pub fn health(&self) -> Health {
        if self.consecutive_failures == 0 {
            Health::Healthy
        } else if self.consecutive_failures >= self.threshold {
            Health::Held
        } else {
            Health::Degraded
        }
    }
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sh() -> SettleHealth {
        SettleHealth::new(3, Duration::from_secs(30), Duration::from_secs(300))
    }

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
        assert!(just_held); // THIS failure crossed into HELD
        assert_eq!(h.health(), Health::Held);
        let (a2, just_held2) = h.on_failure("d".into());
        assert_eq!(a2, NextAction::Hold(Duration::from_secs(300)));
        assert!(!just_held2); // already HELD ⇒ no repeat alert
    }

    #[test]
    fn backoff_never_exceeds_cap() {
        // small cap forces the exponential to clamp
        let mut h = SettleHealth::new(10, Duration::from_secs(30), Duration::from_secs(45));
        h.on_failure("a".into()); // 30
        let (a, _) = h.on_failure("b".into()); // 60 -> clamp 45
        assert_eq!(a, NextAction::Retry(Duration::from_secs(45)));
    }

    #[test]
    fn success_resets_and_rearms_alert() {
        let mut h = sh();
        h.on_failure("a".into());
        h.on_failure("b".into());
        h.on_failure("c".into());
        assert_eq!(h.health(), Health::Held);
        h.on_success();
        assert_eq!(h.health(), Health::Healthy);
        assert_eq!(h.consecutive_failures(), 0);
        assert_eq!(h.last_error(), None);
        // after recovery a fresh HELD episode alerts again
        h.on_failure("x".into());
        h.on_failure("y".into());
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
