//! Bounded, interruptible polling. Only a canonical finalized observation may
//! return a value. Timeout is not evidence of transaction absence.
use crate::service_shutdown::Shutdown;
use std::time::{Duration, Instant};

pub(crate) const FINALITY_BUDGET: Duration = Duration::from_secs(1200);
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) fn wait_for<T>(
    budget: Duration,
    interval: Duration,
    stop: Option<&Shutdown>,
    mut observe: impl FnMut() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or("invalid finality deadline")?;
    loop {
        if stop.is_some_and(Shutdown::started) {
            return Err("clock finality cancelled; retain exact journal".into());
        }
        if let Some(value) = observe()? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err("clock finality deadline reached; retain exact journal".into());
        }
        let sleep_until = Instant::now()
            .checked_add(interval)
            .unwrap_or(deadline)
            .min(deadline);
        while Instant::now() < sleep_until {
            if stop.is_some_and(Shutdown::started) {
                return Err("clock finality cancelled; retain exact journal".into());
            }
            std::thread::sleep(
                sleep_until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_wait_eventual_finality_returns_without_restart() {
        let mut calls = 0;
        let value = wait_for(Duration::from_secs(1), Duration::ZERO, None, || {
            calls += 1;
            Ok((calls == 4).then_some(42))
        })
        .unwrap();
        assert_eq!((value, calls), (42, 4));
    }
    #[test]
    fn clock_wait_timeout_does_not_forge_a_receipt_or_remove_intent() {
        let result: Result<(), _> = wait_for(Duration::ZERO, Duration::ZERO, None, || Ok(None));
        assert!(result.unwrap_err().contains("retain exact journal"));
    }
    #[test]
    fn clock_wait_invalid_context_is_not_treated_as_finality_lag() {
        let result: Result<(), _> = wait_for(Duration::from_secs(1), Duration::ZERO, None, || {
            Err("changed receipt".into())
        });
        assert_eq!(result.unwrap_err(), "changed receipt");
    }
    #[test]
    fn clock_wait_shutdown_cancels_before_another_read() {
        let stop = Shutdown::default();
        stop.begin();
        let result: Result<(), _> =
            wait_for(Duration::from_secs(1), Duration::ZERO, Some(&stop), || {
                panic!("read after cancellation")
            });
        assert!(result.unwrap_err().contains("cancelled"));
    }
}
