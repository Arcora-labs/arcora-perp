//! Test-only, process-wide replacements for the gateway's two non-deterministic
//! inputs: the wall clock (`now_ms`) and the OS entropy behind `csprng_bytes32`
//! (account wallet seeds, API keys and deposit blinds). A test that exports exact
//! bytes, such as the funds lifecycle's witness export, injects both so that the
//! export is reproducible run to run. While neither is injected, both functions
//! read the system clock and the OS CSPRNG exactly as the service does; this module
//! is not compiled into the service.
//!
//! Both replacements are process-wide, so a test injects them only in a process it
//! runs alone in (the funds lifecycle runs in its own child process).
use sha3::{Digest as _, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The injected time in milliseconds; 0 while no clock is injected.
static CLOCK_MS: AtomicU64 = AtomicU64::new(0);

/// The injected entropy: a seed and the number of 32-byte values drawn from it.
static ENTROPY: Mutex<Option<([u8; 32], u64)>> = Mutex::new(None);

/// The injected time, while a clock is injected.
pub(crate) fn clock_ms() -> Option<u64> {
    match CLOCK_MS.load(Ordering::SeqCst) {
        0 => None,
        ms => Some(ms),
    }
}

/// Inject the clock at `ms`, or move an injected clock forward to `ms`. The clock
/// never moves backwards: a smaller `ms` leaves it where it is.
pub(crate) fn advance_clock_to(ms: u64) {
    assert!(ms > 0, "an injected clock starts after the Unix epoch");
    CLOCK_MS.fetch_max(ms, Ordering::SeqCst);
}

/// Replace OS entropy with the stream derived from `seed`: the n-th value drawn is
/// `keccak256(seed ‖ n)` with `n` as a big-endian u64, starting at 1.
pub(crate) fn inject_entropy(seed: [u8; 32]) {
    *ENTROPY.lock().unwrap() = Some((seed, 0));
}

/// The next value of the injected entropy stream, while one is injected.
pub(crate) fn entropy_bytes32() -> Option<[u8; 32]> {
    let mut guard = ENTROPY.lock().unwrap();
    let (seed, drawn) = guard.as_mut()?;
    *drawn += 1;
    Some(stream_value(seed, *drawn))
}

/// The `n`-th value of the entropy stream of `seed`: `keccak256(seed ‖ n)`.
fn stream_value(seed: &[u8; 32], n: u64) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(seed);
    hash.update(n.to_be_bytes());
    hash.finalize().into()
}

#[test]
fn the_entropy_stream_depends_only_on_its_seed_and_position() {
    let seed = [0x6c; 32];
    let first = stream_value(&seed, 1);
    assert_eq!(first, stream_value(&seed, 1));
    assert_ne!(first, stream_value(&seed, 2));
    assert_ne!(first, stream_value(&[0x6d; 32], 1));
    let mut preimage = seed.to_vec();
    preimage.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(first, <[u8; 32]>::from(Keccak256::digest(&preimage)));
}
