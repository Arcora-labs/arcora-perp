//! Candidate Chainlink route. Parsing is NOT DON verification.
//! The separate contract verifies signatures; the separate guest binds every
//! used oracle to those verified bytes. The reviewed v2 guest is unchanged.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod binding;
pub mod policy;
pub mod report;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Version,
    Bounds,
    Price,
    Time,
    Feed,
    Policy,
    Evidence,
    Oracle,
    Transition,
    Clock,
}
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests;
