//! # perp-core — deterministic state-transition core for dark-perp (Phase 0)
//!
//! This crate is the single source of truth for the protocol's settlement logic.
//! It is written once and run in two places:
//!
//! * **natively**, inside the sequencer / matcher enclave on the hot path (§1);
//! * **unchanged inside a zkVM guest** (SP1 / Risc0, RISC-V), where it becomes the
//!   Proof-v1 validity circuit (§4, §10b, §12).
//!
//! To make that dual life possible the crate is `#![no_std]` (with `alloc`) and
//! contains **no floating point, no clocks, no randomness, no I/O** — every
//! transition is a pure function of its inputs. The `std` feature (default) only
//! re-exports `alloc` collections for ergonomic native/test use.
//!
//! ## What Phase 0 proves
//!
//! The six Proof-v1 invariants (§4) are all expressible here and covered by tests:
//!
//! 1. collateral conservation — [`state::State::conservation_holds`]
//! 2. valid nullifiers / no double-spend — [`nullifier::NullifierSet`]
//! 3. post-fill margin sufficiency — [`position::Position::check_initial_margin`]
//! 4. oracle freshness + confidence — [`oracle::OracleTranscript::validate`]
//! 5. funding correctness — [`funding::FundingState`]
//! 6. liquidation threshold correctness — [`position::Position::is_liquidatable`]
//!
//! ## What Phase 0 does NOT do (by design)
//!
//! CLOB matching fairness (price-time priority, self-trade prevention, order
//! types) is **Proof-v2** (§4); in the interim it is backed by signed receipts +
//! the batch manifest + inclusion timeouts + slashing (§2). The TEE attestation,
//! L1 verifier/vault, note archive, and Aztec bridge are later phases (§13).

#![no_std]
#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod commitment;
pub mod engine;
pub mod error;
pub mod fixed;
pub mod funding;
pub mod hash;
pub mod market;
pub mod merkle;
pub mod note;
pub mod nullifier;
pub mod oracle;
pub mod order;
pub mod position;
pub mod state;

// Curated public surface.
pub use engine::BatchOp;
pub use error::EngineError;
pub use hash::{Digest, Hasher, Keccak256};
pub use market::{Market, MarketId};
pub use note::{Note, PubKey};
pub use oracle::{OracleError, OracleTranscript};
pub use order::{BatchManifest, Finality, Order, Receipt, RejectReason, Side, TimeInForce};
pub use position::{HedgeSignal, Position, RiskError};
pub use state::{Mode, State};

/// The default native state type using Keccak-256 (Phase 0). The proving phase
/// instantiates [`state::State`] with a Poseidon hasher instead (§10b).
pub type DefaultState = State<Keccak256>;
