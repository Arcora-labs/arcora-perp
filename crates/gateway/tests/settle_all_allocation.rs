//! The wind-down settlement (`BatchOp::SettleAll`) never copies the note tree or
//! the nullifier log.
//!
//! The phase-1 proof that carries `SettleAll` is the costliest batch the admission
//! cap is sized for, and the op stages its result on copies of the positions, the
//! notes and the balances only: the tree and the log are read, never cloned. A
//! refactor that stages on a copy of the whole state would still pass every
//! functional test while roughly doubling the peak memory of that proof. This guard
//! counts what one op allocates, on a state whose tree and log are far larger than
//! everything else, and requires both a refused and a successful `SettleAll` to
//! allocate well under what one copy of the tree and the log would.
//!
//! The counting allocator serves this test binary only. It is an ignored test so
//! that it runs alone (no other test thread allocating while it counts):
//!
//!     cargo test -p gateway --release --test settle_all_allocation -- --ignored

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use perp_core::engine::BatchOp;
use perp_core::fixed::QUOTE_SCALE;
use perp_core::hash::Keccak256;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, Market};

/// Counts the bytes allocated (and grown by reallocation) while armed.
struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded unchanged to the system allocator; the counter
// only observes the requested sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        // SAFETY: the caller's contract for `alloc` is passed on as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        // SAFETY: the caller's contract for `alloc_zeroed` is passed on as is.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by `System` with `layout` (every allocation
        // is forwarded there).
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && new_size > layout.size() {
            BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        }
        // SAFETY: as for `dealloc`; the caller's contract for `realloc` holds.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The value `f` returns and the bytes it allocated.
fn allocated_by<T>(f: impl FnOnce() -> T) -> (T, usize) {
    BYTES.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let out = f();
    ARMED.store(false, Ordering::SeqCst);
    (out, BYTES.load(Ordering::SeqCst))
}

/// Deposits: each mints a note (a tree leaf) that funding spends (a nullifier).
const DEPOSITS: u64 = 6_000;
/// Distinct owners, one market-0 position entry each.
const OWNERS: u64 = 40;

/// A close-only state with `DEPOSITS` funded deposits spread over `OWNERS` owners.
fn wound_down_state() -> DefaultState {
    let mut s = DefaultState::new(20);
    s.add_market(Market::conservative(0));
    for i in 0..DEPOSITS {
        let sk = [(i % OWNERS) as u8 + 1; 32];
        let owner = owner_from_spend_key::<Keccak256>(&sk);
        let amount = 10 * QUOTE_SCALE;
        let mut blinding = [0xB0; 32];
        blinding[..8].copy_from_slice(&i.to_le_bytes());
        let deposit = BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding,
            from: [0x42; 20],
            deposit_id: s.consumed_deposit_count,
            deposit_blind: [0xDB; 32],
        };
        let fund = BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: Note::new(owner, 0, amount, blinding).commitment::<Keccak256>(),
            spend_key: sk,
        };
        s.apply_op(&deposit).expect("deposit");
        s.apply_op(&fund).expect("fund");
    }
    s.apply_op(&BatchOp::EnterCloseOnly).expect("close-only");
    assert_eq!(s.mode, Mode::CloseOnly);
    s
}

#[test]
#[ignore = "allocation guard; run alone: cargo test -p gateway --test settle_all_allocation -- --ignored"]
fn wind_down_settlement_copies_neither_the_tree_nor_the_nullifier_log() {
    let state = wound_down_state();
    assert_eq!(state.tree.len(), DEPOSITS);
    assert_eq!(state.nullifiers.len() as u64, DEPOSITS);
    assert_eq!(state.positions.len() as u64, OWNERS);
    // What one copy of the tree and the log would allocate at the least: their
    // 32-byte digests.
    let copy = 32 * (state.tree.len() as usize + state.nullifiers.len());
    let budget = copy / 8;

    // The measure sees a copy of the state.
    let (_, cloned) = allocated_by(|| state.clone());
    assert!(
        cloned >= copy,
        "a state copy allocates {cloned} bytes, under {copy}"
    );

    // A refused SettleAll: a pre-state that does not conserve fails the op's last
    // check, after every step is staged.
    let mut refused = state.clone();
    refused.treasury += 1;
    let (out, bytes) = allocated_by(|| refused.apply_op(&BatchOp::SettleAll));
    assert!(
        matches!(out, Err(EngineError::WindDownInsolvent)),
        "{out:?}"
    );
    assert!(
        bytes < budget,
        "a refused SettleAll allocated {bytes} bytes (budget {budget})"
    );

    // A successful one.
    let mut settled = state.clone();
    let (out, bytes) = allocated_by(|| settled.apply_op(&BatchOp::SettleAll));
    assert!(out.is_ok(), "{out:?}");
    assert!(
        bytes < budget,
        "SettleAll allocated {bytes} bytes (budget {budget})"
    );
    eprintln!(
        "SettleAll allocated {bytes} bytes; a state copy {cloned}; one copy of the tree \
         and the log is at least {copy}"
    );
    assert_eq!(settled.tree.len(), state.tree.len());
    assert_eq!(settled.nullifiers.len(), state.nullifiers.len());
}
