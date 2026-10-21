//! In-process fixtures for the anchor-cancel preconditions and the fate of a
//! bound proof's anchor. Headers are self-consistent, so the block time used
//! for the timeout is the header-bound one.
use super::*;
use crate::deposit_rpc::{test_header, Rpc, TEST_GENESIS_TIME};
use observation::{AnchorPolicy, CanonicalRead};
use serde_json::{json, Value};

const SETTLEMENT: &str = "0x00000000000000000000000000000000000000aa";
const VERIFIER: [u8; 20] = [0x11; 20];
const CALLER: [u8; 20] = [0x44; 20];
const RECEIPT: Digest = [0x5a; 32];
const TIMEOUT_MS: u64 = 3_600_000;
const HEAD: u64 = 20;

#[derive(Clone)]
struct Clock {
    batch: u64,
    /// 0 live, 1 close-only, 2 wind-down settled.
    phase: u8,
    exists: bool,
    receipt: Digest,
    anchored_at_ms: u64,
    cancelled: bool,
    sequencer: [u8; 20],
    governance: [u8; 20],
    bound_settlement: [u8; 20],
}
impl Default for Clock {
    fn default() -> Self {
        Self {
            batch: 7,
            phase: 0,
            exists: true,
            receipt: RECEIPT,
            anchored_at_ms: head_ms() - TIMEOUT_MS,
            cancelled: false,
            sequencer: CALLER,
            governance: [0x66; 20],
            bound_settlement: crate::parse_addr20_hex(SETTLEMENT).unwrap(),
        }
    }
}
fn head_ms() -> u64 {
    (TEST_GENESIS_TIME + 2 * HEAD) * 1000
}
fn selector(sig: &str) -> String {
    use sha3::{Digest as _, Keccak256};
    crate::hex0x(&Keccak256::digest(sig.as_bytes())[..4])
}
impl Rpc for Clock {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        match method {
            "eth_getBlockByNumber" => {
                let tag = params[0].as_str().unwrap();
                let n = if tag == "latest" || tag == "finalized" {
                    HEAD
                } else {
                    u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap()
                };
                Ok(test_header(n, 0))
            }
            "eth_call" => {
                let data = params[0]["data"].as_str().unwrap();
                let sig = &data[..10];
                let u = observation::u64_word;
                let a = |x: &[u8; 20]| observation::address_word(x);
                let words: Vec<Digest> = if sig == selector("verifier()") {
                    vec![a(&VERIFIER)]
                } else if sig == selector("settlement()") {
                    vec![a(&self.bound_settlement)]
                } else if sig == selector("sequencer()") {
                    vec![a(&self.sequencer)]
                } else if sig == selector("governance()") {
                    vec![a(&self.governance)]
                } else if sig == selector("batchCount()") {
                    vec![u(self.batch)]
                } else if sig == selector("closeOnly()") {
                    vec![u(u64::from(self.phase > 0))]
                } else if sig == selector("windDownSettled()") {
                    vec![u(u64::from(self.phase > 1))]
                } else if sig == selector("anchorTimeoutMs()") {
                    vec![u(TIMEOUT_MS)]
                } else if sig == selector("cancelledReceipt(bytes32)") {
                    assert_eq!(&data[10..], &crate::hex32(&RECEIPT)[2..]);
                    vec![u(u64::from(self.cancelled))]
                } else if sig == selector("anchor(uint64,uint8)") {
                    if !self.exists {
                        vec![[0; 32]; 8]
                    } else {
                        vec![
                            [1; 32],
                            [2; 32],
                            self.receipt,
                            u(1),
                            u(2),
                            u(1),
                            u(self.anchored_at_ms),
                            u(1),
                        ]
                    }
                } else {
                    panic!("unexpected clock getter {sig}")
                };
                Ok(json!(crate::hex0x(
                    &words.iter().flatten().copied().collect::<Vec<_>>()
                )))
            }
            other => panic!("read-only fixture received {other}"),
        }
    }
}

fn cancel_check(clock: &Clock, batch: u64, phase: u8) -> Result<(), String> {
    let r = CanonicalRead::with_policy(clock, None, None, AnchorPolicy::Latest)?;
    super::check_cancel(&r, SETTLEMENT, &VERIFIER, &CALLER, batch, phase, &RECEIPT)
}

#[test]
fn cancel_preconditions_match_the_verifier_checks() {
    // At exactly anchoredAtMs + anchorTimeoutMs the cancel is allowed.
    cancel_check(&Clock::default(), 7, 0).unwrap();
    let refused = [
        (
            Clock {
                anchored_at_ms: head_ms() - TIMEOUT_MS + 1,
                ..Clock::default()
            },
            7,
            0,
            "timeout",
        ),
        (Clock::default(), 8, 0, "canonical batch"),
        (Clock::default(), 7, 1, "governance"),
        (
            Clock {
                phase: 1,
                governance: CALLER,
                ..Clock::default()
            },
            7,
            0,
            "phase",
        ),
        (
            Clock {
                receipt: [0x5b; 32],
                ..Clock::default()
            },
            7,
            0,
            "receipt",
        ),
        (
            Clock {
                exists: false,
                ..Clock::default()
            },
            7,
            0,
            "receipt",
        ),
        (
            Clock {
                sequencer: [0x45; 20],
                ..Clock::default()
            },
            7,
            0,
            "sequencer",
        ),
        (
            Clock {
                bound_settlement: [0xbb; 20],
                ..Clock::default()
            },
            7,
            0,
            "mismatch",
        ),
    ];
    for (clock, batch, phase, reason) in refused {
        let error = cancel_check(&clock, batch, phase).unwrap_err();
        assert!(error.contains(reason), "{reason}: {error}");
    }
    // Phases 1 and 2 are cancelled by governance in the matching settlement phase.
    for phase in [1, 2] {
        cancel_check(
            &Clock {
                phase,
                governance: CALLER,
                sequencer: [0x45; 20],
                ..Clock::default()
            },
            7,
            phase,
        )
        .unwrap();
    }
}

#[test]
fn cancel_needs_a_header_bound_block_time() {
    struct Minimal(Clock);
    impl Rpc for Minimal {
        fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
            let v = self.0.call(method, params)?;
            Ok(if method == "eth_getBlockByNumber" {
                json!({"number": v["number"], "hash": v["hash"], "timestamp": v["timestamp"]})
            } else {
                v
            })
        }
    }
    let fixture = Minimal(Clock::default());
    let r = CanonicalRead::with_policy(&fixture, None, None, AnchorPolicy::Latest).unwrap();
    let error =
        super::check_cancel(&r, SETTLEMENT, &VERIFIER, &CALLER, 7, 0, &RECEIPT).unwrap_err();
    assert!(error.contains("no block time"), "{error}");
}

#[test]
fn anchor_fate_distinguishes_live_cancelled_replaced_and_absent() {
    let fate = |clock: Clock| {
        let r = CanonicalRead::with_policy(&clock, None, None, AnchorPolicy::Finalized).unwrap();
        super::read_anchor_fate(&r, &crate::hex0x(&VERIFIER), 7, 0, &RECEIPT).unwrap()
    };
    use super::AnchorFate::*;
    assert_eq!(fate(Clock::default()), Live);
    assert_eq!(
        fate(Clock {
            cancelled: true,
            exists: false,
            ..Clock::default()
        }),
        Cancelled
    );
    assert_eq!(
        fate(Clock {
            receipt: [0x5b; 32],
            ..Clock::default()
        }),
        Replaced
    );
    assert_eq!(
        fate(Clock {
            exists: false,
            ..Clock::default()
        }),
        Absent
    );
}

/// Immediately before a recovery settle, its anchor is read at the latest block:
/// only a live anchor with the proof's receipt lets it be sent. Every other fate
/// asks the caller to classify the window again.
#[test]
fn a_recovery_settle_needs_its_anchor_live_at_latest() {
    let permits = |clock: Clock| {
        let r = CanonicalRead::with_policy(&clock, None, None, AnchorPolicy::Latest).unwrap();
        let fate = super::read_anchor_fate(&r, &crate::hex0x(&VERIFIER), 7, 0, &RECEIPT).unwrap();
        super::latest_fate_permits_settle(fate)
    };
    permits(Clock::default()).unwrap();
    for (clock, reason) in [
        (
            Clock {
                cancelled: true,
                exists: false,
                ..Clock::default()
            },
            "cancelled",
        ),
        // A cancelled receipt is refused even while an anchor still reads as live.
        (
            Clock {
                cancelled: true,
                ..Clock::default()
            },
            "cancelled",
        ),
        (
            Clock {
                receipt: [0x5b; 32],
                ..Clock::default()
            },
            "another clock anchor",
        ),
        (
            Clock {
                exists: false,
                ..Clock::default()
            },
            "no longer registered",
        ),
    ] {
        let refused = permits(clock).unwrap_err();
        assert!(refused.contains(reason), "{refused}");
        assert!(refused.ends_with("nothing sent; reclassify"), "{refused}");
    }
}

#[test]
fn proof_receipt_is_read_only_from_a_tagged_proof() {
    let mut proof = perp_core::clock::PROOF_MAGIC.to_vec();
    proof.extend(RECEIPT);
    proof.extend([7; 32]);
    assert_eq!(super::proof_receipt(&proof), Some(RECEIPT));
    assert_eq!(super::proof_receipt(&proof[..proof.len() - 33]), None);
    assert_eq!(super::proof_receipt(&[7; 64]), None);
}

#[test]
fn anchor_age_reports_the_current_anchor_against_block_time() {
    let age = |clock: Clock| {
        let r = CanonicalRead::with_policy(&clock, None, None, AnchorPolicy::Latest).unwrap();
        super::read_anchor_age(&r, SETTLEMENT, &crate::hex0x(&VERIFIER)).unwrap()
    };
    // Exactly at the timeout the anchor may be cancelled but is not yet stale.
    let at_timeout = age(Clock::default()).unwrap();
    assert_eq!(
        (at_timeout.batch, at_timeout.phase, at_timeout.age_ms),
        (7, 0, TIMEOUT_MS)
    );
    assert!(!at_timeout.stale());
    let older = age(Clock {
        anchored_at_ms: head_ms() - TIMEOUT_MS - 1,
        ..Clock::default()
    })
    .unwrap();
    assert!(older.stale());
    // The anchor of the phase the settlement is in is the one measured.
    let wind_down = age(Clock {
        phase: 1,
        ..Clock::default()
    })
    .unwrap();
    assert_eq!(wind_down.phase, 1);
    // A registration from the future (clock skew) is age 0, not an underflow.
    assert_eq!(
        age(Clock {
            anchored_at_ms: head_ms() + 5_000,
            ..Clock::default()
        })
        .unwrap()
        .age_ms,
        0
    );
    assert_eq!(
        age(Clock {
            exists: false,
            ..Clock::default()
        }),
        None
    );
}
