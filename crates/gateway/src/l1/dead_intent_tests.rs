//! In-process fixtures for the dead-intent evidence, the register preflight and
//! the program-vkey walk. Every read is pinned to one self-consistent block.
use super::*;
use crate::deposit_rpc::{test_header, Rpc, TEST_GENESIS_TIME};
use crate::prover_client::PreflightRefusal;
use crate::rollback_journal::{AnchorSlot, ClockIntent};
use observation::{AnchorPolicy, CanonicalRead};
use serde_json::{json, Value};

const SETTLEMENT: &str = "0x00000000000000000000000000000000000000aa";
const VERIFIER: [u8; 20] = [0x11; 20];
const SEQUENCER: [u8; 20] = [0x44; 20];
const PREV: Digest = [0x01; 32];
const BASE: Digest = [0x02; 32];
const RECEIPT: Digest = [0x5a; 32];
const HEAD: u64 = 20;
const ORACLE: [u8; 20] = [0x77; 20];
const ADAPTER: [u8; 20] = [0x88; 20];
const VKEY: Digest = [0x99; 32];
const SKEW_MS: u64 = 30_000;
/// The header-bound time of the finalized block `HEAD`, in milliseconds.
fn head_ms() -> u64 {
    (TEST_GENESIS_TIME + 2 * HEAD) * 1000
}

#[derive(Clone)]
struct Chain {
    batch: u64,
    /// 0 live, 1 close-only, 2 wind-down settled.
    phase: u8,
    exists: bool,
    prev: Digest,
    base: Digest,
    receipt: Digest,
    cancelled: bool,
    /// The sequencer's nonce at the finalized block.
    nonce: u64,
    /// Its latest and pending nonces; `None` reads as `nonce`.
    latest_nonce: Option<u64>,
    pending_nonce: Option<u64>,
    /// The latest and pending nonce reads fail.
    unpinned_nonce_fails: bool,
    /// The finalized header's hash does not match its fields, so it has no
    /// header-bound time.
    unhashed_header: bool,
    /// `innerVerifier()` of the clock: the adapter itself, or an oracle wrapper.
    wrapped: bool,
    /// The SP1 adapter answers `programVKey()`.
    adapter_has_vkey: bool,
}
impl Default for Chain {
    fn default() -> Self {
        Self {
            batch: 7,
            phase: 0,
            exists: true,
            prev: PREV,
            base: BASE,
            receipt: RECEIPT,
            cancelled: false,
            nonce: 10,
            latest_nonce: None,
            pending_nonce: None,
            unpinned_nonce_fails: false,
            unhashed_header: false,
            wrapped: false,
            adapter_has_vkey: true,
        }
    }
}
fn selector(sig: &str) -> String {
    use sha3::{Digest as _, Keccak256};
    crate::hex0x(&Keccak256::digest(sig.as_bytes())[..4])
}
impl Rpc for Chain {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        match method {
            "eth_getBlockByNumber" => {
                let tag = params[0].as_str().unwrap();
                let n = if tag == "latest" || tag == "finalized" {
                    HEAD
                } else {
                    u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap()
                };
                let mut header = test_header(n, 0);
                if self.unhashed_header {
                    header["hash"] = json!(crate::hex32(&[0xee; 32]));
                }
                Ok(header)
            }
            "eth_chainId" => Ok(json!("0x14a34")),
            "eth_getTransactionCount" => {
                assert_eq!(params[0], json!(crate::hex0x(&SEQUENCER)));
                let n = match params[1].as_str() {
                    Some(_) if self.unpinned_nonce_fails => return Err("timed out".into()),
                    Some("latest") => self.latest_nonce.unwrap_or(self.nonce),
                    Some("pending") => self.pending_nonce.unwrap_or(self.nonce),
                    Some(other) => panic!("unexpected nonce tag {other}"),
                    None => {
                        assert!(
                            params[1]["blockHash"].is_string(),
                            "the finalized nonce read is pinned"
                        );
                        self.nonce
                    }
                };
                Ok(json!(format!("0x{n:x}")))
            }
            "eth_call" => {
                let to = params[0]["to"].as_str().unwrap().to_string();
                let data = params[0]["data"].as_str().unwrap();
                let sig = &data[..10];
                let u = observation::u64_word;
                let a = |x: &[u8; 20]| observation::address_word(x);
                let words: Vec<Digest> = if to == crate::hex0x(&ORACLE) {
                    if sig == selector("innerVerifier()") {
                        vec![a(&ADAPTER)]
                    } else {
                        return Err("execution reverted".into());
                    }
                } else if to == crate::hex0x(&ADAPTER) {
                    if sig == selector("programVKey()") && self.adapter_has_vkey {
                        vec![VKEY]
                    } else {
                        return Err("execution reverted".into());
                    }
                } else if sig == selector("verifier()") {
                    vec![a(&VERIFIER)]
                } else if sig == selector("settlement()") {
                    vec![a(&crate::parse_addr20_hex(SETTLEMENT).unwrap())]
                } else if sig == selector("innerVerifier()") {
                    vec![a(if self.wrapped { &ORACLE } else { &ADAPTER })]
                } else if sig == selector("batchCount()") {
                    vec![u(self.batch)]
                } else if sig == selector("currentStateRoot()") {
                    vec![self.prev]
                } else if sig == selector("clockSkewMs()") {
                    vec![u(SKEW_MS)]
                } else if sig == selector("closeOnly()") {
                    vec![u(u64::from(self.phase > 0))]
                } else if sig == selector("windDownSettled()") {
                    vec![u(u64::from(self.phase > 1))]
                } else if sig == selector("cancelledReceipt(bytes32)") {
                    assert_eq!(&data[10..], &crate::hex32(&RECEIPT)[2..]);
                    vec![u(u64::from(self.cancelled))]
                } else if sig == selector("anchor(uint64,uint8)") {
                    if self.exists {
                        vec![
                            self.prev,
                            self.base,
                            self.receipt,
                            u(1),
                            u(2),
                            u(1),
                            u(1_000),
                            u(1),
                        ]
                    } else {
                        vec![[0; 32]; 8]
                    }
                } else {
                    panic!("unexpected getter {sig} on {to}")
                };
                Ok(json!(crate::hex0x(
                    &words.iter().flatten().copied().collect::<Vec<_>>()
                )))
            }
            other => panic!("read-only fixture received {other}"),
        }
    }
}

/// A timed intent whose last operation is at the finalized block's time, so the
/// chain clock has not passed it.
fn intent(receipt: Option<Digest>, phase: u8) -> ClockIntent {
    ClockIntent {
        batch: 7,
        phase,
        prev_root: PREV,
        base: BASE,
        receipt,
        timed: true,
        last_ms: Some(head_ms()),
        underivable: false,
    }
}

fn evidence_on(
    primary: &Chain,
    witness: Option<&Chain>,
    intent: &ClockIntent,
    ceiling: Ceiling,
) -> crate::rollback_journal::DeadIntentEvidence {
    super::dead_intent_evidence_from(
        primary,
        witness.map(|w| w as &dyn Rpc),
        witness.map(|_| 84532),
        SETTLEMENT,
        &VERIFIER,
        &SEQUENCER,
        intent,
        ceiling,
    )
    .unwrap()
}
fn evidence(
    chain: &Chain,
    intent: &ClockIntent,
    ceiling: Ceiling,
) -> crate::rollback_journal::DeadIntentEvidence {
    evidence_on(chain, None, intent, ceiling)
}

#[test]
fn dead_intent_evidence_reads_the_slot_and_the_nonce_fence() {
    let ours = intent(Some(RECEIPT), 0);
    let e = evidence(&Chain::default(), &ours, Ceiling::Nonce(9));
    assert_eq!(
        (e.block, e.batch_count, e.close_only, e.slot, e.nonce),
        (HEAD, 7, false, AnchorSlot::Matching, 10)
    );
    assert!(e.fence_passed && e.quiet && e.fenced());
    // The root, the block time and the skew come from the same finalized read.
    assert_eq!(
        (e.state_root, e.block_time_ms, e.clock_skew_ms),
        (PREV, Some(head_ms()), SKEW_MS)
    );
    let unhashed = Chain {
        unhashed_header: true,
        ..Chain::default()
    };
    assert_eq!(
        evidence(&unhashed, &ours, Ceiling::None).block_time_ms,
        None
    );
    // The fence passes only once the finalized nonce is past every recorded send.
    assert!(!evidence(&Chain::default(), &ours, Ceiling::Nonce(10)).fence_passed);
    assert!(!evidence(&Chain::default(), &ours, Ceiling::Unknown).fence_passed);
    assert!(evidence(&Chain::default(), &ours, Ceiling::None).fence_passed);
    let cancelled = Chain {
        exists: false,
        cancelled: true,
        ..Chain::default()
    };
    assert_eq!(
        evidence(&cancelled, &ours, Ceiling::None).slot,
        AnchorSlot::Cancelled
    );
    let empty = Chain {
        exists: false,
        ..Chain::default()
    };
    assert_eq!(
        evidence(&empty, &ours, Ceiling::None).slot,
        AnchorSlot::Empty
    );
    let other = Chain {
        receipt: [0x5b; 32],
        ..Chain::default()
    };
    assert_eq!(
        evidence(&other, &ours, Ceiling::None).slot,
        AnchorSlot::Different
    );
    // Without a journaled receipt the anchor is ours when its root and base are.
    let intent_only = intent(None, 0);
    assert_eq!(
        evidence(&other, &intent_only, Ceiling::None).slot,
        AnchorSlot::Matching
    );
    let other_base = Chain {
        base: [0x03; 32],
        ..Chain::default()
    };
    assert_eq!(
        evidence(&other_base, &intent_only, Ceiling::None).slot,
        AnchorSlot::Different
    );
    assert_eq!(
        evidence(&empty, &intent_only, Ceiling::None).slot,
        AnchorSlot::Empty
    );
    let closed = Chain {
        phase: 1,
        ..Chain::default()
    };
    assert!(evidence(&closed, &ours, Ceiling::None).close_only);
}

#[test]
fn dead_intent_classification_follows_the_evidence() {
    use crate::rollback_journal::{Classified, DeadBasis, DeadIntent, DeadIntentAction};
    let check = |chain: Chain, intent: ClockIntent, ceiling: Ceiling| {
        let e = evidence(&chain, &intent, ceiling);
        crate::clock_client::classify(intent, e)
    };
    let classify =
        |chain: Chain, intent: ClockIntent, ceiling: Ceiling| check(chain, intent, ceiling).dead;
    // A live anchor, or an empty slot before the fence and the chain clock, is
    // never dead.
    assert_eq!(
        classify(Chain::default(), intent(None, 0), Ceiling::None),
        None
    );
    let empty = Chain {
        exists: false,
        ..Chain::default()
    };
    assert_eq!(
        classify(empty.clone(), intent(None, 0), Ceiling::Nonce(10)),
        None
    );
    // A timed phase-0 window with an empty slot is voided; an untimed one returns.
    assert_eq!(
        classify(empty.clone(), intent(None, 0), Ceiling::Nonce(9)),
        Some((DeadIntent::EmptyAfterFence, DeadIntentAction::LiveVoid))
    );
    let untimed = ClockIntent {
        timed: false,
        last_ms: None,
        ..intent(None, 0)
    };
    assert_eq!(
        classify(empty.clone(), untimed, Ceiling::Nonce(9)),
        Some((
            DeadIntent::EmptyAfterFence,
            DeadIntentAction::ReturnToOpenWindow
        ))
    );
    // A timed phase-0 window past its skew at the finalized block is dead on the
    // chain clock, without the fence.
    let past_skew = ClockIntent {
        last_ms: Some(head_ms() - SKEW_MS - 1),
        ..intent(None, 0)
    };
    let dead = check(empty.clone(), past_skew, Ceiling::Nonce(10));
    assert!(!dead.evidence.fence_passed);
    assert_eq!(
        dead.classified,
        Classified::Dead(DeadIntent::EmptyAfterFence, DeadBasis::ChainClock)
    );
    assert_eq!(
        dead.dead,
        Some((DeadIntent::EmptyAfterFence, DeadIntentAction::LiveVoid))
    );
    // The root, the block time and the skew come from the same canonical read.
    assert_eq!(dead.evidence.state_root, empty.prev);
    assert_eq!(dead.evidence.block_time_ms, Some(head_ms()));
    assert_eq!(dead.evidence.clock_skew_ms, SKEW_MS);
    let at_skew = ClockIntent {
        last_ms: Some(head_ms() - SKEW_MS),
        ..intent(None, 0)
    };
    assert_eq!(
        check(empty.clone(), at_skew, Ceiling::Nonce(10)).classified,
        Classified::MaySettle
    );
    // An empty slot for a journaled receipt is inconsistent, and not dead.
    let journaled = check(empty, intent(Some(RECEIPT), 0), Ceiling::None);
    assert!(matches!(journaled.classified, Classified::Inconsistent(_)));
    assert_eq!(journaled.dead, None);
    // A phase-0 window after close-only returns to the open window.
    let closed = Chain {
        phase: 1,
        ..Chain::default()
    };
    assert_eq!(
        classify(closed, intent(Some(RECEIPT), 0), Ceiling::None),
        Some((
            DeadIntent::CloseOnlyPhaseZero,
            DeadIntentAction::ReturnToOpenWindow
        ))
    );
    // The batch moved on: nothing to classify.
    let moved = Chain {
        batch: 8,
        exists: false,
        ..Chain::default()
    };
    assert_eq!(classify(moved, intent(None, 0), Ceiling::None), None);
}

/// The fence basis needs quiet nonces: on every configured endpoint the
/// sequencer's latest and pending nonces must equal its finalized nonce.
#[test]
fn the_fence_basis_needs_quiet_nonces() {
    use crate::rollback_journal::{Classified, DeadBasis, DeadIntent};
    let untimed = ClockIntent {
        timed: false,
        last_ms: None,
        ..intent(None, 0)
    };
    let classify = |primary: &Chain, witness: Option<&Chain>, ceiling| {
        let e = evidence_on(primary, witness, &untimed, ceiling);
        (
            e.fence_passed,
            e.quiet,
            crate::clock_client::classify(untimed, e).classified,
        )
    };
    let empty = Chain {
        exists: false,
        ..Chain::default()
    };
    let dead = Classified::Dead(DeadIntent::EmptyAfterFence, DeadBasis::Fence);
    assert_eq!(
        classify(&empty, None, Ceiling::Nonce(9)),
        (true, true, dead)
    );
    assert_eq!(
        classify(&empty, Some(&empty), Ceiling::Nonce(9)),
        (true, true, dead)
    );
    // A pending nonce above the finalized one, on the primary or on the witness.
    let pending = Chain {
        pending_nonce: Some(11),
        ..empty.clone()
    };
    for (primary, witness) in [(&pending, &empty), (&empty, &pending)] {
        assert_eq!(
            classify(primary, Some(witness), Ceiling::Nonce(9)),
            (true, false, Classified::MaySettle)
        );
    }
    // A transaction mined after the finalized block.
    let mined = Chain {
        latest_nonce: Some(11),
        pending_nonce: Some(11),
        ..empty.clone()
    };
    assert_eq!(
        classify(&mined, None, Ceiling::Nonce(9)),
        (true, false, Classified::MaySettle)
    );
    // A failed read is not quiet.
    let unreadable = Chain {
        unpinned_nonce_fails: true,
        ..empty.clone()
    };
    assert_eq!(
        classify(&unreadable, None, Ceiling::Nonce(9)),
        (true, false, Classified::MaySettle)
    );
    // A restored `.l1-nonce` below a register that is still pending: the
    // finalized nonce is past the restored ceiling, but the register is visible.
    let restored = Chain {
        nonce: 12,
        pending_nonce: Some(13),
        ..empty.clone()
    };
    assert_eq!(
        classify(&restored, None, Ceiling::Nonce(5)),
        (true, false, Classified::MaySettle)
    );
    // Quiet but not past the ceiling.
    assert_eq!(
        classify(&empty, None, Ceiling::Nonce(10)),
        (false, true, Classified::MaySettle)
    );
}

fn preconditions(chain: &Chain) -> Result<crate::prover_client::RegisterPreconditions, String> {
    let r = CanonicalRead::with_policy(chain, None, None, AnchorPolicy::Latest).unwrap();
    let (batch_count, phase) = super::read_register_state(&r, SETTLEMENT, &VERIFIER)?;
    Ok(crate::prover_client::RegisterPreconditions {
        batch_count,
        phase,
        prover_body_bytes: None,
    })
}
fn preflight(chain: &Chain, batch: u64, phase: u8) -> Result<(), PreflightRefusal> {
    preconditions(chain)
        .map_err(PreflightRefusal::Refused)?
        .admit(batch, phase)
}

#[test]
fn register_preflight_refuses_phase_zero_in_close_only_before_any_send() {
    preflight(&Chain::default(), 7, 0).unwrap();
    for phase in [1, 2] {
        let chain = Chain {
            phase,
            ..Chain::default()
        };
        assert!(matches!(
            preflight(&chain, 7, 0),
            Err(PreflightRefusal::WrongPhase(e)) if e.contains("close-only")
        ));
        preflight(&chain, 7, phase).unwrap();
    }
    assert!(matches!(
        preflight(&Chain::default(), 7, 1),
        Err(PreflightRefusal::WrongPhase(_))
    ));
    assert!(matches!(
        preflight(&Chain::default(), 8, 0),
        Err(PreflightRefusal::Refused(e)) if e.contains("next batch")
    ));
}

#[test]
fn program_vkey_is_read_once_and_only_a_success_is_kept() {
    let cell = std::sync::OnceLock::new();
    let reads = std::cell::Cell::new(0);
    let read = |result: Result<Digest, String>| {
        reads.set(reads.get() + 1);
        result
    };
    assert!(super::cached_once(&cell, || read(Err("execution reverted".into()))).is_err());
    assert_eq!(super::cached_once(&cell, || read(Ok(VKEY))).unwrap(), VKEY);
    assert_eq!(
        super::cached_once(&cell, || panic!("the immutable route was read again")).unwrap(),
        VKEY
    );
    assert_eq!(reads.get(), 2);
}

#[test]
fn program_vkey_walks_through_an_optional_oracle_wrapper() {
    let vkey = |chain: &Chain| {
        let r = CanonicalRead::with_policy(chain, None, None, AnchorPolicy::Latest).unwrap();
        super::read_program_vkey(&r, &VERIFIER)
    };
    assert_eq!(vkey(&Chain::default()).unwrap(), VKEY);
    assert_eq!(
        vkey(&Chain {
            wrapped: true,
            ..Chain::default()
        })
        .unwrap(),
        VKEY
    );
    assert!(vkey(&Chain {
        adapter_has_vkey: false,
        ..Chain::default()
    })
    .is_err());
}
