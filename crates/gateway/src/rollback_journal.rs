//! Crash-recovery rollback journal — the sealed sidecar that survives a restart
//! mid-window-settle.
//!
//! The settle loop's rollback inputs (`WindowWitness` + the window's drained
//! withdrawals) are in-memory clones only; if the gateway dies between
//! `begin_window_settle` and commit/rollback, the restored snapshot has Counter B
//! ahead of (or the settled root behind) the chain and the rollup wedges forever
//! (the 0xEa11 stack's fate). This module persists exactly those inputs to
//! `<DARKPERP_STATE>.rollback` so boot can decide — from the journal, the restored
//! snapshot, and the chain — whether the in-flight window is stale, must be rolled
//! back, or (if the tx landed but the commit was lost) rolled forward.
//!
//! ## Sealing
//!
//! The journal carries the full `WindowWitness` (incl. `pre_state` — private
//! notes), so it is sealed EXACTLY like the snapshot: [`snapshot::seal`]/
//! [`snapshot::open`] under the enclave seed, written via
//! [`snapshot::write_atomic`]. The snapshot format itself is untouched — this is a
//! separate file with its own magic/version inside the sealed plaintext, so a
//! future journal layout change fails closed instead of misreading.

use crate::snapshot;
use crate::withdrawals::Withdrawal;
use std::path::{Path, PathBuf};

/// Journal plaintext magic + format version (INSIDE the sealed payload; the sealed
/// file itself starts with the snapshot module's `snapshot::MAGIC` framing). Bump the
/// trailing digit on layout changes so an old binary refuses a new journal (and
/// vice versa) instead of postcard-misreading it.
/// v2: SEC-022 added `Market.max_fill_deviation_ratio`, carried here via
/// `witness: WindowWitness.pre_state` — same positional-postcard hazard as the
/// snapshot's v2 bump (see `snapshot.rs::MAGIC`).
/// v3: SEC-025-B — `ProveOutcome` gained `new_deposit_count`, and `PreparedSettle`
/// is journaled, so the positional postcard layout changed. SEC-022 already moved
/// this to DPRBJL2 and a pre-025-B binary can therefore already have written
/// DPRBJL2 — reusing it would make an old journal a silent postcard misparse
/// instead of a versioned rejection.
/// v4: SEC-024 — `BatchOp`'s MEANING changed, not just its layout: ordinal 8
/// (`SeedInsurance`, the unbound insurance mint) now always rejects, and ordinal 9
/// (`FundInsurance`) exists. `BatchOp` is positional in the journaled witness via
/// `window_ops`, so a pending pre-SEC-024 journal must be REFUSED here rather than
/// decoded under the new meaning — replaying it would either reject a formerly
/// valid seed op mid-recovery or misread a trailing variant.
/// v5: SEC-025-D — `ProveOutcome` gained `post_mode_is_normal` + `post_insurance_fund`
/// (the launch-gate terms), and `PreparedSettle` embeds it in the journaled
/// `prepared`, so the positional postcard layout moved again. A pre-025-D journal
/// decoded by a post-025-D binary would misparse the outcome — and a roll-forward
/// re-submits those roots to `_requireDepositPrefix`, so this must be a versioned
/// refusal, never a silent misparse.
const MAGIC: &[u8; 8] = b"DPRBJL5\0";

/// Everything boot recovery needs to resolve one in-flight window settle:
/// the sequencer rollback input (`witness`), the withdrawal rollback input (`ww`,
/// the set `begin_window_settle` drained), and — once the prove has returned —
/// the `prepared` outcome whose `new_root`/claim proofs a roll-forward re-commits.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackJournal {
    pub batch_id: u64,
    pub witness: sequencer::WindowWitness,
    pub ww: Vec<Withdrawal>,
    /// `None` before any potential chain mutation (Stage 1). Clock mode first
    /// stores `Some` with an EMPTY proof as its durable registration intent;
    /// that may HOLD/resume the exact witness but is never broadcast as a proof.
    /// A nonempty prepared proof is persisted again before settlement broadcast.
    pub prepared: Option<crate::prover_client::PreparedSettle>,
}

/// The journal's on-disk location: `<state_path>.rollback` (appended, not
/// `with_extension` — `/var/lib/darkperp/state.snap` → `state.snap.rollback`, so
/// the sidecar never shadows the snapshot itself).
pub fn journal_path(state_path: &Path) -> PathBuf {
    let mut os = state_path.as_os_str().to_os_string();
    os.push(".rollback");
    PathBuf::from(os)
}

/// Persist the journal: magic-prefixed postcard plaintext → `snapshot::seal` under
/// the enclave seed → `snapshot::write_atomic` (a crash mid-write never leaves a
/// torn journal). `Err` means durability was not acknowledged. The live settle
/// loop must stop before proving/broadcasting when configured persistence fails;
/// it must not delete the existing recovery record or treat the write as success.
pub fn write(path: &Path, j: &RollbackJournal, seed: &[u8; 32]) -> Result<(), String> {
    let body = postcard::to_allocvec(j).map_err(|e| format!("journal encode: {e}"))?;
    let mut plain = Vec::with_capacity(MAGIC.len() + body.len());
    plain.extend_from_slice(MAGIC);
    plain.extend_from_slice(&body);
    let sealed = snapshot::seal(&plain, seed);
    snapshot::write_atomic(path, &sealed).map_err(|e| format!("journal write: {e}"))
}

/// Load the journal, distinguishing the three boot cases: `Ok(None)` = no journal
/// (clean shutdown — the common case), `Ok(Some)` = an in-flight window to resolve,
/// `Err` = a journal EXISTS but is unreadable (wrong seed / tampered / truncated /
/// future format) — the caller must HOLD, never treat it as absent.
#[cfg(test)]
pub fn read(path: &Path, seed: &[u8; 32]) -> Result<Option<RollbackJournal>, String> {
    let sealed = match snapshot::read_file(path) {
        Ok(bytes) => bytes,
        // The ONLY absent case: the file does not exist. Every other I/O failure
        // (permissions, etc.) is a present-but-unreadable journal → Err → HOLD.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("journal read: {e}")),
    };
    open(&sealed, seed).map(Some)
}

/// Decode exactly the bytes admitted by the startup checkpoint. Never reopen a
/// file after comparing its hash; the existing authenticated format is unchanged.
pub fn open(sealed: &[u8], seed: &[u8; 32]) -> Result<RollbackJournal, String> {
    let plain = snapshot::open(sealed, seed).map_err(|e| format!("journal open: {e}"))?;
    let body = plain
        .strip_prefix(MAGIC.as_slice())
        .ok_or("journal magic/version mismatch")?;
    let j: RollbackJournal =
        postcard::from_bytes(body).map_err(|e| format!("journal decode: {e}"))?;
    // Defense-in-depth: the window id lives in the journal twice — `batch_id`
    // (what the boot recovery table keys on) and `witness.batch_id` (what
    // `rollback_window` asserts on). They are written equal; a decoded journal
    // where they disagree is corrupt/tampered in a way the seal + postcard framing
    // happened not to catch — fail closed like any other unreadable journal (the
    // caller HOLDs), never hand recovery a self-inconsistent journal.
    if j.batch_id != j.witness.batch_id {
        return Err(format!(
            "journal batch_id mismatch: batch_id {} != witness.batch_id {}",
            j.batch_id, j.witness.batch_id
        ));
    }
    Ok(j)
}

/// Best-effort removal once the window is resolved (commit, rollback, or stale).
/// A failed delete only logs: the recovery decision is idempotent against a
/// re-read journal (Stale/SealNeverPersisted re-derive to delete again).
pub fn delete(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("[recovery] rollback journal delete {}: {e}", path.display());
        }
    }
}

/// What boot recovery must do about the journaled window (the spec's
/// recovery_action table, normative).
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Commit already happened and was persisted — delete the journal.
    Stale,
    /// Pre-seal snapshot and stage 1 proves no broadcast occurred; delete the journal.
    SealNeverPersisted,
    /// Seal persisted and stage 1 proves no broadcast occurred; replay rollback
    /// inputs, persist the resolution, then delete.
    RollBack,
    /// The tx landed but the commit was lost — re-commit from the journal's
    /// `prepared`, then delete.
    RollForward,
    /// Anything else: retain the journal and refuse startup until reconciled.
    Hold,
}

/// Pure decision over the spec's recovery table (unit-testable as a full matrix,
/// mirroring `settle_failure_action`). Inputs: `j_batch` = the journaled window's
/// batch id, `has_prepared` = journal carries a prove outcome, `b_snap` = restored
/// Counter B (`seq.state.next_batch_id`), `chain_bc` = on-chain `batchCount`,
/// `root_matches_prepared` = chain `currentStateRoot == prepared.new_root` (false
/// when `prepared` is None), `root_matches_settled` = chain `currentStateRoot ==`
/// restored `l1_status.settled_root`.
pub fn recovery_action(
    j_batch: u64,
    has_prepared: bool,
    b_snap: u64,
    chain_bc: u64,
    root_matches_prepared: bool,
    root_matches_settled: bool,
) -> RecoveryAction {
    // `checked_add` so a (theoretical) u64::MAX journal can never panic a boot;
    // an overflowed "next" simply matches nothing sealed/landed → HOLD.
    let sealed_persisted = Some(b_snap) == j_batch.checked_add(1);
    let tx_landed = Some(chain_bc) == j_batch.checked_add(1);

    // A prepared stage-2 journal is evidence a transaction MAY have been sent.
    // Unchanged counters, even after a long wait, cannot prove it will never land.
    // Rollback and pre-seal deletion therefore require stage 1 (no prepared data).
    // Row order IS the precedence: STALE must beat ROLL-FORWARD (same counters —
    // if the settled root already matches the chain, the commit was persisted and
    // re-committing would double-apply the window).
    //
    // WHY the precedence is sound (i.e. why STALE can never shadow a genuine
    // roll-forward): `root_matches_settled` and `root_matches_prepared` can never
    // both be true, because consecutive settle roots always differ —
    // `state_root()` binds `next_batch_id` into the root
    // (crates/perp-core/src/state.rs:240) and `apply_batch` increments it exactly
    // once per window (crates/perp-core/src/engine.rs:204), so `prepared.new_root`
    // (the new window's post-state) cannot equal the restored
    // `l1_status.settled_root` (the previous window's post-state) even for a
    // window that changed nothing else. A lost commit therefore always presents
    // as `root_matches_settled == false` and falls through to ROLL-FORWARD.
    if sealed_persisted && tx_landed && root_matches_settled {
        RecoveryAction::Stale
    } else if !has_prepared && b_snap == j_batch && chain_bc == j_batch {
        RecoveryAction::SealNeverPersisted
    } else if !has_prepared && sealed_persisted && chain_bc == j_batch {
        RecoveryAction::RollBack
    } else if sealed_persisted && tx_landed && has_prepared && root_matches_prepared {
        RecoveryAction::RollForward
    } else {
        RecoveryAction::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover_client::{prove_and_prepare, MockProverClient, ProverClient as _};
    use crate::Gw;
    use perp_core::fixed::QUOTE_SCALE;

    /// Unpredictable per-test scratch path under the OS temp dir (the l1.rs
    /// keystore pattern) — parallel tests never collide on a fixed name.
    fn scratch_path(tag: &str) -> PathBuf {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).expect("OS CSPRNG");
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("darkperp-journal-{tag}-{suffix}"))
    }

    /// A REAL sealed window (deposit + withdrawal), exactly what the settle loop
    /// would journal — not a hand-built stand-in. SEC-021: the withdrawal goes
    /// through the full authorization path — a caller-signed account whose
    /// registered signer signs the real `withdraw_auth_digest` (no exemption).
    fn sealed_window() -> (sequencer::WindowWitness, Vec<Withdrawal>) {
        use sha3::{Digest as _, Keccak256};
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x51u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&hash[12..]);

        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(Some(signer));
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let (amount, to, nonce) = (5_000 * QUOTE_SCALE, [7u8; 20], 1u64);
        let digest =
            crate::withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, nonce);
        let (s, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&s.to_bytes());
        sig[64] = 27 + recid.to_byte();
        gw.account_withdraw(&key, 0, amount, to, nonce, &sig)
            .unwrap();
        let bc = gw.seq.state.next_batch_id;
        gw.begin_window_settle(bc).unwrap().expect("window sealed")
    }

    #[test]
    fn journal_seal_round_trip() {
        let (witness, ww) = sealed_window();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");

        // capture the expectations before the journal takes ownership
        let batch_id = witness.batch_id;
        let ops_len = witness.ops.len();
        let pre_root = witness.pre_state.state_root();
        let ww_leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
        let commitment = prepared.outcome.commitment;
        let new_root = prepared.outcome.new_root;
        let new_deposit_count = prepared.outcome.new_deposit_count;
        let post_insurance_fund = prepared.outcome.post_insurance_fund;
        let proof = prepared.outcome.proof.clone();
        let withdraw_proofs = prepared.withdraw_proofs.clone();
        assert!(ops_len > 0, "a real window has ops");
        assert!(!ww_leaves.is_empty(), "a real window has a withdrawal");
        // Fixture guard: the window contains a deposit, so the cumulative count is
        // non-zero — the round-trip assert below can never pass vacuously as 0 == 0.
        assert!(
            new_deposit_count > 0,
            "a real window has a consumed deposit"
        );
        // Fixture guards for the SEC-025-D terms (the DPRBJL5 bump): both captured
        // values must differ from what a silently-defaulted decode would produce
        // (false / 0), or the survival asserts below prove nothing.
        assert!(
            prepared.outcome.post_mode_is_normal,
            "a demo-boot window replays to a Normal post-state"
        );
        assert!(
            post_insurance_fund > 0,
            "boot seeds a non-zero insurance fund"
        );

        let j = RollbackJournal {
            batch_id,
            witness,
            ww,
            prepared: Some(prepared),
        };
        let path = scratch_path("round-trip");
        let seed = [42u8; 32];
        write(&path, &j, &seed).expect("journal write");
        let back = read(&path, &seed).expect("journal read").expect("present");

        assert_eq!(back.batch_id, batch_id);
        assert_eq!(back.witness.batch_id, batch_id);
        assert_eq!(back.witness.ops.len(), ops_len);
        assert_eq!(
            back.witness.pre_state.state_root(),
            pre_root,
            "pre_state survives"
        );
        let back_leaves: Vec<[u8; 32]> = back.ww.iter().map(|w| w.leaf()).collect();
        assert_eq!(back_leaves, ww_leaves, "withdrawal set survives byte-exact");
        // the strongest witness check: the restored witness REPLAYS to the same
        // commitment the original prove produced (pre_state + ops + manifest all intact)
        let replay = MockProverClient.prove(&back.witness).expect("replay");
        assert_eq!(
            replay.commitment, commitment,
            "restored witness replays identically"
        );

        let bp = back.prepared.expect("prepared survives");
        assert_eq!(bp.outcome.new_root, new_root);
        assert_eq!(
            bp.outcome.new_deposit_count, new_deposit_count,
            "new_deposit_count survives — the field whose addition motivated the \
             DPRBJL3 bump, and the one a roll-forward resubmits to _requireDepositPrefix"
        );
        // The SEC-025-D terms (the DPRBJL5 bump) survive with non-default values —
        // guarded above, so a decode that silently defaulted them would fail here.
        assert!(bp.outcome.post_mode_is_normal, "gate mode term survives");
        assert_eq!(
            bp.outcome.post_insurance_fund, post_insurance_fund,
            "gate insurance term survives"
        );
        assert_eq!(bp.outcome.proof, proof);
        assert_eq!(bp.withdraw_proofs, withdraw_proofs, "claim proofs survive");

        std::fs::remove_file(&path).ok();
    }

    /// A journal sealed under one enclave seed must never decode under another —
    /// same fail-closed posture as the snapshot restore path.
    #[test]
    fn journal_wrong_seed_fails_closed() {
        let (witness, ww) = sealed_window();
        let j = RollbackJournal {
            batch_id: witness.batch_id,
            witness,
            ww,
            prepared: None,
        };
        let path = scratch_path("wrong-seed");
        write(&path, &j, &[42u8; 32]).expect("journal write");
        // Err — NOT Ok(None): the file exists, so a wrong seed must read as
        // "unreadable journal → HOLD", never as "no journal → clean boot".
        assert!(read(&path, &[43u8; 32]).is_err());
        std::fs::remove_file(&path).ok();
    }

    /// Defense-in-depth (Task 3 fix round 1): the journal carries the window id
    /// twice — `batch_id` (keyed on by the recovery table) and `witness.batch_id`
    /// (asserted by `rollback_window`). A journal where they disagree is
    /// corrupt/tampered in a way postcard can't catch; `read` fails closed (Err →
    /// the caller HOLDs), never handing recovery a self-inconsistent journal.
    #[test]
    fn journal_batch_id_mismatch_fails_closed() {
        let (witness, ww) = sealed_window();
        let j = RollbackJournal {
            batch_id: witness.batch_id + 1, // disagrees with witness.batch_id
            witness,
            ww,
            prepared: None,
        };
        let path = scratch_path("id-mismatch");
        let seed = [42u8; 32];
        write(&path, &j, &seed).expect("journal write");
        // Err — NOT Ok: a self-inconsistent journal must read as unreadable.
        // (no expect_err: RollbackJournal carries a full WindowWitness, no Debug)
        let err = match read(&path, &seed) {
            Err(e) => e,
            Ok(_) => panic!("mismatched window ids must fail closed"),
        };
        assert!(
            err.contains("batch_id mismatch"),
            "unexpected error text: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    /// The DPRBJL5 bump's whole claim, made executable: a journal written under the
    /// PREVIOUS magic must be refused as a versioned mismatch, never handed to
    /// postcard under the new layout (a pre-025-D `ProveOutcome` would misparse, and
    /// a roll-forward re-submits those roots to `_requireDepositPrefix`). No prior
    /// bump (v2/v3/v4) pinned this; each relied on the constant alone.
    #[test]
    fn journal_with_a_stale_magic_is_refused() {
        let seed = [42u8; 32];
        let path = scratch_path("stale-magic");
        // A well-formed v4-era payload is unnecessary: the magic check runs BEFORE
        // postcard, so any body under the old magic must already be refused.
        let mut plain = Vec::new();
        plain.extend_from_slice(b"DPRBJL4\0");
        plain.extend_from_slice(&[0u8; 16]);
        let sealed = snapshot::seal(&plain, &seed);
        snapshot::write_atomic(&path, &sealed).expect("write");
        let err = match read(&path, &seed) {
            Err(e) => e,
            Ok(_) => panic!("a stale-magic journal must be refused"),
        };
        // Under a reverted MAGIC this dies either way: the old-magic journal then
        // strips cleanly and yields Ok (panic above) or a postcard decode error
        // (which does not name the magic) — never this exact refusal.
        assert!(err.contains("magic"), "unexpected error: {err}");
        std::fs::remove_file(&path).ok();
    }

    /// No journal file = the common clean-shutdown boot: Ok(None), not an error.
    #[test]
    fn journal_missing_is_none() {
        let path = scratch_path("missing");
        assert!(matches!(read(&path, &[42u8; 32]), Ok(None)));
    }

    /// Every row of the spec's recovery table, with the "any" slots expanded over
    /// both bool values so no wildcard hides a precedence bug.
    #[test]
    fn recovery_action_full_matrix() {
        use RecoveryAction::*;
        let bools = [false, true];

        // STALE: seal persisted (B=j+1), tx landed (bc=j+1), and the restored
        // settled root already matches the chain — the commit was persisted too.
        // Wins regardless of prepared/rm_prep (precedence over ROLL-FORWARD).
        for prep in bools {
            for rmp in bools {
                assert_eq!(recovery_action(5, prep, 6, 6, rmp, true), Stale);
            }
        }
        // A stage-1 pre-seal snapshot can resolve; stage 2 remains ambiguous.
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(
                        recovery_action(5, prep, 5, 5, rmp, rms),
                        if prep { Hold } else { SealNeverPersisted }
                    );
                }
            }
        }
        // A stage-1 post-seal snapshot can roll back; stage 2 must HOLD.
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(
                        recovery_action(5, prep, 6, 5, rmp, rms),
                        if prep { Hold } else { RollBack }
                    );
                }
            }
        }
        // ROLL-FORWARD: tx landed, commit lost (settled root stale), and the chain
        // root is exactly the journaled prepared new_root.
        assert_eq!(recovery_action(5, true, 6, 6, true, false), RollForward);

        // HOLD: landed but nothing proves the chain root is ours —
        // no prepared outcome at all…
        assert_eq!(recovery_action(5, false, 6, 6, false, false), Hold);
        // …or a prepared outcome whose root does NOT match the chain.
        assert_eq!(recovery_action(5, true, 6, 6, false, false), Hold);
        // HOLD: pre-seal snapshot but the chain advanced past the journal.
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(recovery_action(5, prep, 5, 6, rmp, rms), Hold);
                }
            }
        }
        // HOLD: chain advanced BEYOND the journaled window (bc = j+2).
        for prep in bools {
            for rmp in bools {
                for rms in bools {
                    assert_eq!(recovery_action(5, prep, 6, 7, rmp, rms), Hold);
                }
            }
        }
        // HOLD: Counter B implausibly ahead of the journal (B = j+2), any chain.
        for bc in [4u64, 5, 6, 7] {
            for prep in bools {
                for rmp in bools {
                    for rms in bools {
                        assert_eq!(recovery_action(5, prep, 7, bc, rmp, rms), Hold);
                    }
                }
            }
        }
    }
}
