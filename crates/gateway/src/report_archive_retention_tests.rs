// Reference retirement concerns the bounded canonical index. Immutable files,
// including rejected receipts and historical backup references, stay append-only.

fn reset_archive_market(gw: &mut crate::Gw) {
    gw.seq.set_oracle(
        0,
        transcript_of(Normalized {
            price: 0,
            publish_time_ms: 0,
            confidence: 0,
            backup_twap: 0,
        }),
    );
    let m = gw.mkts.iter_mut().find(|m| m.id == 0).unwrap();
    m.live = false;
    m.feed_ts = 0;
    m.px_ms = 0;
}

/// The real gateway acceptance path, signed with its configured test signer.
/// The full reports are synthetic containers, never DON-authenticated reports.
fn accept_archive_observation(gw: &mut crate::Gw, b: &mut ArchiveBinding, observed: u64) {
    use perp_core::oracle::OracleSig;
    let now = observed * 1000;
    assert_eq!(
        b.admit_with(
            0,
            base_report(observed, now),
            quote_report(observed, now),
            now,
            |n| {
                let oracle = n.with_signature(OracleSig::sign(
                    &gw.oracle_signer,
                    &crate::oracle_digest(
                        0,
                        n.price,
                        n.publish_time_ms,
                        n.confidence,
                        n.backup_twap,
                    ),
                ));
                gw.apply_validated_real_oracle_at(0, oracle, now)
            }
        ),
        Ok(true)
    );
}

#[test]
fn retention_protects_open_live_and_journal_refs_and_rejects_stale_plans() {
    let (t, mut b) = binding("retention-refs");
    let mut admitted = Vec::new();
    for observed in 100..104 {
        let now = observed * 1000;
        admitted.push(admit_installed(
            &mut b,
            0,
            base_report(observed, now),
            quote_report(observed, now),
            now,
        ));
    }
    let before = b.admissions.clone();
    let open = [fill(0, NOW, transcript_of(admitted[0]))];
    let journal = [fill(0, NOW + 1000, transcript_of(admitted[1]))];
    let envelope = b.bind_ops(&journal).unwrap();
    let live = [(0, transcript_of(admitted[2]))];
    let plan = b
        .plan_retention(&open, &live, Some((&journal, &envelope)))
        .unwrap();
    assert_eq!(
        b.admissions, before,
        "planning never releases an index entry"
    );
    assert_eq!(plan.retained.len(), 3);
    let plain = b.snapshot_with_retention(vec![1, 2, 3], &plan).unwrap();
    let mut restarted = reopened_binding(&t, &b);
    assert_eq!(
        restore_snapshot_plain(&plain, Some(&mut restarted)).unwrap(),
        [1, 2, 3]
    );
    assert!(restarted.journal_expected());
    assert_eq!(restarted.admissions, plan.retained);
    b.commit_retention(plan).unwrap();
    assert_eq!(b.admissions.len(), 3);
    assert_eq!(b.bind_ops(&open).unwrap().refs[0].archive_id, before[0].id);
    assert_eq!(
        b.bind_ops(&journal).unwrap().refs[0].archive_id,
        before[1].id
    );
    // A live-only mark remains usable after its source op window has closed.
    assert_eq!(
        b.bind_ops(&[fill(0, NOW + 2000, live[0].1)]).unwrap().refs[0].archive_id,
        before[2].id
    );
    assert!(
        b.archive.load(before[3].id, &b.policy, 0).is_ok(),
        "retirement never deletes historical records"
    );

    let stale = b.plan_retention(&[], &live, None).unwrap();
    admit_installed(
        &mut b,
        0,
        base_report(104, 104_000),
        quote_report(104, 104_000),
        104_000,
    );
    let newer = b.admissions.clone();
    assert_eq!(b.commit_retention(stale), Err(BindError::Mismatch));
    assert_eq!(
        b.admissions, newer,
        "a later accepted ID survives an obsolete capture"
    );

    // No open operations are necessary to detect a missing selected live mark.
    std::fs::remove_file(
        t.0.join("store")
            .join(format!("{}.json", before[2].id.hex())),
    )
    .unwrap();
    assert!(matches!(
        b.plan_retention(&[], &live, None),
        Err(BindError::Archive)
    ));
    assert_eq!(b.admissions, newer);
}

#[test]
fn full_index_and_disk_quota_duplicate_uses_original_id_without_storing_sibling() {
    let (t, mut b) = binding("retention-duplicate");
    b.max_admissions = 1;
    let first = b
        .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
        .unwrap();
    b.install(first).unwrap();
    let mut sibling_full = full_report(feed(0x11), 6_000_000_000_000, 100);
    sibling_full[600] = 0x44;
    let sibling = report_from_full(sibling_full, 100, NOW);
    let usage = b.usage().unwrap();
    b.archive
        .set_limits(ArchiveLimits {
            max_bytes: usage.bytes,
            max_records: usage.records,
        })
        .unwrap();
    let mut callbacks = 0;
    assert_eq!(
        b.admit_with(0, sibling.clone(), quote_report(100, NOW), NOW, |_| {
            callbacks += 1;
            true
        }),
        Ok(true)
    );
    assert_eq!(callbacks, 1);
    assert_eq!(
        b.usage().unwrap(),
        usage,
        "equal normalized receipt never consumes a new slot"
    );
    assert_eq!(b.admissions[0].id, first.id);
    assert_eq!(
        b.admit_with(
            0,
            base_report(101, NOW + 1000),
            quote_report(101, NOW + 1000),
            NOW + 1000,
            |_| {
                callbacks += 1;
                true
            }
        ),
        Err(BindError::Capacity)
    );
    assert_eq!(
        callbacks, 1,
        "a genuinely new identity never reaches acceptance at capacity"
    );
    assert_eq!(b.usage().unwrap(), usage);

    b.max_admissions = 2;
    assert_eq!(
        b.admit_with(
            0,
            base_report(101, NOW + 1000),
            quote_report(101, NOW + 1000),
            NOW + 1000,
            |_| {
                callbacks += 1;
                true
            }
        ),
        Err(BindError::Capacity),
        "the disk quota refuses before acceptance even with an index slot free"
    );
    assert_eq!(callbacks, 1);
    assert_eq!(b.usage().unwrap(), usage);

    // Even with a durable equal-normalized sibling, exact selected ID loss HOLDs.
    b.archive
        .set_limits(ArchiveLimits {
            max_bytes: DEFAULT_ARCHIVE_BYTES,
            max_records: DEFAULT_ARCHIVE_RECORDS,
        })
        .unwrap();
    let pair =
        PreparedPair::new(&b.policy, 0, sibling.clone(), quote_report(100, NOW), NOW).unwrap();
    let other = b.archive.store(&pair).unwrap();
    assert_ne!(other.id, first.id);
    std::fs::remove_file(t.0.join("store").join(format!("{}.json", first.id.hex()))).unwrap();
    assert_eq!(
        b.admit_with(0, sibling, quote_report(100, NOW), NOW, |_| {
            callbacks += 1;
            true
        }),
        Err(BindError::Archive)
    );
    assert_eq!(callbacks, 1);
    assert_eq!(b.admissions[0].id, first.id);
}

#[tokio::test]
async fn retention_failed_runtime_and_final_save_keep_previous_checkpoint_and_whole_index() {
    use std::sync::Arc;
    let (t, b) = binding("retention-save-failure");
    let mut app = crate::tests::test_app();
    Arc::get_mut(&mut app).unwrap().archive = Some(std::sync::Mutex::new(b));
    {
        let mut gw = app.gw.lock().await;
        reset_archive_market(&mut gw);
        accept_archive_observation(
            &mut gw,
            &mut app.archive.as_ref().unwrap().lock().unwrap(),
            100,
        );
    }
    let path = t.0.join("state.snapshot");
    let seed = [42; 32];
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    assert!(crate::write_snapshot(&app, &path, seed, serial.clone()).await);
    let checkpoint = std::fs::read(&path).unwrap();
    {
        let mut gw = app.gw.lock().await;
        let mut b = app.archive.as_ref().unwrap().lock().unwrap();
        accept_archive_observation(&mut gw, &mut b, 101);
        accept_archive_observation(&mut gw, &mut b, 102);
    }
    let before = app
        .archive
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .admissions
        .clone();
    assert_eq!(before.len(), 3);
    let blocked = t.0.join("s".repeat(240));
    std::fs::rename(&path, &blocked).unwrap();
    assert!(!crate::write_snapshot(&app, &blocked, seed, serial.clone()).await);
    assert_eq!(std::fs::read(&blocked).unwrap(), checkpoint);
    assert_eq!(
        app.archive.as_ref().unwrap().lock().unwrap().admissions,
        before
    );
    let (frozen, saved) = crate::final_snapshot(&app, &blocked, seed, serial.clone()).await;
    assert!(!saved);
    drop(frozen);
    assert_eq!(std::fs::read(&blocked).unwrap(), checkpoint);
    assert_eq!(
        app.archive.as_ref().unwrap().lock().unwrap().admissions,
        before
    );
    std::fs::rename(&blocked, &path).unwrap();
    assert!(crate::write_snapshot(&app, &path, seed, serial).await);
    let b = app.archive.as_ref().unwrap().lock().unwrap();
    assert_eq!(b.admissions.len(), 1);
    assert_eq!(b.admissions[0], before[2]);
    for entry in before {
        assert!(b.archive.load(entry.id, &b.policy, entry.market_id).is_ok());
    }
    let plain = crate::snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap();
    let mut restarted = reopened_binding(&t, &b);
    let restored =
        crate::Gw::boot_restored(&restore_snapshot_plain(&plain, Some(&mut restarted)).unwrap())
            .unwrap();
    let live = *restored.seq.oracle(0).unwrap();
    assert_eq!(
        restarted.bind_ops(&[fill(0, 102_000, live)]).unwrap().refs[0].archive_id,
        b.admissions[0].id
    );
}

#[test]
fn retention_requires_authenticated_expected_wal_and_v2_upgrades_conservatively() {
    let (t, mut b) = binding("retention-wal");
    let n = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    let mut gw = crate::Gw::boot();
    gw.seq.set_oracle(0, transcript_of(n));
    let path = t.0.join("state.snapshot");
    let wal = crate::rollback_journal::journal_path(&path);
    let seed = [42; 32];
    b.note_journal(true);
    let plain = b.snapshot_plain(gw.snapshot_plain()).unwrap();
    let mut restarted = reopened_binding(&t, &b);
    restore_snapshot_plain(&plain, Some(&mut restarted)).unwrap();
    assert!(restarted.journal_expected());
    assert!(
        crate::retention_journal(&restarted, &path, &seed).is_err(),
        "startup gate refuses remembered WAL loss"
    );
    assert!(crate::planned_candidate_checkpoint(&gw, &restarted, &path, &seed).is_err());
    let before = restarted.admissions.clone();
    std::fs::write(&wal, b"corrupt sealed journal").unwrap();
    assert!(crate::retention_journal(&restarted, &path, &seed).is_err());
    assert_eq!(restarted.admissions, before);
    let mut witness = open_window_witness(&gw);
    witness.ops = vec![fill(0, NOW, transcript_of(n))];
    let journal = crate::rollback_journal::RollbackJournal {
        batch_id: witness.batch_id,
        witness,
        ww: vec![],
        prepared: None,
    };
    let env = b.bind_ops(&journal.witness.ops).unwrap();
    crate::rollback_journal::write_versioned(&wal, &journal, Some(&env), &seed).unwrap();
    assert!(crate::retention_journal(&restarted, &path, &seed)
        .unwrap()
        .is_some());
    let (cut, plan) = crate::planned_candidate_checkpoint(&gw, &restarted, &path, &seed).unwrap();
    assert!(plan.journal_expected);
    assert_eq!(plan.retained, before);
    let mut from_cut = reopened_binding(&t, &b);
    restore_snapshot_plain(&cut, Some(&mut from_cut)).unwrap();
    assert!(from_cut.journal_expected());

    let v2 = encoded_envelope(&CandidateSnapshotV2 {
        state_plain: gw.snapshot_plain(),
        policy_binding: b.policy_binding,
        admissions: b.admissions.iter().copied().collect(),
    });
    let mut old = reopened_binding(&t, &b);
    restore_snapshot_plain(&v2, Some(&mut old)).unwrap();
    assert_eq!(old.admissions, b.admissions);
    assert!(
        !old.journal_expected(),
        "v2 itself carries no expectation flag"
    );
    old.recover_journal(&journal.witness.ops, &env).unwrap();
    assert!(
        old.journal_expected(),
        "verified WAL is remembered even when v2 lacked metadata"
    );

    // Even a non-mutating recovery must durably clear the remembered WAL need
    // before deletion. A failed save leaves the complete previous checkpoint,
    // canonical index, expectation flag and authenticated WAL untouched.
    let previous = crate::snapshot::seal(&plain, &seed);
    std::fs::write(&path, &previous).unwrap();
    let journal_bytes = std::fs::read(&wal).unwrap();
    let blocked = t.0.join("r".repeat(240));
    let blocked_wal = crate::rollback_journal::journal_path(&blocked);
    std::fs::write(&blocked, &previous).unwrap();
    std::fs::write(&blocked_wal, &journal_bytes).unwrap();
    assert!(!crate::finish_boot_recovery(
        &gw,
        false,
        &blocked,
        &blocked_wal,
        &seed,
        Some(&b)
    ));
    assert_eq!(std::fs::read(&blocked).unwrap(), previous);
    assert_eq!(std::fs::read(&blocked_wal).unwrap(), journal_bytes);
    assert!(b.journal_expected());
    assert_eq!(b.admissions, before);
    assert!(crate::finish_boot_recovery(
        &gw,
        false,
        &path,
        &wal,
        &seed,
        Some(&b)
    ));
    assert!(!wal.exists());
    assert!(!b.journal_expected());
    let completed = crate::snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap();
    let mut completed_binding = reopened_binding(&t, &b);
    let completed_state = restore_snapshot_plain(&completed, Some(&mut completed_binding)).unwrap();
    assert_eq!(completed_state, gw.snapshot_plain());
    assert!(
        !completed_binding.journal_expected(),
        "resolved whole cut remembers that the WAL is no longer needed"
    );
    assert_eq!(completed_binding.admissions, before);
    assert!(crate::retention_journal(&completed_binding, &path, &seed)
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_cancelled_caller_keeps_serial_and_mutation_barriers_until_save_install() {
    use std::sync::Arc;
    let (t, b) = binding("retention-cancel");
    let mut app = crate::tests::test_app();
    Arc::get_mut(&mut app).unwrap().archive = Some(std::sync::Mutex::new(b));
    let mut held = app.gw.lock().await;
    reset_archive_market(&mut held);
    let original = {
        let mut b = app.archive.as_ref().unwrap().lock().unwrap();
        accept_archive_observation(&mut held, &mut b, 100);
        accept_archive_observation(&mut held, &mut b, 101);
        b.admissions.clone()
    };
    let path = t.0.join("state.snapshot");
    let seed = [42; 32];
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    let (worker_entered, entered) = tokio::sync::oneshot::channel();
    let first = tokio::spawn({
        let app = app.clone();
        let path = path.clone();
        let serial = serial.clone();
        async move {
            crate::write_snapshot_with_entry(
                &app,
                &path,
                seed,
                serial,
                crate::SnapshotWorkerEntry {
                    entered: Some(worker_entered),
                },
            )
            .await
        }
    });
    // A failed try_lock can merely observe an unpolled lock_owned reservation.
    // Await actual blocking-worker entry while Gw remains frozen; cancellation
    // now targets a started, uncancellable worker that already owns serial.
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(
        serial.try_lock().is_err(),
        "uncancellable filesystem worker still owns serialization"
    );
    assert_eq!(
        app.archive.as_ref().unwrap().lock().unwrap().admissions,
        original
    );
    assert!(
        !path.exists(),
        "worker cannot capture while Gw mutations are frozen"
    );
    let second = tokio::spawn({
        let app = app.clone();
        let path = path.clone();
        let serial = serial.clone();
        async move { crate::write_snapshot(&app, &path, seed, serial).await }
    });
    drop(held);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap()
    );
    let b = app.archive.as_ref().unwrap().lock().unwrap();
    assert_eq!(b.admissions.len(), 1);
    assert_eq!(b.admissions[0], original[1]);
    assert!(b.archive.load(original[0].id, &b.policy, 0).is_ok());
    let plain = crate::snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap();
    let mut restarted = reopened_binding(&t, &b);
    restore_snapshot_plain(&plain, Some(&mut restarted)).unwrap();
    assert_eq!(restarted.admissions, b.admissions);
}

#[tokio::test]
async fn retention_real_gateway_continues_past_4096_cumulative_admissions_and_restarts() {
    use std::sync::Arc;
    let (t, b) = binding("retention-long-run");
    let mut app = crate::tests::test_app();
    Arc::get_mut(&mut app).unwrap().archive = Some(std::sync::Mutex::new(b));
    let mut protected_ops = Vec::new();
    {
        let mut gw = app.gw.lock().await;
        reset_archive_market(&mut gw);
        let mut b = app.archive.as_ref().unwrap().lock().unwrap();
        for observed in 100..100 + MAX_ADMISSIONS as u64 {
            accept_archive_observation(&mut gw, &mut b, observed);
            protected_ops.push(fill(0, observed * 1000, *gw.seq.oracle(0).unwrap()));
        }
        assert_eq!(b.admissions.len(), 4096);
        let all_live = b.plan_retention(&protected_ops, &[], None).unwrap();
        assert_eq!(
            all_live.retained.len(),
            4096,
            "all exact references remain protected when genuinely usable"
        );
        b.commit_retention(all_live).unwrap();
        let usage = b.usage().unwrap();
        let state = gw.snapshot_plain();
        assert_eq!(
            b.admit_with(
                0,
                base_report(4196, 4_196_000),
                quote_report(4196, 4_196_000),
                4_196_000,
                |_| panic!("full live index cannot invoke acceptance")
            ),
            Err(BindError::Capacity)
        );
        assert_eq!(b.usage().unwrap(), usage);
        assert_eq!(gw.snapshot_plain(), state);
    }
    let first_id = app.archive.as_ref().unwrap().lock().unwrap().admissions[0].id;
    let path = t.0.join("state.snapshot");
    let seed = [42; 32];
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    // The real gateway has no open fills now; only its latest live mark remains
    // usable. Release the expired selections only after publishing that cut.
    assert!(crate::write_snapshot(&app, &path, seed, serial.clone()).await);
    assert_eq!(
        app.archive
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .admissions
            .len(),
        1
    );
    {
        let mut gw = app.gw.lock().await;
        let mut b = app.archive.as_ref().unwrap().lock().unwrap();
        for observed in 4196..4200 {
            accept_archive_observation(&mut gw, &mut b, observed);
        }
        assert_eq!(b.usage().unwrap().records, 4100);
    }
    assert!(crate::write_snapshot(&app, &path, seed, serial).await);
    let b = app.archive.as_ref().unwrap().lock().unwrap();
    assert_eq!(b.admissions.len(), 1);
    assert!(
        b.archive.load(first_id, &b.policy, 0).is_ok(),
        "old backup record was not deleted"
    );
    let plain = crate::snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap();
    let mut restarted = reopened_binding(&t, &b);
    let state = restore_snapshot_plain(&plain, Some(&mut restarted)).unwrap();
    let gw = crate::Gw::boot_restored(&state).unwrap();
    let live = *gw.seq.oracle(0).unwrap();
    assert_eq!(live.publish_time_ms, 4_199_000);
    assert_eq!(restarted.admissions, b.admissions);
    let ops = [fill(0, 4_199_000, live)];
    let env = restarted.bind_ops(&ops).unwrap();
    assert_eq!(env.refs[0].archive_id, b.admissions[0].id);
    restarted.verify(&ops, &env).unwrap();
}
