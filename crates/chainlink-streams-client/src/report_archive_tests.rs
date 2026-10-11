//! Owned local directories and deliberately synthetic reports, never real account data.
use super::*;
use crate::{parse_response, report_pair::PreparedPair, FeedId, Request};
use chainlink_oracle::policy::{MarketFeed, Policy};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    sync::Arc,
    thread,
};
const NOW: u64 = 100_000;
fn feed(n: u8) -> [u8; 32] {
    let mut id = [n; 32];
    id[0] = 0;
    id[1] = 3;
    id
}
fn policy() -> Policy {
    Policy {
        chain_id: 84532,
        network: 0,
        verifier_proxy: [3; 20],
        oracle_wrapper: [4; 20],
        markets: vec![MarketFeed {
            market_id: 0,
            base_symbol: "BTC".into(),
            base_usd_feed: feed(0x11),
            base_decimals: 8,
            usdc_usd_feed: feed(0x22),
            usdc_decimals: 8,
            max_report_age_ms: 10_000,
            max_pair_skew_ms: 1_000,
        }],
    }
}
fn report(
    id: [u8; 32],
    price: u64,
    observed: u64,
    received: u64,
    network: Network,
) -> UnverifiedReport {
    let mut full = crate::tests::full_report();
    full[256..288].copy_from_slice(&id);
    for (i, n) in [
        (1, observed),
        (2, observed),
        (5, observed + 60),
        (6, price),
        (7, price),
        (8, price),
    ] {
        let start = 256 + i * 32;
        full[start..start + 32].fill(0);
        full[start + 24..start + 32].copy_from_slice(&n.to_be_bytes());
    }
    let v = serde_json::json!({"report":{"feedID":format!("0x{}",hex(&id)),"validFromTimestamp":observed,
        "observationsTimestamp":observed,"fullReport":format!("0x{}",hex(&full))}});
    let req = Request::new(
        network,
        FeedId::parse_v3(&format!("0x{}", hex(&id))).unwrap(),
        10_000,
    )
    .unwrap();
    parse_response(&serde_json::to_vec(&v).unwrap(), &req, received).unwrap()
}
fn pair() -> PreparedPair {
    PreparedPair::new(
        &policy(),
        0,
        report(feed(0x11), 6_000_000_000_000, 100, NOW, Network::Testnet),
        report(feed(0x22), 100_000_000, 100, NOW, Network::Testnet),
        NOW,
    )
    .unwrap()
}
fn polled_pair(received: u64) -> PreparedPair {
    PreparedPair::new(
        &policy(),
        0,
        report(
            feed(0x11),
            6_000_000_000_000,
            100,
            received,
            Network::Testnet,
        ),
        report(feed(0x22), 100_000_000, 100, received, Network::Testnet),
        received,
    )
    .unwrap()
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let n = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "arcora-report-archive-tests-{}-{n}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn archive(&self) -> ReportArchive {
        ReportArchive::create(&self.0.join("store")).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn install(archive: &ReportArchive, bytes: &[u8]) -> ArchiveId {
    let id = ArchiveId::of(bytes);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(archive.path(id))
        .unwrap();
    f.write_all(bytes).unwrap();
    id
}

#[test]
fn pair_uses_explicit_usdc_ratio_and_preserves_original_reports() {
    let p = pair();
    let (n, e) = p.for_operation(NOW).unwrap();
    assert_eq!(n.price, 6_000_000_000_000);
    assert_eq!(n.publish_time_ms, NOW);
    assert_eq!(e.base, p.base().body().clone());
    assert_eq!(e.quote, p.quote().body().clone());
    assert_eq!(e.now_ms, NOW);
    assert_eq!(p.base().full_report()[576], 0x11);
}
#[test]
fn depeg_and_different_observation_times_survive_pairing() {
    let p = PreparedPair::new(
        &policy(),
        0,
        pair().base().clone(),
        report(feed(0x22), 80_000_000, 99, NOW, Network::Testnet),
        NOW,
    )
    .unwrap();
    let (n, _) = p.for_operation(NOW).unwrap();
    assert_eq!(n.price, 7_500_000_000_000);
    assert_eq!(n.publish_time_ms, 99_000);
}
#[test]
fn pair_refuses_missing_mapping_network_swap_and_wrong_quote() {
    let p = pair();
    assert!(PreparedPair::new(&policy(), 1, p.base.clone(), p.quote.clone(), NOW).is_err());
    assert!(PreparedPair::new(&policy(), 0, p.quote.clone(), p.base.clone(), NOW).is_err());
    assert!(PreparedPair::new(&policy(), 0, p.base.clone(), p.base.clone(), NOW).is_err());
    let wrong = report(feed(0x22), 100_000_000, 100, NOW, Network::Mainnet);
    assert!(PreparedPair::new(&policy(), 0, p.base.clone(), wrong, NOW).is_err());
    let mut bad = policy();
    bad.markets[0].base_decimals = 19;
    assert!(PreparedPair::new(&bad, 0, p.base, p.quote, NOW).is_err());
}
#[test]
fn pair_rechecks_queue_delay_skew_and_each_receipt_before_use() {
    let p = pair();
    assert!(PreparedPair::new(&policy(), 0, p.base.clone(), p.quote.clone(), NOW - 1).is_err());
    assert!(
        PreparedPair::new(&policy(), 0, p.base.clone(), p.quote.clone(), NOW + 10_001).is_err()
    );
    let old = report(feed(0x22), 100_000_000, 98, NOW, Network::Testnet);
    assert!(PreparedPair::new(&policy(), 0, p.base.clone(), old, NOW).is_err());
    assert!(p.for_operation(NOW - 1).is_err());
    assert!(p.for_operation(NOW + 10_001).is_err());
    assert!(p.for_operation(NOW + 10_000).is_ok());
}
#[test]
fn roundtrip_across_reopen_keeps_all_bytes_and_original_clocks() {
    let t = Temp::new();
    let p = pair();
    let a = t.archive();
    let stored = a.store(&p).unwrap();
    assert_eq!(stored.id, ReportArchive::id_for(&p).unwrap());
    drop(a);
    let a = ReportArchive::open_existing(&t.0.join("store")).unwrap();
    let loaded = a.load(stored.id, &policy(), 0).unwrap();
    assert_eq!(loaded.base().full_report(), p.base().full_report());
    assert_eq!(loaded.quote().full_report(), p.quote().full_report());
    assert_eq!(loaded.base().received_ms(), NOW);
    assert_eq!(loaded.prepared_at_ms(), NOW);
    assert_eq!(
        loaded.for_operation(NOW).unwrap().0,
        p.for_operation(NOW).unwrap().0
    );
}
#[test]
fn restored_history_is_not_fresh_admission_and_newer_file_is_not_fallback() {
    let t = Temp::new();
    let a = t.archive();
    let id = a.store(&pair()).unwrap().id;
    let loaded = a.load(id, &policy(), 0).unwrap();
    assert!(loaded.for_operation(NOW + 10_001).is_err());
    let newer = PreparedPair::new(
        &policy(),
        0,
        report(
            feed(0x11),
            6_100_000_000_000,
            101,
            101_000,
            Network::Testnet,
        ),
        report(feed(0x22), 100_000_000, 101, 101_000, Network::Testnet),
        101_000,
    )
    .unwrap();
    a.store(&newer).unwrap();
    fs::remove_file(a.path(id)).unwrap();
    assert!(matches!(
        a.load(id, &policy(), 0),
        Err(ArchiveError::Missing)
    ));
}
#[test]
fn equal_pair_is_idempotent_without_replacing_the_inode() {
    let t = Temp::new();
    let a = t.archive();
    let p = pair();
    let r = a.store(&p).unwrap();
    let ino = fs::metadata(a.path(r.id)).unwrap().ino();
    assert_eq!(r, a.store(&p).unwrap());
    assert_eq!(ino, fs::metadata(a.path(r.id)).unwrap().ino());
    assert_eq!(fs::read_dir(&a.root).unwrap().count(), 1);
}
#[test]
fn corrupt_existing_entry_is_preserved_not_repaired_or_overwritten() {
    let t = Temp::new();
    let a = t.archive();
    let p = pair();
    let r = a.store(&p).unwrap();
    fs::write(a.path(r.id), b"corrupt").unwrap();
    assert!(matches!(
        a.load(r.id, &policy(), 0),
        Err(ArchiveError::Identity)
    ));
    assert!(a.store(&p).is_err());
    assert_eq!(fs::read(a.path(r.id)).unwrap(), b"corrupt");
}
#[test]
fn policy_addresses_decimals_limits_network_and_market_are_bound() {
    let t = Temp::new();
    let a = t.archive();
    let id = a.store(&pair()).unwrap().id;
    for which in 0..7 {
        let mut p = policy();
        match which {
            0 => p.verifier_proxy[0] ^= 1,
            1 => p.oracle_wrapper[0] ^= 1,
            2 => p.markets[0].base_decimals = 9,
            3 => p.markets[0].max_report_age_ms = 20_000,
            4 => p.markets[0].max_pair_skew_ms = 2_000,
            5 => {
                p.chain_id = 8453;
                p.network = 1
            }
            _ => p.markets[0].usdc_usd_feed = feed(0x33),
        }
        assert!(a.load(id, &p, 0).is_err());
    }
    assert!(a.load(id, &policy(), 99).is_err());
}
#[test]
fn identity_parser_refuses_path_traversal_noncanonical_and_invalid_hashes() {
    for s in [
        "../foo".into(),
        "0".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        format!("0x{}", "0".repeat(64)),
    ] {
        assert!(ArchiveId::parse(&s).is_err());
    }
    let id = ReportArchive::id_for(&pair()).unwrap();
    assert_eq!(ArchiveId::parse(&id.hex()).unwrap(), id);
}
#[test]
fn recovery_does_not_create_missing_archive_and_create_does_not_reuse() {
    let t = Temp::new();
    let p = t.0.join("missing");
    assert!(matches!(
        ReportArchive::open_existing(&p),
        Err(ArchiveError::Missing)
    ));
    assert!(!p.exists());
    let a = t.archive();
    assert!(ReportArchive::create(&a.root).is_err());
    assert!(ReportArchive::open_existing(Path::new("relative")).is_err());
}
#[test]
fn symlink_directory_and_symlink_or_directory_record_are_refused() {
    let t = Temp::new();
    let a = t.archive();
    let alias = t.0.join("alias");
    symlink(&a.root, &alias).unwrap();
    assert!(ReportArchive::open_existing(&alias).is_err());
    let id = ReportArchive::id_for(&pair()).unwrap();
    let other = t.0.join("outside");
    fs::write(&other, encode(&pair()).unwrap()).unwrap();
    symlink(&other, a.path(id)).unwrap();
    assert!(a.load(id, &policy(), 0).is_err());
    assert!(a.store(&pair()).is_err());
    fs::remove_file(a.path(id)).unwrap();
    fs::create_dir(a.path(id)).unwrap();
    assert!(a.load(id, &policy(), 0).is_err());
}
#[test]
fn root_replacement_and_insecure_permissions_are_refused() {
    let t = Temp::new();
    let a = t.archive();
    let p = pair();
    let id = ReportArchive::id_for(&p).unwrap();
    fs::set_permissions(&a.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(a.store(&p).is_err());
    fs::set_permissions(&a.root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&a.root, t.0.join("old")).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&a.root).unwrap();
    assert!(a.store(&p).is_err());
    assert!(a.load(id, &policy(), 0).is_err());
}
#[test]
fn oversized_empty_and_modified_records_fail_before_decode() {
    let t = Temp::new();
    let a = t.archive();
    let id = a.store(&pair()).unwrap().id;
    for bytes in [vec![], vec![0; MAX_RECORD + 1], b"{}".to_vec()] {
        fs::write(a.path(id), bytes).unwrap();
        assert!(a.load(id, &policy(), 0).is_err());
    }
}
#[test]
fn even_self_hashed_records_must_be_canonical_and_schema_valid() {
    let t = Temp::new();
    let a = t.archive();
    let bytes = encode(&pair()).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let mut wrong_time: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    wrong_time["base_received_ms"] = serde_json::json!(0);
    for bad in [
        text.replace("\"schema\":1", "\"schema\":2").into_bytes(),
        text.replace("\"schema\":1", "\"schema\":1,\"schema\":1")
            .into_bytes(),
        text.replace("\"schema\":1", "\"unknown\":true,\"schema\":1")
            .into_bytes(),
        [bytes.clone(), b" ".to_vec()].concat(),
        [bytes, b"{}".to_vec()].concat(),
        serde_json::to_vec(&wrong_time).unwrap(),
    ] {
        let id = install(&a, &bad);
        assert!(a.load(id, &policy(), 0).is_err());
    }
}
#[test]
fn interruption_before_publication_never_yields_an_expected_record() {
    for stage in ["written", "file_synced"] {
        let t = Temp::new();
        let a = t.archive();
        let p = pair();
        let id = ReportArchive::id_for(&p).unwrap();
        assert!(a
            .store_with_checkpoint(&p, |at| if at == stage {
                Err(ArchiveError::Io)
            } else {
                Ok(())
            })
            .is_err());
        assert!(matches!(
            a.load(id, &policy(), 0),
            Err(ArchiveError::Missing)
        ));
        a.store(&p).unwrap();
        assert!(a.load(id, &policy(), 0).is_ok());
    }
}
#[test]
fn uncertain_post_publication_outcome_reconciles_exact_id_without_new_time() {
    for stage in ["published", "directory_synced"] {
        let t = Temp::new();
        let a = t.archive();
        let p = pair();
        let id = ReportArchive::id_for(&p).unwrap();
        assert!(a
            .store_with_checkpoint(&p, |at| if at == stage {
                Err(ArchiveError::Io)
            } else {
                Ok(())
            })
            .is_err());
        let r = a.load(id, &policy(), 0).unwrap();
        assert_eq!(r.prepared_at_ms(), NOW);
        assert_eq!(a.store(&p).unwrap().id, id);
    }
}
#[test]
fn partial_temporary_files_are_never_promoted_to_final_entries() {
    let t = Temp::new();
    let a = t.archive();
    let id = ReportArchive::id_for(&pair()).unwrap();
    let leftover = a.root.join(".pending-previous-crash");
    fs::write(&leftover, b"partial").unwrap();
    fs::set_permissions(&leftover, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(a.load(id, &policy(), 0).is_err());
    a.store(&pair()).unwrap();
    assert_eq!(fs::read(leftover).unwrap(), b"partial");
}

#[test]
fn finite_limits_validate_without_destroying_existing_history() {
    let t = Temp::new();
    let mut a = t.archive();
    let original = a.store(&pair()).unwrap();
    // An operator can lower the quota below a sizeable already-retained
    // history. Inventory bounds must not shrink with that quota.
    for n in 1..=100 {
        install(&a, &encode(&polled_pair(NOW + n)).unwrap());
    }
    for limits in [
        ArchiveLimits {
            max_bytes: 0,
            max_records: 1,
        },
        ArchiveLimits {
            max_bytes: 1,
            max_records: 0,
        },
        ArchiveLimits {
            max_bytes: 1,
            max_records: MAX_ARCHIVE_RECORDS + 1,
        },
    ] {
        assert_eq!(a.set_limits(limits), Err(ArchiveError::Bounds));
    }
    a.set_limits(ArchiveLimits {
        max_bytes: 1,
        max_records: 1,
    })
    .unwrap();
    assert_eq!(
        a.store(&pair()).unwrap(),
        original,
        "exact existing ID never consumes quota"
    );
    assert_eq!(
        a.store(&polled_pair(NOW + 101)),
        Err(ArchiveError::Capacity)
    );
    assert!(a.load(original.id, &policy(), 0).is_ok());
}

#[test]
fn novel_records_stop_at_byte_or_record_quota_before_any_temporary_write() {
    for by_bytes in [false, true] {
        let t = Temp::new();
        let p = pair();
        let bytes = encode(&p).unwrap().len() as u64;
        let a = t
            .archive()
            .with_limits(ArchiveLimits {
                max_bytes: if by_bytes { bytes } else { bytes * 10 },
                max_records: if by_bytes { 10 } else { 1 },
            })
            .unwrap();
        let first = a.store(&p).unwrap();
        let inode = fs::metadata(a.path(first.id)).unwrap().ino();
        assert_eq!(a.usage().unwrap(), ArchiveUsage { bytes, records: 1 });
        let mut callback = false;
        assert_eq!(
            a.store_with_checkpoint(&polled_pair(NOW + 1), |_| {
                callback = true;
                Ok(())
            }),
            Err(ArchiveError::Capacity)
        );
        assert!(
            !callback,
            "quota refusal precedes all publication checkpoints"
        );
        assert_eq!(fs::read_dir(&a.root).unwrap().count(), 1);
        assert_eq!(a.store(&p).unwrap(), first);
        assert_eq!(fs::metadata(a.path(first.id)).unwrap().ino(), inode);
        assert!(a.load(first.id, &policy(), 0).is_ok());
    }
}

#[test]
fn unchanged_source_poll_siblings_cannot_grow_archive_beyond_quota() {
    let t = Temp::new();
    let a = t
        .archive()
        .with_limits(ArchiveLimits {
            max_bytes: 1_000_000,
            max_records: 4,
        })
        .unwrap();
    let mut ids = Vec::new();
    let normalized = pair().for_operation(NOW).unwrap().0;
    for n in 0..16 {
        // Same full report/source time, different receipt/preparation time. Even
        // when downstream rejects stale observations, each stored sibling is
        // charged, preventing the rejected-poll history from growing forever.
        let p = polled_pair(NOW + n);
        assert_eq!(p.for_operation(NOW + n).unwrap().0, normalized);
        if n < 4 {
            ids.push(a.store(&p).unwrap().id);
        } else {
            assert_eq!(a.store(&p), Err(ArchiveError::Capacity));
        }
    }
    assert_eq!(a.usage().unwrap().records, 4);
    assert!(ids.windows(2).all(|ids| ids[0] != ids[1]));
    drop(a);
    let a = ReportArchive::open_existing(&t.0.join("store"))
        .unwrap()
        .with_limits(ArchiveLimits {
            max_bytes: 1_000_000,
            max_records: 4,
        })
        .unwrap();
    assert_eq!(a.usage().unwrap().records, 4);
    assert_eq!(a.store(&polled_pair(NOW + 17)), Err(ArchiveError::Capacity));
    for id in ids {
        assert!(a.load(id, &policy(), 0).is_ok());
    }
}

#[test]
fn crash_leftovers_consume_bytes_and_slots_without_promotion_or_deletion() {
    for by_bytes in [false, true] {
        let t = Temp::new();
        let bytes = encode(&pair()).unwrap().len() as u64;
        let a = t
            .archive()
            .with_limits(ArchiveLimits {
                max_bytes: if by_bytes { bytes } else { bytes * 10 },
                max_records: if by_bytes { 10 } else { 1 },
            })
            .unwrap();
        let pending = a.root.join(".pending-previous-crash");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .unwrap();
        f.write_all(b"partial").unwrap();
        assert_eq!(
            a.usage().unwrap(),
            ArchiveUsage {
                bytes: 7,
                records: 1
            }
        );
        assert_eq!(a.store(&pair()), Err(ArchiveError::Capacity));
        assert_eq!(fs::read(&pending).unwrap(), b"partial");
        assert!(matches!(
            a.load(ReportArchive::id_for(&pair()).unwrap(), &policy(), 0),
            Err(ArchiveError::Missing)
        ));
    }
}

#[test]
fn quota_inventory_refuses_foreign_symlink_directory_and_oversized_entries() {
    for kind in [
        "foreign",
        "symlink",
        "directory",
        "empty",
        "oversized",
        "insecure",
    ] {
        let t = Temp::new();
        let a = t.archive();
        let expected = a.store(&pair()).unwrap().id;
        let path = a.root.join(if kind == "foreign" {
            "foreign.backup".into()
        } else {
            format!("{}.json", "a".repeat(64))
        });
        match kind {
            "symlink" => symlink(a.path(expected), &path).unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            _ => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(if kind == "insecure" { 0o644 } else { 0o600 })
                    .open(&path)
                    .unwrap();
                f.write_all(if kind == "empty" { &[] } else { b"foreign" })
                    .unwrap();
                if kind == "oversized" {
                    f.set_len(MAX_RECORD as u64 + 1).unwrap();
                }
                if kind == "insecure" {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
        }
        assert!(a.usage().is_err(), "inventory must refuse {kind}");
        let mut reached = false;
        assert!(a
            .store_with_checkpoint(&polled_pair(NOW + 1), |_| {
                reached = true;
                Ok(())
            })
            .is_err());
        assert!(!reached);
        assert!(
            path.symlink_metadata().is_ok(),
            "foreign entry is preserved"
        );
        assert!(
            a.load(expected, &policy(), 0).is_ok(),
            "recovery load ignores quota inventory"
        );
    }
}

#[test]
fn uncertain_published_record_counts_at_quota_and_exact_retry_does_not_grow() {
    let t = Temp::new();
    let a = t
        .archive()
        .with_limits(ArchiveLimits {
            max_bytes: 1_000_000,
            max_records: 1,
        })
        .unwrap();
    let p = pair();
    let id = ReportArchive::id_for(&p).unwrap();
    assert_eq!(
        a.store_with_checkpoint(&p, |stage| {
            if stage == "published" {
                Err(ArchiveError::Io)
            } else {
                Ok(())
            }
        }),
        Err(ArchiveError::Io)
    );
    assert_eq!(a.usage().unwrap().records, 1);
    assert!(a.load(id, &policy(), 0).is_ok());
    assert_eq!(a.store(&polled_pair(NOW + 1)), Err(ArchiveError::Capacity));
    assert_eq!(a.store(&p).unwrap().id, id);
    assert_eq!(a.usage().unwrap().records, 1);
}

#[test]
fn inventory_scan_is_bounded_and_shared_handle_quota_is_serialized() {
    let t = Temp::new();
    let a = t
        .archive()
        .with_limits(ArchiveLimits {
            max_bytes: 1_000_000,
            max_records: 1,
        })
        .unwrap();
    for n in 0..67 {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(a.root.join(format!(".pending-{n}")))
            .unwrap();
    }
    assert_eq!(a.inventory_with_budget(66), Err(ArchiveError::Capacity));
    assert_eq!(
        a.usage().unwrap().records,
        67,
        "lowered quota does not hide retained inventory"
    );
    let t = Temp::new();
    let a = Arc::new(
        t.archive()
            .with_limits(ArchiveLimits {
                max_bytes: 1_000_000,
                max_records: 2,
            })
            .unwrap(),
    );
    let workers: Vec<_> = (0..8)
        .map(|n| {
            let a = a.clone();
            thread::spawn(move || a.store(&polled_pair(NOW + n)))
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert!(results
        .iter()
        .all(|result| result.is_ok() || *result == Err(ArchiveError::Capacity)));
    assert_eq!(a.usage().unwrap().records, 2);
}
#[test]
fn concurrent_equal_writes_converge_without_partial_or_duplicate_final_record() {
    let t = Temp::new();
    let a = Arc::new(t.archive());
    let mut workers = Vec::new();
    for _ in 0..4 {
        let a = a.clone();
        workers.push(thread::spawn(move || a.store(&pair()).unwrap()));
    }
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(results.iter().all(|r| r == &results[0]));
    assert_eq!(fs::read_dir(&a.root).unwrap().count(), 1);
    assert!(a.load(results[0].id, &policy(), 0).is_ok());
}
#[test]
fn record_contains_no_credential_or_authentication_headers() {
    let t = Temp::new();
    let a = t.archive();
    let id = a.store(&pair()).unwrap().id;
    let text = String::from_utf8(a.read_exact(id).unwrap()).unwrap();
    for secret in [
        crate::tests::USER,
        std::str::from_utf8(crate::tests::SECRET).unwrap(),
        "Authorization",
        "secret",
        "verified",
    ] {
        assert!(!text.contains(secret));
    }
    assert_eq!(fs::metadata(a.path(id)).unwrap().mode() & 0o777, 0o600);
}

// Subprocess fixture only; the parent asserts exit=77 at all four write stages.
#[test]
#[ignore = "fixture driver; invoked explicitly by owned process recovery test"]
fn owned_abrupt_exit_child() {
    let directory = std::env::var_os("ARCORA_ARCHIVE_TEST_DIR").expect("owned test directory");
    let path = PathBuf::from(directory).canonicalize().unwrap();
    assert!(path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("arcora-report-archive-tests-"));
    let stage = std::env::var("ARCORA_ARCHIVE_CRASH_STAGE").unwrap();
    assert!(["written", "file_synced", "published", "directory_synced"].contains(&stage.as_str()));
    let archive = ReportArchive::open_existing(&path.join("store")).unwrap();
    archive
        .store_with_checkpoint(&pair(), |at| {
            if at == stage {
                std::process::exit(77);
            }
            Ok(())
        })
        .unwrap();
    panic!("crash stage was not reached");
}
#[test]
fn real_process_abrupt_exit_and_reopen_never_substitutes_partial_records() {
    for stage in ["written", "file_synced", "published", "directory_synced"] {
        let t = Temp::new();
        let a = t.archive();
        let id = ReportArchive::id_for(&pair()).unwrap();
        drop(a);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "report_archive::tests::owned_abrupt_exit_child",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("ARCORA_ARCHIVE_TEST_DIR", t.0.canonicalize().unwrap())
            .env("ARCORA_ARCHIVE_CRASH_STAGE", stage)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "owned child failed before expected stage {stage}"
        );
        let a = ReportArchive::open_existing(&t.0.join("store")).unwrap();
        let leftovers = fs::read_dir(&a.root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".pending-"))
            .count();
        assert_eq!(
            leftovers, 1,
            "abrupt process exit must not run temporary destructor"
        );
        if ["written", "file_synced"].contains(&stage) {
            assert!(matches!(
                a.load(id, &policy(), 0),
                Err(ArchiveError::Missing)
            ));
        } else {
            let recovered = a.load(id, &policy(), 0).unwrap();
            assert_eq!(recovered.prepared_at_ms(), NOW);
            assert_eq!(recovered.base().full_report(), pair().base().full_report());
        }
        assert_eq!(a.store(&pair()).unwrap().id, id);
        assert_eq!(
            a.load(id, &policy(), 0).unwrap().quote().full_report(),
            pair().quote().full_report()
        );
    }
}
