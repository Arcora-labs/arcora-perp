//! S3 local-only parser/migration vectors. All keys and accounts are synthetic.
use super::*;

fn with_order() -> Gw {
    let mut gw = Gw::boot();
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
    gw.account_place_order(
        &key,
        &OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: gw.px_of(0).to_string(),
            tif: "Gtc".into(),
            ..Default::default()
        },
    )
    .unwrap();
    gw
}

#[test]
fn s3_marker_inside_execution_payload_is_not_a_delimiter() {
    let mut gw = with_order();
    let order = &mut gw.accounts.values_mut().next().unwrap().orders[0];
    // Digests are arbitrary bytes; marker-like bytes cannot delimit their record.
    order.order_hash[..EXT.len()].copy_from_slice(EXT);
    order.execution.as_mut().unwrap().reason = Some("payload DPRECOV1 marker".into());
    let plain = gw.snapshot_plain();
    let restored = Gw::boot_restored(&plain);
    assert!(
        restored.is_ok(),
        "valid framed snapshot rejected: {:?}",
        restored.err()
    );
    assert_eq!(Gw::boot_restored(&plain).unwrap().snapshot_plain(), plain);
}

#[test]
fn s3_recovery_error_preserves_existing_state() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    gw.register_account(None);
    gw.register_account(None);
    for a in gw.accounts.values_mut() {
        a.recovery_nonce = 91;
    }
    let owners: Vec<_> = gw.accounts.values().map(|a| a.wallet.owner).collect();
    let before = gw.snapshot_plain();
    for rows in [
        vec![(owners[0], 123)],
        vec![(owners[0], 123), (owners[1], 124), ([0xEE; 32], 125)],
        vec![(owners[0], 123), (owners[0], 124)],
    ] {
        let mut trailer = EXT.to_vec();
        trailer.extend(postcard::to_allocvec(&rows).unwrap());
        assert!(restore(&mut gw, &trailer).is_err());
        assert_eq!(
            gw.snapshot_plain(),
            before,
            "rejected recovery extension mutated state"
        );
    }
}

#[test]
fn s3_execution_error_preserves_existing_state() {
    let mut gw = with_order();
    let before = gw.snapshot_plain();
    let order = &gw.accounts.values().next().unwrap().orders[0];
    let mut replacement = order.execution.clone();
    replacement.as_mut().unwrap().reason = Some("changed before orphan error".into());
    let rows = vec![
        (order.order_hash, replacement),
        ([0xEE; 32], Some(execution::Execution::new(1))),
    ];
    let mut trailer = b"DPEXEC2\0".to_vec();
    trailer.extend(postcard::to_allocvec(&rows).unwrap());
    assert!(execution::restore_snapshot_prefix(&mut gw, &trailer).is_err());
    assert_eq!(
        gw.snapshot_plain(),
        before,
        "rejected execution extension mutated state"
    );
}

#[test]
fn s3_file_limits_and_failed_write_preserve_durable_target() {
    let dir = std::env::temp_dir().join(format!(
        "arcora-s3-file-{}-{}",
        std::process::id(),
        hex0x(&csprng_bytes32())
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("state");
    let gw = with_order();
    let plain = gw.snapshot_plain();
    let sealed = snapshot::seal(&plain, &[0xC3; 32]);
    snapshot::write_atomic(&path, &sealed).unwrap();
    assert_eq!(snapshot::read_file(&path).unwrap(), sealed);
    let too_large = vec![0; snapshot::MAX_SEALED_BYTES + 1];
    assert!(snapshot::open(&too_large, &[0xC3; 32])
        .unwrap_err()
        .contains("limit"));
    assert_eq!(
        snapshot::write_atomic(&path, &too_large)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        snapshot::read_file(&path).unwrap(),
        sealed,
        "size rejection must precede destination mutation"
    );
    let large_path = dir.join("oversized");
    let sparse = std::fs::File::create(&large_path).unwrap();
    sparse
        .set_len(snapshot::MAX_SEALED_BYTES as u64 + 1)
        .unwrap();
    assert_eq!(
        snapshot::read_file(&large_path).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        sparse.metadata().unwrap().len(),
        snapshot::MAX_SEALED_BYTES as u64 + 1
    );
    let directory_target = dir.join("directory-target");
    std::fs::create_dir(&directory_target).unwrap();
    assert!(snapshot::write_atomic(&directory_target, b"rename must fail").is_err());
    assert!(snapshot::write_atomic(&dir.join("missing/state"), b"missing parent").is_err());
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        3,
        "failed write cleans only its exclusive temporary file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        Gw::boot_restored(
            &snapshot::open(&snapshot::read_file(&path).unwrap(), &[0xC3; 32]).unwrap()
        )
        .unwrap()
        .snapshot_plain(),
        plain
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn s3_recovery_legacy_absence_cannot_downgrade_existing_generation() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().recovery_nonce = 9;
    let before = gw.snapshot_plain();
    assert!(
        restore(&mut gw, &[]).is_err(),
        "legacy absence must not reset an existing generation"
    );
    assert_eq!(gw.snapshot_plain(), before);
}

fn frozen(version: &str, name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/snapshots")
            .join(version)
            .join(name),
    )
    .unwrap()
}

/// The frozen files the v5-v8 writers produced are refused: the envelope reader
/// accepts only DPSNAP10, so not even their authentication is attempted, and their
/// payloads are no layout this gateway decodes.
#[test]
fn s3_historical_writers_are_refused() {
    for (version, magic) in [
        ("v5", b"DPSNAP5\0"),
        ("v6", b"DPSNAP6\0"),
        ("v7", b"DPSNAP7\0"),
        ("v8", b"DPSNAP8\0"),
    ] {
        let sealed = frozen(version, "sealed.bin");
        assert_eq!(
            &sealed[..8],
            magic,
            "{version} is the genuine historical file"
        );
        let error = snapshot::open(&sealed, &[0xC3; 32]).unwrap_err();
        assert!(error.contains("DPSNAP10"), "{version}: {error}");
        // The same bytes under the current header fail authentication.
        let mut relabelled = sealed.clone();
        relabelled[..8].copy_from_slice(b"DPSNAP10");
        assert!(
            snapshot::open(&relabelled, &[0xC3; 32]).is_err(),
            "{version}"
        );
    }
}

/// A v10 payload with orders, a deposit, a pending withdrawal, recovery
/// generations and a resting order: every layer and extension is populated.
fn rich() -> Vec<u8> {
    let mut gw = with_order();
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 1, 2_000 * QUOTE_SCALE).unwrap();
    for (i, a) in gw.accounts.values_mut().enumerate() {
        a.recovery_nonce = 3 + i as u64;
    }
    gw.pending_withdrawals.push(Withdrawal {
        owner: [0x5a; 32],
        to: [0x5b; 20],
        amount: 7,
        nonce: 9,
    });
    gw.snapshot_plain()
}

#[test]
fn s3_authenticated_parser_mutation_budget() {
    let plain = rich();
    let canonical = Gw::boot_restored(&plain).unwrap().snapshot_plain();
    assert_eq!(canonical, plain);
    let mut inputs: Vec<(String, Vec<u8>, bool)> = Vec::new();
    let cut_step = (plain.len() / 128).max(1);
    for cut in (0..plain.len())
        .step_by(cut_step)
        .chain(plain.len().saturating_sub(64)..plain.len())
    {
        inputs.push((format!("truncated-{cut}"), plain[..cut].to_vec(), true));
    }
    let exec = plain.windows(8).position(|w| w == b"DPEXEC2\0").unwrap();
    let recovery = plain.windows(8).rposition(|w| w == EXT).unwrap();
    for boundary in [exec, recovery] {
        let mut huge = plain.clone();
        huge.splice(boundary + 8..boundary + 9, [0xff; 10]);
        inputs.push((format!("oversized-count-{boundary}"), huge, true));
        let mut duplicate = plain.clone();
        duplicate.extend_from_slice(&plain[boundary..]);
        inputs.push((format!("duplicate-{boundary}"), duplicate, true));
        let mut unknown = plain.clone();
        unknown[boundary] ^= 0x20;
        inputs.push((format!("unknown-extension-{boundary}"), unknown, true));
    }
    let mut swapped = plain[..exec].to_vec();
    swapped.extend_from_slice(&plain[recovery..]);
    swapped.extend_from_slice(&plain[exec..recovery]);
    inputs.push(("swapped-extensions".into(), swapped, true));
    let mut trailing = plain.clone();
    trailing.push(0);
    inputs.push(("trailing-byte".into(), trailing, true));
    for at in 0..=snapshot::PAYLOAD_MAGIC.len() {
        let mut header = plain.clone();
        header[at] ^= if at == snapshot::PAYLOAD_MAGIC.len() {
            0x02
        } else {
            0x01
        };
        inputs.push((format!("header-{at}"), header, true));
    }
    let mut rng = 0xA07_20260927u64;
    for iteration in 0..512 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let mut mutated = plain.clone();
        let at = rng as usize % mutated.len();
        mutated[at] ^= ((rng >> 32) as u8).max(1);
        inputs.push((format!("seeded-mutation-{iteration}"), mutated, false));
    }
    let mut rejected = 0;
    let mut accepted = 0;
    for (name, input, must_reject) in &inputs {
        // A real test-only seal reaches authenticated inner parsing. Production
        // authentication remains active and verifies the identical input bytes.
        let sealed = snapshot::seal(input, &[0xC3; 32]);
        let authenticated = snapshot::open(&sealed, &[0xC3; 32]).unwrap();
        assert_eq!(&authenticated, input);
        let result = std::panic::catch_unwind(|| Gw::boot_restored(&authenticated));
        assert!(result.is_ok(), "panic for {name}");
        match result.unwrap() {
            Err(_) => rejected += 1,
            Ok(restored) => {
                assert!(!must_reject, "malformed case accepted: {name}");
                accepted += 1;
                let replay = restored.snapshot_plain();
                let again = Gw::boot_restored(&replay).unwrap();
                assert_eq!(
                    restored.seq.state.state_root(),
                    again.seq.state.state_root()
                );
            }
        }
        // Each malformed attempt must leave the previously established payload
        // independently loadable; boot returns ownership only after full success.
        assert_eq!(
            Gw::boot_restored(&plain).unwrap().snapshot_plain(),
            canonical
        );
        if *must_reject {
            if let Ok(directory) = std::env::var("S3_CAPTURE_CORPUS") {
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(
                    std::path::Path::new(&directory).join(format!("{name}.bin")),
                    input,
                )
                .unwrap();
            }
        }
    }
    println!("S3_FUZZ seed=0xA0720260927 inputs={} rejected={rejected} accepted={accepted} max_input={} authenticated_inner=true",inputs.len(),inputs.iter().map(|(_,b,_)|b.len()).max().unwrap());
}

#[test]
fn s3_envelope_mutations_wrong_seed_and_versions_are_rejected() {
    let sealed = snapshot::seal(&rich(), &[0xC3; 32]);
    assert!(snapshot::open(&sealed, &[0xC3; 32]).is_ok());
    let mut tested = 0;
    for index in (0..sealed.len())
        .step_by((sealed.len() / 128).max(1))
        .chain(0..72)
    {
        let mut input = sealed.clone();
        input[index] ^= 1;
        assert!(
            snapshot::open(&input, &[0xC3; 32]).is_err(),
            "outer mutation byte {index}"
        );
        tested += 1;
    }
    for length in [0, 1, 7, 8, 39, 40, 71, sealed.len() - 1] {
        assert!(snapshot::open(&sealed[..length], &[0xC3; 32]).is_err());
        tested += 1;
    }
    assert!(snapshot::open(&sealed, &[0xC4; 32]).is_err());
    for version in [&b"9\0"[..], b"11", b"00", b"1\0", b"01"] {
        let mut input = sealed.clone();
        input[6..8].copy_from_slice(version);
        assert!(snapshot::open(&input, &[0xC3; 32]).is_err());
        tested += 1;
    }
    println!(
        "S3_ENVELOPE negative_vectors={} wrong_seed=true",
        tested + 1
    );
}
