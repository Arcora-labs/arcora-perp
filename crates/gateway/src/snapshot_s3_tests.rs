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
    assert!(execution::restore_snapshot(&mut gw, &trailer).is_err());
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

#[test]
fn s3_historical_writers_preserve_state_authority_and_replay() {
    for version in ["v5", "v6", "v7", "v8"] {
        let sealed = frozen(version, "sealed.bin");
        let plain = snapshot::open(&sealed, &[0xC3; 32]).unwrap();
        let mut gw = Gw::boot_restored(&plain).unwrap_or_else(|e| panic!("{version}: {e}"));
        let meta: serde_json::Value =
            serde_json::from_slice(&frozen(version, "meta.json")).unwrap();
        assert_eq!(
            hex0x(&gw.seq.state.state_root()),
            String::from_utf8(frozen(version, "root.txt")).unwrap(),
            "{version} native root"
        );
        assert_eq!(
            postcard::to_allocvec(&gw.seq.state).unwrap(),
            frozen(version, "state.bin"),
            "{version} full native state including nullifiers/notes"
        );
        assert_eq!(
            postcard::to_allocvec(&gw.accounts).unwrap(),
            frozen(version, "accounts.bin"),
            "{version} legacy account fields and authority"
        );
        assert_eq!(
            postcard::to_allocvec(&gw.pending_withdrawals).unwrap(),
            frozen(version, "withdrawals.bin"),
            "{version} pending withdrawals"
        );
        assert_eq!(
            gw.pending_withdrawals.len(),
            meta["pending_withdrawals"].as_u64().unwrap() as usize
        );
        assert!(!gw.seq.state.nullifiers.is_empty());
        assert!(gw.accounts.values().any(|a| !a.orders.is_empty()));
        if version == "v5" || version == "v6" {
            assert!(
                gw.accounts
                    .values()
                    .flat_map(|a| &a.orders)
                    .filter(|o| o.sealed)
                    .all(|o| !o.execution.as_ref().unwrap().known),
                "{version}: history must stay unavailable"
            );
        }
        if version != "v5" {
            assert_eq!(gw.deposits.routes.len(), 1);
            assert_eq!(gw.deposits.credits.len(), 1);
            assert_eq!(
                postcard::to_allocvec(&gw.deposits).unwrap(),
                frozen(version, "deposits.bin"),
                "{version} pending and consumed A01 routing"
            );
        }
        let upgrade = gw.snapshot_plain();
        let mut upgraded = Gw::boot_restored(&upgrade).unwrap();
        assert_eq!(
            upgraded.snapshot_plain(),
            upgrade,
            "{version} -> v9 is stable"
        );
        let key = parse_hex32(meta["replay_key"].as_str().unwrap()).unwrap();
        gw.account_cancel(&key, "o2").unwrap();
        upgraded.account_cancel(&key, "o2").unwrap();
        assert_eq!(
            gw.seq.state.state_root(),
            upgraded.seq.state.state_root(),
            "{version} cancellation replay root"
        );
        assert_eq!(
            postcard::to_allocvec(&gw.seq.state).unwrap(),
            postcard::to_allocvec(&upgraded.seq.state).unwrap()
        );
        let withdraw_key = parse_hex32(meta["withdraw_key"].as_str().unwrap()).unwrap();
        let owner = gw.accounts[&withdraw_key].wallet.owner;
        // Apply the exact same authenticated engine operation to both migrated
        // instances, including one fixed oracle timestamp/signature. This changes
        // native collateral and unspent notes, rather than only comparing decode.
        let now = now_ms();
        let op = BatchOp::Unbind {
            owner,
            market_id: 0,
            amount: 100 * QUOTE_SCALE,
            blinding: [0xA8; 32],
            oracle: oracle_of(gw.px_of(0), now, 0, &gw.oracle_signer),
            now_ms: now,
        };
        gw.seq.apply(&op).unwrap();
        upgraded.seq.apply(&op).unwrap();
        assert_eq!(
            gw.seq.state.state_root(),
            upgraded.seq.state.state_root(),
            "{version} collateral/note operation replay root"
        );
        assert_eq!(
            postcard::to_allocvec(&gw.seq.state).unwrap(),
            postcard::to_allocvec(&upgraded.seq.state).unwrap()
        );
        assert!(gw.seq.state.conservation_holds());
        let witness = gw.seq.seal_window();
        let replayed = perp_core::commitment::derive_roots(
            &mut witness.pre_state.clone(),
            &witness.ops,
            &witness.manifest,
        )
        .unwrap();
        assert_eq!(
            replayed.new_state_root,
            gw.seq.state.state_root(),
            "{version} native proof-program replay"
        );
        let nonce = if version == "v8" { 7 } else { 0 };
        assert_eq!(gw.accounts[&withdraw_key].recovery_nonce, nonce);
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x51; 32]).unwrap();
        let d = digest(gw.chain_id, &gw.vault, &owner, nonce);
        let (sig, recovery) = sk.sign_prehash_recoverable(&d).unwrap();
        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&sig.to_bytes());
        signature[64] = recovery.to_byte() + 27;
        let new_key = gw.recover_account(owner, nonce, &signature).unwrap();
        assert_eq!(gw.accounts[&new_key].recovery_nonce, nonce + 1);
        assert!(!gw.accounts.contains_key(&withdraw_key));
        let after = gw.snapshot_plain();
        assert!(gw.recover_account(owner, nonce, &signature).is_err());
        assert!(gw.snapshot_plain() == after);
        assert_eq!(
            Gw::boot_restored(&after).unwrap().accounts[&new_key].recovery_nonce,
            nonce + 1
        );
        println!("S3_MIGRATION {version} state/root/accounts/withdrawals/replay/authority PASS");
    }
}

#[test]
fn s3_authenticated_parser_mutation_budget() {
    let plain = snapshot::open(&frozen("v8", "sealed.bin"), &[0xC3; 32]).unwrap();
    let canonical = Gw::boot_restored(&plain).unwrap().snapshot_plain();
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
        // Each malformed attempt must leave the previously established fixture
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
    let sealed = frozen("v8", "sealed.bin");
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
    for version in *b"D45679" {
        let mut input = sealed.clone();
        input[6] = version;
        assert!(snapshot::open(&input, &[0xC3; 32]).is_err());
        tested += 1;
    }
    println!(
        "S3_ENVELOPE negative_vectors={} wrong_seed=true",
        tested + 1
    );
}
