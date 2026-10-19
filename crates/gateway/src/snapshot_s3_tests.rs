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

/// The public test key every frozen snapshot fixture is sealed under.
const FIXTURE_SEED: [u8; 32] = [0xC3; 32];

/// The public test key behind the fixture's signed withdrawal and recovery.
const FIXTURE_AUTHORIZER: [u8; 32] = [0x51; 32];

/// The recovery generation the fixture records for its signing account.
const FIXTURE_RECOVERY_NONCE: u64 = 7;

/// The wind-down recipient bound into the fixture's genesis.
const FIXTURE_RECIPIENT: [u8; 20] = [0x77; 20];

/// What `snapshot::open` returns for any envelope that is not DPSNAP10.
const ENVELOPE_REFUSED: &str = "snapshot magic/version mismatch (this gateway reads only DPSNAP10)";

/// What `Gw::boot_restored` returns for a payload without the v10 header.
const PAYLOAD_REFUSED: &str =
    "snapshot payload is not the v10 gateway state layout; earlier layouts are not read";

fn fixture_dir(version: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/snapshots")
        .join(version)
}

fn frozen(version: &str, name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir(version).join(name)).unwrap()
}

/// The committed v10 file and the payload it authenticates.
fn frozen_v10() -> (Vec<u8>, Vec<u8>) {
    let sealed = frozen("v10", "sealed.bin");
    let plain = snapshot::open(&sealed, &FIXTURE_SEED).unwrap();
    (sealed, plain)
}

/// The frozen files the v5-v9 writers produced are refused by their envelope magic
/// alone: the reader accepts only DPSNAP10, so it neither authenticates nor decrypts
/// them, and the same bytes under the current header fail authentication. The v9
/// rollback journal shares the envelope and is refused the same way.
#[test]
fn s3_historical_writers_are_refused() {
    for (version, file, magic, seed) in [
        ("v5", "sealed.bin", b"DPSNAP5\0", FIXTURE_SEED),
        ("v6", "sealed.bin", b"DPSNAP6\0", FIXTURE_SEED),
        ("v7", "sealed.bin", b"DPSNAP7\0", FIXTURE_SEED),
        ("v8", "sealed.bin", b"DPSNAP8\0", FIXTURE_SEED),
        ("v9", "state.snapshot", b"DPSNAP9\0", [0x65; 32]),
        ("v9", "state.snapshot.rollback", b"DPSNAP9\0", [0x65; 32]),
    ] {
        let sealed = frozen(version, file);
        assert_eq!(
            &sealed[..8],
            magic,
            "{version}/{file} is the genuine historical file"
        );
        assert_eq!(
            snapshot::open(&sealed, &seed).unwrap_err(),
            ENVELOPE_REFUSED,
            "{version}/{file}"
        );
        let mut relabelled = sealed.clone();
        relabelled[..8].copy_from_slice(b"DPSNAP10");
        assert_eq!(
            snapshot::open(&relabelled, &seed).unwrap_err(),
            "snapshot authentication failed (wrong seed or tampered file)",
            "{version}/{file}"
        );
    }
    let journal = frozen("v9", "state.snapshot.rollback");
    assert_eq!(
        crate::rollback_journal::open(&journal, &[0x65; 32]).err(),
        Some(format!("journal open: {ENVELOPE_REFUSED}"))
    );
}

/// The Ethereum address of a fixture signing key.
fn signer_address(key: &k256::ecdsa::SigningKey) -> [u8; 20] {
    use sha3::Digest as _;
    let point = key.verifying_key().to_encoded_point(false);
    let hash = sha3::Keccak256::digest(&point.as_bytes()[1..]);
    hash[12..].try_into().unwrap()
}

/// A 65-byte `r ‖ s ‖ v` signature over a prehashed digest.
fn sign_prehash(key: &k256::ecdsa::SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    let (signature, recovery) = key.sign_prehash_recoverable(digest).unwrap();
    let mut wire = [0; 65];
    wire[..64].copy_from_slice(&signature.to_bytes());
    wire[64] = recovery.to_byte() + 27;
    wire
}

/// The state the v10 writer froze, with every layer of the payload populated: a
/// filled and a resting order, demo collateral, a routed L1 deposit credited through
/// the ingestion path and one permit still outstanding, a signed pending withdrawal,
/// recovery generations on both accounts and a bound wind-down recipient.
fn v10_fixture_state() -> (Gw, serde_json::Value) {
    let mut gw = Gw::boot_genesis(GenesisMode::Demo, FIXTURE_RECIPIENT);
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
    for (size, limit_price) in [
        (SIZE_SCALE / 10, gw.px_of(0)),
        (SIZE_SCALE / 20, gw.px_of(0) / 2),
    ] {
        gw.account_place_order(
            &key,
            &OrderReq {
                market_id: 0,
                side: "Buy".into(),
                size: size.to_string(),
                limit_price: limit_price.to_string(),
                tif: "Gtc".into(),
                ..Default::default()
            },
        )
        .unwrap();
        gw.tick();
    }

    let authorizer = k256::ecdsa::SigningKey::from_slice(&FIXTURE_AUTHORIZER).unwrap();
    let payer = signer_address(&authorizer);
    let (withdraw_key, owner) = gw.register_account(Some(payer));
    gw.account_deposit(&withdraw_key, 0, 20_000 * QUOTE_SCALE)
        .unwrap();
    let amount = 5_000 * QUOTE_SCALE;
    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &[7; 20], 1);
    gw.account_withdraw(
        &withdraw_key,
        0,
        amount,
        [7; 20],
        1,
        &sign_prehash(&authorizer, &digest),
    )
    .unwrap();

    let from = [0x44; 20];
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(from);
    let commit = gw
        .authorize_routed_deposit(
            &key,
            from,
            5_000_000,
            0,
            deposit_ingestion::Purpose::Collateral,
            u64::MAX,
        )
        .unwrap();
    let start = gw.deposit_cursor();
    let block = crate::deposit_rpc::Block {
        number: 42,
        hash: [0x42; 32],
        timestamp: None,
    };
    let event = crate::deposit_rpc::Event {
        id: start.count,
        from,
        commit,
        amount: 5_000_000,
        tip: perp_core::merkle::deposit_chain_fold(
            &start.tip,
            &perp_core::merkle::deposit_leaf(&from, &commit, 5_000_000, start.count),
        ),
        tx: [0x89; 32],
        tx_index: 0,
        log_index: 0,
        block: block.clone(),
    };
    let page = crate::deposit_rpc::Page {
        start,
        end: block,
        events: vec![event],
    };
    assert_eq!(gw.apply_deposit_page(page).unwrap(), 1);
    gw.authorize_routed_deposit(
        &key,
        from,
        7_000_000,
        1,
        deposit_ingestion::Purpose::Collateral,
        u64::MAX,
    )
    .unwrap();

    gw.accounts.get_mut(&key).unwrap().recovery_nonce = 3;
    gw.accounts.get_mut(&withdraw_key).unwrap().recovery_nonce = FIXTURE_RECOVERY_NONCE;
    gw.validate_deposit_state().unwrap();
    let meta = serde_json::json!({
        "schema": "arcora-public-snapshot-fixture/v10",
        "synthetic_public_fixture": true,
        "accounts": gw.accounts.len(),
        "orders": gw.accounts.values().map(|a| a.orders.len()).sum::<usize>(),
        "pending_withdrawals": gw.pending_withdrawals.len(),
        "nullifiers": gw.seq.state.nullifiers.len(),
        "deposit_credits": gw.deposits.credits.len(),
        "outstanding_permits": gw.deposits.routes.len(),
        "plain_bytes": gw.snapshot_plain().len(),
        "replay_key": hex0x(&key),
        "withdraw_key": hex0x(&withdraw_key),
        "recovery_owner": hex0x(&owner),
        "recovery_authorizer": hex0x(&payer),
        "recovery_nonce": FIXTURE_RECOVERY_NONCE,
        "wind_down_recipient": hex0x(&FIXTURE_RECIPIENT),
        "scope": "Synthetic accounts and receipts under public test keys; never operational data or funds.",
    });
    (gw, meta)
}

/// The fixed malformed corpus of the frozen v10 file, keyed by file stem. It is a
/// pure function of the committed `sealed.bin` and the payload it authenticates.
/// `sealed-*` cases are envelopes `snapshot::open` must refuse. Every other case is
/// a payload a genuine writer could have sealed, which `Gw::boot_restored` must
/// refuse after authentication: truncations, oversized counts, repeated, unknown
/// and reordered extensions, a trailing byte, a flipped payload header or flag,
/// and an earlier, later, missing or journal header in place of the current one.
fn malformed_corpus(sealed: &[u8], plain: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut cases = std::collections::BTreeMap::new();
    let cut_step = (plain.len() / 128).max(1);
    for cut in (0..plain.len())
        .step_by(cut_step)
        .chain(plain.len().saturating_sub(64)..plain.len())
    {
        cases.insert(format!("truncated-{cut}"), plain[..cut].to_vec());
    }
    let exec = plain.windows(8).position(|w| w == b"DPEXEC2\0").unwrap();
    let recovery = plain.windows(8).rposition(|w| w == EXT).unwrap();
    for boundary in [exec, recovery] {
        let mut huge = plain.to_vec();
        huge.splice(boundary + 8..boundary + 9, [0xff; 10]);
        cases.insert(format!("oversized-count-{boundary}"), huge);
        let mut duplicate = plain.to_vec();
        duplicate.extend_from_slice(&plain[boundary..]);
        cases.insert(format!("duplicate-{boundary}"), duplicate);
        let mut unknown = plain.to_vec();
        unknown[boundary] ^= 0x20;
        cases.insert(format!("unknown-extension-{boundary}"), unknown);
    }
    let mut swapped = plain[..exec].to_vec();
    swapped.extend_from_slice(&plain[recovery..]);
    swapped.extend_from_slice(&plain[exec..recovery]);
    cases.insert("swapped-extensions".into(), swapped);
    let mut trailing = plain.to_vec();
    trailing.push(0);
    cases.insert("trailing-byte".into(), trailing);
    for at in 0..=snapshot::PAYLOAD_MAGIC.len() {
        let mut header = plain.to_vec();
        header[at] ^= if at == snapshot::PAYLOAD_MAGIC.len() {
            0x02
        } else {
            0x01
        };
        cases.insert(format!("header-{at}"), header);
    }
    let body = &plain[snapshot::PAYLOAD_MAGIC.len()..];
    for (name, header) in [
        ("payload-magic-v6", &b"\xffDPA01-SNAPSHOT-v6\0"[..]),
        ("payload-magic-v7", b"\xffDPA05-SNAPSHOT-v7\0"),
        ("payload-magic-v8", b"\xffDPA07-SNAPSHOT-v8\0"),
        ("payload-magic-v9", b"\xffDP-WIND-DOWN-v9\0"),
        ("payload-magic-v11", b"\xffDP-GATEWAY-STATE-v11\0"),
        ("payload-magic-none", b""),
        ("payload-magic-journal", b"DPRBJL7\0"),
    ] {
        cases.insert(name.into(), [header, body].concat());
    }

    for length in [0, 1, 7, 8, 39, 40, 71, 72, sealed.len() - 1] {
        cases.insert(
            format!("sealed-truncated-{length}"),
            sealed[..length].to_vec(),
        );
    }
    for at in 0..8 {
        let mut flipped = sealed.to_vec();
        flipped[at] ^= 0x01;
        cases.insert(format!("sealed-magic-flip-{at}"), flipped);
    }
    for (name, magic) in [
        ("sealed-magic-v5", b"DPSNAP5\0"),
        ("sealed-magic-v6", b"DPSNAP6\0"),
        ("sealed-magic-v7", b"DPSNAP7\0"),
        ("sealed-magic-v8", b"DPSNAP8\0"),
        ("sealed-magic-v9", b"DPSNAP9\0"),
    ] {
        let mut relabelled = sealed.to_vec();
        relabelled[..8].copy_from_slice(magic);
        cases.insert(name.into(), relabelled);
    }
    let mut trailing = sealed.to_vec();
    trailing.push(0);
    cases.insert("sealed-trailing-byte".into(), trailing);
    for (name, at) in [
        ("sealed-nonce-flip", 8),
        ("sealed-tag-flip", 40),
        ("sealed-ciphertext-flip-first", 72),
        ("sealed-ciphertext-flip-last", sealed.len() - 1),
    ] {
        let mut flipped = sealed.to_vec();
        flipped[at] ^= 0x01;
        cases.insert(name.into(), flipped);
    }
    cases
}

/// Write the corpus as `<stem>.bin` files into a new directory.
fn write_corpus(directory: &std::path::Path, sealed: &[u8], plain: &[u8]) {
    std::fs::create_dir_all(directory).unwrap();
    for (name, bytes) in malformed_corpus(sealed, plain) {
        std::fs::write(directory.join(format!("{name}.bin")), bytes).unwrap();
    }
}

/// Produces `testdata/snapshots/v10` (the files and `malformed/`) into a new
/// directory. Account keys, timestamps, the order-log and note-archive sealing and
/// the envelope nonce are fresh on every run, so a new export never reproduces the
/// committed bytes; the committed files are the fixture.
#[test]
#[ignore = "explicit export of the public synthetic v10 snapshot fixture into a new directory"]
fn export_v10_snapshot_fixture() {
    let output = std::path::PathBuf::from(
        std::env::var_os("ARCORA_SNAPSHOT_V10_EXPORT").expect("explicit new fixture directory"),
    );
    std::fs::create_dir(&output).expect("export requires a new directory");
    let (gw, meta) = v10_fixture_state();
    let plain = gw.snapshot_plain();
    assert_eq!(Gw::boot_restored(&plain).unwrap().snapshot_plain(), plain);
    let sealed = snapshot::seal(&plain, &FIXTURE_SEED);
    for (name, bytes) in [
        ("sealed.bin", sealed.clone()),
        ("plain.bin", plain.clone()),
        ("state.bin", postcard::to_allocvec(&gw.seq.state).unwrap()),
        ("accounts.bin", postcard::to_allocvec(&gw.accounts).unwrap()),
        (
            "withdrawals.bin",
            postcard::to_allocvec(&gw.pending_withdrawals).unwrap(),
        ),
        ("deposits.bin", postcard::to_allocvec(&gw.deposits).unwrap()),
        ("root.txt", hex0x(&gw.seq.state.state_root()).into_bytes()),
        ("meta.json", serde_json::to_vec_pretty(&meta).unwrap()),
    ] {
        std::fs::write(output.join(name), bytes).unwrap();
    }
    write_corpus(&output.join("malformed"), &sealed, &plain);
    println!("SNAPSHOT_V10_EXPORT {}", output.display());
}

/// The committed v10 file authenticates to the committed payload, which restores
/// into exactly the committed engine state, accounts, withdrawals and deposit
/// ledger and re-encodes byte for byte. The restored state then replays its open
/// window natively and honours the recorded recovery generation.
#[test]
fn s3_v10_frozen_writer_restores_exactly() {
    let (sealed, plain) = frozen_v10();
    assert_eq!(&sealed[..8], b"DPSNAP10");
    assert_eq!(plain, frozen("v10", "plain.bin"));
    assert!(plain.starts_with(snapshot::PAYLOAD_MAGIC));
    let mut gw = Gw::boot_restored(&plain).unwrap();
    assert_eq!(gw.snapshot_plain(), plain, "byte-exact re-encoding");
    let meta: serde_json::Value = serde_json::from_slice(&frozen("v10", "meta.json")).unwrap();
    assert_eq!(meta["schema"], "arcora-public-snapshot-fixture/v10");
    assert_eq!(meta["plain_bytes"].as_u64(), Some(plain.len() as u64));
    assert_eq!(
        hex0x(&gw.seq.state.state_root()),
        String::from_utf8(frozen("v10", "root.txt")).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&gw.seq.state).unwrap(),
        frozen("v10", "state.bin"),
        "engine state including notes, nullifiers and funding"
    );
    assert_eq!(
        postcard::to_allocvec(&gw.accounts).unwrap(),
        frozen("v10", "accounts.bin")
    );
    assert_eq!(
        postcard::to_allocvec(&gw.pending_withdrawals).unwrap(),
        frozen("v10", "withdrawals.bin")
    );
    assert_eq!(
        postcard::to_allocvec(&gw.deposits).unwrap(),
        frozen("v10", "deposits.bin")
    );
    for (field, value) in [
        ("accounts", gw.accounts.len()),
        (
            "orders",
            gw.accounts.values().map(|a| a.orders.len()).sum::<usize>(),
        ),
        ("pending_withdrawals", gw.pending_withdrawals.len()),
        ("nullifiers", gw.seq.state.nullifiers.len()),
        ("deposit_credits", gw.deposits.credits.len()),
        ("outstanding_permits", gw.deposits.routes.len()),
    ] {
        assert_eq!(meta[field].as_u64(), Some(value as u64), "{field}");
        assert!(value > 0, "{field} is populated");
    }
    assert_eq!(gw.seq.state.wind_down_recipient, FIXTURE_RECIPIENT);
    assert!(!gw.wind_down_started);

    // The same cancellation on two restored copies reaches the same state, and
    // the open window replays through the proof program to the restored root.
    let key = parse_hex32(meta["replay_key"].as_str().unwrap()).unwrap();
    let resting = gw.accounts[&key].orders.last().unwrap().id.clone();
    let mut again = Gw::boot_restored(&plain).unwrap();
    gw.account_cancel(&key, &resting).unwrap();
    again.account_cancel(&key, &resting).unwrap();
    assert_eq!(
        postcard::to_allocvec(&gw.seq.state).unwrap(),
        postcard::to_allocvec(&again.seq.state).unwrap()
    );
    assert!(gw.seq.state.conservation_holds());
    let witness = gw.seq.seal_window();
    let replayed = perp_core::commitment::derive_roots(
        &mut witness.pre_state.clone(),
        &witness.ops,
        &witness.manifest,
    )
    .unwrap();
    assert_eq!(replayed.new_state_root, gw.seq.state.state_root());

    // The recorded recovery generation authorizes exactly one recovery.
    let withdraw_key = parse_hex32(meta["withdraw_key"].as_str().unwrap()).unwrap();
    let owner = gw.accounts[&withdraw_key].wallet.owner;
    assert_eq!(
        gw.accounts[&withdraw_key].recovery_nonce,
        FIXTURE_RECOVERY_NONCE
    );
    let authorizer = k256::ecdsa::SigningKey::from_slice(&FIXTURE_AUTHORIZER).unwrap();
    assert_eq!(
        meta["recovery_authorizer"],
        hex0x(&signer_address(&authorizer))
    );
    let signature = sign_prehash(
        &authorizer,
        &digest(gw.chain_id, &gw.vault, &owner, FIXTURE_RECOVERY_NONCE),
    );
    let new_key = gw
        .recover_account(owner, FIXTURE_RECOVERY_NONCE, &signature)
        .unwrap();
    assert_eq!(
        gw.accounts[&new_key].recovery_nonce,
        FIXTURE_RECOVERY_NONCE + 1
    );
    let after = gw.snapshot_plain();
    assert!(gw
        .recover_account(owner, FIXTURE_RECOVERY_NONCE, &signature)
        .is_err());
    assert_eq!(gw.snapshot_plain(), after);
    println!(
        "S3_V10_FIXTURE plain_bytes={} restore/re-encode/replay/recovery PASS",
        plain.len()
    );
}

/// The committed corpus is exactly the derivation of the committed v10 file (no
/// case missing, added or edited), and every case is refused at its own layer.
#[test]
fn s3_v10_malformed_corpus_is_exact_and_refused() {
    let (sealed, plain) = frozen_v10();
    let expected = malformed_corpus(&sealed, &plain);
    let mut committed = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(fixture_dir("v10").join("malformed")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        let stem = name.strip_suffix(".bin").expect("corpus files are .bin");
        committed.insert(stem.to_string(), std::fs::read(&path).unwrap());
    }
    assert_eq!(
        committed.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    let (mut envelopes, mut payloads) = (0, 0);
    for (name, input) in &committed {
        assert_eq!(input, &expected[name], "{name} differs from its derivation");
        if name.starts_with("sealed-") {
            let error = snapshot::open(input, &FIXTURE_SEED).unwrap_err();
            let short = name
                .strip_prefix("sealed-truncated-")
                .is_some_and(|length| length.parse::<usize>().unwrap() < 72);
            let refused = if short {
                "snapshot too short"
            } else if name.starts_with("sealed-magic-") {
                ENVELOPE_REFUSED
            } else {
                "snapshot authentication failed (wrong seed or tampered file)"
            };
            assert_eq!(error, refused, "{name}");
            envelopes += 1;
        } else {
            let authenticated =
                snapshot::open(&snapshot::seal(input, &FIXTURE_SEED), &FIXTURE_SEED).unwrap();
            let result = std::panic::catch_unwind(|| Gw::boot_restored(&authenticated));
            let Err(error) = result.unwrap_or_else(|_| panic!("panic for {name}")) else {
                panic!("malformed case accepted: {name}");
            };
            let header = name
                .strip_prefix("header-")
                .map(|at| at.parse::<usize>().unwrap());
            if name.starts_with("payload-magic-")
                || header.is_some_and(|at| at < snapshot::PAYLOAD_MAGIC.len())
            {
                assert_eq!(error, PAYLOAD_REFUSED, "{name}");
            } else if header.is_some() {
                assert_eq!(error, "invalid wind-down snapshot flag", "{name}");
            }
            payloads += 1;
        }
    }
    println!("S3_V10_CORPUS payload_cases={payloads} envelope_cases={envelopes} refused=all");
}

#[test]
fn s3_authenticated_parser_mutation_budget() {
    let (sealed, plain) = frozen_v10();
    let canonical = Gw::boot_restored(&plain).unwrap().snapshot_plain();
    assert_eq!(canonical, plain);
    let mut inputs: Vec<(String, Vec<u8>, bool)> = malformed_corpus(&sealed, &plain)
        .into_iter()
        .filter(|(name, _)| !name.starts_with("sealed-"))
        .map(|(name, input)| (name, input, true))
        .collect();
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
        let sealed = snapshot::seal(input, &FIXTURE_SEED);
        let authenticated = snapshot::open(&sealed, &FIXTURE_SEED).unwrap();
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
        // Each malformed attempt must leave the frozen payload independently
        // loadable; boot returns ownership only after full success.
        assert_eq!(
            Gw::boot_restored(&plain).unwrap().snapshot_plain(),
            canonical
        );
    }
    // Recapture the committed corpus (`testdata/snapshots/v10/malformed`) from the
    // committed fixture.
    if let Ok(directory) = std::env::var("S3_CAPTURE_CORPUS") {
        write_corpus(std::path::Path::new(&directory), &sealed, &plain);
    }
    println!("S3_FUZZ seed=0xA0720260927 inputs={} rejected={rejected} accepted={accepted} max_input={} authenticated_inner=true",inputs.len(),inputs.iter().map(|(_,b,_)|b.len()).max().unwrap());
}

#[test]
fn s3_envelope_mutations_wrong_seed_and_versions_are_rejected() {
    let (sealed, _) = frozen_v10();
    let mut tested = 0;
    for index in (0..sealed.len())
        .step_by((sealed.len() / 128).max(1))
        .chain(0..72)
    {
        let mut input = sealed.clone();
        input[index] ^= 1;
        assert!(
            snapshot::open(&input, &FIXTURE_SEED).is_err(),
            "outer mutation byte {index}"
        );
        tested += 1;
    }
    for length in [0, 1, 7, 8, 39, 40, 71, sealed.len() - 1] {
        assert!(snapshot::open(&sealed[..length], &FIXTURE_SEED).is_err());
        tested += 1;
    }
    assert!(snapshot::open(&sealed, &[0xC4; 32]).is_err());
    for version in [&b"9\0"[..], b"11", b"00", b"1\0", b"01"] {
        let mut input = sealed.clone();
        input[6..8].copy_from_slice(version);
        assert!(snapshot::open(&input, &FIXTURE_SEED).is_err());
        tested += 1;
    }
    println!(
        "S3_ENVELOPE negative_vectors={} wrong_seed=true",
        tested + 1
    );
}
