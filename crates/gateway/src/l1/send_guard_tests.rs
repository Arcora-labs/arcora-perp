//! The guards in front of sequencer-key sends made for a clock window: the
//! registration's skew guard and existing-only mode, and the bounded nonce
//! burn. The sends are fakes that record their nonce in a real fence, as
//! `send_on` does before cast runs, so a refusal shows up as an unchanged
//! ceiling.
use super::*;
use crate::clock_client::RegisterMode;
use std::cell::Cell;

const LAST_MS: u64 = 1_700_000_000_000;
const SKEW_MS: u64 = 30_000;

fn scratch_fence(ceiling: Option<u64>) -> (NonceFence, std::path::PathBuf) {
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).unwrap();
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let path = std::env::temp_dir().join(format!("darkperp-send-guard-{suffix}"));
    let fence = NonceFence::open(path.clone(), [9; 32], false).unwrap();
    if let Some(n) = ceiling {
        fence.cover(n).unwrap();
    }
    (fence, path)
}

fn timed(last_ms: u64) -> TimeBounds {
    TimeBounds {
        first_ms: last_ms - 5_000,
        last_ms,
        count: 3,
    }
}

fn context() -> ClockContext {
    ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: 7,
        previous_root: [1; 32],
        base_commitment: [2; 32],
        phase: 0,
        first_ms: LAST_MS - 5_000,
        last_ms: LAST_MS,
        timed_ops: 3,
        anchored_at_ms: LAST_MS + 1_000,
        max_window_ms: 60_000,
        clock_skew_ms: SKEW_MS,
    }
}

#[test]
fn a_timed_register_past_its_skew_is_refused_before_the_nonce_is_recorded() {
    let (fence, path) = scratch_fence(Some(6));
    let sends = Cell::new(0);
    // A send records its nonce before cast runs, as `send_on` does.
    let send = || {
        sends.set(sends.get() + 1);
        fence.cover(7)
    };
    let margin = 2_000;
    for now in [
        LAST_MS + SKEW_MS - margin + 1,
        LAST_MS + SKEW_MS,
        LAST_MS + SKEW_MS + 1,
        u64::MAX,
    ] {
        let refused = register_or_reuse(
            RegisterMode::SendIfAbsent,
            None,
            &timed(LAST_MS),
            now,
            || Ok(SKEW_MS),
            send,
        )
        .unwrap_err();
        assert_eq!(
            refused,
            "timed window is past its registration skew; nothing sent"
        );
    }
    assert_eq!(sends.get(), 0, "no registration was sent");
    assert_eq!(fence.ceiling(), Ceiling::Nonce(6), "no nonce was recorded");
    // An unreadable skew refuses as well.
    assert!(register_or_reuse(
        RegisterMode::SendIfAbsent,
        None,
        &timed(LAST_MS),
        LAST_MS,
        || Err("settlement observation: primary eth_call failed".into()),
        send,
    )
    .is_err());
    assert_eq!((sends.get(), fence.ceiling()), (0, Ceiling::Nonce(6)));
    // Inside the margin the registration is sent once and its nonce recorded.
    assert_eq!(
        register_or_reuse(
            RegisterMode::SendIfAbsent,
            None,
            &timed(LAST_MS),
            LAST_MS + SKEW_MS - margin,
            || Ok(SKEW_MS),
            send,
        ),
        Ok(None)
    );
    assert_eq!((sends.get(), fence.ceiling()), (1, Ceiling::Nonce(7)));
    // The margin is a tenth of a short skew, and at most 2 s.
    check_register_skew(LAST_MS, 400, LAST_MS + 360).unwrap();
    assert!(check_register_skew(LAST_MS, 400, LAST_MS + 361).is_err());
    check_register_skew(LAST_MS, 60_000, LAST_MS + 58_000).unwrap();
    assert!(check_register_skew(LAST_MS, 60_000, LAST_MS + 58_001).is_err());
    assert!(check_register_skew(u64::MAX, u64::MAX, u64::MAX).is_ok());
    // An untimed window has no skew to keep and reads none.
    assert_eq!(
        register_or_reuse(
            RegisterMode::SendIfAbsent,
            None,
            &TimeBounds::default(),
            u64::MAX,
            || panic!("an untimed window reads no skew"),
            send,
        ),
        Ok(None)
    );
    assert_eq!(sends.get(), 2);
    // An anchor that already exists is reused at any time, without a send.
    assert_eq!(
        register_or_reuse(
            RegisterMode::SendIfAbsent,
            Some(context()),
            &timed(LAST_MS),
            u64::MAX,
            || panic!("a reused anchor reads no skew"),
            || panic!("a reused anchor sends nothing"),
        ),
        Ok(Some(context()))
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn existing_only_never_sends_a_register() {
    for bounds in [timed(LAST_MS), TimeBounds::default()] {
        for now in [0, LAST_MS, u64::MAX] {
            assert_eq!(
                register_or_reuse(
                    RegisterMode::ExistingOnly,
                    None,
                    &bounds,
                    now,
                    || panic!("existing-only reads no skew"),
                    || panic!("existing-only never sends"),
                ),
                Err(ANCHOR_NOT_REGISTERED.to_string())
            );
        }
    }
    assert!(ANCHOR_NOT_REGISTERED.ends_with("; reclassify"));
    // With the anchor in place it proves against it.
    assert_eq!(
        register_or_reuse(
            RegisterMode::ExistingOnly,
            Some(context()),
            &timed(LAST_MS),
            u64::MAX,
            || panic!("existing-only reads no skew"),
            || panic!("existing-only never sends"),
        ),
        Ok(Some(context()))
    );
    // The client's existing-only copy keeps its prover and bridge.
    let client = crate::clock_client::ClockProverClient {
        inner: std::sync::Arc::new(crate::prover_client::MockProverClient),
        l1: L1::test_clocked_reader("http://127.0.0.1:9".into(), [1; 20], 84532),
        register: RegisterMode::SendIfAbsent,
    };
    let existing = client.existing_only();
    assert_eq!(existing.register, RegisterMode::ExistingOnly);
    assert!(std::sync::Arc::ptr_eq(&existing.inner, &client.inner));
    assert_eq!(existing.l1.rpc, client.l1.rpc);
}

#[test]
fn a_nonce_burn_sends_only_at_the_expected_nonce() {
    // The checks: the latest nonce, and the lane's next nonce when known.
    check_burn(7, 7, None).unwrap();
    check_burn(7, 7, Some(7)).unwrap();
    for (latest, lane_next) in [(6, None), (8, None), (7, Some(8)), (7, Some(6))] {
        let refused = check_burn(7, latest, lane_next).unwrap_err();
        assert!(refused.ends_with("; nothing sent"), "{refused}");
    }
    // The argv: a zero-value transfer to the sequencer itself at the expected
    // nonce, with no calldata and the plain-transfer gas limit, so no estimate.
    assert_eq!(
        burn_send_args("0xSEQ", 7, "/tmp/ks", "/tmp/pw", "http://rpc.example"),
        [
            "send",
            "0xSEQ",
            "--value",
            "0",
            "--gas-limit",
            "21000",
            "--nonce",
            "7",
            "--keystore",
            "/tmp/ks",
            "--password-file",
            "/tmp/pw",
            "--rpc-url",
            "http://rpc.example",
            "--json",
        ]
    );
    // A refusal sends nothing and leaves the ceiling and the lane as they were.
    let (fence, path) = scratch_fence(Some(7));
    let sends = Cell::new(0);
    let send = || {
        sends.set(sends.get() + 1);
        Ok("0xburn".to_string())
    };
    let quiet = || (true, Some((7, 7)));
    for (latest, known) in [(6, None), (8, Some(8)), (7, Some(9))] {
        let mut lane_next = known;
        assert!(burn_on(7, &mut lane_next, || Ok(latest), quiet, Some(&fence), send).is_err());
        assert_eq!(lane_next, known);
    }
    let mut lane_next = None;
    assert!(burn_on(
        7,
        &mut lane_next,
        || Err("nonce read failed".into()),
        quiet,
        Some(&fence),
        send
    )
    .is_err());
    // A sequencer-key transaction pending at the expected nonce on any RPC (a
    // timed-out send whose transaction is still in a mempool), or a pending
    // read that failed: a burn would replace it, so nothing is sent.
    for (seen, why) in [
        (Some((7, 8)), "pending"),
        (Some((8, 8)), "pending"),
        (None, "could not be read"),
    ] {
        let mut lane_next = None;
        let refused = burn_on(
            7,
            &mut lane_next,
            || Ok(7),
            || (false, seen),
            Some(&fence),
            send,
        )
        .unwrap_err();
        assert!(refused.contains(why), "{refused}");
        assert!(refused.ends_with("; nothing sent"), "{refused}");
        assert_eq!(lane_next, None);
    }
    assert_eq!((sends.get(), fence.ceiling()), (0, Ceiling::Nonce(7)));
    // At the expected nonce, at or below the ceiling: one send, the ceiling
    // unchanged, and the lane moves past the burned nonce.
    for expected in [7, 5] {
        let mut lane_next = Some(expected);
        assert_eq!(
            burn_on(
                expected,
                &mut lane_next,
                || Ok(expected),
                || (true, Some((expected, expected))),
                Some(&fence),
                send
            ),
            Ok("0xburn".to_string())
        );
        assert_eq!(lane_next, Some(expected + 1));
    }
    assert_eq!((sends.get(), fence.ceiling()), (2, Ceiling::Nonce(7)));
    // A failed send re-seeds the lane from the chain, as `send_on` does.
    let mut lane_next = None;
    assert!(burn_on(
        7,
        &mut lane_next,
        || Ok(7),
        quiet,
        Some(&fence),
        || Err("cast timed out".to_string())
    )
    .is_err());
    assert_eq!((lane_next, fence.ceiling()), (None, Ceiling::Nonce(7)));
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "requires real anvil and cast; run explicitly in native verification"]
fn anvil_nonce_burn_uses_only_the_expected_nonce() {
    struct Anvil(std::process::Child);
    impl Drop for Anvil {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _anvil = Anvil(
        Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("anvil"),
    );
    let rpc = format!("http://127.0.0.1:{port}");
    let mut l1 = L1::test_reader(rpc.clone());
    let up = (0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        l1.cast(&["chain-id", "--rpc-url", &rpc]).is_ok()
    });
    assert!(up, "anvil did not start");
    // A fresh random key, funded on the local chain only.
    let key: [u8; 32] = rand::random();
    let (keystore, password, dir) = create_keystore(&crate::hex0x(&key)).unwrap();
    l1.keystore_path = keystore;
    l1.password_file = password;
    let address = l1.sequencer_address().unwrap();
    l1.cast(&[
        "rpc",
        "anvil_setBalance",
        &address,
        "0x8ac7230489e80000",
        "--rpc-url",
        &rpc,
    ])
    .unwrap();
    let (fence, fence_path) = scratch_fence(None);
    l1.set_nonce_fence(fence).unwrap();
    // A send recorded nonce 0 and was never broadcast.
    l1.nonce_fence.get().unwrap().cover(0).unwrap();
    let latest = || l1.account_nonce(&address, "latest").unwrap();
    assert_eq!(latest(), 0);

    // Not the latest nonce: nothing is sent.
    assert!(l1
        .burn_sequencer_nonce(1)
        .unwrap_err()
        .ends_with("nothing sent"));
    assert_eq!((latest(), l1.nonce_ceiling()), (0, Ceiling::Nonce(0)));

    // The unused nonce: a zero-value transfer to itself, with no calldata and
    // 21000 gas; the ceiling is unchanged and the lane moves past it.
    let tx = l1.burn_sequencer_nonce(0).unwrap();
    assert_eq!((latest(), l1.nonce_ceiling()), (1, Ceiling::Nonce(0)));
    assert_eq!(*l1.nonce.lock().unwrap(), Some(1));
    let mined: serde_json::Value = serde_json::from_str(
        &l1.cast(&["rpc", "eth_getTransactionByHash", &tx, "--rpc-url", &rpc])
            .unwrap(),
    )
    .unwrap();
    assert!(mined["from"]
        .as_str()
        .unwrap()
        .eq_ignore_ascii_case(&address));
    assert!(mined["to"].as_str().unwrap().eq_ignore_ascii_case(&address));
    assert_eq!(
        (
            &mined["nonce"],
            &mined["value"],
            &mined["gas"],
            &mined["input"]
        ),
        (
            &serde_json::json!("0x0"),
            &serde_json::json!("0x0"),
            &serde_json::json!("0x5208"),
            &serde_json::json!("0x")
        )
    );

    // A lane that expects another nonce refuses, even at the latest nonce.
    *l1.nonce.lock().unwrap() = Some(5);
    assert!(l1.burn_sequencer_nonce(1).is_err());
    assert_eq!(latest(), 1);
    // Above the ceiling the burn is recorded before it is broadcast.
    *l1.nonce.lock().unwrap() = None;
    l1.burn_sequencer_nonce(1).unwrap();
    assert_eq!((latest(), l1.nonce_ceiling()), (2, Ceiling::Nonce(1)));

    // A sequencer-key transaction at the expected nonce that no block has mined
    // yet: the latest nonce is still the expected one, but a burn would replace
    // the pending transaction, so nothing is sent.
    l1.cast(&["rpc", "evm_setAutomine", "false", "--rpc-url", &rpc])
        .unwrap();
    let (keystore, password) = (l1.keystore_path.clone(), l1.password_file.clone());
    l1.cast(&[
        "send",
        &address,
        "--value",
        "0",
        "--gas-limit",
        "21000",
        "--nonce",
        "2",
        "--keystore",
        &keystore,
        "--password-file",
        &password,
        "--rpc-url",
        &rpc,
        "--async",
    ])
    .unwrap();
    assert_eq!(latest(), 2);
    let refused = l1.burn_sequencer_nonce(2).unwrap_err();
    assert!(refused.contains("pending"), "{refused}");
    assert!(refused.ends_with("nothing sent"), "{refused}");
    assert_eq!(l1.nonce_ceiling(), Ceiling::Nonce(1));
    l1.cast(&["rpc", "evm_mine", "--rpc-url", &rpc]).unwrap();
    assert_eq!(
        latest(),
        3,
        "the pending transaction was mined, not replaced"
    );
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_file(fence_path);
}
