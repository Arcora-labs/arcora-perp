// Appended as a test-only module to EACH historical source checkout; never linked
// into the audited production binary. All keys are synthetic fixtures.
#[cfg(test)]
mod frozen_fixture_generator {
    use super::*;
    use k256::ecdsa::SigningKey;
    use sha3::{Digest as _, Keccak256 as RawKeccak};

    #[test]
    fn generate_historical_snapshot_fixture() {
        let output = std::path::PathBuf::from(std::env::var("ARCORA_FIXTURE_OUTPUT").unwrap());
        let mut gw = Gw::boot();
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
        gw.account_place_order(&key, &OrderReq {
            market_id: 0, side: "Buy".into(), size: (SIZE_SCALE / 10).to_string(),
            limit_price: gw.px_of(0).to_string(), tif: "Gtc".into(),
            ..Default::default()
        }).unwrap();
        gw.tick();
        gw.account_place_order(&key, &OrderReq {
            market_id: 0, side: "Buy".into(), size: (SIZE_SCALE / 20).to_string(),
            limit_price: (gw.px_of(0) / 2).to_string(), tif: "Gtc".into(),
            ..Default::default()
        }).unwrap();
        let sk = SigningKey::from_slice(&[0x51; 32]).unwrap();
        let public = sk.verifying_key().to_encoded_point(false);
        let hash = RawKeccak::digest(&public.as_bytes()[1..]);
        let payer: [u8; 20] = hash[12..].try_into().unwrap();
        let (withdraw_key, owner) = gw.register_account(Some(payer));
        gw.account_deposit(&withdraw_key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let d = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000 * QUOTE_SCALE, &[7;20], 1);
        let (sig, rid) = sk.sign_prehash_recoverable(&d).unwrap();
        let mut wire = [0;65]; wire[..64].copy_from_slice(&sig.to_bytes()); wire[64] = rid.to_byte() + 27;
        gw.account_withdraw(&withdraw_key, 0, 5_000 * QUOTE_SCALE, [7;20], 1, &wire).unwrap();
        // SOURCE_VERSION_SETUP
        let plain = gw.snapshot_plain();
        let sealed = snapshot::seal(&plain, &[0xC3;32]);
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("sealed.bin"), sealed).unwrap();
        std::fs::write(output.join("state.bin"), postcard::to_allocvec(&gw.seq.state).unwrap()).unwrap();
        std::fs::write(output.join("accounts.bin"), postcard::to_allocvec(&gw.accounts).unwrap()).unwrap();
        std::fs::write(output.join("withdrawals.bin"), postcard::to_allocvec(&gw.pending_withdrawals).unwrap()).unwrap();
        std::fs::write(output.join("root.txt"), hex0x(&gw.seq.state.state_root())).unwrap();
        std::fs::write(output.join("meta.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "orders": gw.accounts.values().map(|a| a.orders.len()).sum::<usize>(),
            "accounts": gw.accounts.len(), "pending_withdrawals": gw.pending_withdrawals.len(),
            "nullifiers": gw.seq.state.nullifiers.len(), "plain_bytes": plain.len(),
            "replay_key": hex0x(&key), "recovery_owner": hex0x(&owner),
            "withdraw_key": hex0x(&withdraw_key), "recovery_authorizer": hex0x(&payer)
        })).unwrap()).unwrap();
        println!("FIXTURE GENERATED {}", output.display());
    }
}
