use super::*;
use sha3::{Digest as _, Keccak256 as RawKeccak};

pub(super) const SNAPSHOT_V8: &[u8] = b"\xffDPA07-SNAPSHOT-v8\0";
pub(super) const EXT: &[u8; 8] = b"DPRECOV1";

pub(super) fn digest(chain_id: u64, vault: &[u8; 20], owner: &PubKey, nonce: u64) -> [u8; 32] {
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:recover-account:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}
pub(super) fn append(gw: &Gw, bytes: &mut Vec<u8>) {
    let rows: Vec<_> = gw
        .accounts
        .values()
        .map(|a| (a.wallet.owner, a.recovery_nonce))
        .collect();
    bytes.extend_from_slice(EXT);
    bytes.extend_from_slice(&postcard::to_allocvec(&rows).expect("recovery snapshot encode"));
}
pub(super) fn restore(gw: &mut Gw, trailer: &[u8]) -> Result<(), String> {
    if trailer.is_empty() {
        for a in gw.accounts.values_mut() {
            a.recovery_nonce = 0;
        }
        return Ok(());
    }
    let payload = trailer
        .strip_prefix(EXT)
        .ok_or("unknown recovery snapshot extension")?;
    let (rows, rest): (Vec<(PubKey, u64)>, _) =
        postcard::take_from_bytes(payload).map_err(|e| format!("recovery snapshot decode: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing recovery snapshot bytes".into());
    }
    let n = rows.len();
    let mut map: std::collections::BTreeMap<_, _> = rows.into_iter().collect();
    if map.len() != n {
        return Err("duplicate recovery owner".into());
    }
    for a in gw.accounts.values_mut() {
        a.recovery_nonce = map
            .remove(&a.wallet.owner)
            .ok_or("missing recovery owner")?;
    }
    if !map.is_empty() {
        return Err("orphan recovery owner".into());
    }
    Ok(())
}
impl Gw {
    pub(super) fn recovery_view(&self, owner: &PubKey) -> Option<serde_json::Value> {
        let a = self.accounts.values().find(|a| &a.wallet.owner == owner)?;
        let authorizer = a.signer.or(a.deposit_address)?;
        Some(
            serde_json::json!({"owner":hex0x(owner),"authorizer":hex0x(&authorizer),"recoveryNonce":a.recovery_nonce,"chainId":self.chain_id,"vault":hex0x(&self.vault)}),
        )
    }
    pub(super) fn recovery_control(
        &self,
        owner: &PubKey,
    ) -> Option<Arc<credential_session::Control>> {
        self.accounts
            .values()
            .find(|a| &a.wallet.owner == owner)
            .map(|a| a.credential_control.clone())
    }

    // Synchronous unit-test callers must also respect the send fence. HTTP
    // acquires it asynchronously without holding Gw, using the method below.
    #[cfg(test)]
    pub(super) fn recover_account(
        &mut self,
        owner: PubKey,
        nonce: u64,
        sig: &[u8; 65],
    ) -> Result<[u8; 32], String> {
        let control = self
            .recovery_control(&owner)
            .ok_or("Unknown account owner.")?;
        let fence = control
            .fence
            .clone()
            .try_write_owned()
            .map_err(|_| "credential send/recovery in progress; retry")?;
        self.recover_account_fenced(owner, nonce, sig, &control, &fence)
    }

    fn recover_account_fenced(
        &mut self,
        owner: PubKey,
        nonce: u64,
        sig: &[u8; 65],
        control: &Arc<credential_session::Control>,
        _fence: &tokio::sync::OwnedRwLockWriteGuard<()>,
    ) -> Result<[u8; 32], String> {
        let old = self
            .accounts
            .iter()
            .find_map(|(k, a)| (a.wallet.owner == owner).then_some(*k))
            .ok_or("Unknown account owner.")?;
        if !Arc::ptr_eq(&self.accounts[&old].credential_control, control) {
            return Err("account recovery fence changed; retry".into());
        }
        let (expected, current) = {
            let a = &self.accounts[&old];
            (
                a.signer
                    .or(a.deposit_address)
                    .ok_or("account has no recovery authorizer")?,
                a.recovery_nonce,
            )
        };
        let d = digest(self.chain_id, &self.vault, &owner, nonce);
        if !eip191_prehash_candidates(&d)
            .iter()
            .any(|p| recover_eth_address(p, sig) == Some(expected))
        {
            return Err(
                "recovery signature does not recover to this account's authorizing address".into(),
            );
        }
        if nonce != current {
            // S1: idempotent retry. A caller whose POST succeeded in memory but got
            // a 503 "durability unknown" re-submits the SAME authorization: nonce is
            // one behind and matches the recorded last rotation, so return the same
            // key without mutating anything. Requires the author's valid signature
            // for that exact nonce (verified above), and only answers for the
            // CURRENT generation — an older retry after a newer rotation falls
            // through to the mismatch error.
            if nonce.checked_add(1) == Some(current) {
                if let Some((last_nonce, last_key)) = self.accounts[&old].recovery_last {
                    if last_nonce == nonce && last_key == old {
                        return Ok(last_key);
                    }
                }
            }
            return Err("recovery nonce mismatch (stale or replayed authorization)".into());
        }
        let next = current.checked_add(1).ok_or("recovery nonce exhausted")?;
        let new_key = loop {
            let k = csprng_bytes32();
            if !self.accounts.contains_key(&k) {
                break k;
            }
        };
        let mut a = self.accounts.remove(&old).expect("located account");
        a.recovery_nonce = next;
        a.recovery_last = Some((nonce, new_key));
        // Notify existing subscribers even after restore creates fresh controls.
        a.credential_control.changed.send_replace(next);
        self.accounts.insert(new_key, a);
        // A01 stores account lookup credentials in permits and credited receipts.
        // Move those references under the same Gw lock as the account rotation.
        // Owner, destination market, purpose, event bytes and L1 prefix stay intact.
        for route in self.deposits.routes.values_mut() {
            if route.key == old {
                route.key = new_key;
            }
        }
        for credit in self.deposits.credits.values_mut() {
            if credit.route.key == old {
                credit.route.key = new_key;
            }
        }
        Ok(new_key)
    }
}

fn recovery_response(status: StatusCode, value: serde_json::Value) -> axum::response::Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(super) async fn post(app: Shared, req: RecoveryReq) -> axum::response::Response {
    if app.snapshot_req.is_none() {
        return recovery_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "error":"state persistence is required for credential recovery", "durability":"unknown"
            }),
        );
    }
    let Some(owner) = parse_hex32(&req.owner) else {
        return recovery_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error":"bad owner (expected 32-byte 0x hex)"}),
        );
    };
    let Some(sig) = parse_hex65(&req.signature) else {
        return recovery_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error":"bad signature"}),
        );
    };
    let control = {
        let gw = app.gw.lock().await;
        match gw.recovery_control(&owner) {
            Some(control) => control,
            None => {
                return recovery_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error":"Unknown account owner."}),
                )
            }
        }
    };
    // This per-account fence is stable across API-key rotations. It is NOT Gw,
    // and the snapshot writer never acquires it. Cancellation releases the fence
    // but never undoes a mutation or resets a recovery nonce.
    let fence = match tokio::time::timeout(
        Duration::from_secs(SNAPSHOT_ACK_TIMEOUT_SECS),
        control.fence.clone().write_owned(),
    )
    .await
    {
        Ok(fence) => fence,
        Err(_) => {
            return recovery_response(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "error":"credential recovery busy; retry after reading current recovery metadata", "durability":"unknown"
                }),
            )
        }
    };
    let key = {
        let mut gw = app.gw.lock().await;
        match gw.recover_account_fenced(owner, req.nonce, &sig, &control, &fence) {
            Ok(key) => key,
            Err(error) => {
                return recovery_response(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"error":error}),
                )
            }
        }
    };
    if let Err(error) = snapshot_now(&app.snapshot_req).await {
        return recovery_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error":error,"durability":"unknown"}),
        );
    }
    let gw = app.gw.lock().await;
    let current = gw.accounts.get(&key).is_some_and(|a| {
        a.wallet.owner == owner
            && req.nonce.checked_add(1) == Some(a.recovery_nonce)
            && Arc::ptr_eq(&a.credential_control, &control)
            && a.signer.or(a.deposit_address).is_some_and(|authorizer| {
                let digest = digest(gw.chain_id, &gw.vault, &owner, req.nonce);
                eip191_prehash_candidates(&digest)
                    .iter()
                    .any(|hash| recover_eth_address(hash, &sig) == Some(authorizer))
            })
    });
    if !current {
        return recovery_response(
            StatusCode::CONFLICT,
            serde_json::json!({
                "error":"recovery authorization changed; fetch current recovery metadata and re-authorize",
                "durability":"unknown"
            }),
        );
    }
    // Same-account rotation cannot supersede this key before this response is
    // constructed. A subsequent deliberate rotation may still revoke it before
    // the client receives TCP bytes; network delivery cannot be made atomic.
    recovery_response(
        StatusCode::OK,
        serde_json::json!({
            "apiKey":hex0x(&key), "owner":hex0x(&owner),
            "recoveryNonce":gw.accounts[&key].recovery_nonce, "durability":"confirmed"
        }),
    )
}

#[cfg(test)]
#[path = "account_recovery_tests.rs"]
mod tests;
