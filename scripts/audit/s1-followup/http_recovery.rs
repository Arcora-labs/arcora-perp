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
        return recovery_response(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({
            "error":"state persistence is required for credential recovery", "durability":"unknown"
        }));
    }
    let Some(owner) = parse_hex32(&req.owner) else {
        return recovery_response(StatusCode::BAD_REQUEST, serde_json::json!({"error":"bad owner (expected 32-byte 0x hex)"}));
    };
    let Some(sig) = parse_hex65(&req.signature) else {
        return recovery_response(StatusCode::BAD_REQUEST, serde_json::json!({"error":"bad signature"}));
    };
    let control = {
        let gw = app.gw.lock().await;
        match gw.recovery_control(&owner) {
            Some(control) => control,
            None => return recovery_response(StatusCode::BAD_REQUEST, serde_json::json!({"error":"Unknown account owner."})),
        }
    };
    // This per-account fence is stable across API-key rotations. It is NOT Gw,
    // and the snapshot writer never acquires it. Cancellation releases the fence
    // but never undoes a mutation or resets a recovery nonce.
    let fence = match tokio::time::timeout(
        Duration::from_secs(SNAPSHOT_ACK_TIMEOUT_SECS), control.fence.clone().write_owned()
    ).await {
        Ok(fence) => fence,
        Err(_) => return recovery_response(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({
            "error":"credential recovery busy; retry after reading current recovery metadata", "durability":"unknown"
        })),
    };
    let key = {
        let mut gw = app.gw.lock().await;
        match gw.recover_account_fenced(owner, req.nonce, &sig, &control, &fence) {
            Ok(key) => key,
            Err(error) => return recovery_response(StatusCode::BAD_REQUEST, serde_json::json!({"error":error})),
        }
    };
    if let Err(error) = snapshot_now(&app.snapshot_req).await {
        return recovery_response(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"error":error,"durability":"unknown"}));
    }
    let gw = app.gw.lock().await;
    let current = gw.accounts.get(&key).is_some_and(|a| {
        a.wallet.owner == owner
            && req.nonce.checked_add(1) == Some(a.recovery_nonce)
            && Arc::ptr_eq(&a.credential_control, &control)
            && a.signer.or(a.deposit_address).is_some_and(|authorizer| {
                let digest = digest(gw.chain_id, &gw.vault, &owner, req.nonce);
                eip191_prehash_candidates(&digest).iter()
                    .any(|hash| recover_eth_address(hash, &sig) == Some(authorizer))
            })
    });
    if !current {
        return recovery_response(StatusCode::CONFLICT, serde_json::json!({
            "error":"recovery authorization changed; fetch current recovery metadata and re-authorize",
            "durability":"unknown"
        }));
    }
    // Same-account rotation cannot supersede this key before this response is
    // constructed. A subsequent deliberate rotation may still revoke it before
    // the client receives TCP bytes; network delivery cannot be made atomic.
    recovery_response(StatusCode::OK, serde_json::json!({
        "apiKey":hex0x(&key), "owner":hex0x(&owner),
        "recoveryNonce":gw.accounts[&key].recovery_nonce, "durability":"confirmed"
    }))
}
