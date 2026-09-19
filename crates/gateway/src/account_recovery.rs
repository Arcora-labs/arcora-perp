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
    pub(super) fn recover_account(
        &mut self,
        owner: PubKey,
        nonce: u64,
        sig: &[u8; 65],
    ) -> Result<[u8; 32], String> {
        let old = self
            .accounts
            .iter()
            .find_map(|(k, a)| (a.wallet.owner == owner).then_some(*k))
            .ok_or("Unknown account owner.")?;
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
                    if last_nonce == nonce {
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

#[cfg(test)]
#[path = "account_recovery_tests.rs"]
mod tests;
