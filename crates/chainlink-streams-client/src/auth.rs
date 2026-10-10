use crate::{hex, Error, Network, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Caller-provided credentials. No Clone/Serialize, implicit demo key, URL or disk discovery.
/// Zeroizing protects these owned buffers, not every HTTP-library/compiler memory copy.
pub struct Credentials {
    pub(crate) network: Network,
    pub(crate) username: Zeroizing<String>,
    secret: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("network", &self.network)
            .field("username", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl Credentials {
    pub fn new(network: Network, username: String, secret: Vec<u8>) -> Result<Self> {
        let username = Zeroizing::new(username);
        let secret = Zeroizing::new(secret);
        let valid = username.len() == 36
            && username.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        if !valid || secret.is_empty() || secret.len() > 4096 {
            return Err(Error::Credentials);
        }
        Ok(Self {
            network,
            username,
            secret,
        })
    }
    pub(crate) fn sign_get(&self, path: &str, timestamp_ms: u64) -> Result<Zeroizing<String>> {
        if timestamp_ms == 0 {
            return Err(Error::Clock);
        }
        // This function is private to the client; path is generated from a validated feed ID.
        let text = Zeroizing::new(format!(
            "GET {} {} {} {}",
            path,
            hex(&Sha256::digest([])),
            self.username.as_str(),
            timestamp_ms
        ));
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|_| Error::Credentials)?;
        mac.update(text.as_bytes());
        Ok(Zeroizing::new(hex(&mac.finalize().into_bytes())))
    }
}
