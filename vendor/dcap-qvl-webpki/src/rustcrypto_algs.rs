//! Signature verification algorithms implemented using RustCrypto crates.

use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use sha2::Digest;

// ============================================================================
// ECDSA Implementation
// ============================================================================

/// Enum to specify which hash algorithm to use for ECDSA verification
#[derive(Debug, Clone, Copy)]
enum EcdsaDigest {
    Sha256,
    Sha384,
}

/// ECDSA signature verification using P-256 curve
#[derive(Debug)]
struct EcdsaP256 {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    digest: EcdsaDigest,
}

impl SignatureVerificationAlgorithm for EcdsaP256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::VerifyingKey;

        // Validate public key format (SEC1: 0x04 uncompressed, 0x02/0x03 compressed)
        match public_key.first() {
            Some(0x04) | Some(0x02) | Some(0x03) => {}
            _ => return Err(InvalidSignature),
        };

        let verifying_key =
            VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;

        let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;

        // Hash the message with the appropriate digest and verify
        match self.digest {
            EcdsaDigest::Sha256 => {
                let digest = sha2::Sha256::digest(message);
                verifying_key
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
            EcdsaDigest::Sha384 => {
                let digest = sha2::Sha384::digest(message);
                verifying_key
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
        }
    }
}

/// ECDSA signature verification using P-384 curve
#[derive(Debug)]
struct EcdsaP384 {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    digest: EcdsaDigest,
}

impl SignatureVerificationAlgorithm for EcdsaP384 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        use p384::ecdsa::VerifyingKey;

        // Validate public key format (SEC1: 0x04 uncompressed, 0x02/0x03 compressed)
        match public_key.first() {
            Some(0x04) | Some(0x02) | Some(0x03) => {}
            _ => return Err(InvalidSignature),
        };

        let verifying_key =
            VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;

        let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;

        // Hash the message with the appropriate digest and verify
        match self.digest {
            EcdsaDigest::Sha256 => {
                let digest = sha2::Sha256::digest(message);
                verifying_key
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
            EcdsaDigest::Sha384 => {
                let digest = sha2::Sha384::digest(message);
                verifying_key
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
        }
    }
}

// ============================================================================
// Ed25519 Implementation
// ============================================================================

/// Ed25519 signature verification
#[derive(Debug)]
struct Ed25519Algorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Ed25519Algorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Ed25519 public key must be exactly 32 bytes
        let pk_bytes: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| InvalidSignature)?;

        // Signature must be exactly 64 bytes
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| InvalidSignature)?;

        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| InvalidSignature)
    }
}

// ============================================================================
// RSA Implementation (requires alloc)
// ============================================================================

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy)]
enum RsaPadding {
    Pkcs1v15,
    Pss,
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy)]
enum RsaHash {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
struct RsaAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    padding: RsaPadding,
    hash: RsaHash,
    min_key_bits: usize,
}

#[cfg(feature = "alloc")]
impl SignatureVerificationAlgorithm for RsaAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPublicKey;
        use rsa::signature::Verifier;

        // Parse RSA public key from PKCS#1 DER encoding
        let pk = RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;

        // Validate key size
        let key_bits = pk.n().bits();
        if key_bits < self.min_key_bits || key_bits > 8192 {
            return Err(InvalidSignature);
        }

        match (&self.padding, &self.hash) {
            (RsaPadding::Pkcs1v15, RsaHash::Sha256) => {
                use rsa::pkcs1v15::{Signature, VerifyingKey};
                let verifying_key = VerifyingKey::<sha2::Sha256>::new(pk);
                let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| InvalidSignature)
            }
            (RsaPadding::Pkcs1v15, RsaHash::Sha384) => {
                use rsa::pkcs1v15::{Signature, VerifyingKey};
                let verifying_key = VerifyingKey::<sha2::Sha384>::new(pk);
                let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| InvalidSignature)
            }
            (RsaPadding::Pkcs1v15, RsaHash::Sha512) => {
                use rsa::pkcs1v15::{Signature, VerifyingKey};
                let verifying_key = VerifyingKey::<sha2::Sha512>::new(pk);
                let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| InvalidSignature)
            }
            (RsaPadding::Pss, RsaHash::Sha256) => {
                use rsa::pss::{Signature, VerifyingKey};
                let verifying_key = VerifyingKey::<sha2::Sha256>::new(pk);
                let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| InvalidSignature)
            }
            (RsaPadding::Pss, RsaHash::Sha384) => {
                use rsa::pss::{Signature, VerifyingKey};
                let verifying_key = VerifyingKey::<sha2::Sha384>::new(pk);
                let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| InvalidSignature)
            }
            (RsaPadding::Pss, RsaHash::Sha512) => {
                use rsa::pss::{Signature, VerifyingKey};
                let verifying_key = VerifyingKey::<sha2::Sha512>::new(pk);
                let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                verifying_key
                    .verify(message, &sig)
                    .map_err(|_| InvalidSignature)
            }
        }
    }
}

// ============================================================================
// Algorithm Exports
// ============================================================================

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256 {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    digest: EcdsaDigest::Sha256,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP256 {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    digest: EcdsaDigest::Sha384,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP384 {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    digest: EcdsaDigest::Sha256,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384 {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    digest: EcdsaDigest::Sha384,
};

/// ED25519 signatures according to RFC 8410
pub static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Algorithm {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &RsaAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    padding: RsaPadding::Pkcs1v15,
    hash: RsaHash::Sha256,
    min_key_bits: 2048,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &RsaAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    padding: RsaPadding::Pkcs1v15,
    hash: RsaHash::Sha384,
    min_key_bits: 2048,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &RsaAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    padding: RsaPadding::Pkcs1v15,
    hash: RsaHash::Sha512,
    min_key_bits: 2048,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits,
/// with illegally absent AlgorithmIdentifier parameters.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &RsaAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::AlgorithmIdentifier::from_slice(include_bytes!(
            "data/alg-rsa-pkcs1-sha256-absent-params.der"
        )),
        padding: RsaPadding::Pkcs1v15,
        hash: RsaHash::Sha256,
        min_key_bits: 2048,
    };

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits,
/// with illegally absent AlgorithmIdentifier parameters.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &RsaAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::AlgorithmIdentifier::from_slice(include_bytes!(
            "data/alg-rsa-pkcs1-sha384-absent-params.der"
        )),
        padding: RsaPadding::Pkcs1v15,
        hash: RsaHash::Sha384,
        min_key_bits: 2048,
    };

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits,
/// with illegally absent AlgorithmIdentifier parameters.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &RsaAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::AlgorithmIdentifier::from_slice(include_bytes!(
            "data/alg-rsa-pkcs1-sha512-absent-params.der"
        )),
        padding: RsaPadding::Pkcs1v15,
        hash: RsaHash::Sha512,
        min_key_bits: 2048,
    };

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
#[cfg(feature = "alloc")]
pub static RSA_PKCS1_3072_8192_SHA384: &dyn SignatureVerificationAlgorithm = &RsaAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    padding: RsaPadding::Pkcs1v15,
    hash: RsaHash::Sha384,
    min_key_bits: 3072,
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
#[cfg(feature = "alloc")]
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &RsaAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA256,
        padding: RsaPadding::Pss,
        hash: RsaHash::Sha256,
        min_key_bits: 2048,
    };

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
#[cfg(feature = "alloc")]
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &RsaAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA384,
        padding: RsaPadding::Pss,
        hash: RsaHash::Sha384,
        min_key_bits: 2048,
    };

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
#[cfg(feature = "alloc")]
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &RsaAlgorithm {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA512,
        padding: RsaPadding::Pss,
        hash: RsaHash::Sha512,
        min_key_bits: 2048,
    };

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "."]
mod tests {
    use crate::Error;

    static SUPPORTED_ALGORITHMS_IN_TESTS: &[&dyn super::SignatureVerificationAlgorithm] = &[
        // Reasonable algorithms.
        super::ECDSA_P256_SHA256,
        super::ECDSA_P384_SHA384,
        super::ED25519,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_2048_8192_SHA256,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_2048_8192_SHA384,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_2048_8192_SHA512,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_3072_8192_SHA384,
        #[cfg(feature = "alloc")]
        super::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        #[cfg(feature = "alloc")]
        super::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        #[cfg(feature = "alloc")]
        super::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        // Algorithms deprecated because they are nonsensical combinations.
        super::ECDSA_P256_SHA384, // Truncates digest.
        super::ECDSA_P384_SHA256, // Digest is unnecessarily short.
    ];

    const UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_RSA_KEY: Error = if cfg!(feature = "alloc") {
        Error::UnsupportedSignatureAlgorithmForPublicKey
    } else {
        Error::UnsupportedSignatureAlgorithm
    };

    const UNSUPPORTED_ECDSA_SHA512_SIGNATURE: Error = Error::UnsupportedSignatureAlgorithm;

    const INVALID_SIGNATURE_FOR_RSA_KEY: Error = if cfg!(feature = "alloc") {
        Error::InvalidSignatureForPublicKey
    } else {
        Error::UnsupportedSignatureAlgorithm
    };

    const OK_IF_RSA_AVAILABLE: Result<(), Error> = if cfg!(feature = "alloc") {
        Ok(())
    } else {
        Err(Error::UnsupportedSignatureAlgorithm)
    };

    // RustCrypto curves support point compression
    const OK_IF_POINT_COMPRESSION_SUPPORTED: Result<(), Error> = Ok(());

    #[path = "alg_tests.rs"]
    mod alg_tests;
}
