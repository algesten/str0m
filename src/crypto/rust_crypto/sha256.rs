//! RustCrypto SHA-256 implementation.

use sha2::{Digest, Sha256};

use super::super::Sha256Provider;

/// RustCrypto-based SHA-256 provider.
#[derive(Debug)]
pub struct RustCryptoSha256Provider;

impl Sha256Provider for RustCryptoSha256Provider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}
