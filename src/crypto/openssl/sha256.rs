//! OpenSSL SHA-256 implementation.

use super::super::Sha256Provider;

/// OpenSSL-based SHA-256 provider.
#[derive(Debug)]
pub struct OsslSha256Provider;

impl Sha256Provider for OsslSha256Provider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        use openssl::hash::{hash, MessageDigest};
        let digest = hash(MessageDigest::sha256(), data).expect("SHA-256 hash");
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }
}
