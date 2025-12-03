//! SHA-256 provider implementation using Windows CNG.

use str0m_proto::crypto::Sha256Provider;

#[derive(Debug)]
pub(super) struct WinCryptoSha256Provider;

impl Sha256Provider for WinCryptoSha256Provider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        crate::sys::sha256(data).expect("SHA-256 computation")
    }
}
