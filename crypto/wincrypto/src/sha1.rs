//! SHA-1 hash and HMAC provider implementations using Windows CNG.

use str0m_proto::crypto::{Sha1HmacProvider, Sha1Provider};

#[derive(Debug)]
pub(super) struct WinCryptoSha1Provider;

impl Sha1Provider for WinCryptoSha1Provider {
    fn sha1(&self, data: &[u8]) -> [u8; 20] {
        crate::sys::sha1(data).expect("SHA-1 computation")
    }
}

#[derive(Debug)]
pub(super) struct WinCryptoSha1HmacProvider;

impl Sha1HmacProvider for WinCryptoSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        crate::sys::sha1_hmac(key, payloads).expect("SHA1-HMAC computation")
    }
}
