//! SHA1-HMAC provider implementation using Windows CNG.

use crate::crypto::Sha1HmacProvider;

#[derive(Debug)]
pub(super) struct WinCryptoSha1HmacProvider;

impl Sha1HmacProvider for WinCryptoSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        str0m_wincrypto::sha1_hmac(key, payloads).expect("SHA1-HMAC computation")
    }
}
