//! SHA1-HMAC implementation using RustCrypto.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::provider::Sha1HmacProvider;

type HmacSha1 = Hmac<Sha1>;

// ============================================================================
// SHA1 HMAC Provider Implementation
// ============================================================================

pub(super) struct RustCryptoSha1HmacProvider;

impl std::fmt::Debug for RustCryptoSha1HmacProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSha1HmacProvider").finish()
    }
}

impl Sha1HmacProvider for RustCryptoSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");

        for payload in payloads {
            mac.update(payload);
        }

        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut output = [0u8; 20];
        output.copy_from_slice(&bytes);
        output
    }
}
