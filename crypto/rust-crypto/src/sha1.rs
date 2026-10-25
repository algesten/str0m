//! SHA-1 hash and HMAC implementations using RustCrypto.

use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest, Sha1};

use str0m_proto::crypto::{Sha1HmacProvider, Sha1Provider};

#[derive(Debug)]
pub(super) struct RustCryptoSha1Provider;

impl Sha1Provider for RustCryptoSha1Provider {
    fn sha1(&self, data: &[u8]) -> [u8; 20] {
        Sha1::digest(data).into()
    }
}

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
