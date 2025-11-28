//! SHA1-HMAC implementation using OpenSSL.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::crypto::provider::Sha1HmacProvider;

// ============================================================================
// SHA1 HMAC Provider Implementation
// ============================================================================

pub(super) struct OsslSha1HmacProvider;

impl std::fmt::Debug for OsslSha1HmacProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslSha1HmacProvider").finish()
    }
}

impl Sha1HmacProvider for OsslSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let key = PKey::hmac(key).expect("valid hmac key");
        let mut signer = Signer::new(MessageDigest::sha1(), &key).expect("valid signer");

        for payload in payloads {
            signer.update(payload).expect("signer update");
        }

        let mut hash = [0u8; 20];
        signer.sign(&mut hash).expect("sign to array");
        hash
    }
}
