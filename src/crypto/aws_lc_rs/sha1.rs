//! SHA1-HMAC implementation using AWS-LC-RS.

use aws_lc_rs::hmac;

use crate::crypto::provider::Sha1HmacProvider;

// ============================================================================
// SHA1 HMAC Provider Implementation
// ============================================================================

pub(super) struct AwsLcRsSha1HmacProvider;

impl std::fmt::Debug for AwsLcRsSha1HmacProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsLcRsSha1HmacProvider").finish()
    }
}

impl Sha1HmacProvider for AwsLcRsSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let mut ctx = hmac::Context::with_key(&key);

        for payload in payloads {
            ctx.update(payload);
        }

        let tag = ctx.sign();
        let mut result = [0u8; 20];
        result.copy_from_slice(tag.as_ref());
        result
    }
}
