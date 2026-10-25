//! Apple CommonCrypto/Security framework implementation of cryptographic functions.
//! DTLS via dimpl with Apple CommonCrypto as crypto backend.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_import_braces)]
#![deny(unused_lifetimes)]
#![deny(unused_macro_rules)]
// Avoid rewriting existing code: nested conditions are often more readable than long if-chains.
#![allow(clippy::collapsible_if)]
#![deny(clippy::as_ptr_cast_mut)]
#![deny(clippy::branches_sharing_code)]
#![deny(clippy::clear_with_drain)]
#![deny(clippy::collection_is_never_read)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::derive_partial_eq_without_eq)]
#![deny(clippy::equatable_if_let)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::iter_on_empty_collections)]
#![deny(clippy::iter_on_single_items)]
#![deny(clippy::iter_with_drain)]
#![deny(clippy::large_stack_frames)]
#![deny(clippy::missing_const_for_fn)]
#![deny(clippy::mutex_integer)]
#![deny(clippy::needless_collect)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::nonstandard_macro_braces)]
#![deny(clippy::option_if_let_else)]
#![deny(clippy::or_fun_call)]
#![deny(clippy::path_buf_push_overwrite)]
#![deny(clippy::read_zero_byte_vec)]
#![deny(clippy::redundant_clone)]
#![deny(clippy::semicolon_if_nothing_returned)]
#![deny(clippy::set_contains_or_insert)]
#![deny(clippy::significant_drop_in_scrutinee)]
#![deny(clippy::suboptimal_flops)]
#![deny(clippy::suspicious_operation_groupings)]
#![deny(clippy::trailing_empty_array)]
#![deny(clippy::use_self)]
#![allow(clippy::redundant_pub_crate)]
#![allow(unsafe_code)]
#![cfg(target_vendor = "apple")]

mod cert;
mod common_crypto;
mod dimpl_provider;
mod dtls;
mod sha1;
mod sha256;
mod srtp;

use str0m_proto::crypto::CryptoProvider;

use dtls::AppleCryptoDtlsProvider;
use sha1::{AppleCryptoSha1HmacProvider, AppleCryptoSha1Provider};
use sha256::AppleCryptoSha256Provider;
use srtp::AppleCryptoSrtpProvider;

/// Create the default Apple CommonCrypto crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + Apple CommonCrypto)
/// - SRTP for encrypted media
/// - SHA1-HMAC for STUN message integrity
/// - SHA-1 and SHA-256 for certificate fingerprints
///
/// # Supported SRTP Profiles
///
/// - `SRTP_AES128_CM_SHA1_80`
/// - `SRTP_AEAD_AES_128_GCM`
/// - `SRTP_AEAD_AES_256_GCM`
pub fn default_provider() -> CryptoProvider {
    static SRTP: AppleCryptoSrtpProvider = AppleCryptoSrtpProvider;
    static SHA1_HMAC: AppleCryptoSha1HmacProvider = AppleCryptoSha1HmacProvider;
    static SHA1: AppleCryptoSha1Provider = AppleCryptoSha1Provider;
    static SHA256: AppleCryptoSha256Provider = AppleCryptoSha256Provider;
    static DTLS: AppleCryptoDtlsProvider = AppleCryptoDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha1_provider: &SHA1,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}

/// Create the Apple CommonCrypto crypto provider used by the Dimpl DTLS backend.
///
/// This allows callers that need non-default Dimpl configuration to construct
/// `dimpl::Config` directly while retaining the Apple CommonCrypto implementation.
pub fn dimpl_crypto_provider() -> dimpl::crypto::CryptoProvider {
    dimpl_provider::default_provider()
}

#[cfg(test)]
mod tests {
    #[test]
    fn exposed_dimpl_provider_builds_config() {
        dimpl::Config::builder()
            .with_crypto_provider(super::dimpl_crypto_provider())
            .build()
            .expect("Apple CommonCrypto Dimpl provider should build a valid config");
    }
}
