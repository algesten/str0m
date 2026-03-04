//! Android JNI cryptographic backend for str0m WebRTC.
//!
//! This crate provides cryptographic operations by calling into Android's
//! `javax.crypto` and `java.security` APIs via JNI.

#![allow(clippy::redundant_pub_crate)]
#![allow(unsafe_code)]
#![cfg(target_os = "android")]

mod dimpl_provider;
mod dtls;
mod jni_crypto;
mod jvm;
mod sha1;
mod sha256;
mod srtp;

use str0m_proto::crypto::CryptoProvider;

use dtls::AndroidCryptoDtlsProvider;
pub(crate) use jvm::get_jvm;
use sha1::AndroidCryptoSha1HmacProvider;
use sha256::AndroidCryptoSha256Provider;
use srtp::AndroidCryptoSrtpProvider;

/// Initialize the Android crypto provider with the JVM.
///
/// This must be called before using any crypto operations, typically in
/// `JNI_OnLoad` or during application initialization.
///
/// # Panics
///
/// Panics if called more than once.
///
/// # Example
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn JNI_OnLoad(vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jni::sys::jint {
///     str0m_android_crypto::init_jvm(vm);
///     jni::sys::JNI_VERSION_1_6
/// }
/// ```
#[cfg(not(test))]
pub use jvm::init_jvm;

/// Create the default Android JNI crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2/1.3 for secure key exchange (using dimpl protocol + Android crypto)
/// - SRTP for encrypted media
/// - SHA1-HMAC for STUN message integrity
/// - SHA-256 for certificate fingerprints
///
/// # Supported SRTP Profiles
///
/// - `SRTP_AES128_CM_SHA1_80`
/// - `SRTP_AEAD_AES_128_GCM`
/// - `SRTP_AEAD_AES_256_GCM`
///
/// # Panics
///
/// The returned provider will panic on use if `init_jvm()` has not been called.
pub fn default_provider() -> CryptoProvider {
    static SRTP: AndroidCryptoSrtpProvider = AndroidCryptoSrtpProvider;
    static SHA1_HMAC: AndroidCryptoSha1HmacProvider = AndroidCryptoSha1HmacProvider;
    static SHA256: AndroidCryptoSha256Provider = AndroidCryptoSha256Provider;
    static DTLS: AndroidCryptoDtlsProvider = AndroidCryptoDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}
