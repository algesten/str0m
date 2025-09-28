#![allow(unreachable_patterns)]

use once_cell::sync::OnceCell;
use std::fmt;

/// Crypto provider setting.
///
/// The provider implementations will need turning on using the feature flags:
///
/// * **openssl** (defaults to on) for crypto backed by OpenSSL.
/// * **wincrypto** for crypto backed by windows crypto.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoProvider {
    /// OpenSSL (the default)
    ///
    /// Requires feature flag **openssl**.
    OpenSsl,
    /// Windows SChannel + CNG implementation of cryptographic functions.
    ///
    /// Requires feature flag **wincrypto**.
    WinCrypto,
    /// Dimpl
    ///
    /// Pure rust DTLS 1.2 implementation.
    Dimpl,
}

static PROCESS_DEFAULT: OnceCell<CryptoProvider> = OnceCell::new();

impl CryptoProvider {
    pub(crate) fn srtp_crypto(&self) -> SrtpCrypto {
        match self {
            CryptoProvider::OpenSsl => SrtpCrypto::new_openssl(),
            CryptoProvider::WinCrypto => SrtpCrypto::new_wincrypto(),
            CryptoProvider::Dimpl => SrtpCrypto::new_rust_crypto(),
        }
    }

    /// Install the selected crypto provider as default for the process.
    ///
    /// This makes any new instance of [`Rtc`][crate::Rtc] pick up this default automatically.
    ///
    /// The process default can only be installed once, the second time will panic. Libraries
    /// should never install a process default.
    ///
    /// # When to use this
    ///
    /// This is particularly important when building without the `openssl` feature.
    /// Since `openssl` is the default crypto provider, disabling it requires you to
    /// explicitly configure an alternative like `wincrypto`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use str0m::config::CryptoProvider;
    ///
    /// // At application startup, before creating any Rtc instances
    /// CryptoProvider::from_feature_flags().install_process_default();
    /// ```
    pub fn install_process_default(&self) {
        PROCESS_DEFAULT
            .set(*self)
            .expect("CryptoProvider::install_process_default() called once");
    }

    /// Can be repeated in the same process.
    #[doc(hidden)]
    pub fn __test_install_process_default(&self) {
        let _ = PROCESS_DEFAULT.set(*self);
    }

    /// Get a possible crypto backend using feature flags.
    ///
    /// The order of preference is: **openssl**, **wincrypto**, **dimpl**.
    ///
    /// **NB** It's likely we will put **dimpl** first in a future release.
    ///
    /// This is useful for applications that want to automatically select the
    /// available crypto provider based on enabled features.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use str0m::config::CryptoProvider;
    ///
    /// // Automatically select available crypto provider and set as default
    /// CryptoProvider::from_feature_flags().install_process_default();
    /// ```
    pub fn from_feature_flags() -> CryptoProvider {
        if cfg!(feature = "openssl") {
            return CryptoProvider::OpenSsl;
        } else if cfg!(all(feature = "wincrypto", target_os = "windows")) {
            return CryptoProvider::WinCrypto;
        } else if cfg!(feature = "dimpl") {
            return CryptoProvider::Dimpl;
        }
        panic!("No crypto backend enabled");
    }

    pub(crate) fn process_default() -> Option<CryptoProvider> {
        PROCESS_DEFAULT.get().cloned()
    }
}

#[cfg(feature = "openssl")]
mod ossl;

#[cfg(all(feature = "wincrypto", target_os = "windows"))]
mod wincrypto;

#[cfg(feature = "dimpl")]
mod dimpl;

#[cfg(feature = "dimpl")]
mod rcrypto;

mod dtls;
pub(crate) use dtls::DtlsImpl;
pub use dtls::{DtlsCert, DtlsCertOptions, DtlsEvent, DtlsPKeyType};

mod finger;
pub use finger::Fingerprint;

mod keying;
pub use keying::KeyingMaterial;

mod srtp;
pub use srtp::{aead_aes_128_gcm, aead_aes_256_gcm, aes_128_cm_sha1_80, SrtpCrypto, SrtpProfile};

mod error;
pub use error::{CryptoError, DtlsError};

/// SHA1 HMAC as used for STUN and older SRTP.
/// If sha1 feature is enabled, it uses `rust-crypto` crate.
#[cfg(feature = "sha1")]
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    use hmac::Hmac;
    use hmac::Mac;
    use sha1::Sha1;

    let mut hmac = Hmac::<Sha1>::new_from_slice(key).expect("hmac to normalize size to 20");

    for payload in payloads {
        hmac.update(payload);
    }

    hmac.finalize().into_bytes().into()
}

/// If openssl is enabled and sha1 is not, it uses `openssl` crate.
#[cfg(all(feature = "openssl", not(feature = "sha1")))]
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    let key = PKey::hmac(key).expect("valid hmac key");
    let mut signer = Signer::new(MessageDigest::sha1(), &key).expect("valid signer");

    for payload in payloads {
        signer.update(payload).expect("signer update");
    }

    let mut hash = [0u8; 20];
    signer.sign(&mut hash).expect("sign to array");
    hash
}

/// If wincrypto is enabled and sha1 is not, it uses `wincrypto` crate.
#[cfg(all(feature = "wincrypto", not(feature = "sha1")))]
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    wincrypto::sha1_hmac(key, payloads)
}

#[cfg(all(
    not(feature = "sha1"),
    not(feature = "openssl"),
    not(feature = "wincrypto"),
))]
pub fn sha1_hmac(_key: &[u8], _payloads: &[&[u8]]) -> [u8; 20] {
    panic!("Need sha1 feature (via dimpl), openssl or wincrypto");
}

impl fmt::Display for CryptoProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoProvider::OpenSsl => write!(f, "openssl"),
            CryptoProvider::WinCrypto => write!(f, "wincrypto"),
            CryptoProvider::Dimpl => write!(f, "dimpl"),
        }
    }
}
