mod provider;
pub use provider::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
pub use provider::{Aes128CmSha1_80, Aes128CmSha1_80Cipher, CryptoProvider, CryptoSafe};
pub use provider::{Sha1HmacProvider, Sha256Provider};
pub use provider::{SrtpProvider, SupportedAeadAes128Gcm};
pub use provider::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

/// DTLS related types and traits.
pub mod dtls {
    pub use super::provider::{DtlsInstance, DtlsProvider};

    pub use dimpl::DtlsCertificate as DtlsCert;
    pub use dimpl::KeyingMaterial;
    pub use dimpl::SrtpProfile;
    // Note: dimpl::Error is renamed to DtlsImplError to avoid conflict with str0m's DtlsError
    pub use dimpl::{Error as DtlsImplError, Output as DtlsOutput};
}

#[cfg(any(test, feature = "_internal_test_exports"))]
#[allow(unused)]
pub(crate) use provider::test_default_provider;

#[cfg(feature = "aws-lc-rs")]
pub mod aws_lc_rs;

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(all(feature = "wincrypto", target_os = "windows"))]
pub mod wincrypto;

mod finger;
pub use finger::Fingerprint;

mod error;
pub use error::{CryptoError, DtlsError};
