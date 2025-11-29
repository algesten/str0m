mod provider;
pub use provider::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
pub use provider::{Aes128CmSha1_80, Aes128CmSha1_80Cipher, CryptoProvider, CryptoSafe};
pub use provider::{DimplError, Sha1HmacProvider, Sha256Provider, SrtpProfile};
pub use provider::{DtlsCert, DtlsInstance, DtlsOutput, DtlsProvider, KeyingMaterial};
pub use provider::{SrtpProvider, SupportedAeadAes128Gcm};
pub use provider::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

/// Re-exports from dimpl for implementing custom DTLS crypto providers.
///
/// This module re-exports all the types needed to implement a `dimpl::crypto::CryptoProvider`
/// for use with str0m's DTLS layer. External crypto crates can depend only on str0m
/// and use these types to provide their own crypto implementations.
pub mod dimpl_types {
    // Core DTLS types
    pub use dimpl::{Config, Dtls, DtlsCertificate};

    // Buffer types
    pub use dimpl::buffer::{Buf, TmpBuf};

    // Crypto provider trait and types
    pub use dimpl::crypto::{
        Aad, ActiveKeyExchange, Cipher, CipherSuite, CryptoProvider, HashAlgorithm, HashContext,
        HashProvider, HmacProvider, KeyProvider, NamedGroup, Nonce, PrfProvider, SecureRandom,
        SignatureAlgorithm, SignatureVerifier, SigningKey, SupportedCipherSuite, SupportedKxGroup,
    };
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
