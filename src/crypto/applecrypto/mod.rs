//! Windows SChannel + CNG implementation of cryptographic functions.

use super::CryptoError;

mod cert;
pub use cert::AppleCryptoDtlsCert;

mod dtls;
pub use dtls::AppleCryptoDtls;

mod srtp;
pub use srtp::AppleCryptoSrtpCryptoImpl;

#[cfg(not(feature = "sha1"))]
mod sha1;
#[cfg(not(feature = "sha1"))]
pub use sha1::sha1_hmac;

pub use str0m_applecrypto::AppleCryptoError;
