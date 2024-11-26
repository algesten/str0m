//! Windows SChannel + CNG implementation of cryptographic functions.

use super::CryptoError;

mod cert;
pub use cert::WinCryptoDtlsCert;

mod dtls;
pub use dtls::WinCryptoDtls;

mod srtp;
pub use srtp::WinCryptoSrtpCryptoImpl;

mod sha1;
#[allow(unused_imports)] // If 'sha1' feature is enabled this is not used.
pub use sha1::sha1_hmac;

pub use str0m_wincrypto::WinCryptoError;
