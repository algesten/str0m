//! Windows SChannel + CNG implementation of cryptographic functions.

use super::CryptoError;

mod cert;
mod dtls;
mod sha1;
mod srtp;

pub use cert::WinCryptoDtlsCert as Cert;
pub use dtls::WinCryptoDtls as Dtls;
pub use srtp::srtp_aes_128_ecb_round;
pub use srtp::WinCryptoAeadAes128Gcm as AeadAes128Gcm;
pub use srtp::WinCryptoAes128CmSha1_80 as Aes128CmSha1_80;
pub use str0m_wincrypto::WinCryptoError as Error;

#[allow(unused_imports)] // If 'sha1' feature is enabled this is not used.
pub use sha1::sha1_hmac;
