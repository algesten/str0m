#![allow(unreachable_patterns)]

use std::io;
use thiserror::Error;

#[cfg(feature = "openssl")]
mod ossl;

mod dtls;
pub use dtls::{DtlsCert, DtlsEvent, DtlsImpl};

mod finger;
pub use finger::Fingerprint;

mod keying;
pub use keying::KeyingMaterial;

mod srtp;
pub use srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80, new_aead_aes_128_gcm};
pub use srtp::{new_aes_128_cm_sha1_80, srtp_aes_128_ecb_round, SrtpProfile};

/// SHA1 HMAC as used for STUN and older SRTP.
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

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Some error from OpenSSL layer (used for DTLS).
    #[error("{0}")]
    #[cfg(feature = "openssl")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}
