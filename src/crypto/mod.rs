#![allow(unreachable_patterns)]

use std::io;
use thiserror::Error;

#[cfg(all(not(target_family = "windows"), feature = "openssl"))]
#[path = "ossl/mod.rs"]
mod _impl;

#[cfg(all(target_family = "windows", feature = "wincrypto"))]
#[path = "wincrypto/mod.rs"]
mod _impl;

#[cfg(any(
    all(target_family = "windows", not(feature = "wincrypto")),
    all(not(target_family = "windows"), not(feature = "openssl"))
))]
#[path = "dummy.rs"]
mod _impl;

mod dtls;
pub use dtls::{DtlsCert, DtlsEvent, DtlsImpl};

mod finger;
pub use finger::Fingerprint;

mod keying;
pub use keying::KeyingMaterial;

mod srtp;
pub use _impl::{AeadAes128Gcm, Aes128CmSha1_80};
pub use srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80, new_aead_aes_128_gcm};
pub use srtp::{new_aes_128_cm_sha1_80, srtp_aes_128_ecb_round, SrtpProfile};

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

/// if sha1 is not enabled, delegate to the crypto impl.
#[cfg(not(feature = "sha1"))]
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    _impl::sha1_hmac(key, payloads)
}

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Some error from crypto layer (used for DTLS).
    #[error("{0}")]
    Impl(#[from] _impl::Error),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}
