#[macro_use]
extern crate tracing;

use openssl::error::ErrorStack;
use std::io;
use thiserror::Error;

mod d;
pub use d::{Dtls, DtlsEvent};

mod ossl;
pub use ossl::KeyingMaterial;

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// Some error from OpenSSL layer (used for DTLS).
    #[error("{0}")]
    OpenSsl(#[from] ErrorStack),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// Certificate fingerprint.
///
/// DTLS uses self signed certificates, and the fingerprint is communicated via
/// SDP to let the remote peer verify who is connecting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// Hash function used to produce the `bytes`.
    ///
    /// This is normally `sha-256`.
    pub hash_func: String,

    /// Digest of the certificate by the algorithm in `hash_func`.
    pub bytes: Vec<u8>,
}
