#[macro_use]
extern crate tracing;

use std::{error::Error, fmt};

pub(crate) mod apple_common_crypto;

mod cert;
pub use cert::*;

mod sha1;
pub use sha1::*;

mod srtp;
pub use srtp::*;

mod dtls;
pub use dtls::*;

#[derive(Debug)]
pub enum AppleCryptoError {
    Generic(String),
}

impl AppleCryptoError {}

impl fmt::Display for AppleCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic(message) => write!(f, "{}", message),
        }
    }
}

impl Error for AppleCryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Generic(_) => None,
        }
    }
}

/// Conversion from an &str to a AppleCryptoError. The AppleCryptoError
/// will include the message.
impl From<&str> for AppleCryptoError {
    fn from(msg: &str) -> Self {
        Self::Generic(msg.to_string())
    }
}

/// Conversion from a String to a AppleCryptoError. The AppleCryptoError
/// will include the message.
impl From<String> for AppleCryptoError {
    fn from(msg: String) -> Self {
        Self::Generic(msg)
    }
}
