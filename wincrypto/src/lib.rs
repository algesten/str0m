#[macro_use]
extern crate tracing;

use thiserror::Error;
use windows::{core::Error as WindowsError, Win32::Foundation::NTSTATUS};

mod cert;
pub use cert::*;

mod sha1;
pub use sha1::*;

mod srtp;
pub use srtp::*;

mod dtls;
pub use dtls::*;

#[derive(Error, Debug)]
#[error("{0}")]
pub struct WinCryptoError(pub String);

impl WinCryptoError {
    /// Conversion function from NTSTATUS to Result. The result will
    /// be Ok(()) if the NTSTATUS indicates OK, otherwise it will be
    /// an Err with a message containing the status code.
    pub fn from_ntstatus(status: NTSTATUS) -> Result<(), Self> {
        if status.is_ok() {
            Ok(())
        } else {
            let status = status.0;
            Err(Self(format!("NTSTATUS({status})")))
        }
    }
}

/// Conversion from a WindowsError to a WinCryptoError. The WinCryptoError
/// will include the windows error code in the message.
impl From<WindowsError> for WinCryptoError {
    fn from(err: WindowsError) -> Self {
        let code = err.code();
        Self(format!("WindowsError({code})"))
    }
}
