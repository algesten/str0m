#[macro_use]
extern crate tracing;

use windows::{core::Error as WindowsError, Win32::Foundation::NTSTATUS};

mod cert;
pub use cert::*;

mod sha1;
pub use sha1::*;

mod srtp;
pub use srtp::*;

mod dtls;
pub use dtls::*;

#[derive(Debug)]
pub enum WinCryptoError {
    NtStatus(NTSTATUS),
    WindowsError(WindowsError),
}

impl WinCryptoError {
    /// Conversion function from NTSTATUS to Result. The result will
    /// be Ok(()) if the NTSTATUS indicates OK, otherwise it will be
    /// an Err with the NTSTATUS.
    pub fn from_ntstatus(ntstatus: NTSTATUS) -> Result<(), Self> {
        if ntstatus.is_ok() {
            Ok(())
        } else {
            Err(Self::NtStatus(ntstatus))
        }
    }
}

impl fmt::Display for WinCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NtStatus(ntstatus) => write!(f, "{}", ntstatus),
            Self::WindowsError(err) => write!(f, "{}", err),
        }
    }
}

impl Error for NetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NtStatus(_) => None,
            Self::WindowsError(err) => Some(err),
        }
    }
}

/// Conversion from a WindowsError to a WinCryptoError. The WinCryptoError
/// will include the windows error code in the message.
impl From<WindowsError> for WinCryptoError {
    fn from(err: WindowsError) -> Self {
        Self::WindowsError(err)
    }
}
