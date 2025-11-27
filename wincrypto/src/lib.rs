#[macro_use]
extern crate tracing;

use std::sync::Arc;
use std::{error::Error, fmt};
use windows::core::{Error as WindowsError, HRESULT};
use windows::Win32::Foundation::{NTSTATUS, WIN32_ERROR};
use windows::Win32::System::Rpc::{RPC_STATUS, RPC_S_OK};

mod cert;
pub use cert::*;

mod sha1;
pub use sha1::*;

mod sha256;
pub use sha256::*;

mod srtp;
pub use srtp::*;

mod dtls;
pub use dtls::*;

#[derive(Debug)]
pub enum WinCryptoError {
    Generic(String),
    Hresult(HRESULT),
    NtStatus(NTSTATUS),
    RpcStatus(RPC_STATUS),
    Win32Error(WIN32_ERROR),
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

    pub fn from_rpc_status(rpc_status: RPC_STATUS) -> Result<(), Self> {
        if rpc_status == RPC_S_OK {
            Ok(())
        } else {
            Err(Self::RpcStatus(rpc_status))
        }
    }
}

impl fmt::Display for WinCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic(message) => write!(f, "{}", message),
            Self::Hresult(hresult) => write!(f, "Hresult({})", hresult.0),
            Self::Win32Error(win32_error) => write!(f, "Win32Error({})", win32_error.0),
            Self::RpcStatus(rpc_status) => write!(f, "RpcStatus({})", rpc_status.0),
            Self::NtStatus(ntstatus) => write!(f, "NtStatus({})", ntstatus.0),
            Self::WindowsError(err) => write!(f, "{}", err),
        }
    }
}

impl Error for WinCryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Generic(_) => None,
            Self::Hresult(_) => None,
            Self::Win32Error(_) => None,
            Self::RpcStatus(_) => None,
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

/// Conversion from an &str to a WinCryptoError. The WinCryptoError
/// will include the message.
impl From<&str> for WinCryptoError {
    fn from(msg: &str) -> Self {
        Self::Generic(msg.to_string())
    }
}

/// Conversion from a String to a WinCryptoError. The WinCryptoError
/// will include the message.
impl From<String> for WinCryptoError {
    fn from(msg: String) -> Self {
        Self::Generic(msg)
    }
}

/// Conversion from a WIN32_ERROR to a WinCryptoError. The WinCryptoError
/// will include the message.
impl From<WIN32_ERROR> for WinCryptoError {
    fn from(win32_error: WIN32_ERROR) -> Self {
        Self::Win32Error(win32_error)
    }
}

/// Conversion from a HRESULT to a WinCryptoError. The WinCryptoError
/// will include the message.
impl From<HRESULT> for WinCryptoError {
    fn from(hresult: HRESULT) -> Self {
        Self::Hresult(hresult)
    }
}
