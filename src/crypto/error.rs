use std::error::Error;
use std::fmt;
use std::io;

/// Errors that can arise in DTLS.
#[derive(Debug)]
pub enum CryptoError {
    /// Some error from OpenSSL layer (used for DTLS).
    #[cfg(feature = "openssl")]
    OpenSsl(openssl::error::ErrorStack),

    /// Some error from OpenSSL layer (used for DTLS).
    #[cfg(all(feature = "wincrypto", target_os = "windows"))]
    WinCrypto(super::wincrypto::WinCryptoError),

    /// Other IO errors.
    Io(io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "openssl")]
            CryptoError::OpenSsl(err) => write!(f, "{}", err),
            #[cfg(all(feature = "wincrypto", target_os = "windows"))]
            CryptoError::WinCrypto(err) => write!(f, "{}", err),
            CryptoError::Io(err) => write!(f, "{}", err),
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "openssl")]
            CryptoError::OpenSsl(err) => Some(err),
            #[cfg(all(feature = "wincrypto", target_os = "windows"))]
            CryptoError::WinCrypto(err) => Some(err),
            CryptoError::Io(err) => Some(err),
        }
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        CryptoError::OpenSsl(err)
    }
}

#[cfg(all(feature = "wincrypto", target_os = "windows"))]
impl From<super::wincrypto::WinCryptoError> for CryptoError {
    fn from(err: super::wincrypto::WinCryptoError) -> Self {
        CryptoError::WinCrypto(err)
    }
}

impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> Self {
        CryptoError::Io(err)
    }
}

/// Errors that can arise in DTLS.
#[derive(Debug)]
pub enum DtlsError {
    /// Error arising in the crypto
    CryptoError(CryptoError),

    /// Other IO errors.
    Io(io::Error),
}

impl fmt::Display for DtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DtlsError::CryptoError(err) => write!(f, "{}", err),
            DtlsError::Io(err) => write!(f, "{}", err),
        }
    }
}

impl Error for DtlsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DtlsError::CryptoError(err) => Some(err),
            DtlsError::Io(err) => Some(err),
        }
    }
}

impl From<io::Error> for DtlsError {
    fn from(err: io::Error) -> Self {
        DtlsError::Io(err)
    }
}

impl From<CryptoError> for DtlsError {
    fn from(err: CryptoError) -> Self {
        DtlsError::CryptoError(err)
    }
}
