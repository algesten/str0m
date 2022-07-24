use combine::error::StringStreamError;
use openssl::error::ErrorStack;
use std::fmt;
use std::io;

/// Error states of str0m RTC.
pub enum Error {
    /// The UDP data packet is not recognized.
    UnknownUdpData,
    /// Parsing STUN packet failed.
    StunParse(String),
    /// Stun handling failed, such as checking integrity or verifying password.
    StunError(String),
    /// Parsing of SDP failed.
    SdpParse(String),
    /// Some error from OpenSSL layer (used for DTLS).
    OpenSsl(ErrorStack),
    /// Generic std::io::Error.
    Io(io::Error),
}

impl Error {
    pub(crate) fn is_fatal(&self) -> bool {
        use Error::*;
        match self {
            UnknownUdpData => false,
            StunParse(_) => false, // UDP packet might be damaged
            StunError(_) => true,  // Bad STUN state, better abort.
            SdpParse(_) => true,   // If we can't understand the SDP, we can't continue.
            OpenSsl(_) => true,    // DTLS setup errors
            Io(_) => true,         // For async we should explicitly handle WouldBlock.
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            UnknownUdpData => write!(f, "Unknown UDP data"),
            StunParse(v) => write!(f, "STUN parse failed: {}", v),
            StunError(v) => write!(f, "STUN handling failed: {}", v),
            SdpParse(v) => write!(f, "SDP parse failed: {}", v),
            OpenSsl(v) => write!(f, "openssl: {}", v),
            Io(v) => write!(f, "io: {}", v),
        }
    }
}

impl From<StringStreamError> for Error {
    fn from(e: StringStreamError) -> Self {
        Error::SdpParse(e.to_string())
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Error::OpenSsl(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
