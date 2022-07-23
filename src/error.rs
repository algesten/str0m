use std::fmt;

use combine::error::StringStreamError;

pub enum Error {
    UnknownUdpData,
    StunParse(String),
    StunError(String),
    SdpParse(String),
}

impl Error {
    pub(crate) fn is_fatal(&self) -> bool {
        use Error::*;
        match self {
            UnknownUdpData => false,
            StunParse(_) => false, // UDP packet might be damaged
            StunError(_) => true,  // Bad STUN state, better abort.
            SdpParse(_) => true,   // If we can't understand the SDP, we can't continue.
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
        }
    }
}

impl From<StringStreamError> for Error {
    fn from(e: StringStreamError) -> Self {
        Error::SdpParse(e.to_string())
    }
}
