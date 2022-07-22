use std::fmt;

use combine::error::StringStreamError;

pub enum Error {
    SdpParse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            SdpParse(v) => write!(f, "SDP parse failed: {}", v),
        }
    }
}

impl From<StringStreamError> for Error {
    fn from(e: StringStreamError) -> Self {
        Error::SdpParse(e.to_string())
    }
}
