use std::error::Error;
use std::fmt;
use std::io;

/// A STUN message could not be parsed or processed.
#[derive(Debug)]
pub enum StunError {
    /// A STUN message could not be parsed.
    Parse(String),

    /// An IO error occurred while handling a STUN message.
    Io(io::Error),
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StunError::Parse(msg) => write!(f, "STUN parse error: {}", msg),
            StunError::Io(err) => write!(f, "STUN io: {}", err),
        }
    }
}

impl Error for StunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            StunError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for StunError {
    fn from(err: io::Error) -> Self {
        StunError::Io(err)
    }
}
