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

/// Errors from parsing network data.
#[derive(Debug)]
pub enum NetError {
    /// Some STUN protocol error.
    Stun(StunError),

    /// A wrapped IO error.
    Io(io::Error),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Stun(err) => write!(f, "{}", err),
            NetError::Io(err) => write!(f, "{}", err),
        }
    }
}

impl Error for NetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NetError::Stun(err) => Some(err),
            NetError::Io(err) => Some(err),
        }
    }
}

impl From<StunError> for NetError {
    fn from(err: StunError) -> Self {
        NetError::Stun(err)
    }
}

impl From<io::Error> for NetError {
    fn from(err: io::Error) -> Self {
        NetError::Io(err)
    }
}
