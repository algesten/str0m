use std::error::Error;
use std::fmt;

/// Errors from the ICE agent.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum IceError {
    BadCandidate(String),
}

impl fmt::Display for IceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IceError::BadCandidate(msg) => write!(f, "ICE bad candidate: {}", msg),
        }
    }
}

impl Error for IceError {}
