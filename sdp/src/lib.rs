#[macro_use]
extern crate tracing;

use combine::error::StringStreamError;
use thiserror::Error;

mod data;
pub use data::{MediaLine, MediaType, Mid, Sdp, SessionId};

mod parser;

#[derive(Debug, Error)]
pub enum SdpError {
    #[error("SDP parse: {0}")]
    Parse(#[from] StringStreamError),

    #[error("SDP inconsistent: {0}")]
    Inconsistent(String),
}
