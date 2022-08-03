//!

#[macro_use]
extern crate tracing;

use thiserror::Error;

mod id;

mod ice;
pub use ice::{Candidate, IceAgent, StunError};

mod sdp;
pub use sdp::SdpError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Stun(#[from] StunError),

    #[error("{0}")]
    Sdp(#[from] SdpError),
}
