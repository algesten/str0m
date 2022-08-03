//!

#[macro_use]
extern crate tracing;

use thiserror::Error;

mod id;

mod ice;
use ice::StunError;

mod sdp;
use sdp::SdpError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Stun(#[from] StunError),

    #[error("{0}")]
    Sdp(#[from] SdpError),
}
