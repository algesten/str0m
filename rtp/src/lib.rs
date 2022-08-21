#[macro_use]
extern crate tracing;

use std::io;

use openssl::error::ErrorStack;
use thiserror::Error;

mod id;
pub use id::{Mid, Pt, SeqNo, SessionId, Ssrc, StreamId};
// TODO: Move this to some other crate.
pub use id::MLineIdx;

mod ext;
pub use ext::{ExtMap, Extension, Extensions};

mod dir;
pub use dir::Direction;

mod mtime;
pub use mtime::MediaTime;

mod header;
pub use header::RtpHeader;

mod srtp;
pub use srtp::{SrtpContext, SrtpKey};

mod rtcp;
pub use rtcp::{ReportBlock, RtcpHeader, RtcpType};

/// Errors that can arise in RTP.
#[derive(Debug, Error)]
pub enum RtpError {
    /// Some error from OpenSSL layer (used for SRTP).
    #[error("{0}")]
    OpenSsl(#[from] ErrorStack),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("Differing ext id to ext type: {0} != {1}")]
    ExtMapDiffers(Extension, Extension),
}
