#[macro_use]
extern crate tracing;

use std::io;

use openssl::error::ErrorStack;
use thiserror::Error;

mod id;
pub use id::{CName, Mid, Pt, Ssrc};

mod ext;
pub use ext::{ExtMap, RtpExtensionType};

mod mtime;
pub use mtime::MediaTime;

mod r;
pub use r::RtpHeader;

mod srtp;
pub use srtp::{SrtpContext, SrtpKey};

mod rtcp;

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
    ExtMapDiffers(RtpExtensionType, RtpExtensionType),
}

pub struct RtpSession {
    cname: CName,
}

pub struct Endpoint {}
