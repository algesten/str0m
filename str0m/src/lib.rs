#[macro_use]
extern crate tracing;

use std::io;

use thiserror::Error;

mod media;

/// Errors for the whole Rtc engine.
#[derive(Debug, Error)]
pub enum RtcError {
    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub struct Rtc {
    //
}
