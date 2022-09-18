#![cfg_attr(fuzzing, feature(no_coverage))]

#[macro_use]
extern crate tracing;

use std::io;

use openssl::error::ErrorStack;
use thiserror::Error;

mod id;
pub use id::{Mid, Pt, SeqNo, SessionId, Ssrc, StreamId};

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
pub use srtp::{SRTCP_BLOCK_SIZE, SRTCP_OVERHEAD_SUFFIX};

mod rtcp;
pub use rtcp::*;

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

#[cfg(all(fuzzing, test))]
mod tests {
    use super::*;

    #[test]
    fn fuzz_rtcp_parse() {
        fn parse_rtcp(buf: &Vec<u8>) -> bool {
            let _ = Rtcp::read_packet(&buf);
            true
        }
        let result = fuzzcheck::fuzz_test(parse_rtcp).default_options().launch();
        assert!(!result.found_test_failure);
    }
}
