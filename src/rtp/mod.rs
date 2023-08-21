#![cfg_attr(fuzzing, feature(no_coverage))]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]

use std::io;

use openssl::error::ErrorStack;
use thiserror::Error;

mod id;
pub use id::{Mid, Pt, Rid, SeqNo, SessionId, Ssrc};

mod ext;
pub use ext::{Extension, ExtensionMap, ExtensionValues, VideoOrientation};

mod dir;
pub use dir::Direction;

mod mtime;
pub(crate) use mtime::InstantExt;
pub use mtime::MediaTime;

mod header;
pub use header::RtpHeader;
pub(crate) use header::{extend_u16, extend_u32, extend_u8};

mod srtp;
pub(crate) use srtp::SrtpContext;
pub(crate) use srtp::{SRTCP_OVERHEAD, SRTP_BLOCK_SIZE, SRTP_OVERHEAD};

mod rtcp;
pub use rtcp::*;

mod bandwidth;
pub use bandwidth::{Bitrate, DataSize};

// Max in the RFC 3550 is 255 bytes, we limit it to be modulus 16 for SRTP and to match libWebRTC
pub const MAX_BLANK_PADDING_PAYLOAD_SIZE: usize = 224;

/// Errors that can arise in RTP.
#[derive(Debug, Error)]
pub enum RtpError {
    /// Some error from OpenSSL layer (used for SRTP).
    #[error("{0}")]
    OpenSsl(#[from] ErrorStack),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    /// Failed to parse RTP header.
    #[error("Failed to parse RTP header")]
    ParseHeader,
}

#[cfg(all(fuzzing, test))]
mod tests {
    use fuzzcheck::*;
    use serde::{Deserialize, Serialize};
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn fuzz_rtp_header_parse() {
        fn parse_rtp(buf: &Vec<u8>) -> bool {
            let e = ExtensionMap::standard();
            let _ = RtpHeader::parse(&buf, &e);
            true
        }
        let result = fuzzcheck::fuzz_test(parse_rtp).default_options().launch();
        assert!(!result.found_test_failure);
    }

    #[test]
    fn fuzz_rtcp_parse() {
        fn parse_rtcp(buf: &Vec<u8>) -> bool {
            let _ = Rtcp::read_packet(&buf);
            true
        }
        let result = fuzzcheck::fuzz_test(parse_rtcp).default_options().launch();
        assert!(!result.found_test_failure);
    }

    #[test]
    fn fuzz_twcc() {
        #[derive(Debug, Clone, DefaultMutator, Serialize, Deserialize)]
        enum Operation {
            Register(u16, u32),
            BuildReport(u16),
        }
        fn apply_operations(opers: &Vec<Operation>) {
            use rtcp::TwccRecvRegister;
            let now = Instant::now();
            let mut reg = TwccRecvRegister::new(100);
            for o in opers {
                match o {
                    Operation::Register(seq_no, micros) => {
                        reg.update_seq(
                            (*seq_no as u64).into(),
                            now + Duration::from_micros(*micros as u64),
                        );
                    }
                    Operation::BuildReport(max_bytes) => {
                        let report = match reg.build_report(*max_bytes as usize) {
                            Some(v) => v,
                            None => return,
                        };

                        let mut buf = vec![0_u8; 1500];
                        let n = report.write_to(&mut buf[..]);
                        buf.truncate(n);

                        let header: RtcpHeader = match (&buf[..]).try_into() {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let parsed: Twcc = match (&buf[4..]).try_into() {
                            Ok(v) => v,
                            Err(_) => return,
                        };

                        assert_eq!(header, report.header());
                        assert_eq!(parsed, report);
                    }
                }
            }
        }
        let result = fuzzcheck::fuzz_test(apply_operations)
            .default_options()
            .launch();
        println!("{:?}", result.reason_for_stopping);
        assert!(!result.found_test_failure);
    }
}
