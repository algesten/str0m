mod id;
pub(crate) use id::MidRid;
pub use id::{Mid, Pt, Rid, SeqNo, SessionId, Ssrc};

mod ext;
pub use ext::{Extension, ExtensionMap, ExtensionSerializer, ExtensionValues};
pub use ext::{UserExtensionValues, VideoOrientation};

mod dir;
pub use dir::Direction;

mod mtime;
pub use mtime::Frequency;
pub use mtime::MediaTime;

mod header;
pub use header::RtpHeader;
pub(crate) use header::{extend_u15, extend_u16, extend_u32, extend_u7, extend_u8};

mod srtp;
pub(crate) use srtp::SrtpContext;
pub(crate) use srtp::{SRTCP_OVERHEAD, SRTP_BLOCK_SIZE, SRTP_OVERHEAD};

mod rtcp;
pub use rtcp::*;

mod bandwidth;
pub use bandwidth::{Bitrate, DataSize};

// Max in the RFC 3550 is 255 bytes, we limit it to be modulus 16 for SRTP and to match libWebRTC
pub const MAX_BLANK_PADDING_PAYLOAD_SIZE: usize = 240;

/// Errors that can arise in RTP.
mod error;
pub use error::RtpError;
