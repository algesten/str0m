//! Media (m-line) related stuff.

use crate::sdp::{MediaAttribute, MediaLine, MediaType, Proto};

///
pub struct Media {
    /// The corresponding transceiver config in the m-line.
    media_line: MediaLine,

    /// Whether this transceiver has been negotiated with the remote side.
    need_negotiating: bool,
}

impl Media {
    pub fn new(typ: MediaType) -> Self {
        Media {
            media_line: MediaLine {
                typ,
                proto: Proto::Srtp,
                pts: vec![96],
                bw: None,
                attrs: vec![MediaAttribute::RtcpMuxOnly],
            },

            need_negotiating: false,
        }
    }

    pub fn mid(&self) -> &str {
        self.media_line.mid()
    }

    pub fn media_line(&self) -> &MediaLine {
        &self.media_line
    }

    pub fn include_in_local_sdp(&self) -> bool {
        !self.need_negotiating
    }

    pub fn include_in_remote_sdp(&self) -> bool {
        self.need_negotiating
    }
}
