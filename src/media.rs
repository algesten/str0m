//! Media (m-line) related stuff.

use crate::sdp::{Direction, MediaAttribute, MediaLine, MediaType, Proto, Setup};
use crate::util::random_id;

///
pub struct Media {
    /// The corresponding transceiver config in the m-line.
    media_line: MediaLine,

    /// Whether this transceiver has been negotiated with the remote side.
    need_negotiating: bool,
}

impl Media {
    pub fn new(typ: MediaType, direction: Direction) -> Self {
        let mid = random_id::<3>().to_string();

        // TODO: this should not be hard coded.
        Media {
            media_line: MediaLine {
                typ,
                proto: Proto::Srtp,
                pts: vec![96],
                bw: None,
                attrs: vec![
                    // These are inserted later when creating the full SDP.
                    // a=ice-ufrag:HhS+
                    // a=ice-pwd:FhYTGhlAtKCe6KFIX8b+AThW
                    // a=ice-options:trickle
                    // a=fingerprint:sha-256 B4:12:1C:7C:7D:ED:F1:FA:61:07:57:9C:29:BE:58:E3:BC:41:E7:13:8E:7D:D3:9D:1F:94:6E:A5:23:46:94:23
                    MediaAttribute::Setup(Setup::ActPass),
                    MediaAttribute::Mid(mid),
                    // a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
                    // a=extmap:9 urn:ietf:params:rtp-hdrext:sdes:mid
                    direction.into(),
                    // a=msid:- 39a7c3c3-ab8c-4b25-a47b-db52d89c2db1
                    MediaAttribute::RtcpMuxOnly,
                ],
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
