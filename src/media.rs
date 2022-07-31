//! Media (m-line) related stuff.

use crate::sdp::{Direction, MediaAttribute, MediaLine, MediaType, Proto, Setup};
use crate::util::random_id;

///
pub(crate) struct Media {
    /// The corresponding transceiver config in the m-line.
    media_line: MediaLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Kind when adding media.
pub enum MediaKind {
    /// Add audio media.
    Audio,
    /// Add video media.
    Video,
}

impl Media {
    pub fn new_data_channel(setup: Setup) -> Self {
        let mid = random_id::<3>().to_string();

        Media {
            media_line: MediaLine {
                typ: MediaType::Application,
                proto: Proto::Sctp,
                pts: vec![96], // TODO
                bw: None,
                attrs: vec![
                    // These are inserted later when creating the full SDP.
                    // a=ice-ufrag:HhS+
                    // a=ice-pwd:FhYTGhlAtKCe6KFIX8b+AThW
                    // a=ice-options:trickle
                    // a=fingerprint:sha-256 B4:12:1C:7C:7D:ED:F1:FA:61:07:57:9C:29:BE:58:E3:BC:41:E7:13:8E:7D:D3:9D:1F:94:6E:A5:23:46:94:23
                    MediaAttribute::Setup(setup),
                    MediaAttribute::Mid(mid),
                    MediaAttribute::SctpPort(5000), // TODO investigate this port
                    MediaAttribute::MaxMessageSize(262144), // TODO this value is from Safari
                ],
            },
        }
    }

    pub fn new_media(setup: Setup, kind: MediaKind, dir: Direction) -> Self {
        let mid = random_id::<3>().to_string();

        Media {
            media_line: MediaLine {
                typ: kind.into(),
                proto: Proto::Srtp,
                pts: vec![96], // TODO
                bw: None,
                attrs: vec![
                    // These are inserted later when creating the full SDP.
                    // a=ice-ufrag:HhS+
                    // a=ice-pwd:FhYTGhlAtKCe6KFIX8b+AThW
                    // a=ice-options:trickle
                    // a=fingerprint:sha-256 B4:12:1C:7C:7D:ED:F1:FA:61:07:57:9C:29:BE:58:E3:BC:41:E7:13:8E:7D:D3:9D:1F:94:6E:A5:23:46:94:23
                    MediaAttribute::Setup(setup),
                    MediaAttribute::Mid(mid),
                    // a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
                    // a=extmap:9 urn:ietf:params:rtp-hdrext:sdes:mid
                    dir.into(),
                    // a=msid:- 39a7c3c3-ab8c-4b25-a47b-db52d89c2db1
                    MediaAttribute::RtcpMuxOnly,
                ],
            },
        }
    }

    pub fn mid(&self) -> &str {
        self.media_line.mid()
    }

    pub fn media_line(&self) -> &MediaLine {
        &self.media_line
    }
}

impl From<MediaKind> for MediaType {
    fn from(v: MediaKind) -> Self {
        match v {
            MediaKind::Audio => MediaType::Audio,
            MediaKind::Video => MediaType::Video,
        }
    }
}
