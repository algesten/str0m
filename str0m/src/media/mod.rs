use std::time::Instant;

use rtp::{MLineIdx, RtpHeader};

pub use rtp::{Direction, Mid, Pt};
pub use sdp::{Codec, FormatParams};

mod codec;
pub use codec::CodecParams;

mod channel;
pub use channel::Channel;

mod receiver;
use receiver::ReceiverSource;

mod sender;
use sender::SenderSource;

pub struct Media {
    mid: Mid,
    kind: MediaKind,
    m_line_idx: MLineIdx,
    dir: Direction,
    params: Vec<CodecParams>,
    sources_rx: Vec<ReceiverSource>,
    sources_tx: Vec<SenderSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Types of media.
pub enum MediaKind {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
}

impl Media {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub(crate) fn kind(&self) -> MediaKind {
        self.kind
    }

    pub(crate) fn m_line_idx(&self) -> MLineIdx {
        self.m_line_idx
    }

    pub fn direction(&self) -> Direction {
        self.dir
    }

    pub fn codecs(&self) -> &[CodecParams] {
        &self.params
    }

    pub fn write(&mut self, pt: Pt, data: &[u8]) {
        //
    }

    pub(crate) fn get_source_rx(
        &mut self,
        header: &RtpHeader,
        now: Instant,
    ) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc == header.ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.sources_rx.push(ReceiverSource::new(header, now));
            self.sources_rx.last_mut().unwrap()
        }
    }

    pub(crate) fn get_params(&self, header: &RtpHeader) -> Option<&CodecParams> {
        let pt = header.payload_type;
        self.params
            .iter()
            .find(|p| p.inner().codec.pt == pt || p.inner().resend == Some(pt))
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
        self.sources_rx.iter_mut().map(|s| s.poll_timeout()).min()
    }
}
