use std::time::{Duration, Instant};

use rtp::{MLineIdx, RtcpFb, RtpHeader};

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

// How often we remove unused senders/receivers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

pub struct Media {
    mid: Mid,
    kind: MediaKind,
    m_line_idx: MLineIdx,
    dir: Direction,
    params: Vec<CodecParams>,
    sources_rx: Vec<ReceiverSource>,
    sources_tx: Vec<SenderSource>,
    last_cleanup: Instant,
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
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc() == header.ssrc);

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

    pub(crate) fn has_nack(&mut self) -> bool {
        self.sources_rx.iter_mut().any(|s| s.has_nack())
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if now >= self.cleanup_at() {
            self.last_cleanup = now;
            self.sources_rx.retain(|s| s.is_alive(now));
        }
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
        Some(self.cleanup_at())
    }

    fn cleanup_at(&self) -> Instant {
        self.last_cleanup + CLEANUP_INTERVAL
    }

    /// Creates sender info and receiver reports for all senders/receivers
    pub(crate) fn create_regular_feedback(&mut self, feedback: &mut Vec<RtcpFb>) {
        for s in &mut self.sources_tx {
            feedback.push(s.create_sender_info());
        }
        for s in &mut self.sources_rx {
            feedback.push(s.create_receiver_report());
        }
    }

    // Creates nack reports for receivers, if needed.
    pub(crate) fn create_nack(&mut self, feedback: &mut Vec<RtcpFb>) {
        for s in &mut self.sources_rx {
            if let Some(nack) = s.create_nack() {
                feedback.push(nack);
            }
        }
    }
}
