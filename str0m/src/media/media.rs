use std::time::{Duration, Instant};

use rtp::{Direction, MLineIdx, Mid, Pt, RtpHeader, SeqNo, Ssrc};

use crate::not_happening;
use crate::util::Soonest;

use super::receiver::ReceiverRegister;
use super::CodecParams;

const SSRC_ALIVE: Duration = Duration::from_millis(10_000);

// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
const RR_INTERVAL: Duration = Duration::from_millis(4000);
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(250);

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

pub struct SenderSource {
    pub ssrc: Ssrc,
    pub last_used: Instant,
}

pub struct ReceiverSource {
    pub ssrc: Ssrc,
    pub register: ReceiverRegister,
    pub last_used: Instant,
    pub last_rr: Instant,
    pub last_nack: Instant,
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

impl ReceiverSource {
    pub fn new(header: &RtpHeader, now: Instant) -> Self {
        let base_seq = header.sequence_number(None);
        ReceiverSource {
            ssrc: header.ssrc,
            register: ReceiverRegister::new(base_seq),
            last_used: now,
            last_rr: now,
            last_nack: now,
        }
    }

    pub fn update(&mut self, now: Instant, header: &RtpHeader, clock_rate: u32) -> SeqNo {
        self.last_used = now;

        let seq_no = header.sequence_number(Some(self.register.max_seq()));

        self.register.update_seq(seq_no);
        self.register.update_time(now, header.timestamp, clock_rate);

        seq_no
    }

    pub fn is_valid(&self) -> bool {
        self.register.is_valid()
    }

    pub fn poll_timeout(&mut self) -> Instant {
        // cleanup when it's time to remove the SSRC receiver.
        let cleanup_at = self.last_used + SSRC_ALIVE;

        // next regular receiver report
        let rr_at = self.last_rr + RR_INTERVAL;

        // if we need to send a nack.
        let nack_at = if self.register.has_nack_report() {
            self.last_nack + NACK_MIN_INTERVAL
        } else {
            not_happening()
        };

        [cleanup_at, rr_at, nack_at].into_iter().min().unwrap()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        //
    }
}
