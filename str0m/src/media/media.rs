use std::time::Instant;

use rtp::{Direction, MLineIdx, Mid, Pt, RtpHeader, SeqNo, Ssrc};

use super::receiver::ReceiverRegister;
use super::CodecParams;

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
    pub last_used: Instant,
    pub register: ReceiverRegister,
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

    pub(crate) fn get_source_rx(&mut self, header: &RtpHeader) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc == header.ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.sources_rx.push(ReceiverSource::from(header));
            self.sources_rx.last_mut().unwrap()
        }
    }

    pub(crate) fn get_params(&self, header: &RtpHeader) -> Option<&CodecParams> {
        let pt = header.payload_type;
        self.params
            .iter()
            .find(|p| p.inner().codec.pt == pt || p.inner().resend == Some(pt))
    }
}

impl ReceiverSource {
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
}

impl<'a> From<&'a RtpHeader> for ReceiverSource {
    fn from(v: &'a RtpHeader) -> Self {
        let base_seq = v.sequence_number(None);
        ReceiverSource {
            ssrc: v.ssrc,
            register: ReceiverRegister::new(base_seq),
            last_used: Instant::now(), // this will be overwritten
        }
    }
}
