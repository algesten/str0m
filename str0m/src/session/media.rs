use std::time::Instant;

use rtp::{Direction, MLineIdx, Mid, RtpHeader, Ssrc};

use crate::CodecParams;

use super::MediaKind;

pub struct Media {
    mid: Mid,
    kind: MediaKind,
    m_line_idx: MLineIdx,
    dir: Direction,
    params: Vec<CodecParams>,
    sources_rx: Vec<Source>,
    sources_tx: Vec<Source>,
}

pub struct Source {
    pub ssrc: Ssrc,
    pub seq_no: u64,
    pub last_used: Instant,
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

    pub(crate) fn get_source(&mut self, header: &RtpHeader) -> &mut Source {
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc == header.ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.sources_rx.push(Source::from(header));
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

impl<'a> From<&'a RtpHeader> for Source {
    fn from(v: &'a RtpHeader) -> Self {
        Source {
            ssrc: v.ssrc,
            seq_no: v.sequence_number(None),
            last_used: Instant::now(),
        }
    }
}
