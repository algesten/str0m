use rtp::{MLineIdx, Mid};
use sdp::MediaLine;

pub struct Channel {
    mid: Mid,
    m_line_idx: MLineIdx,
}

impl Channel {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub(crate) fn m_line_idx(&self) -> MLineIdx {
        self.m_line_idx
    }

    pub(crate) fn apply_changes(&mut self, m: &MediaLine) {
        todo!()
    }
}

impl<'a> From<(&'a MediaLine, MLineIdx)> for Channel {
    fn from((l, m_line_idx): (&'a MediaLine, MLineIdx)) -> Self {
        Channel {
            mid: l.mid(),
            m_line_idx,
        }
    }
}
