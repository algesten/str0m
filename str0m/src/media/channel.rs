use rtp::{MLineIdx, Mid};
use sdp::MediaLine;

pub struct Channel {
    mid: Mid,
    m_line_idx: MLineIdx,
}

impl Channel {
    pub(crate) fn new(mid: Mid) -> Self {
        Channel {
            mid,
            m_line_idx: 0.into(),
        }
    }

    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub(crate) fn m_line_idx(&self) -> MLineIdx {
        self.m_line_idx
    }

    pub(crate) fn apply_changes(&mut self, _m: &MediaLine) {
        // nothing can be changed on a datachannel, right?
    }
}

impl<'a> From<(&'a MediaLine, MLineIdx)> for Channel {
    fn from((l, m_line_idx): (&'a MediaLine, MLineIdx)) -> Self {
        let mut c = Channel::new(l.mid());
        c.m_line_idx = m_line_idx;
        c
    }
}
