use rtp::{MLineIdx, Mid};

pub struct Channel {
    mid: Mid,
    m_line_idx: MLineIdx,
}

impl Channel {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn m_line_idx(&self) -> MLineIdx {
        self.m_line_idx
    }
}
