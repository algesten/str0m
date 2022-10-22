use rtp::Mid;
use sdp::MediaLine;

#[derive(Debug)]
pub struct Channel {
    mid: Mid,
    index: usize,
}

impl Channel {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn apply_changes(&mut self, _m: &MediaLine) {
        // nothing can be changed on a datachannel, right?
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
        }
    }
}

impl From<(Mid, usize)> for Channel {
    fn from((mid, index): (Mid, usize)) -> Self {
        Channel {
            mid,
            index,
            ..Default::default()
        }
    }
}
