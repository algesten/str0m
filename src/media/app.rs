use crate::rtp::Mid;
use crate::sdp::MediaLine;

/// App media. There can only be one of these in the session.
#[derive(Debug)]
pub struct App {
    mid: Mid,
    index: usize,
}

impl App {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn apply_changes(&mut self, _m: &MediaLine) {}
}

impl Default for App {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
        }
    }
}

impl From<(Mid, usize)> for App {
    fn from((mid, index): (Mid, usize)) -> Self {
        App { mid, index }
    }
}
