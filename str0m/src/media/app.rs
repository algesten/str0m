use rtp::Mid;
use sdp::MediaLine;

/// m=application m-line. There can only be one of these in the SDP.
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

    pub(crate) fn apply_changes(&mut self, _m: &MediaLine) {
        // nothing can be changed on the m-line for application, right?
    }
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
