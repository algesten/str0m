use rtp::{Direction, Mid};
use sdp::Offer;

use crate::media::MediaKind;
use crate::Rtc;

pub struct Changes(pub Vec<Change>);

pub enum Change {
    AddMedia(Mid, MediaKind, Direction),
    AddChannel(Mid),
}

pub struct ChangeSet<'a> {
    rtc: &'a mut Rtc,
    changes: Changes,
}

impl<'a> ChangeSet<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        ChangeSet {
            rtc,
            changes: Changes(vec![]),
        }
    }

    pub fn add_media(&mut self, kind: MediaKind, dir: Direction) -> Mid {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddMedia(mid, kind, dir));
        mid
    }

    pub fn add_channel(&mut self) -> Mid {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddChannel(mid));
        mid
    }

    pub fn apply(self) -> Offer {
        self.rtc.set_changes(self.changes)
    }
}
