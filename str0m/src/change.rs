use rtp::{Direction, Mid};
use sdp::Offer;

use crate::MediaKind;
use crate::Rtc;

pub(crate) struct Changes(pub Vec<Change>);

pub(crate) enum Change {
    AddMedia(Mid, MediaKind, Direction),
    AddDataChannel(Mid),
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

    pub fn add_media(mut self, kind: MediaKind, dir: Direction) -> Self {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddMedia(mid, kind, dir));
        self
    }

    pub fn add_data_channel(mut self) -> Self {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddDataChannel(mid));
        self
    }

    pub fn apply(self) -> Offer {
        self.rtc.set_changes(self.changes);
        todo!()
    }
}
