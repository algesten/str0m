use std::marker::PhantomData;

use rtp::{Direction, Mid};

use crate::state;
use crate::Rtc;

pub mod change {
    pub struct Unchanged(());
    pub struct Changed(());
}

pub(crate) struct Changes(pub Vec<Change>);

pub(crate) enum Change {
    AddMedia(Mid, MediaKind, Direction),
    AddDataChannel(Mid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Kind when adding media.
pub enum MediaKind {
    /// Add audio media.
    Audio,
    /// Add video media.
    Video,
}

pub struct ChangeSet<S, C> {
    changes: Changes,
    rtc: Rtc<S>,
    _ph: PhantomData<C>,
}

impl<S, C> ChangeSet<S, C> {
    pub(crate) fn new(rtc: Rtc<S>) -> Self {
        ChangeSet {
            changes: Changes(vec![]),
            rtc,
            _ph: PhantomData,
        }
    }

    fn into_change_state<T>(self) -> ChangeSet<S, T> {
        ChangeSet {
            changes: self.changes,
            rtc: self.rtc,
            _ph: PhantomData,
        }
    }

    fn do_add_media(&mut self, kind: MediaKind, dir: Direction) -> Mid {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddMedia(mid, kind, dir));
        mid
    }

    fn do_add_data_channel(&mut self) -> Mid {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddDataChannel(mid));
        mid
    }
}

impl ChangeSet<state::Inited, change::Unchanged> {
    pub fn add_media(
        mut self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Inited, change::Changed> {
        self.do_add_media(kind, dir);
        self.into_change_state()
    }

    pub fn add_data_channel(mut self) -> ChangeSet<state::Inited, change::Changed> {
        self.do_add_data_channel();
        self.into_change_state()
    }
}

impl ChangeSet<state::Inited, change::Changed> {
    pub fn add_media(
        mut self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Inited, change::Changed> {
        self.do_add_media(kind, dir);
        self.into_change_state()
    }

    pub fn add_data_channel(mut self) -> ChangeSet<state::Inited, change::Changed> {
        self.do_add_data_channel();
        self.into_change_state()
    }

    pub fn apply(self) -> Rtc<state::FirstOffer> {
        self.rtc.into_state()
    }
}

impl ChangeSet<state::Connected, change::Unchanged> {
    pub fn add_media(
        mut self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Connected, change::Changed> {
        self.do_add_media(kind, dir);
        self.into_change_state()
    }

    pub fn add_data_channel(mut self) -> ChangeSet<state::Connected, change::Changed> {
        self.do_add_data_channel();
        self.into_change_state()
    }
}

impl ChangeSet<state::Connected, change::Changed> {
    pub fn add_media(
        mut self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Connected, change::Changed> {
        self.do_add_media(kind, dir);
        self.into_change_state()
    }

    pub fn add_data_channel(mut self) -> ChangeSet<state::Connected, change::Changed> {
        self.do_add_data_channel();
        self.into_change_state()
    }

    pub fn apply(self) -> Rtc<state::Offering> {
        self.rtc.into_state()
    }
}
