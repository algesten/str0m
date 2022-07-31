use std::marker::PhantomData;
use std::mem;

use crate::media::Media;
use crate::sdp::Setup;
use crate::{state, Direction, MediaKind, Offer, Peer};

/// Possible states of a [`crate::ChangeSet`].
pub mod change_state {
    /// `ChangeSet` contains no changes.
    pub struct NoChange(());

    /// `ChangeSet` contains changes.
    pub struct Changed(());
}

/// Set of media changes to be applied to a [`crate::Peer`].
pub struct ChangeSet<PeerState, ChangeState> {
    /// The changes collected so far.
    pub(crate) changes: Changes,

    /// The peer that will receive the changes, once applied.
    peer: Peer<PeerState>,

    /// ChangeSet state. We require at least one change to allow `apply`.
    _ph: PhantomData<ChangeState>,
}

pub(crate) struct Changes(pub Vec<Change>);

pub(crate) enum Change {
    AddMedia(MediaKind, Direction),
    AddDataChannel,
}

impl<T, V> ChangeSet<T, V> {
    pub(crate) fn new(peer: Peer<T>) -> Self {
        ChangeSet {
            changes: Changes(vec![]),
            peer,
            _ph: PhantomData,
        }
    }

    fn _add_media<W>(mut self, kind: MediaKind, dir: Direction) -> ChangeSet<T, W> {
        self.changes.0.push(Change::AddMedia(kind, dir));
        self.into_state()
    }

    fn _add_data_channel<W>(mut self) -> ChangeSet<T, W> {
        self.changes.0.push(Change::AddDataChannel);
        self.into_state()
    }

    fn _apply<U>(self) -> (Offer, Peer<U>) {
        let mut peer = self.peer;
        let offer = peer.set_pending_changes(self.changes);
        (offer, peer.into_state())
    }

    fn into_state<W>(self) -> ChangeSet<T, W> {
        // SAFETY: this is fine, because we only change the PhantomData.
        unsafe { mem::transmute(self) }
    }
}

impl<ChangeState> ChangeSet<state::Init, ChangeState> {
    /// Adds audio/video media.
    pub fn add_media(
        self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Init, change_state::Changed> {
        self._add_media(kind, dir)
    }

    /// Adds a data channel.
    pub fn add_data_channel(self) -> ChangeSet<state::Init, change_state::Changed> {
        self._add_data_channel()
    }
}

impl ChangeSet<state::Init, change_state::Changed> {
    /// Applies these changes to the [`crate::Peer`].
    ///
    /// This is only available once some changes have been made.
    pub fn apply(self) -> (Offer, Peer<state::InitialOffering>) {
        self._apply()
    }
}

impl<ChangeState> ChangeSet<state::Connected, ChangeState> {
    /// Adds audio/video media.
    pub fn add_media(
        self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Connected, change_state::Changed> {
        self._add_media(kind, dir)
    }

    /// Adds a data channel.
    pub fn add_data_channel(self) -> ChangeSet<state::Connected, change_state::Changed> {
        self._add_data_channel()
    }

    // TODO: more changes here (i.e. changing direction etc).
}

impl ChangeSet<state::Connected, change_state::Changed> {
    /// Applies these changes to the [`crate::Peer`].
    ///
    /// This is only available once some changes have been made.
    pub fn apply(self) -> (Offer, Peer<state::InitialOffering>) {
        self._apply()
    }
}

impl Changes {
    pub fn new_media_lines(&self, setup: Setup) -> Vec<Media> {
        self.0
            .iter()
            .filter_map(|c| match c {
                Change::AddMedia(kind, dir) => Some(Media::new_media(setup, *kind, *dir)),
                Change::AddDataChannel => Some(Media::new_data_channel(setup)),
                // _ => None,
            })
            .collect()
    }
}
