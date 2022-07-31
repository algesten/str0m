use std::marker::PhantomData;
use std::mem;

use crate::media::Media;
use crate::sdp::Setup;
use crate::{state, Direction, MediaKind, Offer, Peer};

use self::change_state::Changed;

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

    fn do_add_media<W>(mut self, kind: MediaKind, dir: Direction) -> ChangeSet<T, W> {
        self.changes.0.push(Change::AddMedia(kind, dir));
        self.into_state()
    }

    fn do_add_data_channel<W>(mut self) -> ChangeSet<T, W> {
        self.changes.0.push(Change::AddDataChannel);
        self.into_state()
    }

    fn do_apply<U>(self) -> (Offer, Peer<U>) {
        let mut peer = self.peer;
        let offer = peer.set_pending_changes(self.changes);
        (offer, peer.into_state())
    }

    fn into_state<W>(self) -> ChangeSet<T, W> {
        // SAFETY: this is fine, because we only change the PhantomData.
        unsafe { mem::transmute(self) }
    }
}

impl<Any> ChangeSet<state::Init, Any> {
    /// Adds audio/video media.
    pub fn add_media(self, kind: MediaKind, dir: Direction) -> ChangeSet<state::Init, Changed> {
        self.do_add_media(kind, dir)
    }

    /// Adds a data channel.
    pub fn add_data_channel(self) -> ChangeSet<state::Init, Changed> {
        self.do_add_data_channel()
    }
}

impl ChangeSet<state::Init, Changed> {
    /// Applies these changes to the [`crate::Peer`].
    ///
    /// This is only available once some changes have been made.
    pub fn apply(self) -> (Offer, Peer<state::InitialOffering>) {
        self.do_apply()
    }
}

impl<Any> ChangeSet<state::Connected, Any> {
    /// Adds audio/video media.
    pub fn add_media(
        self,
        kind: MediaKind,
        dir: Direction,
    ) -> ChangeSet<state::Connected, Changed> {
        self.do_add_media(kind, dir)
    }

    /// Adds a data channel.
    pub fn add_data_channel(self) -> ChangeSet<state::Connected, Changed> {
        self.do_add_data_channel()
    }

    // TODO: more changes here (i.e. changing direction etc).
}

impl ChangeSet<state::Connected, Changed> {
    /// Applies these changes to the [`crate::Peer`].
    ///
    /// This is only available once some changes have been made.
    pub fn apply(self) -> (Offer, Peer<state::InitialOffering>) {
        self.do_apply()
    }
}

impl Changes {
    pub fn new_media_lines(&self, setup: Setup) -> impl Iterator<Item = Media> + '_ {
        self.0.iter().filter_map(move |c| match c {
            Change::AddMedia(kind, dir) => Some(Media::new_media(setup, *kind, *dir)),
            Change::AddDataChannel => Some(Media::new_data_channel(setup)),
            // _ => None,
        })
    }
}
