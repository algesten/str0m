use crate::{ChangeSet, Error};

use super::change::change_state;
use super::inout::{Answer, Offer};
use super::Peer;
use super::{state, Io};

impl Peer<state::Init> {
    /// Create an initial offer to start the session.
    ///
    /// The offer must be provided _in some way_ to the remote side.
    pub fn change_set(self) -> ChangeSet<state::Init, change_state::NoChange> {
        info!("{:?} Create initial change set", self.session_id);
        ChangeSet::new(self)
    }

    /// Accept an initial offer created on the remote side.
    pub fn accept_offer(
        mut self,
        offer: Offer,
    ) -> Result<(Answer, Peer<state::Connecting>), Error> {
        info!("{:?} Accept initial offer", self.session_id);
        let answer = self.do_handle_offer(offer)?;
        info!("{:?} Reply with initial answer", self.session_id);
        Ok((answer, self.into_state()))
    }
}

impl Peer<state::InitialOffering> {
    /// Accept an answer from the remote side.
    pub fn accept_answer(mut self, answer: Answer) -> Result<Peer<state::Connecting>, Error> {
        info!("{:?} Accept initial answer", self.session_id);
        self.do_handle_answer(answer)?;
        Ok(self.into_state())
    }

    /// Abort the changes.
    ///
    /// Goes back to a state where we can accept an offer from the remote side instead.
    pub fn rollback(mut self) -> Peer<state::Init> {
        info!("{:?} Rollback initial offer", self.session_id);
        self.pending_changes.take();
        self.into_state()
    }
}

impl Peer<state::Connecting> {
    /// Do network IO.
    pub fn io(&mut self) -> Io<'_, state::Connecting> {
        Io(self)
    }

    /// Tests if the peer is connected.
    ///
    /// If connected, the peer is transitioned to [`state::Connected`].
    pub fn try_connect(self) -> ConnectionResult {
        info!("{:?} Try connect", self.session_id);
        let has_stun = self.ice_state.has_any_verified();
        let has_dtls = self.dtls_state.dtls.is_some();

        if has_stun && has_dtls {
            trace!("{:?} Connected", self.session_id);
            ConnectionResult::Connected(self.into_state())
        } else {
            trace!("{:?} Still connecting", self.session_id);
            ConnectionResult::Connecting(self)
        }
    }
}

/// The result of `Peer::try_connected()`.
pub enum ConnectionResult {
    /// Peer is still connecting.
    Connecting(Peer<state::Connecting>),

    /// Peer has connected.
    Connected(Peer<state::Connected>),
}
