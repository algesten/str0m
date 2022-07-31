use std::net::SocketAddr;
use std::time::Instant;

use crate::{ChangeSet, Error};

use super::change::change_state;
use super::inout::{Answer, NetworkInput, NetworkOutput, Offer};
use super::state;
use super::Peer;

impl Peer<state::Init> {
    /// Create an initial offer to start the RTC session.
    ///
    /// The offer must be provided _in some way_ to the remote side.
    pub fn change_set(self) -> ChangeSet<state::Init, change_state::NoChange> {
        ChangeSet::new(self)
    }

    /// Accept an initial offer created on the remote side.
    pub fn accept_offer(
        mut self,
        offer: Offer,
    ) -> Result<(Answer, Peer<state::Connecting>), Error> {
        let answer = self.do_handle_offer(offer)?;
        Ok((answer, self.into_state()))
    }
}

impl Peer<state::InitialOffering> {
    /// Accept an answer from the remote side.
    pub fn accept_answer(mut self, answer: Answer) -> Result<Peer<state::Connecting>, Error> {
        self.apply_pending_changes(answer)?;
        todo!()
    }

    /// Abort the changes.
    ///
    /// Goes back to a state where we can accept an offer from the remote side instead.
    pub fn rollback(mut self) -> Peer<state::Init> {
        self.pending_changes.take();
        self.into_state()
    }
}

impl Peer<state::Connecting> {
    /// Tests if this peer will accept the network input.
    ///
    /// This is used in a server side peer to multiplex multiple peer
    /// connections over the same UDP port. After the initial STUN, the
    /// remote (client) peer is recognized by IP/port.
    pub fn accepts_network_input<'a>(
        &self,
        addr: SocketAddr,
        input: &NetworkInput<'a>,
    ) -> Result<bool, Error> {
        self.do_accepts_network_input(addr, input)
    }

    /// Provides network input.
    ///
    /// While connecting, we only accept input from the network.
    pub fn network_input<'a>(
        &mut self,
        time: Instant,
        addr: SocketAddr,
        input: NetworkInput<'a>,
    ) -> Result<(), Error> {
        self.do_network_input(time, addr, input)
    }

    /// Polls for network output.
    ///
    /// For every input provided, this needs to be polled until it returns `None`.
    pub fn network_output(&mut self) -> Option<(SocketAddr, &NetworkOutput)> {
        self.do_network_output()
    }

    /// Tests if the peer is connected.
    ///
    /// If connected, the peer is transitioned to [`state::Connected`].
    pub fn try_connect(self) -> ConnectionResult {
        let has_stun = !self.stun_state.verified.is_empty();
        let has_dtls = self.dtls_state.dtls.is_some();

        if has_stun && has_dtls {
            ConnectionResult::Connected(self.into_state())
        } else {
            ConnectionResult::Connecting(self)
        }
    }
}

/// The result of [`Peer::try_connected`].
pub enum ConnectionResult {
    /// Peer is still connecting.
    Connecting(Peer<state::Connecting>),

    /// Peer has connected.
    Connected(Peer<state::Connected>),
}
