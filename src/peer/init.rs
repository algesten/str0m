use std::net::SocketAddr;
use std::time::Instant;

use crate::media::{Media, MediaKind};
use crate::sdp::Direction;
use crate::{Error, Input};

use super::inout::{Answer, InputInner, NetworkInput, NetworkOutput, Offer, Output};
use super::state;
use super::Peer;

impl Peer<state::Init> {
    /// Create an initial offer to start the RTC session.
    ///
    /// The offer must be provided _in some way_ to the remote side.
    pub fn create_offer(self) -> Peer<state::AddMedia> {
        self.into_state()
    }

    /// Accept an initial offer created on the remote side.
    pub fn accept_offer(
        mut self,
        offer: Offer,
    ) -> Result<(Answer, Peer<state::Connecting>), Error> {
        let answer = self.handle_offer(offer)?;
        Ok((answer, self.into_state()))
    }
}

impl Peer<state::AddMedia> {
    /// Add audio or video media.
    ///
    /// To produce an initial offer, we need some media added. This adds audio or video.
    pub fn add_media(mut self, kind: MediaKind, dir: Direction) -> (Offer, Peer<state::Offering>) {
        let m = Media::new_media(self.setup, kind, dir);
        self.media.push(m);

        let offer = Offer(self.as_sdp());
        (offer, self.into_state())
    }

    /// Add a data channel.
    ///
    /// To produce an initial offer, we need some media added. This adds a data channel.
    pub fn add_data_channel(mut self) -> (Offer, Peer<state::Offering>) {
        let m = Media::new_data_channel(self.setup);
        self.media.push(m);

        let offer = Offer(self.as_sdp());
        (offer, self.into_state())
    }
}

impl Peer<state::Offering> {
    /// Accept an answer from the remote side.
    pub fn accept_answer(mut self, answer: Answer) -> Result<Peer<state::Connecting>, Error> {
        self.handle_answer(answer)?;
        todo!()
    }
}

impl Peer<state::Connecting> {
    /// Tests whether this [`Peer`] accepts the input.
    ///
    /// This is useful in a server scenario when multiplexing several Peers on the same UDP port.
    pub fn accepts(&self, addr: SocketAddr, data: &NetworkInput<'_>) -> Result<bool, Error> {
        let owned = NetworkInput(data.0.clone());
        let input = Input(InputInner::Network(addr, owned));
        self._accepts(&input)
    }

    /// Provide network input.
    ///
    /// While connecting, we only accept input from the network.
    pub fn handle_network_input<'a>(
        &mut self,
        time: Instant,
        addr: SocketAddr,
        data: NetworkInput<'a>,
    ) -> Result<(), Error> {
        let input = (addr, data).into();

        let out = self._handle_input(time, input)?;
        // When we only provide network data as input, there should be no output.
        assert!(matches!(out, Output::None));

        Ok(())
    }

    /// Poll network output.
    ///
    /// For every input provided, this needs to be polled until it returns `None`.
    pub fn network_output(&mut self) -> Option<(SocketAddr, &NetworkOutput)> {
        self._network_output()
    }

    /// Tests if the peer is connected.
    ///
    /// If connected, the peer is transitioned to [`state::Connected`].
    pub fn try_connected(self) -> ConnectionResult {
        let has_stun = !self.stun_state.verified.is_empty();
        let has_dtls = self.dtls_state.dtls.is_some();

        if has_stun && has_dtls {
            ConnectionResult::Connected(self.into_state())
        } else {
            ConnectionResult::Connecting(self)
        }
    }
}

pub enum ConnectionResult {
    Connecting(Peer<state::Connecting>),
    Connected(Peer<state::Connected>),
}
