use std::net::SocketAddr;
use std::time::Instant;

use crate::media::Media;
use crate::sdp::{Direction, MediaType};
use crate::{Error, Input};

use super::inout::{Answer, InputInner, NetworkInput, NetworkOutput, Offer, Output};
use super::state;
use super::Peer;

impl Peer<state::Init> {
    /// Create an initial offer to start the RTC session.
    ///
    /// The offer must be provided _in some way_ to the remote side.
    pub fn create_offer(mut self) -> (Offer, Peer<state::Offering>) {
        // TODO fix this.
        self.media
            .push(Media::new(MediaType::Audio, Direction::RecvOnly));

        let sdp = self.as_local_sdp();
        let offer = Offer(sdp);

        (offer, self.into_state())
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
        let input = Input(InputInner::Network(addr, data.clone()));
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
}
