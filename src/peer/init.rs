use std::net::SocketAddr;

use crate::media::Media;
use crate::sdp::{Direction, MediaType};
use crate::util::Ts;
use crate::Error;

use super::inout::{Answer, NetworkInput, Offer, Output};
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
    /// Provide network input.
    ///
    /// While connecting, we only accept input from the network.
    pub fn handle_network_input<'a>(
        &mut self,
        ts: Ts,
        addr: SocketAddr,
        data: NetworkInput<'a>,
    ) -> Result<(), Error> {
        let input = (addr, data).into();

        let out = self._handle_input(ts, input)?;
        // When we only provide network data as input, there should be no output.
        assert!(matches!(out, Output::None));

        Ok(())
    }
}
