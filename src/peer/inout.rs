use std::convert::TryFrom;
use std::net::SocketAddr;
use std::ops::Deref;
use std::time::Instant;

use crate::ice::StunMessage;
use crate::output::Output;
use crate::sdp::{parse_sdp, Sdp};
use crate::udp::UdpKind;
use crate::Addrs;
use crate::{Error, Peer};

/// Handle to perform network input/output for a [`Peer`].
pub struct Io<'a, State>(pub(crate) &'a mut Peer<State>);

impl<'a, State> Io<'a, State> {
    /// Tests if this peer will accept the network input.
    ///
    /// This is used in a server side peer to multiplex multiple peer
    /// connections over the same UDP port. After the initial STUN, the
    /// remote (client) peer is recognized by IP/port.
    pub fn accepts(&self, addr: SocketAddr, input: &Input<'_>) -> Result<bool, Error> {
        use InputInner::*;
        if let Stun(stun) = &input.0 {
            self.0.ice_state.accepts_stun(addr, stun)
        } else {
            // All other kind of network input must be "unlocked" by STUN recognizing the
            // ice-ufrag/passwd from the SDP. Any sucessful STUN cause the remote IP/port
            // combo to be considered associated with this peer.
            Ok(self.0.ice_state.is_stun_verified(addr))
        }
    }

    /// Provide network input.
    ///
    /// While connecting, we only accept input from the network.
    pub fn push(&mut self, time: Instant, addrs: Addrs, input: Input<'_>) -> Result<(), Error> {
        use InputInner::*;

        let time = time.into();

        let output = &mut self.0.output;
        let x = match input.0 {
            Stun(stun) => self.0.ice_state.handle_stun(time, addrs, output, stun),
            Dtls(buf) => self.0.dtls_state.handle_dtls(time, addrs, output, buf),
        };

        // Also drive internal state forward.
        self.0.do_tick(time)?;

        x
    }

    /// Used in absence of network input to drive the engine.
    pub fn tick(&mut self, time: Instant) -> Result<(), Error> {
        self.0.do_tick(time.into())
    }

    /// Polls for network output.
    ///
    /// Changes to the `Peer` state will queue up network output to send.
    /// For every change, this function must be polled until it returns `None`.
    pub fn pull(&mut self) -> Option<(Addrs, &Output)> {
        self.0.output.dequeue()
    }
}

/// Encapsulates network input (typically from a UDP socket).
///
/// Cannot deal with partial data. Must be entire UDP packets at a time.
///
/// ```no_run
/// # use str0m::*;
/// # use std::convert::TryFrom;
/// # use std::net::SocketAddr;
/// # fn main() -> Result<(), Error> {
/// let data: &[u8] = todo!(); // obtain data from socket.
///
/// // This parses the input data, and it can throw an
/// // error if there are problems understanding the data.
/// let input = Input::try_from(data)?;
/// # Ok(())}
/// ```
pub struct Input<'a>(pub(crate) InputInner<'a>);

#[derive(Clone)]
pub(crate) enum InputInner<'a> {
    #[doc(hidden)]
    Stun(StunMessage<'a>),
    #[doc(hidden)]
    Dtls(&'a [u8]),
}

/// SDP offer.
#[derive(Debug)]
pub struct Offer(pub(crate) Sdp);

/// SDP answer.
#[derive(Debug)]
pub struct Answer(pub(crate) Sdp);

impl Deref for Offer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Answer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for Offer {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let sdp = parse_sdp(value)?;
        Ok(Offer(sdp))
    }
}

impl<'a> TryFrom<&'a str> for Answer {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let sdp = parse_sdp(value)?;
        Ok(Answer(sdp))
    }
}

impl<'a> TryFrom<&'a [u8]> for Input<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = UdpKind::try_from(value)?;

        Ok(Input(match kind {
            UdpKind::Stun => InputInner::Stun(StunMessage::parse(&value)?),
            UdpKind::Dtls => InputInner::Dtls(value),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        }))
    }
}
