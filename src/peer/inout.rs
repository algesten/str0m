use std::convert::TryFrom;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::time::Instant;

use crate::sdp::{parse_sdp, Sdp};
use crate::stun::{self, StunMessage};
use crate::udp::UdpKind;
use crate::{Error, Peer, UDP_MTU};

/// Handle to perform network input/output for a [`Peer`].
pub struct Io<'a, State>(pub(crate) &'a mut Peer<State>);

/// Network output.
///
/// The `source`/`target` is used to match up which external interface to send
/// the data via. The data is chunked up for UDP transport.
pub struct Output<'a> {
    /// Source address to send from.
    pub source: SocketAddr,
    /// Target address to send to.
    pub target: SocketAddr,
    /// The data to deliver.
    pub data: &'a NetworkOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Addrs {
    pub source: SocketAddr,
    pub target: SocketAddr,
}

impl<'a, State> Io<'a, State> {
    /// Tests if this peer will accept the network input.
    ///
    /// This is used in a server side peer to multiplex multiple peer
    /// connections over the same UDP port. After the initial STUN, the
    /// remote (client) peer is recognized by IP/port.
    pub fn accepts_network_input(
        &self,
        addr: SocketAddr,
        input: &NetworkInput<'_>,
    ) -> Result<bool, Error> {
        use NetworkInputInner::*;
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
    pub fn network_input(
        &mut self,
        time: Instant,
        source: SocketAddr,
        target: SocketAddr,
        input: NetworkInput<'_>,
    ) -> Result<(), Error> {
        use NetworkInputInner::*;

        let time = time.into();
        let addrs = Addrs { source, target };

        let output = &mut self.0.output;
        let x = match input.0 {
            Stun(stun) => self.0.ice_state.handle_stun(time, addrs, output, stun),
            Dtls(buf) => self.0.dtls_state.handle_dtls(addrs, output, buf),
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
    pub fn network_output(&mut self) -> Option<Output<'_>> {
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
/// let addr: SocketAddr = todo!(); // address of data.
///
/// // This parses the input data, and it can throw an
/// // error if there are problems understanding the data.
/// let input = NetworkInput::try_from(data)?;
/// # Ok(())}
/// ```
pub struct NetworkInput<'a>(pub(crate) NetworkInputInner<'a>);

#[derive(Clone)]
pub(crate) enum NetworkInputInner<'a> {
    #[doc(hidden)]
    Stun(StunMessage<'a>),
    #[doc(hidden)]
    Dtls(&'a [u8]),
}

#[derive(Clone)]
pub struct NetworkOutput(Box<[u8; UDP_MTU]>, usize);

impl NetworkOutput {
    pub(crate) fn new() -> Self {
        NetworkOutput(Box::new([0_u8; UDP_MTU]), 0)
    }

    /// This provides _the entire_ buffer to write. `set_len` must be done on
    /// the writer onoce write is complete.
    pub(crate) fn into_writer(self) -> NetworkOutputWriter {
        NetworkOutputWriter(self, false)
    }
}

impl Deref for NetworkOutput {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[0..self.1]
    }
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

impl<'a> TryFrom<&'a [u8]> for NetworkInput<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = UdpKind::try_from(value)?;

        Ok(NetworkInput(match kind {
            UdpKind::Stun => NetworkInputInner::Stun(stun::parse_message(&value)?),
            UdpKind::Dtls => NetworkInputInner::Dtls(value),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        }))
    }
}

/// RAII guard for writing to [`NetworkOutput`].
pub(crate) struct NetworkOutputWriter(NetworkOutput, bool);

impl NetworkOutputWriter {
    #[must_use]
    pub fn set_len(mut self, len: usize) -> NetworkOutput {
        assert!(len <= self.0 .0.len());
        self.1 = true;
        self.0 .1 = len;
        self.0
    }
}

impl Deref for NetworkOutputWriter {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0 .0[..]
    }
}

impl DerefMut for NetworkOutputWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0 .0[..]
    }
}
