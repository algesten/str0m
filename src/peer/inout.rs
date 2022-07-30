use std::convert::TryFrom;
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

use crate::sdp::{parse_sdp, Sdp};
use crate::stun::{self, StunMessage};
use crate::udp::UdpKind;
use crate::{Error, UDP_MTU};

/// Encapsulates input to the [`crate::Peer`].
///
/// Created input by using the various `From` trait implementations.
pub struct Input<'a>(pub(crate) InputInner<'a>);

pub(crate) enum InputInner<'a> {
    Tick,
    Offer(Offer),
    Answer(Answer),
    Network(SocketAddr, NetworkInput<'a>),
}

/// Output as a response to [`Input`].
#[derive(Debug)]
pub enum Output {
    /// No specific output.
    None,

    /// An SDP offer.
    ///
    /// Returned in response to [`Input`] making changes to the local media config.
    Offer(Offer),

    /// An SDP answer.
    ///
    /// Returned in response to [`Input`] being an SDP offer.
    Answer(Answer),
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
/// let network = NetworkInput::try_from(data)?;
///
/// // This is the input into [`crate::Peer::handle_input`].
/// let input: Input<'_> = (addr, network).into();
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

impl<'a> From<Offer> for Input<'a> {
    fn from(v: Offer) -> Self {
        Input(InputInner::Offer(v))
    }
}

impl<'a> From<Answer> for Input<'a> {
    fn from(v: Answer) -> Self {
        Input(InputInner::Answer(v))
    }
}

impl From<Offer> for Output {
    fn from(v: Offer) -> Self {
        Output::Offer(v)
    }
}

impl From<Answer> for Output {
    fn from(v: Answer) -> Self {
        Output::Answer(v)
    }
}

impl<'a> From<()> for Output {
    fn from(_: ()) -> Self {
        Output::None
    }
}

impl<'a> From<(SocketAddr, NetworkInput<'a>)> for Input<'a> {
    fn from((addr, data): (SocketAddr, NetworkInput<'a>)) -> Self {
        Input(InputInner::Network(addr, data))
    }
}

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

impl<'a> fmt::Debug for Input<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Input(")?;
        write!(
            f,
            "{}",
            match &self.0 {
                InputInner::Tick => "Tick",
                InputInner::Offer(_) => "Offer",
                InputInner::Answer(_) => "Answer",
                InputInner::Network(_, _) => "Network",
            }
        )?;
        write!(f, ")")
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

impl<'a> From<()> for Input<'a> {
    fn from(_: ()) -> Self {
        Input(InputInner::Tick)
    }
}
