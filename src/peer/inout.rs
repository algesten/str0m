use std::convert::TryFrom;
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

use crate::sdp::{parse_sdp, Sdp};
use crate::stun::{self, StunMessage};
use crate::udp::UdpKind;
use crate::{Error, UDP_MTU};

pub struct Input<'a>(pub(crate) InputInner<'a>);

pub(crate) enum InputInner<'a> {
    Tick,
    Offer(Offer),
    Answer(Answer),
    Network(SocketAddr, NetworkInput<'a>),
}

#[derive(Debug)]
pub enum Output {
    None,
    Offer(Offer),
    Answer(Answer),
}

#[derive(Debug, Clone)]
pub enum NetworkInput<'a> {
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

#[derive(Debug)]
pub struct Offer(pub(crate) Sdp);

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

impl<'a> From<StunMessage<'a>> for NetworkInput<'a> {
    fn from(v: StunMessage<'a>) -> Self {
        NetworkInput::Stun(v)
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

        Ok(match kind {
            UdpKind::Stun => NetworkInput::Stun(stun::parse_message(&value)?),
            UdpKind::Dtls => todo!(),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        })
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
