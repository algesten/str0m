#![warn(missing_docs)]

//! WebRTC the Rust way.

#[macro_use]
extern crate tracing;

mod dtls;
mod error;
mod media;
mod sdp;
mod stun;
mod udp;
mod util;

use rand::Rng;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::Deref;

use dtls::{dtls_create_ctx, dtls_ssl_create, Dtls};
pub use error::Error;
use media::Media;
use openssl::ssl::SslContext;
use sdp::{parse_sdp, Fingerprint, IceCreds, MediaType, Sdp, Session, SessionId};
use stun::StunMessage;
use udp::UdpKind;
use util::{random_id, PtrBuffer, Ts};

/// States the `Peer` can be in.
pub mod state {
    /// First state after creation.
    pub struct Init {}
    /// If we do `create_offer.
    pub struct Offering {}
    /// When we're ready to connect (Offer/Answer exchange is finished).
    pub struct Connecting {}
    /// When we have connected.
    pub struct Connected {}
}

/// A single peer connection.
pub struct Peer<State> {
    /// Unique id of the session, as transmitted on the o= line.
    session_id: SessionId,

    /// State of STUN.
    stun_state: StunState,

    /// State of DTLS.
    dtls_state: DtlsState,

    /// The configured media (audio/video or datachannel).
    media: Vec<Media>,

    _ph: PhantomData<State>,
}

struct StunState {
    /// Local credentials for STUN. We use one set for all m-lines.
    local_creds: IceCreds,

    /// Remote credentials for STUN. Obtained from SDP.
    remote_creds: Vec<IceCreds>,

    /// Addresses that have been "unlocked" via STUN. These IP:PORT combos
    /// are now verified for other kinds of data like DTLS, RTP, RTCP...
    verified: HashSet<SocketAddr>,
}

struct DtlsState {
    /// DTLS context for this peer.
    ///
    /// TODO: Should we share this for the entire app?
    ctx: SslContext,

    /// DTLS wrapper a special stream we read/write DTLS packets to.
    /// Instantiation is delayed until we know whether this instance is
    /// active or passive, which is evident from the a=setup:actpass,
    /// a=setup:active or a=setup:passive in the negotiation.
    dtls: Option<Dtls<PtrBuffer>>,

    /// Local fingerprint for DTLS. We use one certificate per peer.
    local_fingerprint: Fingerprint,

    /// Remote fingerprints for DTLS. Obtained from SDP.
    remote_fingerprints: Vec<Fingerprint>,
}

impl<T> Peer<T> {
    /// Creates a new `Peer`.
    ///
    /// New peers starts out in the [`state::Init`] state which requires an SDP offer/answer
    /// dance to become active.
    pub fn new() -> Result<Peer<state::Init>, Error> {
        let (ctx, local_fingerprint) = dtls_create_ctx()?;

        let mut rng = rand::thread_rng();
        let id = (u64::MAX as f64 * rng.gen::<f64>()) as u64;

        let peer = Peer {
            session_id: SessionId(id),
            stun_state: StunState {
                local_creds: IceCreds {
                    username: random_id::<8>().to_string(),
                    password: random_id::<24>().to_string(),
                },
                remote_creds: vec![],
                verified: HashSet::new(),
            },
            dtls_state: DtlsState {
                ctx,
                dtls: None,
                local_fingerprint,
                remote_fingerprints: vec![],
            },
            media: vec![],
            _ph: PhantomData,
        };

        Ok(peer)
    }

    fn accepts(&self, input: &Input<'_>) -> Result<bool, Error> {
        use Input::*;
        use NetworkData::*;
        match input {
            Tick(_) => Ok(true),
            Offer(_) => Ok(true),
            Answer(_) => Ok(true),
            Network(addr, data) => match data {
                Stun(stun) => self.stun_state.accepts_stun(*addr, stun),
            },
        }
    }

    fn handle_input<'a>(&mut self, ts: Ts, input: Input<'a>) -> Result<Output<'a>, Error> {
        use Input::*;
        use NetworkData::*;
        Ok(match input {
            Tick(buf) => Output::Yield,
            Offer(v) => self.handle_offer(v)?.into(),
            Answer(v) => self.handle_answer(v)?.into(),
            Network(addr, data) => match data {
                Stun(stun) => (addr, self.stun_state.handle_stun(addr, stun)?.into()).into(),
            },
        })
    }

    fn handle_offer(&mut self, offer: Offer) -> Result<Answer, Error> {
        todo!()
    }

    fn handle_answer(&mut self, offer: Answer) -> Result<(), Error> {
        todo!()
    }
}

impl Peer<state::Init> {
    /// Create an initial offer to start the RTC session.
    ///
    /// The offer must be provided _in some way_ to the remote side.
    pub fn create_offer(mut self) -> (Offer, Peer<state::Offering>) {
        todo!()
    }

    /// Accept an initial offer created on the remote side.
    pub fn accept_offer(self, offer: Offer) -> (Answer, Peer<state::Connecting>) {
        todo!()
    }
}

impl Peer<state::Offering> {
    /// Accept an answer from the remote side.
    pub fn accept_answer(mut self, answer: Answer) -> Peer<state::Connecting> {
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
        data: NetworkData<'a>,
    ) -> Result<Output<'a>, Error> {
        let input = (addr, data).into();
        self.handle_input(ts, input)
    }
}

impl StunState {
    fn accepts_stun(&self, addr: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
        let (local_username, remote_username) = stun.local_remote_username();

        let remote_creds_has_username = self
            .remote_creds
            .iter()
            .any(|c| c.username == remote_username);

        if !remote_creds_has_username {
            // this is not a fault, the packet might not be for this peer.
            return Ok(false);
        }

        if local_username != self.local_creds.username {
            // this is a bit suspicious... maybe a name clash on the remote username?
            return Err(Error::StunError(format!(
                "STUN local != peer.local ({}): {} != {}",
                addr, local_username, self.local_creds.username
            )));
        }

        if !stun.check_integrity(&self.local_creds.password) {
            // this is also sus.
            return Err(Error::StunError(format!(
                "STUN check_integrity failed ({})",
                addr,
            )));
        }

        Ok(true)
    }

    fn handle_stun<'a>(
        &mut self,
        addr: SocketAddr,
        stun: StunMessage<'a>,
    ) -> Result<StunMessage<'a>, Error> {
        let reply = stun.reply()?;

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if self.verified.insert(addr) {
            trace!("STUN new verified peer ({})", addr);
        }

        Ok(reply)
    }

    fn is_stun_verified(&self, addr: &SocketAddr) -> bool {
        self.verified.contains(addr)
    }
}

pub enum Input<'a> {
    Tick(&'a mut [u8]),
    Offer(Offer),
    Answer(Answer),
    Network(SocketAddr, NetworkData<'a>),
}

pub enum Output<'a> {
    Yield,
    NeedTick,
    Offer(Offer),
    Answer(Answer),
    Network(SocketAddr, NetworkData<'a>),
}

pub enum NetworkData<'a> {
    Stun(StunMessage<'a>),
}

pub struct Offer(Sdp);

pub struct Answer(Sdp);

impl<'a> TryFrom<&'a [u8]> for NetworkData<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = UdpKind::try_from(value)?;

        Ok(match kind {
            UdpKind::Stun => NetworkData::Stun(stun::parse_message(&value)?),
            UdpKind::Dtls => todo!(),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        })
    }
}

impl<'a> From<Offer> for Input<'a> {
    fn from(v: Offer) -> Self {
        Input::Offer(v)
    }
}

impl<'a> From<Answer> for Input<'a> {
    fn from(v: Answer) -> Self {
        Input::Answer(v)
    }
}

impl<'a> From<Offer> for Output<'a> {
    fn from(v: Offer) -> Self {
        Output::Offer(v)
    }
}

impl<'a> From<Answer> for Output<'a> {
    fn from(v: Answer) -> Self {
        Output::Answer(v)
    }
}

impl<'a> From<()> for Output<'a> {
    fn from(_: ()) -> Self {
        Output::NeedTick
    }
}

impl<'a> From<(SocketAddr, NetworkData<'a>)> for Input<'a> {
    fn from((addr, data): (SocketAddr, NetworkData<'a>)) -> Self {
        Input::Network(addr, data)
    }
}

impl<'a> From<(SocketAddr, NetworkData<'a>)> for Output<'a> {
    fn from((addr, data): (SocketAddr, NetworkData<'a>)) -> Self {
        Output::Network(addr, data)
    }
}

impl<'a> From<StunMessage<'a>> for NetworkData<'a> {
    fn from(v: StunMessage<'a>) -> Self {
        NetworkData::Stun(v)
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
