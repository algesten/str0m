mod init;
mod inout;
mod serialize;

use openssl::ssl::SslContext;
use rand::Rng;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::mem;
use std::net::SocketAddr;

use crate::dtls::{dtls_create_ctx, dtls_ssl_create, Dtls};
use crate::media::Media;
use crate::sdp::SessionId;
use crate::sdp::{Fingerprint, IceCreds};
use crate::sdp::{MediaAttributeExt, Sdp};
use crate::stun::StunMessage;
use crate::util::{random_id, PtrBuffer, Ts};
use crate::Error;

pub use self::inout::{Answer, Input, NetworkData, Offer, Output};

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
    remote_creds: HashSet<IceCreds>,

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
    remote_fingerprints: HashSet<Fingerprint>,
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

impl<T> Peer<T> {
    fn into_state<U>(self) -> Peer<U> {
        // SAFETY: this is fine, because we only change the PhantomData.
        unsafe { mem::transmute(self) }
    }

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
                remote_creds: HashSet::new(),
                verified: HashSet::new(),
            },
            dtls_state: DtlsState {
                ctx,
                dtls: None,
                local_fingerprint,
                remote_fingerprints: HashSet::new(),
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

    fn _handle_input<'a>(&mut self, ts: Ts, input: Input<'a>) -> Result<Output<'a>, Error> {
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
        self.extract_remote_secrets(&offer.0);
        todo!()
    }

    fn handle_answer(&mut self, answer: Answer) -> Result<(), Error> {
        self.extract_remote_secrets(&answer.0);
        todo!()
    }

    fn extract_remote_secrets(&mut self, sdp: &Sdp) {
        for mline in &sdp.media_lines {
            if let Some(creds) = mline.attrs.ice_creds() {
                self.stun_state.remote_creds.insert(creds);
            }
            if let Some(fp) = mline.attrs.fingerprint() {
                self.dtls_state.remote_fingerprints.insert(fp);
            }
        }
    }
}

impl Peer<state::Connected> {
    pub fn handle_input<'a>(&mut self, ts: Ts, input: Input<'a>) -> Result<Output<'a>, Error> {
        self._handle_input(ts, input)
    }
}
