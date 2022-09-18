#[macro_use]
extern crate tracing;

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use change::Changes;
use dtls::{Dtls, DtlsEvent, Fingerprint};
use ice::{Candidate, IceAgent};
use ice::{IceAgentEvent, IceConnectionState};
use rtp::{Mid, Pt, Ssrc};
use sdp::{Answer, Offer, Sdp, Setup};
use thiserror::Error;

pub mod net {
    pub use dtls::DtlsError;
    pub use net_::{DatagramRecv, DatagramSend, Receive, StunMessage, Transmit};
}

pub mod media;
use media::{Channel, Media};

mod change;
pub use change::ChangeSet;

mod util;
pub(crate) use util::*;

mod session;
use session::{MediaEvent, Session};

mod session_sdp;
use session_sdp::AsSdpParams;

/// Errors for the whole Rtc engine.
#[derive(Debug, Error)]
pub enum RtcError {
    /// Some problem with the remote SDP.
    #[error("remote sdp: {0}")]
    RemoteSdp(String),

    /// SDP errors.
    #[error("{0}")]
    Sdp(#[from] sdp::SdpError),

    /// RTP errors.
    #[error("{0}")]
    Rtp(#[from] rtp::RtpError),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    /// DTLS errors
    #[error("{0}")]
    Dtls(#[from] net::DtlsError),

    /// RTP packetization error
    #[error("{0}")]
    Packet(#[from] packet::PacketError),

    /// The PT attempted to write to is not known.
    #[error("PT is unknown {0}")]
    UnknownPt(Pt),
}

pub struct Rtc {
    alive: bool,
    ice: IceAgent,
    dtls: Dtls,
    setup: Setup,
    session: Session,
    remote_fingerprint: Option<Fingerprint>,
    pending: Option<Changes>,
    remote_addrs: Vec<SocketAddr>,
    send_addr: Option<SendAddr>,
    last_now: Instant,
}

struct SendAddr {
    source: SocketAddr,
    destination: SocketAddr,
}

pub enum Event {
    IceCandidate(Candidate),
    IceConnectionStateChange(IceConnectionState),
    MediaAdded(Mid),
    ChannelAdded(Mid),
    MediaData(Mid, Pt, Vec<u8>),
    MediaError(Mid, Pt, RtcError),
}

pub enum Input<'a> {
    Timeout(Instant),
    Receive(Instant, net::Receive<'a>),
}

pub enum Output {
    Timeout(Instant),
    Transmit(net::Transmit),
    Event(Event),
}

impl Rtc {
    pub fn new() -> Self {
        Rtc {
            alive: true,
            ice: IceAgent::new(),
            dtls: Dtls::new().expect("DTLS to init without problem"),
            setup: Setup::ActPass,
            session: Session::new(),
            remote_fingerprint: None,
            pending: None,
            remote_addrs: vec![],
            send_addr: None,
            last_now: already_happened(),
        }
    }

    pub fn create_offer(&mut self) -> ChangeSet {
        if !self.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            self.ice.set_controlling(true);
        }

        ChangeSet::new(self)
    }

    pub fn accept_offer(&mut self, offer: Offer) -> Result<Answer, RtcError> {
        self.add_ice_details(&offer)?;

        // rollback any pending offer.
        self.accept_answer(None)?;

        if self.remote_fingerprint.is_none() {
            if let Some(f) = offer.fingerprint() {
                self.remote_fingerprint = Some(f);
            } else {
                self.alive = false;
                return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
            }
        }

        if !self.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            self.ice.set_controlling(false);
        }

        // If we receive an offer, we are not allowed to answer with actpass.
        if self.setup == Setup::ActPass {
            let remote_setup = offer.setup().unwrap_or(Setup::Active);
            self.setup = remote_setup.invert();
            debug!(
                "Change setup for answer: {} -> {}",
                Setup::ActPass,
                self.setup
            );
        }

        // Ensure setup=active/passive is corresponding remote and init dtls.
        self.init_setup_dtls(&offer);

        // Modify session with offer
        self.session.apply_offer(offer)?;

        let params = self.as_sdp_params(false);
        let sdp = self.session.as_sdp(params);

        Ok(sdp.into())
    }

    pub(crate) fn set_changes(&mut self, changes: Changes) -> Offer {
        self.pending = Some(changes);

        let params = self.as_sdp_params(true);
        let sdp = self.session.as_sdp(params);

        sdp.into()
    }

    fn as_sdp_params(&self, include_pending: bool) -> AsSdpParams {
        AsSdpParams {
            candidates: self.ice.local_candidates(),
            creds: self.ice.local_credentials(),
            fingerprint: self.dtls.local_fingerprint(),
            setup: self.setup,
            pending: if include_pending {
                &self.pending
            } else {
                &None
            },
        }
    }

    pub fn pending_changes(&mut self) -> Option<PendingChanges> {
        self.pending.as_ref()?;
        Some(PendingChanges { rtc: self })
    }

    fn accept_answer(&mut self, answer: Option<Answer>) -> Result<(), RtcError> {
        if let Some(answer) = answer {
            self.add_ice_details(&answer)?;

            // Ensure setup=active/passive is corresponding remote and init dtls.
            self.init_setup_dtls(&answer);

            if self.remote_fingerprint.is_none() {
                if let Some(f) = answer.fingerprint() {
                    self.remote_fingerprint = Some(f);
                } else {
                    self.alive = false;
                    return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
                }
            }

            // Modify session with answer
            let pending = self.pending.take().expect("pending changes");
            self.session.apply_answer(pending, answer)?;
        } else {
            // rollback
            self.pending = None;
        }

        Ok(())
    }

    fn add_ice_details(&mut self, sdp: &Sdp) -> Result<(), RtcError> {
        if let Some(creds) = sdp.ice_creds() {
            self.ice.set_remote_credentials(creds);
        } else {
            return Err(RtcError::RemoteSdp("missing a=ice-ufrag/pwd".into()));
        }

        for r in sdp.ice_candidates() {
            self.ice.add_remote_candidate(r.clone());
        }

        Ok(())
    }

    fn init_setup_dtls(&mut self, remote_sdp: &Sdp) -> Option<()> {
        if let Some(remote_setup) = remote_sdp.setup() {
            self.setup = self.setup.compare_to_remote(remote_setup)?;
        }

        if !self.dtls.is_inited() {
            let active = self.setup == Setup::Active;
            self.dtls.set_active(active);
        }

        Some(())
    }

    /// Creates a new Mid that is not in the session already.
    pub(crate) fn new_mid(&self) -> Mid {
        loop {
            let mid = Mid::new();
            if !self.session.has_mid(mid) {
                break mid;
            }
        }
    }

    /// Creates an Ssrc that is not in the session already.
    pub(crate) fn new_ssrc(&self) -> Ssrc {
        loop {
            let ssrc: Ssrc = (rand::random::<u32>()).into();
            if !self.session.has_ssrc(ssrc) {
                break ssrc;
            }
        }
    }

    pub fn poll_output(&mut self) -> Result<Output, RtcError> {
        if !self.alive {
            return Ok(Output::Timeout(not_happening()));
        }

        while let Some(e) = self.ice.poll_event() {
            match e {
                IceAgentEvent::IceRestart(_) => {
                    //
                }
                IceAgentEvent::IceConnectionStateChange(v) => {
                    return Ok(Output::Event(Event::IceConnectionStateChange(v)))
                }
                IceAgentEvent::NewLocalCandidate(v) => {
                    return Ok(Output::Event(Event::IceCandidate(v)))
                }
                IceAgentEvent::DiscoveredRecv { source } => {
                    self.remote_addrs.push(source);
                    while self.remote_addrs.len() > 20 {
                        self.remote_addrs.remove(0);
                    }
                }
                IceAgentEvent::NominatedSend {
                    source,
                    destination,
                } => {
                    self.send_addr = Some(SendAddr {
                        source,
                        destination,
                    });
                }
            }
        }

        while let Some(e) = self.dtls.poll_event() {
            match e {
                DtlsEvent::Connected => {
                    //
                }
                DtlsEvent::SrtpKeyingMaterial(mat) => {
                    self.session.set_keying_material(mat);
                }
                DtlsEvent::RemoteFingerprint(v1) => {
                    if let Some(v2) = &self.remote_fingerprint {
                        if v1 != *v2 {
                            self.alive = false;
                            return Err(RtcError::RemoteSdp("remote fingerprint no match".into()));
                        }
                    } else {
                        self.alive = false;
                        return Err(RtcError::RemoteSdp("no a=fingerprint before dtls".into()));
                    }
                }
            }
        }

        while let Some(e) = self.session.poll_event() {
            match e {
                MediaEvent::MediaData(mid, pt, data) => {
                    return Ok(Output::Event(Event::MediaData(mid, pt, data)))
                }
                MediaEvent::MediaError(mid, pt, err) => {
                    return Ok(Output::Event(Event::MediaError(mid, pt, err)))
                }
            }
        }

        if let Some(v) = self.ice.poll_transmit() {
            return Ok(Output::Transmit(v));
        }

        if let Some(send) = &self.send_addr {
            // These can only be sent after we got an ICE connection.
            let datagram = None
                .or_else(|| self.dtls.poll_datagram())
                .or_else(|| self.session.poll_datagram());

            if let Some(contents) = datagram {
                let t = net::Transmit {
                    source: send.source,
                    destination: send.destination,
                    contents,
                };
                return Ok(Output::Transmit(t));
            }
        }

        let time = None
            .soonest(self.ice.poll_timeout())
            .soonest(self.session.poll_timeout())
            .unwrap_or_else(not_happening);

        // We want to guarantee time doesn't go backwards.
        let next = if time < self.last_now {
            self.last_now
        } else {
            time
        };

        Ok(Output::Timeout(next))
    }

    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        if !self.alive {
            return Ok(());
        }

        match input {
            Input::Timeout(now) => self.do_handle_timeout(now),
            Input::Receive(now, r) => self.do_handle_receive(now, r)?,
        }
        Ok(())
    }

    pub fn media(&mut self, mid: Mid) -> Option<&mut Media> {
        self.session.get_media(mid)
    }

    pub fn channel(&mut self, mid: Mid) -> Option<&mut Channel> {
        self.session.get_channel(mid)
    }

    fn do_handle_timeout(&mut self, now: Instant) {
        self.last_now = now;
        self.ice.handle_timeout(now);
        self.session.handle_timeout(now);
    }

    fn do_handle_receive(&mut self, now: Instant, r: net::Receive) -> Result<(), RtcError> {
        self.last_now = now;
        use net::DatagramRecv::*;
        match r.contents {
            Stun(_) => self.ice.handle_receive(now, r),
            Dtls(_) => self.dtls.handle_receive(r)?,
            Rtp(_) | Rtcp(_) => self.session.handle_receive(now, r),
        }

        Ok(())
    }
}

pub struct PendingChanges<'a> {
    rtc: &'a mut Rtc,
}

impl<'a> PendingChanges<'a> {
    pub fn accept_answer(self, answer: Answer) -> Result<(), RtcError> {
        self.rtc.accept_answer(Some(answer))
    }

    pub fn rollback(self) {
        self.rtc.accept_answer(None).expect("rollback to not error");
    }
}
