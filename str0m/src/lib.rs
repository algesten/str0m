#[macro_use]
extern crate tracing;

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use change::Changes;
use dtls::{Dtls, DtlsEvent, Fingerprint};
use ice::{Candidate, IceAgent};
use ice::{IceAgentEvent, IceConnectionState};
use media::{AsSdpParams, Session};
use net::{Receive, Transmit};
use rtp::Mid;
use sdp::{Answer, Offer, Sdp, Setup};
use thiserror::Error;

mod media;
use media::MediaKind;

mod change;
pub use change::ChangeSet;

/// Errors for the whole Rtc engine.
#[derive(Debug, Error)]
pub enum RtcError {
    /// Some problem with the remote SDP.
    #[error("remote sdp: {0}")]
    RemoteSdp(String),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    /// DTLS errors
    #[error("{0}")]
    Dtls(#[from] dtls::DtlsError),
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
}

struct SendAddr {
    source: SocketAddr,
    destination: SocketAddr,
}

pub enum Event {
    IceCandidate(Candidate),
    IceConnectionStateChange(IceConnectionState),
}

pub enum Input<'a> {
    Timeout(Instant),
    Receive(Instant, Receive<'a>),
}

pub enum Output {
    Timeout(Instant),
    Transmit(Transmit),
    Event(Event),
}

fn future() -> Instant {
    Instant::now() + Duration::from_secs(60 * 60 * 24 * 365 * 10)
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

    pub(crate) fn new_mid(&self) -> Mid {
        loop {
            let mid = Mid::new();
            if !self.session.has_mid(mid) {
                break mid;
            }
        }
    }

    pub fn poll_output(&mut self) -> Result<Output, RtcError> {
        if !self.alive {
            return Ok(Output::Timeout(future()));
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
            match e {}
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
                let t = Transmit {
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
            .unwrap_or_else(future);

        Ok(Output::Timeout(time))
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

    fn do_handle_timeout(&mut self, now: Instant) {
        self.ice.handle_timeout(now);
        self.session.handle_timeout(now);
    }

    fn do_handle_receive(&mut self, now: Instant, r: Receive) -> Result<(), RtcError> {
        use net::DatagramRecv::*;
        match r.contents {
            Stun(_) => self.ice.handle_receive(now, r),
            Dtls(_) => self.dtls.handle_receive(r)?,
            Rtp(_) | Rtcp(_) => self.session.handle_receive(r),
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

trait Soonest {
    fn soonest(self, other: Self) -> Self;
}

impl Soonest for Option<Instant> {
    fn soonest(self, other: Self) -> Self {
        match (self, other) {
            (Some(v1), Some(v2)) => {
                if v1 < v2 {
                    Some(v1)
                } else {
                    Some(v2)
                }
            }
            (None, None) => None,
            (None, v) => v,
            (v, None) => v,
        }
    }
}
