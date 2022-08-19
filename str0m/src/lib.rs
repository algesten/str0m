#[macro_use]
extern crate tracing;

use std::io;
use std::time::Instant;

use change::Changes;
use dtls::Dtls;
use ice::IceAgent;
use media::Session;
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
    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    /// DTLS errors
    #[error("{0}")]
    Dtls(#[from] dtls::DtlsError),
}

pub struct Rtc {
    ice: IceAgent,
    dtls: Dtls,
    setup: Setup,
    session: Session,
    pending: Option<Changes>,
}

pub enum Event {
    //
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

impl Rtc {
    pub fn new() -> Self {
        Rtc {
            ice: IceAgent::new(),
            dtls: Dtls::new().expect("DTLS to init without problem"),
            setup: Setup::ActPass,
            session: Session::new(),
            pending: None,
        }
    }

    pub fn create_offer(&mut self) -> ChangeSet {
        // Creating an offer means we are initiating the DTLS as well.
        // self.dtls.set_active(true);

        ChangeSet::new(self)
    }

    pub fn accept_offer(&mut self, offer: Offer) -> Option<Answer> {
        // rollback any pending changes.
        self.accept_answer(None);

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

        todo!()
    }

    pub(crate) fn set_changes(&mut self, changes: Changes) {
        self.pending = Some(changes);
    }

    pub fn pending_changes(&mut self) -> Option<PendingChanges> {
        self.pending.as_ref()?;
        Some(PendingChanges { rtc: self })
    }

    fn accept_answer(&mut self, answer: Option<Answer>) {
        if let Some(answer) = answer {
            // Ensure setup=active/passive is corresponding remote and init dtls.
            self.init_setup_dtls(&answer);

            todo!()
        } else {
            // rollback
            self.pending = None;
        }
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

    pub fn poll_output(&mut self) -> Output {
        todo!()
    }

    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        match input {
            Input::Timeout(now) => self.do_handle_timeout(now),
            Input::Receive(now, r) => self.do_handle_receive(now, r)?,
        }
        Ok(())
    }

    fn do_handle_timeout(&mut self, now: Instant) {
        self.ice.handle_timeout(now);
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
    pub fn accept_answer(self, answer: Answer) {
        self.rtc.accept_answer(Some(answer));
    }

    pub fn rollback(self) {
        self.rtc.accept_answer(None);
    }
}
