#[macro_use]
extern crate tracing;

use std::io;
use std::marker::PhantomData;
use std::time::Instant;

use dtls::Dtls;
use ice::IceAgent;
use media::Session;
use net::{Receive, Transmit};
use rtp::Mid;
use sdp::{Answer, Offer};
use thiserror::Error;

mod media;

mod change_set;
pub use change_set::change;
pub use change_set::{ChangeSet, MediaKind};

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

pub struct Rtc<State> {
    ice: IceAgent,
    dtls: Dtls,
    session: Session,
    _ph: PhantomData<State>,
}

/// States the `Rtc` can be in.
pub mod state {
    /// First state after creation.
    pub struct Inited(());

    /// While doing the initial offer, we are only accepting an answer. This is before
    /// any UDP traffic has started.
    pub struct FirstOffer(());

    /// When we're ready to connect (first Offer/Answer exchange is finished).
    pub struct Connecting(());

    /// When we have connected.
    pub struct Connected(());

    /// While we have made a new offer.
    ///
    /// This goes back to `Connected` once the answer for the offer
    /// has been received back and applied.
    pub struct Offering(());
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

impl<S> Rtc<S> {
    pub(crate) fn into_state<T>(self) -> Rtc<T> {
        Rtc {
            ice: self.ice,
            dtls: self.dtls,
            session: self.session,
            _ph: PhantomData,
        }
    }

    pub(crate) fn new_mid(&self) -> Mid {
        loop {
            let mid = Mid::new();
            if !self.session.has_mid(mid) {
                break mid;
            }
        }
    }

    fn do_poll_output(&mut self) -> Output {
        todo!()
    }

    fn do_handle_input(&mut self, input: Input) -> Result<(), RtcError> {
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

impl Rtc<state::Inited> {
    pub fn new() -> Self {
        Rtc {
            ice: IceAgent::new(),
            dtls: Dtls::new().expect("DTLS to init without problem"),
            session: Session::new(),
            _ph: PhantomData,
        }
    }

    pub fn create_offer(mut self) -> ChangeSet<state::Inited, change::Unchanged> {
        // Creating an offer means we are initiating the DTLS as well.
        self.dtls.set_active(true);

        ChangeSet::new(self)
    }

    pub fn accept_offer(mut self, offer: Offer) -> Rtc<state::Connecting> {
        // Accepting an offer means we're not initiating the DTLS connection.
        self.dtls.set_active(false);

        todo!()
    }
}

impl Rtc<state::FirstOffer> {
    pub fn accept_answer(mut self, answer: Answer) -> Rtc<state::Connecting> {
        todo!()
    }
}

impl Rtc<state::Connecting> {
    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        self.do_handle_input(input)
    }

    pub fn poll_output(&mut self) -> Output {
        self.do_poll_output()
    }
}

impl Rtc<state::Connected> {
    pub fn create_change(self) -> ChangeSet<state::Connected, change::Unchanged> {
        ChangeSet::new(self)
    }

    pub fn accept_offer(self) -> Answer {
        todo!()
    }

    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        self.do_handle_input(input)
    }

    pub fn poll_output(&mut self) -> Output {
        self.do_poll_output()
    }
}

impl Rtc<state::Offering> {
    pub fn accept_answer(self, answer: Answer) -> Rtc<state::Connected> {
        todo!()
    }

    pub fn rollback(self) -> Rtc<state::Connected> {
        todo!()
    }

    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        self.do_handle_input(input)
    }

    pub fn poll_output(&mut self) -> Output {
        self.do_poll_output()
    }
}
