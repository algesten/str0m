use crate::sdp::{Candidate, Setup};
use crate::{state, Error, Peer};

/// Configuration for instantiating a [`crate::Peer`].
#[derive(Default)]
pub struct PeerConfig {
    pub(crate) session_id: Option<u64>,
    pub(crate) disable_trickle_ice: bool,
    pub(crate) offer_setup: Setup,
    pub(crate) answer_active: bool,
    pub(crate) ice_lite: bool,
    pub(crate) local_candidates: Vec<Candidate>,
    pub(crate) end_of_candidates: bool,
}

impl PeerConfig {
    /// Creates a PeerConfig with default values.
    pub fn new() -> Self {
        PeerConfig::default()
    }

    #[doc(hidden)]
    pub fn with_session_id(id: u64) -> Self {
        let mut p = PeerConfig::new();
        p.session_id = Some(id);
        p
    }

    /// Disable trickle ice.
    ///
    /// Trickle ice is enabled by default.
    pub fn disable_trickle_ice(mut self) -> Self {
        self.disable_trickle_ice = true;
        self
    }

    /// Initial offer as `a=setup:active`.
    ///
    /// Default is `a=setup:actpass`.
    pub fn offer_active(mut self) -> Self {
        self.offer_setup = Setup::Active;
        self
    }

    /// Initial offer as `a=setup:passive`.
    ///
    /// Default is `a=setup:actpass`.
    pub fn offer_passive(mut self) -> Self {
        self.offer_setup = Setup::Passive;
        self
    }

    /// Initial answer as `a=setup:active`, if possible.
    ///
    /// Answering `active` is only possible if the offer we respond to is
    /// `actpass` or `passive`. If the incoming offer is `active`, the
    /// answer _must_ be `passive`.
    ///
    /// Default is to assume the passive role.
    pub fn answer_active(mut self) -> Self {
        self.answer_active = true;
        self
    }

    /// Whether this peer will run ice-lite, i.e. only use host candidates.
    ///
    /// This is suitable for a server.
    pub fn ice_lite(mut self) -> Self {
        self.ice_lite = true;
        self
    }

    /// Provide a local ICE candidate.
    pub fn local_candidate(mut self, c: Candidate) -> Self {
        self.local_candidates.push(c);
        self
    }

    /// Mark that there will be no further ICE candidates.
    ///
    /// If trickle-ice is enabled, this allows for "half trickle", where this side will not trickle
    /// anything, but the remote is allowed to trickle further from their end.
    pub fn end_of_candidates(mut self) -> Self {
        self.end_of_candidates = true;
        self
    }

    /// Creates a new [`Peer`] from this config.
    pub fn build(self) -> Result<Peer<state::Init>, Error> {
        Peer::<state::Init>::with_config(self)
    }
}
