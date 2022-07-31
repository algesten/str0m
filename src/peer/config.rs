use crate::sdp::Setup;
use crate::{state, Error, Peer};

/// Configuration for instantiating a [`crate::Peer`].
#[derive(Default)]
pub struct PeerConfig {
    pub(crate) session_id: Option<u64>,
    pub(crate) disable_trickle_ice: bool,
    pub(crate) offer_setup: Setup,
    pub(crate) answer_active: bool,
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
    /// Enabled by default.
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

    /// Creates a new [`Peer`] from this config.
    pub fn build(self) -> Result<Peer<state::Init>, Error> {
        Peer::<state::Init>::with_config(self)
    }
}
