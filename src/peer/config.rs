use crate::sdp::Setup;

#[derive(Default)]
pub struct PeerConfig {
    pub(crate) offset_setup: Setup,
    pub(crate) answer_active: bool,
}

impl PeerConfig {
    pub fn new() -> PeerConfig {
        PeerConfig::default()
    }

    pub fn offset_active(mut self) -> Self {
        self.offset_setup = Setup::Active;
        self
    }

    pub fn offset_passive(mut self) -> Self {
        self.offset_setup = Setup::Passive;
        self
    }

    pub fn offset_actpass(mut self) -> Self {
        self.offset_setup = Setup::ActPass;
        self
    }

    pub fn answer_active(mut self) -> Self {
        self.answer_active = true;
        self
    }

    pub fn answer_passive(mut self) -> Self {
        self.answer_active = false;
        self
    }
}
