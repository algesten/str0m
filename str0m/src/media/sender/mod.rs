use std::time::Instant;

use rtp::{RtcpFb, Ssrc};

pub struct SenderSource {
    ssrc: Ssrc,
    last_used: Instant,
}

impl SenderSource {
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub(crate) fn create_sender_info(&self) -> RtcpFb {
        todo!()
    }
}
