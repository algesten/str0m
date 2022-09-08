use std::time::Instant;

use rtp::{Rtcp, Ssrc};

pub struct SenderSource {
    ssrc: Ssrc,
    last_used: Instant,
}

impl SenderSource {
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub(crate) fn create_sender_info(&self) -> Rtcp {
        todo!()
    }
}
