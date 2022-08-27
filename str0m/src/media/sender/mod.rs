use std::time::Instant;

use rtp::Ssrc;

pub struct SenderSource {
    pub ssrc: Ssrc,
    pub last_used: Instant,
}
