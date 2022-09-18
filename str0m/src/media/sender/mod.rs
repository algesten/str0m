use std::time::Instant;

use rtp::{ReportList, SenderInfo, SenderReport, Ssrc};

use crate::util::already_happened;

pub struct SenderSource {
    ssrc: Ssrc,
    last_used: Instant,
}

impl SenderSource {
    pub fn new(ssrc: Ssrc) -> Self {
        SenderSource {
            ssrc,
            last_used: already_happened(),
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub fn create_sender_report(&self, now: Instant) -> SenderReport {
        SenderReport {
            sender_info: self.sender_info(now),
            reports: ReportList::new(),
        }
    }

    fn sender_info(&self, now: Instant) -> SenderInfo {
        SenderInfo {
            ssrc: self.ssrc,
            ntp_time: now.into(),
            rtp_time: 0,
            sender_packet_count: 0,
            sender_octet_count: 0,
        }
    }
}
