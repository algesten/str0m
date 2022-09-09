use std::time::Instant;

use rtp::{ReportList, SenderInfo, SenderReport, Ssrc};

pub struct SenderSource {
    ssrc: Ssrc,
    last_used: Instant,
}

impl SenderSource {
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub(crate) fn create_sender_report(&self, now: Instant) -> SenderReport {
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
