use std::time::Instant;

use rtp::{Descriptions, ReportList, Sdes, SdesType, SenderInfo, SenderReport, SeqNo, Ssrc};

use crate::util::already_happened;

#[derive(Debug)]
pub struct SenderSource {
    ssrc: Ssrc,
    is_rtx: bool,
    next_seq_no: SeqNo,
    last_used: Instant,
}

impl SenderSource {
    pub fn new(ssrc: Ssrc, is_rtx: bool) -> Self {
        SenderSource {
            ssrc,
            is_rtx,
            // https://www.rfc-editor.org/rfc/rfc3550#page-13
            // The initial value of the sequence number SHOULD be random (unpredictable)
            // to make known-plaintext attacks on encryption more difficult
            next_seq_no: (rand::random::<u16>() as u64).into(),
            last_used: already_happened(),
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub fn is_rtx(&self) -> bool {
        self.is_rtx
    }

    pub fn create_sender_report(&self, now: Instant) -> SenderReport {
        SenderReport {
            sender_info: self.sender_info(now),
            reports: ReportList::new(),
        }
    }

    pub fn create_sdes(&self, cname: &str) -> Descriptions {
        let mut s = Sdes {
            ssrc: self.ssrc,
            values: ReportList::new(),
        };
        s.values.push((SdesType::CNAME, cname.to_string()));

        let mut d = Descriptions {
            reports: ReportList::new(),
        };
        d.reports.push(s);

        d
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

    pub fn next_seq_no(&mut self, now: Instant) -> SeqNo {
        self.last_used = now;
        let s = self.next_seq_no;
        self.next_seq_no = (*s + 1).into();
        s
    }
}
