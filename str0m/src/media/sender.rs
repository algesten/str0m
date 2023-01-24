use std::time::Instant;

use rtp::{Descriptions, ReportList, Rid, Sdes, SdesType, SenderInfo, SenderReport, SeqNo, Ssrc};

use crate::util::already_happened;

use super::Source;

#[derive(Debug)]
pub struct SenderSource {
    ssrc: Ssrc,
    repairs: Option<Ssrc>,
    rid: Option<Rid>,
    next_seq_no: SeqNo,
    last_used: Instant,
    pub bytes_tx: u64,
}

impl SenderSource {
    pub fn new(ssrc: Ssrc) -> Self {
        info!("New SenderSource: {}", ssrc);
        SenderSource {
            ssrc,
            repairs: None,
            rid: None,
            // https://www.rfc-editor.org/rfc/rfc3550#page-13
            // The initial value of the sequence number SHOULD be random (unpredictable)
            // to make known-plaintext attacks on encryption more difficult
            next_seq_no: (rand::random::<u16>() as u64).into(),
            last_used: already_happened(),
            bytes_tx: 0,
        }
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

impl Source for SenderSource {
    fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    fn rid(&self) -> Option<Rid> {
        self.rid
    }

    fn set_rid(&mut self, rid: Rid) -> bool {
        if self.rid != Some(rid) {
            info!("SenderSource {} has Rid: {}", self.ssrc, rid);
            self.rid = Some(rid);
            true
        } else {
            false
        }
    }

    fn is_rtx(&self) -> bool {
        self.repairs.is_some()
    }

    fn repairs(&self) -> Option<Ssrc> {
        self.repairs
    }

    fn set_repairs(&mut self, repairs: Ssrc) -> bool {
        assert!(repairs != self.ssrc);
        if self.repairs != Some(repairs) {
            info!("SenderSource {} repairs: {}", self.ssrc, repairs);
            self.repairs = Some(repairs);
            true
        } else {
            false
        }
    }
}
