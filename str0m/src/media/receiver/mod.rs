use std::time::{Duration, Instant};

use rtp::{ReceiverReport, Rtcp, RtpHeader, SeqNo, Ssrc};

mod register;
use register::ReceiverRegister;

// How long an SSRC receiver is alive without receiving any packets.
const SSRC_ALIVE: Duration = Duration::from_millis(10_000);

pub struct ReceiverSource {
    ssrc: Ssrc,
    register: ReceiverRegister,
    last_used: Instant,
}

impl ReceiverSource {
    pub fn new(header: &RtpHeader, now: Instant) -> Self {
        let base_seq = header.sequence_number(None);
        ReceiverSource {
            ssrc: header.ssrc,
            register: ReceiverRegister::new(base_seq),
            last_used: now,
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub fn update(&mut self, now: Instant, header: &RtpHeader, clock_rate: u32) -> SeqNo {
        self.last_used = now;

        let seq_no = header.sequence_number(Some(self.register.max_seq()));

        self.register.update_seq(seq_no);
        self.register.update_time(now, header.timestamp, clock_rate);

        seq_no
    }

    pub fn is_alive(&self, now: Instant) -> bool {
        now <= (self.last_used + SSRC_ALIVE)
    }

    pub fn is_valid(&self) -> bool {
        self.register.is_valid()
    }

    pub fn create_receiver_report(&mut self) -> Rtcp {
        let mut block = self.register.report_block();
        block.ssrc = self.ssrc;

        Rtcp::ReceiverReport(ReceiverReport {
            reports: block.into(),
        })
    }

    pub fn has_nack(&mut self) -> bool {
        self.register.has_nack_report()
    }

    pub fn create_nack(&mut self) -> Option<Rtcp> {
        if let Some(mut nack) = self.register.nack_report() {
            nack.ssrc = self.ssrc;
            return Some(Rtcp::Nack(nack));
        }

        None
    }
}
