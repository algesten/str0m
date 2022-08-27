use std::time::{Duration, Instant};

use rtp::{RtpHeader, SeqNo, Ssrc};

mod register;
use register::ReceiverRegister;

use crate::util::not_happening;

const SSRC_ALIVE: Duration = Duration::from_millis(10_000);

// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
const RR_INTERVAL: Duration = Duration::from_millis(4000);
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(250);

pub struct ReceiverSource {
    pub ssrc: Ssrc,
    pub register: ReceiverRegister,
    pub last_used: Instant,
    pub last_rr: Instant,
    pub last_nack: Instant,
}

impl ReceiverSource {
    pub fn new(header: &RtpHeader, now: Instant) -> Self {
        let base_seq = header.sequence_number(None);
        ReceiverSource {
            ssrc: header.ssrc,
            register: ReceiverRegister::new(base_seq),
            last_used: now,
            last_rr: now,
            last_nack: now,
        }
    }

    pub fn update(&mut self, now: Instant, header: &RtpHeader, clock_rate: u32) -> SeqNo {
        self.last_used = now;

        let seq_no = header.sequence_number(Some(self.register.max_seq()));

        self.register.update_seq(seq_no);
        self.register.update_time(now, header.timestamp, clock_rate);

        seq_no
    }

    pub fn is_valid(&self) -> bool {
        self.register.is_valid()
    }

    pub fn poll_timeout(&mut self) -> Instant {
        // cleanup when it's time to remove the SSRC receiver.
        let cleanup_at = self.last_used + SSRC_ALIVE;

        // next regular receiver report
        let rr_at = self.last_rr + RR_INTERVAL;

        // if we need to send a nack.
        let nack_at = if self.register.has_nack_report() {
            self.last_nack + NACK_MIN_INTERVAL
        } else {
            not_happening()
        };

        [cleanup_at, rr_at, nack_at].into_iter().min().unwrap()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        //
    }
}
