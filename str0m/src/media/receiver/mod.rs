use std::time::{Duration, Instant};

use rtp::{MediaTime, ReceiverReport, Rtcp, RtpHeader, SenderInfo, SeqNo, Ssrc};

mod register;
use register::ReceiverRegister;
use sdp::SsrcInfo;

// How long an SSRC receiver is alive without receiving any packets.
const SSRC_ALIVE: Duration = Duration::from_millis(10_000);

pub struct ReceiverSource {
    ssrc: Ssrc,
    info: Option<SsrcInfo>,
    register: ReceiverRegister,
    last_used: Instant,
    sender_info: Option<SenderInfo>,
    sender_info_at: Option<Instant>,
}

impl ReceiverSource {
    pub fn new(header: &RtpHeader, now: Instant) -> Self {
        let base_seq = header.sequence_number(None);
        ReceiverSource {
            ssrc: header.ssrc,
            info: None,
            register: ReceiverRegister::new(base_seq),
            last_used: now,
            sender_info: None,
            sender_info_at: None,
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

    pub fn create_receiver_report(&mut self, now: Instant) -> ReceiverReport {
        let mut report = self.register.reception_report();
        report.ssrc = self.ssrc;

        // The middle 32 bits out of 64 in the NTP timestamp (as explained in
        // Section 4) received as part of the most recent RTCP sender report
        // (SR) packet from source SSRC_n.  If no SR has been received yet,
        // the field is set to zero.
        report.last_sr_time = {
            let t = self
                .sender_info
                .map(|s| s.ntp_time)
                .unwrap_or(MediaTime::ZERO);

            let t64 = t.as_ntp_64();
            (t64 >> 16) as u32
        };

        // The delay, expressed in units of 1/65_536 seconds, between
        // receiving the last SR packet from source SSRC_n and sending this
        // reception report block.  If no SR packet has been received yet
        // from SSRC_n, the DLSR field is set to zero.
        report.last_sr_delay = if let Some(t) = self.sender_info_at {
            let delay = now - t;
            ((delay.as_micros() * 65_536) / 1_000_000) as u32
        } else {
            0
        };

        ReceiverReport {
            sender_ssrc: 0.into(), // set one level up
            reports: report.into(),
        }
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

    pub fn set_sender_info(&mut self, now: Instant, s: SenderInfo) {
        self.sender_info = Some(s);
        self.sender_info_at = Some(now);
    }

    pub fn matches_ssrc_info(&self, info: &SsrcInfo) -> bool {
        self.ssrc == info.ssrc || Some(self.ssrc) == info.repair
    }

    pub fn set_ssrc_info(&mut self, info: &SsrcInfo) {
        if self.info.as_ref() != Some(info) {
            debug!("ReceiverSource({}) set info: {:?}", self.ssrc(), info);
            self.info = Some(info.clone());
        }
    }
}
