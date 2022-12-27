use std::time::Instant;

use rtp::{MediaTime, ReceiverReport, ReportList, Rtcp, RtpHeader, SenderInfo, SeqNo, Ssrc};

use super::register::ReceiverRegister;

#[derive(Debug)]
pub struct ReceiverSource {
    ssrc: Ssrc,
    repairs: Option<Ssrc>,
    stream_id: Option<String>,
    register: Option<ReceiverRegister>,
    last_used: Instant,
    sender_info: Option<SenderInfo>,
    sender_info_at: Option<Instant>,
}

impl ReceiverSource {
    pub fn new(ssrc: Ssrc, now: Instant) -> Self {
        info!("New ReceiverSource: {:?}", ssrc);
        ReceiverSource {
            ssrc,
            repairs: None,
            stream_id: None,
            register: None,
            last_used: now,
            sender_info: None,
            sender_info_at: None,
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub fn repairs(&self) -> Option<Ssrc> {
        self.repairs
    }

    pub fn set_repairs(&mut self, repairs: Ssrc) {
        assert!(repairs != self.ssrc);
        info!("ReceiverSource {:?} repairs: {:?}", self.ssrc, repairs);
        self.repairs = Some(repairs);
    }

    pub fn is_rtx(&self) -> bool {
        self.repairs.is_some()
    }

    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_ref().map(|s| s.as_str())
    }

    pub fn set_stream_id(&mut self, id: String) {
        info!("ReceiverSource {:?} stream ID: {}", self.ssrc, id);
        self.stream_id = Some(id);
    }

    pub fn update(&mut self, now: Instant, header: &RtpHeader, clock_rate: u32) -> SeqNo {
        self.last_used = now;

        let previous = self.register.as_ref().map(|r| r.max_seq());
        let seq_no = header.sequence_number(previous);

        if self.register.is_none() {
            self.register = Some(ReceiverRegister::new(seq_no));
        }

        if let Some(register) = &mut self.register {
            register.update_seq(seq_no);
            register.update_time(now, header.timestamp, clock_rate);
        }

        seq_no
    }

    pub fn is_valid(&self) -> bool {
        self.register
            .as_ref()
            .map(|r| r.is_valid())
            .unwrap_or(false)
    }

    pub fn create_receiver_report(&mut self, now: Instant) -> ReceiverReport {
        let Some(mut report) = self.register.as_mut().map(|r| r.reception_report()) else {
            return ReceiverReport {
                sender_ssrc: 0.into(), // set one level up
                reports: ReportList::new(),
            };
        };
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
        self.register
            .as_mut()
            .map(|r| r.has_nack_report())
            .unwrap_or(false)
    }

    pub fn create_nack(&mut self) -> Option<Rtcp> {
        let mut nack = self.register.as_mut().and_then(|r| r.nack_report())?;
        nack.ssrc = self.ssrc;

        info!("Send nack: {:?}", nack);
        Some(Rtcp::Nack(nack))
    }

    pub fn set_sender_info(&mut self, now: Instant, s: SenderInfo) {
        self.sender_info = Some(s);
        self.sender_info_at = Some(now);
    }
}
