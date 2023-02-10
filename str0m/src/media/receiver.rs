use std::time::Instant;

use rtp::{
    MediaTime, Mid, Nack, ReceiverReport, ReportList, Rid, RtpHeader, SenderInfo, SeqNo, Ssrc,
};

use crate::{
    stats::{MediaIngressStats, StatsSnapshot},
    util::already_happened,
};

use super::{register::ReceiverRegister, KeyframeRequestKind, Source};

#[derive(Debug)]
pub(crate) struct ReceiverSource {
    ssrc: Ssrc,
    repairs: Option<Ssrc>,
    rid: Option<Rid>,
    register: Option<ReceiverRegister>,
    last_used: Instant,
    sender_info: Option<SenderInfo>,
    sender_info_at: Option<Instant>,
    fir_seq_no: u8,
    // count of bytes received, including retransmissions
    bytes: u64,
    // count of packets received, including retransmissions
    packets: u64,
    firs: u64,
    plis: u64,
    nacks: u64,
}

impl ReceiverSource {
    pub fn new(ssrc: Ssrc) -> Self {
        info!("New ReceiverSource: {}", ssrc);
        ReceiverSource {
            ssrc,
            repairs: None,
            rid: None,
            register: None,
            last_used: already_happened(),
            sender_info: None,
            sender_info_at: None,
            fir_seq_no: 0,
            bytes: 0,
            packets: 0,
            firs: 0,
            plis: 0,
            nacks: 0,
        }
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

    pub fn create_nack(&mut self) -> Option<Nack> {
        let mut nack = self.register.as_mut().and_then(|r| r.nack_report())?;
        // sender set one level up
        nack.ssrc = self.ssrc;

        info!("Send nack: {:?}", nack);
        Some(nack)
    }

    pub fn set_sender_info(&mut self, now: Instant, s: SenderInfo) {
        self.sender_info = Some(s);
        self.sender_info_at = Some(now);
    }

    pub fn update_packet_counts(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
    }

    pub fn update_with_keyframe_request(&mut self, req: KeyframeRequestKind) {
        match req {
            KeyframeRequestKind::Pli => self.plis += 1,
            KeyframeRequestKind::Fir => self.firs += 1,
        }
    }

    pub fn update_with_nack(&mut self) {
        self.nacks += 1;
    }

    pub(crate) fn next_fir_seq_no(&mut self) -> u8 {
        let x = self.fir_seq_no;
        self.fir_seq_no = self.fir_seq_no.wrapping_add(1);
        x
    }

    pub fn visit_stats(&self, now: Instant, mid: Mid, snapshot: &mut StatsSnapshot) {
        if self.bytes == 0 {
            return;
        }
        let key = (mid, self.rid);
        if let Some(stat) = snapshot.ingress.get_mut(&key) {
            stat.bytes += self.bytes;
            stat.packets += self.packets;
            stat.firs += self.firs;
            stat.plis += self.plis;
            stat.nacks += self.nacks;
        } else {
            snapshot.ingress.insert(
                key,
                MediaIngressStats {
                    mid,
                    rid: self.rid,
                    bytes: self.bytes,
                    packets: self.packets,
                    ts: now,
                    firs: self.firs,
                    plis: self.plis,
                    nacks: self.nacks,
                },
            );
        }
    }
}

impl Source for ReceiverSource {
    fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    fn repairs(&self) -> Option<Ssrc> {
        self.repairs
    }

    fn set_repairs(&mut self, repairs: Ssrc) -> bool {
        assert!(repairs != self.ssrc);
        if self.repairs != Some(repairs) {
            info!("ReceiverSource {} repairs: {}", self.ssrc, repairs);
            self.repairs = Some(repairs);
            true
        } else {
            false
        }
    }

    fn is_rtx(&self) -> bool {
        self.repairs.is_some()
    }

    fn rid(&self) -> Option<Rid> {
        self.rid
    }

    #[must_use]
    fn set_rid(&mut self, rid: Rid) -> bool {
        if self.rid != Some(rid) {
            info!("ReceiverSource {} has Rid: {}", self.ssrc, rid);
            self.rid = Some(rid);
            true
        } else {
            false
        }
    }
}
