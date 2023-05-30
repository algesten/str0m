use std::time::Instant;

use crate::rtp::{DlrrItem, ExtendedReport, InstantExt, MediaTime, Mid, Nack, ReceiverReport};
use crate::rtp::{ReportBlock, ReportList, Rid, Rrtr, RtpHeader, SenderInfo, SeqNo, Ssrc};

use crate::{
    stats::{MediaIngressStats, StatsSnapshot},
    util::{already_happened, calculate_rtt_ms},
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
    // round trip time (ms)
    // Can be null in case of missing or bad reports
    rtt: Option<f32>,
    loss: Option<f32>,
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
            rtt: None,
            loss: None,
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

    pub fn update_loss(&mut self, fraction_lost: u8) {
        self.loss = Some(fraction_lost as f32 / u8::MAX as f32)
    }

    pub fn create_extended_receiver_report(&self, now: Instant) -> ExtendedReport {
        // we only want to report our time to measure RTT,
        // the source will answer with Dlrr feedback, allowing us to calculate RTT
        let block = ReportBlock::Rrtr(Rrtr {
            ntp_time: MediaTime::new_ntp_time(now),
        });
        ExtendedReport {
            ssrc: self.ssrc,
            blocks: vec![block],
        }
    }

    pub fn has_nack(&mut self) -> bool {
        self.register
            .as_mut()
            .map(|r| r.has_nack_report())
            .unwrap_or(false)
    }

    pub fn create_nacks(&mut self) -> Option<Vec<Nack>> {
        let mut nacks = self.register.as_mut().map(|r| r.nack_reports())?;
        for nack in &mut nacks {
            // sender set one level up,
            nack.ssrc = self.ssrc;
        }

        debug!("Send nacks: {:?}", nacks);
        Some(nacks)
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

    pub fn set_dlrr_item(&mut self, now: Instant, dlrr: DlrrItem) {
        let ntp_time = now.to_ntp_duration();
        let rtt = calculate_rtt_ms(ntp_time, dlrr.last_rr_delay, dlrr.last_rr_time);
        self.rtt = rtt;
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
        let main = !self.is_rtx();
        let key = (mid, self.rid);
        if let Some(stat) = snapshot.ingress.get_mut(&key) {
            stat.bytes += self.bytes;
            stat.packets += self.packets;
            stat.firs += self.firs;
            stat.plis += self.plis;
            stat.nacks += self.nacks;
            if main {
                stat.rtt = self.rtt;
                stat.loss = self.loss;
            }
        } else {
            snapshot.ingress.insert(
                key,
                MediaIngressStats {
                    mid,
                    rid: self.rid,
                    bytes: self.bytes,
                    packets: self.packets,
                    timestamp: now,
                    firs: self.firs,
                    plis: self.plis,
                    nacks: self.nacks,
                    rtt: if main { self.rtt } else { None },
                    loss: if main { self.loss } else { None },
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
