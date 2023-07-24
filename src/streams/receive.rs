use std::collections::VecDeque;
use std::time::Instant;

use crate::media::KeyframeRequestKind;
use crate::packet::QueueSnapshot;
use crate::rtp_::{
    extend_u16, extend_u32, DlrrItem, ExtendedReport, Fir, FirEntry, InstantExt, MediaTime, Mid,
    Pli, Pt, ReceiverReport, ReportBlock, ReportList, Rid, Rrtr, Rtcp, RtcpFb, RtpHeader,
    SenderInfo, SeqNo,
};
use crate::rtp_::{SdesType, Ssrc};
use crate::stats::{MediaIngressStats, StatsSnapshot};
use crate::util::{already_happened, calculate_rtt_ms};

use super::register::ReceiverRegister;
use super::{rr_interval, RtpPacket};

/// Incoming encoded stream.
///
/// A stream is a primary SSRC + optional RTX SSRC.
#[derive(Debug)]
pub struct StreamRx {
    /// Unique idenfier of the remote stream.
    ///
    /// If the remote changes the SSRC, we will create a new stream, not change this id.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. This can be set later, once we discover it.
    rtx: Option<Ssrc>,

    /// The Media mid this stream belongs to.
    mid: Mid,

    /// The rid that might be used for this stream.
    rid: Option<Rid>,

    /// Whether we explicitly want to supress NACK sending. This is normally done by not
    /// setting an RTX, however this can be toggled off manually despite RTX being there.
    ///
    /// Defaults to false.
    suppress_nack: bool,

    /// Timestamp when we got some indication of remote using this stream.
    last_used: Instant,

    /// Last received sender info.
    sender_info: Option<(Instant, SenderInfo)>,

    /// Register of received packets. For NACK handling.
    ///
    /// Set on first ever packet.
    register: Option<ReceiverRegister>,

    /// Last observed media time in an RTP packet.
    last_time: Option<MediaTime>,

    /// If we have a pending keyframe request to send.
    pending_request_keyframe: Option<KeyframeRequestKind>,

    /// Sequence number of the next FIR.
    fir_seq_no: u8,

    /// Last time we produced regular feedback RR.
    last_receiver_report: Instant,

    /// Statistics of incoming data.
    stats: StreamRxStats,
}

/// Holder of stats.
#[derive(Debug, Default)]
pub(crate) struct StreamRxStats {
    /// count of bytes received, including retransmissions
    bytes: u64,
    /// count of packets received, including retransmissions
    packets: u64,
    /// count of FIR requests sent
    firs: u64,
    /// count of PLI requests sent
    plis: u64,
    /// count of NACKs sent
    nacks: u64,
    /// round trip time (ms) from the last DLRR, if any
    rtt: Option<f32>,
    /// fraction of packets lost from the last RR, if any
    loss: Option<f32>,
}

impl StreamRx {
    pub(crate) fn new(ssrc: Ssrc, mid: Mid, rid: Option<Rid>) -> Self {
        debug!("Create StreamRx for SSRC: {}", ssrc);

        StreamRx {
            ssrc,
            rtx: None,
            mid,
            rid,
            suppress_nack: false,
            last_used: already_happened(),
            sender_info: None,
            register: None,
            last_time: None,
            pending_request_keyframe: None,
            fir_seq_no: 0,
            last_receiver_report: already_happened(),
            stats: StreamRxStats::default(),
        }
    }

    pub(crate) fn set_rtx_ssrc(&mut self, rtx: Ssrc) {
        if self.rtx != Some(rtx) {
            debug!("SSRC {} associated with RTX: {}", self.ssrc, rtx);
            self.rtx = Some(rtx);
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub fn rtx(&self) -> Option<Ssrc> {
        self.rtx
    }

    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn rid(&self) -> Option<Rid> {
        self.rid
    }

    /// Request a keyframe for an incoming encoded stream.
    ///
    /// * SSRC the identifier of the remote encoded stream to request a keyframe for.
    /// * kind PLI or FIR.
    pub fn request_keyframe(&mut self, kind: KeyframeRequestKind) {
        self.pending_request_keyframe = Some(kind);
    }

    /// Suppress NACK sending.
    ///
    /// Normally NACK is disabled by not having an RTX SSRC set. In some situations it might be
    /// desirable to manuall suppress NACK sending regardless of RTX setting.
    pub fn suppress_nack(&mut self, suppress: bool) {
        self.suppress_nack = suppress;
    }

    pub(crate) fn receiver_report_at(&self) -> Instant {
        let is_audio = self.rtx.is_none(); // this is maybe not correct, but it's all we got.
        self.last_receiver_report + rr_interval(is_audio)
    }

    pub(crate) fn handle_rtcp(&mut self, now: Instant, fb: RtcpFb) {
        use RtcpFb::*;
        match fb {
            SenderInfo(v) => {
                self.set_sender_info(now, v);
            }
            SourceDescription(v) => {
                for (sdes, st) in v.values {
                    if sdes == SdesType::CNAME {
                        if st.is_empty() {
                            // In simulcast, chrome doesn't send the SSRC lines, but
                            // expects us to infer that from rtp headers. It does
                            // however send the SourceDescription RTCP with an empty
                            // string CNAME. ¯\_(ツ)_/¯
                            return;
                        }

                        // Here we _could_ check CNAME here matches something. But
                        // CNAMEs are a bit unfashionable with the WebRTC spec people.
                        return;
                    }
                }
            }
            DlrrItem(v) => {
                self.set_dlrr_item(now, v);
            }
            Goodbye(_v) => {
                // For some reason, Chrome sends a Goodbye on every SDP negotiation for all active
                // m-lines. Seems strange, but lets not reset any state.
                // self.sources_rx.retain(|s| {
                //     let remove = s.ssrc() == v || s.repairs() == Some(v);
                //     if remove {
                //         trace!("Remove ReceiverSource on Goodbye: {:?}", s.ssrc());
                //     }
                //     !remove
                // });
            }
            _ => {}
        }
    }

    fn set_sender_info(&mut self, now: Instant, info: SenderInfo) {
        self.sender_info = Some((now, info));
    }

    fn set_dlrr_item(&mut self, now: Instant, dlrr: DlrrItem) {
        let ntp_time = now.to_ntp_duration();
        let rtt = calculate_rtt_ms(ntp_time, dlrr.last_rr_delay, dlrr.last_rr_time);
        self.stats.rtt = rtt;
    }

    pub(crate) fn update(
        &mut self,
        now: Instant,
        header: &RtpHeader,
        clock_rate: u32,
    ) -> (SeqNo, MediaTime) {
        self.last_used = now;

        let previous_seq = self.register.as_ref().map(|r| r.max_seq());
        let seq_no = header.sequence_number(previous_seq);

        let previous_time = self.last_time.map(|t| t.numer() as u64);
        let time_u32 = extend_u32(previous_time, header.timestamp);
        let time = MediaTime::new(time_u32 as i64, clock_rate as i64);

        if self.register.is_none() {
            self.register = Some(ReceiverRegister::new(seq_no));
        }

        if let Some(register) = &mut self.register {
            register.update_seq(seq_no);
            register.update_time(now, header.timestamp, clock_rate);
            self.last_time = Some(time);
        }

        (seq_no, time)
    }

    pub(crate) fn handle_rtp(
        &mut self,
        now: Instant,
        mut header: RtpHeader,
        mut data: Vec<u8>,
        mut seq_no: SeqNo,
        time: MediaTime,
        pt: Pt,
        is_repair: bool,
    ) -> Option<RtpPacket> {
        trace!("Handle RTP: {:?}", header);

        // RTX packets must be rewritten to be a normal packet.
        if is_repair {
            let keep_packet = self.un_rtx(&mut header, &mut data, &mut seq_no, pt);

            if !keep_packet {
                return None;
            }
        }

        let packet = RtpPacket {
            seq_no,
            pt: header.payload_type,
            time,
            header,
            payload: data,
            nackable: false,
            timestamp: now,
        };

        self.stats.bytes += packet.payload.len() as u64;
        self.stats.packets += 1;

        Some(packet)
    }

    fn un_rtx(
        &self,
        header: &mut RtpHeader,
        data: &mut Vec<u8>,
        seq_no: &mut SeqNo,
        pt: Pt,
    ) -> bool {
        // Initial packets with just nulls for the RTX.
        if RtpHeader::is_rtx_null_packet(&data) {
            trace!("Drop RTX null packet");
            return false;
        }

        let mut orig_seq_no_16 = 0;

        let n = RtpHeader::read_original_sequence_number(&data, &mut orig_seq_no_16);
        data.drain(0..n);

        trace!(
            "Repaired seq no {} -> {}",
            header.sequence_number,
            orig_seq_no_16
        );

        header.sequence_number = orig_seq_no_16;
        *seq_no = extend_u16(Some(**seq_no), orig_seq_no_16).into();

        header.ssrc = self.ssrc;
        header.payload_type = pt;

        true
    }

    pub(crate) fn maybe_create_keyframe_request(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        let Some(kind) = self.pending_request_keyframe.take() else {
            return;
        };

        let ssrc = self.ssrc;

        match kind {
            KeyframeRequestKind::Pli => {
                self.stats.plis += 1;
                feedback.push_back(Rtcp::Pli(Pli { sender_ssrc, ssrc }))
            }
            KeyframeRequestKind::Fir => {
                self.stats.firs += 1;
                feedback.push_back(Rtcp::Fir(Fir {
                    sender_ssrc,
                    reports: FirEntry {
                        ssrc,
                        seq_no: self.next_fir_seq_no(),
                    }
                    .into(),
                }))
            }
        }
    }

    fn next_fir_seq_no(&mut self) -> u8 {
        let x = self.fir_seq_no;
        self.fir_seq_no += 1;
        x
    }

    pub(crate) fn maybe_create_rr(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        if now < self.receiver_report_at() {
            return;
        }

        let mut rr = self.create_receiver_report(now);
        rr.sender_ssrc = sender_ssrc;

        if !rr.reports.is_empty() {
            let l = rr.reports[rr.reports.len() - 1].fraction_lost;
            self.stats.update_loss(l);
        }

        debug!("Created feedback RR: {:?}", rr);
        feedback.push_back(Rtcp::ReceiverReport(rr));

        let er = self.create_extended_receiver_report(now);
        debug!("Created feedback extended receiver report: {:?}", er);
        feedback.push_back(Rtcp::ExtendedReport(er));

        self.last_receiver_report = now;
    }

    fn create_receiver_report(&mut self, now: Instant) -> ReceiverReport {
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
                .map(|(_, s)| s.ntp_time)
                .unwrap_or(MediaTime::ZERO);

            let t64 = t.as_ntp_64();
            (t64 >> 16) as u32
        };

        // The delay, expressed in units of 1/65_536 seconds, between
        // receiving the last SR packet from source SSRC_n and sending this
        // reception report block.  If no SR packet has been received yet
        // from SSRC_n, the DLSR field is set to zero.
        report.last_sr_delay = if let Some((t, _)) = self.sender_info {
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

    fn create_extended_receiver_report(&self, now: Instant) -> ExtendedReport {
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
        if self.rtx.is_none() || self.suppress_nack {
            return false;
        }
        self.register
            .as_mut()
            .map(|r| r.has_nack_report())
            .unwrap_or(false)
    }

    pub(crate) fn maybe_create_nack(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        if self.rtx.is_none() || self.suppress_nack {
            return None;
        }

        let mut nacks = self.register.as_mut().map(|r| r.nack_reports())?;

        for nack in &mut nacks {
            nack.sender_ssrc = sender_ssrc;
            nack.ssrc = self.ssrc;

            debug!("Created feedback NACK: {:?}", nack);
            self.stats.nacks += 1;
        }

        debug!("Send nacks: {:?}", nacks);

        for nack in nacks {
            feedback.push_back(Rtcp::Nack(nack));
            self.stats.nacks += 1;
        }

        Some(())
    }

    pub(crate) fn visit_stats(&mut self, snapshot: &mut StatsSnapshot, now: Instant) {
        self.stats.fill(snapshot, self.mid, self.rid, now);
    }
}

impl StreamRxStats {
    fn update_loss(&mut self, fraction_lost: u8) {
        self.loss = Some(fraction_lost as f32 / u8::MAX as f32)
    }

    pub(crate) fn fill(
        &mut self,
        snapshot: &mut StatsSnapshot,
        mid: Mid,
        rid: Option<Rid>,
        now: Instant,
    ) {
        if self.bytes == 0 {
            return;
        }

        let key = (mid, rid);

        snapshot.ingress.insert(
            key,
            MediaIngressStats {
                mid,
                rid,
                bytes: self.bytes,
                packets: self.packets,
                firs: self.firs,
                plis: self.plis,
                nacks: self.nacks,
                rtt: self.rtt,
                loss: self.loss,
                timestamp: now,
            },
        );
    }
}
