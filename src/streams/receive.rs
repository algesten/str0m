use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::media::KeyframeRequestKind;
use crate::rtp_::{
    extend_u32, DlrrItem, ExtendedReport, Fir, FirEntry, InstantExt, MediaTime, Mid, Pli, Pt,
    ReceiverReport, ReportBlock, ReportList, Rid, Rrtr, Rtcp, RtcpFb, RtpHeader, SenderInfo, SeqNo,
};
use crate::rtp_::{SdesType, Ssrc};
use crate::stats::{MediaIngressStats, StatsSnapshot};
use crate::util::{already_happened, calculate_rtt_ms};

use super::register::ReceiverRegister;
use super::StreamPaused;
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

    /// Register of received packets for RTX.
    ///
    /// Set on first ever RTXpacket.
    register_rtx: Option<ReceiverRegister>,

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

    /// When we need to evaluate the paused state.
    ///
    /// now + pause_threshold
    check_paused_at: Option<Instant>,

    /// Whether we consider this StreamRx paused.
    ///
    /// A stream is considered paused if it has received no packets for some (configurable) duration.
    /// This defaults to 1.5s.
    paused: bool,

    /// Whether we need to emit a paused event for the current paused state.
    need_paused_event: bool,

    /// The configured threshold before considering the lack of packets as going into paused.
    pause_threshold: Duration,
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
            register_rtx: None,
            last_time: None,
            pending_request_keyframe: None,
            fir_seq_no: 0,
            last_receiver_report: already_happened(),
            stats: StreamRxStats::default(),
            check_paused_at: None,
            paused: true,
            need_paused_event: false,
            pause_threshold: Duration::from_millis(1500),
        }
    }

    pub(crate) fn set_rtx_ssrc(&mut self, rtx: Ssrc) {
        if self.rtx != Some(rtx) {
            debug!("SSRC {} associated with RTX: {}", self.ssrc, rtx);
            self.rtx = Some(rtx);
        }
    }

    /// The (primary) SSRC of this encoded stream.
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    /// The resend (RTX) SSRC of this encoded stream.
    pub fn rtx(&self) -> Option<Ssrc> {
        self.rtx
    }

    /// Mid for this stream.
    ///
    /// In SDP this corresponds to m-line and "Media".
    pub fn mid(&self) -> Mid {
        self.mid
    }

    /// Rid for this stream.
    ///
    /// This is used to separate streams with the same [`Mid`] when using simulcast.
    pub fn rid(&self) -> Option<Rid> {
        self.rid
    }

    /// Set threshold duration for emitting the paused event.
    ///
    /// This event is emitted when no packet have received for this duration.
    pub fn set_pause_threshold(&mut self, t: Duration) {
        self.pause_threshold = t;
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
                // We get Goodbye at weird times, like SDP renegotiation, which makes
                // pausing on the BYE not a good idea.
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

    pub(crate) fn paused_at(&self) -> Option<Instant> {
        self.check_paused_at
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        // No scheduled paused check?
        if self.check_paused_at.is_none() {
            return;
        }

        // Not reached scheduled paused check?
        if Some(now) < self.check_paused_at {
            return;
        }

        // Every update() schedules a paused check in the future. If we have reached that
        // future we have implicitly also paused.
        self.check_paused_at = None;

        self.paused = true;
        self.need_paused_event = true;
    }

    pub(crate) fn update(
        &mut self,
        now: Instant,
        header: &RtpHeader,
        clock_rate: u32,
        is_repair: bool,
    ) -> RegisterUpdateReceipt {
        self.last_used = now;

        if self.paused {
            self.paused = false;
            self.need_paused_event = true;
        }
        self.check_paused_at = Some(now + self.pause_threshold);

        // Select reference to register to use depending on RTX or not. The RTX has a separate
        // sequence number series to the main register.
        let register_ref = if is_repair {
            &mut self.register_rtx
        } else {
            &mut self.register
        };

        let register =
            register_ref.get_or_insert_with(|| ReceiverRegister::new(header.sequence_number(None)));

        let seq_no = header.sequence_number(Some(register.max_seq()));

        let is_new_packet = register.update_seq(seq_no);
        register.update_time(now, header.timestamp, clock_rate);

        let previous_time = self.last_time.map(|t| t.numer() as u64);
        let time_u32 = extend_u32(previous_time, header.timestamp);
        let time = MediaTime::new(time_u32 as i64, clock_rate as i64);

        if !is_repair {
            self.last_time = Some(time);
        }

        RegisterUpdateReceipt {
            seq_no,
            time,
            is_new_packet,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_rtp(
        &mut self,
        now: Instant,
        header: RtpHeader,
        data: Vec<u8>,
        seq_no: SeqNo,
        time: MediaTime,
    ) -> Option<RtpPacket> {
        trace!("Handle RTP: {:?}", header);

        let packet = RtpPacket {
            seq_no,
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

    pub(crate) fn un_rtx(&self, header: &mut RtpHeader, data: &mut Vec<u8>, pt: Pt) {
        let mut orig_seq_no_16 = 0;

        let n = RtpHeader::read_original_sequence_number(data, &mut orig_seq_no_16);
        data.drain(0..n);

        trace!(
            "Repaired seq no {} -> {}",
            header.sequence_number,
            orig_seq_no_16
        );

        header.sequence_number = orig_seq_no_16;

        header.ssrc = self.ssrc;
        header.payload_type = pt;
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

    pub(crate) fn has_nack(&mut self) -> bool {
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
        if self.suppress_nack {
            return None;
        }

        let mut nacks = self.register.as_mut().map(|r| r.nack_reports())?;

        for nack in &mut nacks {
            nack.sender_ssrc = sender_ssrc;
            nack.ssrc = self.ssrc;

            debug!("Created feedback NACK: {:?}", nack);
            self.stats.nacks += 1;
        }

        if !nacks.is_empty() {
            debug!("Send nacks: {:?}", nacks);
        }

        for nack in nacks {
            feedback.push_back(Rtcp::Nack(nack));
            self.stats.nacks += 1;
        }

        Some(())
    }

    pub(crate) fn visit_stats(&mut self, snapshot: &mut StatsSnapshot, now: Instant) {
        self.stats.fill(snapshot, self.mid, self.rid, now);
    }

    pub(crate) fn poll_paused(&mut self) -> Option<StreamPaused> {
        if !self.need_paused_event {
            return None;
        }

        self.need_paused_event = false;

        info!(
            "{} StreamRx with mid: {} rid: {:?} and SSRC: {}",
            if self.paused { "Paused" } else { "Unpaused" },
            self.mid,
            self.rid,
            self.ssrc
        );

        Some(StreamPaused {
            ssrc: self.ssrc,
            mid: self.mid,
            rid: self.rid,
            paused: self.paused,
        })
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct RegisterUpdateReceipt {
    pub seq_no: SeqNo,
    pub time: MediaTime,
    pub is_new_packet: bool,
}
