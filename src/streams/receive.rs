use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::media::KeyframeRequestKind;
use crate::rtp_::{
    extend_u32, Bitrate, DlrrItem, ExtendedReport, Fir, FirEntry, Frequency, MediaTime, Remb,
};
use crate::rtp_::{Mid, Pli, Pt, ReceiverReport};
use crate::rtp_::{ReportBlock, ReportList, Rid, Rrtr, Rtcp, RtcpFb, RtpHeader, SenderInfo, SeqNo};
use crate::rtp_::{SdesType, Ssrc};
use crate::stats::{MediaIngressStats, StatsSnapshot};
use crate::util::InstantExt;
use crate::util::{already_happened, calculate_rtt_ms};

use super::register::ReceiverRegister;
use super::StreamPaused;
use super::{rr_interval, RtpPacket};

/// Incoming encoded stream.
///
/// A stream is a primary SSRC + optional RTX SSRC.
///
/// This is RTP level API. For sample level API see [`Rtc::writer`][crate::Rtc::writer].
#[derive(Debug)]
pub struct StreamRx {
    /// Unique idenfier of the remote stream.
    ///
    /// If the remote changes the SSRC, we will create a new stream, not change this id.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. This can be set later, once we discover it.
    rtx: Option<Ssrc>,

    /// Previous main SSRC. This is to ensure we never go "backwards" in terms
    /// of changing SSRC (for FF).
    previous_ssrc: Option<Ssrc>,

    /// The Media mid this stream belongs to.
    mid: Mid,

    /// The rid that might be used for this stream.
    rid: Option<Rid>,

    /// Incoming CNAME in Sdes reports.
    cname: Option<String>,

    /// Whether we explicitly want to supress NACK sending. This is normally done by not
    /// setting an RTX, however this can be toggled off manually despite RTX being there.
    ///
    /// This is also set to true if the SDP negotiation disables RTX.
    ///
    /// Defaults to false.
    suppress_nack: bool,

    /// Timestamp when we got some indication of remote using this stream.
    last_used: Instant,

    /// Last seen pt and clock_rate in
    last_clock_rate: Option<(Pt, Frequency)>,

    /// Last received sender info.
    sender_info: Option<(Instant, SenderInfo)>,

    /// ROC to reset with on next incoming packet.
    reset_roc: Option<u64>,

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

    /// If we have a pending REMB request to send.
    pending_request_remb: Option<Bitrate>,

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
    pub(crate) fn new(ssrc: Ssrc, mid: Mid, rid: Option<Rid>, suppress_nack: bool) -> Self {
        debug!("Create StreamRx for SSRC: {}", ssrc);

        StreamRx {
            ssrc,
            rtx: None,
            previous_ssrc: None,
            mid,
            rid,
            cname: None,
            suppress_nack,
            last_used: already_happened(),
            last_clock_rate: None,
            sender_info: None,
            reset_roc: None,
            register: None,
            register_rtx: None,
            last_time: None,
            pending_request_keyframe: None,
            pending_request_remb: None,
            fir_seq_no: 0,
            last_receiver_report: already_happened(),
            stats: StreamRxStats::default(),
            check_paused_at: None,
            paused: true,
            need_paused_event: false,
            pause_threshold: Duration::from_millis(1500),
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

    /// CNAME as sent by remote peer in a Sdes.
    ///
    /// The value is None until we receive a first report with the value set.
    pub fn cname(&self) -> Option<&str> {
        self.cname.as_deref()
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

    /// Request max recv bitrate for an incoming encoded stream.
    ///
    /// * bitrate Bitrate.
    pub fn request_remb(&mut self, bitrate: Bitrate) {
        self.pending_request_remb = Some(bitrate);
    }

    /// Suppress NACK sending.
    ///
    /// Normally NACK is disabled by not having an RTX SSRC set. In some situations it might be
    /// desirable to manually suppress NACK sending regardless of RTX setting.
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
                        // CNAMEs are a bit unfashionable.
                        self.cname = Some(st);
                        return;
                    }
                }
            }
            DlrrItem(v) => {
                self.set_dlrr_item(now, v);
            }
            Goodbye(_v) => {
                // We get Goodbye at weird times, like SDP renegotiation, which makes
                // pausing on the BYE not a good idea. Chrome also reuses the SSRC it
                // just sent BYE on. Very not helpful.
            }
            _ => {}
        }
    }

    fn set_sender_info(&mut self, now: Instant, mut info: SenderInfo) {
        // Extend the incoming time given our knowledge of last time.
        let extended = {
            let prev = self.sender_info.map(|(_, sr)| sr.rtp_time.numer() as u64);
            let r_u32 = info.rtp_time.numer() as u32;
            extend_u32(prev, r_u32)
        };

        // The MediaTime has a base 1 after being parsed. At this point
        // we know whether it's audio or video and set the base accordingly.
        let clock_rate = self
            .last_clock_rate
            .map(|(_, r)| r)
            .unwrap_or(Frequency::SECONDS);

        // Clock rate is that of the last received packet.
        info.rtp_time = MediaTime::new(extended as i64, clock_rate);

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
        clock_rate: Frequency,
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

        let register = register_ref.get_or_insert_with(ReceiverRegister::new);

        // If the user has called `reset_seq_no`, this is the time to handle it, but only
        // if the incoming packet is for main (not repair).
        let mut reset_seq_no = None;
        if !is_repair {
            if let Some(reset_roc) = self.reset_roc.take() {
                let s: SeqNo = (reset_roc << 16 | header.sequence_number as u64).into();
                reset_seq_no = Some(s);
            }
        }

        let seq_no = if let Some(reset_seq_no) = reset_seq_no {
            reset_seq_no
        } else {
            header.sequence_number(register.max_seq())
        };

        let is_new_packet = register.update(seq_no, now, header.timestamp, clock_rate.get());

        let previous_time = self.last_time.map(|t| t.numer() as u64);
        let time_u32 = extend_u32(previous_time, header.timestamp);
        let time = MediaTime::new(time_u32 as i64, clock_rate);

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

        let need_clock_rate = self.last_clock_rate.map(|(pt, _)| pt) != Some(header.payload_type);
        if need_clock_rate {
            self.last_clock_rate = Some((header.payload_type, time.frequency()));

            // If we get an SR before the first packet, we update the potential clock rate.
            if let Some(info) = &mut self.sender_info {
                info.1.rtp_time = MediaTime::new(info.1.rtp_time.numer(), time.frequency());
            }
        }

        let packet = RtpPacket {
            seq_no,
            time,
            header,
            payload: data,
            nackable: false,
            last_sender_info: self.sender_info.map(|(_, s)| s),
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
        header.ext_vals.rid = header.ext_vals.rid_repair.take();
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

    pub(crate) fn maybe_create_remb_request(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        let Some(bitrate) = self.pending_request_remb.take() else {
            return;
        };

        feedback.push_back(Rtcp::Remb(Remb {
            sender_ssrc,
            ssrc: 0.into(),
            bitrate: bitrate.as_f64() as f32,
            ssrcs: vec![*self.ssrc],
        }))
    }

    fn next_fir_seq_no(&mut self) -> u8 {
        let x = self.fir_seq_no;
        self.fir_seq_no = self.fir_seq_no.wrapping_add(1);
        x
    }

    pub(crate) fn need_rr(&self, now: Instant) -> bool {
        now >= self.receiver_report_at()
    }

    pub(crate) fn create_rr_and_update(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        let mut rr = self.create_receiver_report(now);
        rr.sender_ssrc = sender_ssrc;

        if !rr.reports.is_empty() {
            let l = rr.reports[rr.reports.len() - 1].fraction_lost;
            self.stats.update_loss(l);
        }

        let xr = self.create_extended_receiver_report(now);

        debug!(
            "Created feedback RR/XR ({:?}/{:?}): {:?} {:?}",
            self.mid, self.rid, rr, xr
        );
        feedback.push_back(Rtcp::ReceiverReport(rr));
        feedback.push_back(Rtcp::ExtendedReport(xr));

        self.last_receiver_report = now;
    }

    fn create_receiver_report(&mut self, now: Instant) -> ReceiverReport {
        let Some(mut report) = self.register.as_mut().and_then(|r| r.reception_report()) else {
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
                .unwrap_or(already_happened());

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
        let block = ReportBlock::Rrtr(Rrtr { ntp_time: now });
        ExtendedReport {
            ssrc: self.ssrc,
            blocks: vec![block],
        }
    }

    fn nack_enabled(&self) -> bool {
        // Deliberately don't look at RTX is_some() here, since when using dynamic SSRC, we might need
        // to send NACK before discovering the remote RTX.
        !self.suppress_nack
    }

    pub(crate) fn maybe_create_nack(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        if !self.nack_enabled() {
            return None;
        }

        let nacks = self.register.as_mut().and_then(|r| r.nack_report())?;

        for mut nack in nacks {
            nack.sender_ssrc = sender_ssrc;
            nack.ssrc = self.ssrc;

            debug!("Created feedback NACK: {:?}", nack);
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

    pub(crate) fn reset_buffers(&mut self) {
        if let Some(r) = &mut self.register {
            r.clear();
        }

        if let Some(r) = &mut self.register_rtx {
            r.clear();
        }
        self.pending_request_keyframe = None;
    }

    pub(crate) fn change_ssrc(&mut self, ssrc: Ssrc) {
        if ssrc == self.ssrc || Some(ssrc) == self.previous_ssrc {
            return;
        }

        info!(
            "Change main SSRC: {} -> {} mid: {} rid: {:?}",
            self.ssrc, ssrc, self.mid, self.rid
        );

        // Remember which was the previous in case a stray packet turns up
        // so do we don't go "backwards".
        self.previous_ssrc = Some(self.ssrc);
        self.ssrc = ssrc;
        self.register = None;
    }

    pub(crate) fn maybe_reset_rtx(&mut self, rtx: Ssrc) {
        if let Some(current) = self.rtx {
            if current == rtx {
                return;
            }

            info!(
                "Change RTX SSRC {} -> {} for main SSRC: {} mid: {} rid: {:?}",
                current, rtx, self.ssrc, self.mid, self.rid
            );
        } else {
            debug!("SSRC {} associated with RTX: {}", self.ssrc, rtx);
        }

        self.rtx = Some(rtx);
        self.register_rtx = None;
    }

    /// Reset the current rollover counter (ROC).
    ///
    /// This is used in scenarios where we use a single sequence number across all
    /// receivers of the same stream (as opposed to a sequence number unique per peer).
    ///
    /// [RFC3711](https://datatracker.ietf.org/doc/html/rfc3711#section-3.3.1):
    ///
    /// > Receivers joining an on-going session MUST be given the
    /// > current ROC value using out-of-band signaling such as key-management
    /// > signaling.  Furthermore, the receiver SHALL initialize s_l to the RTP
    /// > sequence number (SEQ) of the first observed SRTP packet (unless the
    /// > initial value is provided by out of band signaling such as key
    /// > management).
    pub fn reset_roc(&mut self, roc: u64) {
        self.register = None;
        self.register_rtx = None;
        self.reset_roc = Some(roc);
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
        let stats = MediaIngressStats {
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
        };

        // Several SSRCs can back a given (mid, rid) tuple. For example, Firefox creates new SSRCs
        // when a Transceiver transitions from send -> inactive -> send. In order to continue
        // correctly reporting stats for this (mid, rid) pair we need to merge the stats across all
        // the SSRCs that have been used.
        snapshot
            .ingress
            .entry(key)
            .and_modify(|s| s.merge_by_mid_rid(&stats))
            .or_insert(stats);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RegisterUpdateReceipt {
    pub seq_no: SeqNo,
    pub time: MediaTime,
    pub is_new_packet: bool,
}
