use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config_mod::RtcpReportIntervals;
use crate::format::PayloadParams;
use crate::media::KeyframeRequestKind;
use crate::packet::MAX_RED_RECOVERY_DEPTH;
use crate::rtp_::MidRid;
use crate::rtp_::{Bitrate, DlrrItem, ExtendedReport, extend_u32};
use crate::rtp_::{Fir, FirEntry, Frequency, MediaTime, Remb};
use crate::rtp_::{Mid, Pli, Pt, ReceiverReport};
use crate::rtp_::{ReportBlock, ReportList, Rid, Rrtr, Rtcp};
use crate::rtp_::{RtcpFb, RtpHeader, SenderInfo, SeqNo};
use crate::rtp_::{SdesType, Ssrc};
use crate::stats::{MediaIngressStats, RemoteEgressStats, StatsSnapshot};
use crate::util::{InstantExt, SystemTimeExt};
use crate::util::{already_happened, calculate_rtt};

use super::RtpPacket;
use super::StreamPaused;
use super::register::ReceiverRegister;

/// How many recent packets to remember for placing RED redundant blocks. Must cover the
/// recovery depth plus some reordering slack.
const RED_RECENT_PACKETS: usize = 32;

#[derive(Debug)]
struct EventTimeReference {
    seq_no: Option<SeqNo>,
    timestamp: u64,
}

/// Incoming encoded stream.
///
/// A stream is a primary SSRC + optional RTX SSRC.
///
/// This is RTP level API. For frame level API see [`Rtc::writer`][crate::Rtc::writer].
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

    /// The Media mid/rid this stream belongs to.
    midrid: MidRid,

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
    sender_info: Option<LastSenderInfo>,

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

    /// Recent audio packets as `(seq_no, primary pt, extended rtp time)`, used to place
    /// RFC 2198 RED blocks. Telephone events share sequence numbers, not audio timestamps.
    /// Bounded by `RED_RECENT_PACKETS`.
    red_recent: VecDeque<(SeqNo, Pt, MediaTime)>,

    /// Last observed media time in an RTP packet.
    last_time: Option<MediaTime>,

    /// Timestamp extension reference for ordinary media.
    last_media_time: Option<MediaTime>,

    /// Telephone-event references by clock rate, bounded by configured payload types.
    event_times: HashMap<u32, EventTimeReference>,

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

/// The last sender info we recieved.
#[derive(Debug)]
pub(crate) struct LastSenderInfo {
    /// When this SenderInfo was received.
    received_at: Instant,
    /// The sender info itself.
    info: SenderInfo,
    /// Whether we have emitted it yet via `poll_sender_info`
    emitted: bool,
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
    /// interarrival jitter (RTP timestamp units) from the last RR we sent
    jitter: u32,
    /// round trip time from the last DLRR, if any
    rtt: Option<Duration>,
    /// fraction of packets lost from the last RR, if any
    loss: Option<f32>,
}

impl StreamRx {
    pub(crate) fn new(ssrc: Ssrc, midrid: MidRid, suppress_nack: bool) -> Self {
        debug!("Create StreamRx for SSRC: {}", ssrc);

        StreamRx {
            ssrc,
            rtx: None,
            previous_ssrc: None,
            midrid,
            cname: None,
            suppress_nack,
            last_used: already_happened(),
            last_clock_rate: None,
            sender_info: None,
            reset_roc: None,
            register: None,
            register_rtx: None,
            red_recent: VecDeque::new(),
            last_time: None,
            last_media_time: None,
            event_times: HashMap::new(),
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
        self.midrid.mid()
    }

    /// Rid for this stream.
    ///
    /// This is used to separate streams with the same [`Mid`] when using simulcast.
    pub fn rid(&self) -> Option<Rid> {
        self.midrid.rid()
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

    /// The last time we received a packet.
    ///
    /// Resets if the SSRC changes.
    pub fn last_time(&self) -> Option<MediaTime> {
        self.last_time
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

    fn is_audio(&self) -> bool {
        self.rtx.is_none() // this is maybe not correct, but it's all we got.
    }

    pub(crate) fn receiver_report_at(&self, intervals: RtcpReportIntervals) -> Instant {
        self.last_receiver_report + intervals.for_audio(self.is_audio())
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
            let prev = self
                .sender_info
                .as_ref()
                .map(|last| last.info.rtp_time.numer());
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
        info.rtp_time = MediaTime::new(extended, clock_rate);

        self.sender_info = Some(LastSenderInfo {
            received_at: now,
            info,
            emitted: false,
        });
    }

    fn set_dlrr_item(&mut self, now: Instant, dlrr: DlrrItem) {
        let ntp_time = now.to_ntp_duration();
        let rtt = calculate_rtt(ntp_time, dlrr.last_rr_delay, dlrr.last_rr_time);
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

    pub(crate) fn extend_seq(
        &mut self,
        header: &RtpHeader,
        is_repair: bool,
        max_seq_lookup: impl Fn(Ssrc) -> Option<SeqNo>,
    ) -> SeqNo {
        // Select reference to register to use depending on RTX or not. The RTX has a separate
        // sequence number series to the main register.
        let register_ref = if is_repair {
            &mut self.register_rtx
        } else {
            &mut self.register
        };

        let register =
            register_ref.get_or_insert_with(|| ReceiverRegister::new(max_seq_lookup(header.ssrc)));

        // If the user has called `reset_seq_no`, this is the time to handle it, but only
        // if the incoming packet is for main (not repair).
        let mut reset_seq_no = None;
        if !is_repair {
            if let Some(reset_roc) = self.reset_roc.take() {
                let s: SeqNo = (reset_roc << 16 | header.sequence_number as u64).into();
                reset_seq_no = Some(s);
            }
        }

        if let Some(reset_seq_no) = reset_seq_no {
            reset_seq_no
        } else {
            header.sequence_number(register.max_seq())
        }
    }

    pub(crate) fn is_new_packet(&self, is_repair: bool, seq_no: SeqNo) -> bool {
        let register_ref = if is_repair {
            self.register_rtx.as_ref()
        } else {
            self.register.as_ref()
        };

        // Unwrap is OK because we always call extend_seq() for the same is_repair flag beforehand
        register_ref.unwrap().accepts(seq_no)
    }

    fn remember_recent(&mut self, seq_no: SeqNo, pt: Pt, time: MediaTime) {
        self.red_recent.push_back((seq_no, pt, time));
        while self.red_recent.len() > RED_RECENT_PACKETS {
            self.red_recent.pop_front();
        }
    }

    fn red_history(
        &self,
        pt: Pt,
        clock_rate: Frequency,
    ) -> impl Iterator<Item = (SeqNo, u64)> + '_ {
        self.red_recent
            .iter()
            .filter(move |(_, p, t)| *p == pt && t.frequency() == clock_rate)
            .map(|(s, _, t)| (*s, t.numer()))
    }

    /// Work out which (still missing) sequence number a RED redundant block belongs to.
    ///
    /// RFC 2198 blocks carry a timestamp offset, not a sequence number, and the frame duration
    /// is neither signalled nor constant (Opus 10/20/40/60 ms, DTX, CN interleaved on the same
    /// SSRC). Rather than guess a duration from the offsets, bracket the block's time between the
    /// nearest received audio packets of the same PT/clock, `L` (latest with time before) and
    /// `U` (earliest with time after), and look at the missing sequence numbers between them.
    /// Received telephone-event packets occupy sequence numbers but are not time bounds:
    ///
    /// * exactly one missing: that is the block, whatever the durations were — this case is
    ///   exact;
    /// * several missing with telephone-event enabled: give up, even if no event has arrived.
    ///   Lost events cannot be distinguished from lost audio using RED timestamps;
    /// * several missing without telephone-event: only if `L..U` is uniformly spaced and the
    ///   block time lands exactly on one of the missing slots. This case *assumes* a constant frame
    ///   duration across the gap, which holds for the fixed-ptime senders seen in practice
    ///   (WebRTC uses 20 ms). Under variable Opus ptime the derived slot can be a neighbouring
    ///   lost sequence number rather than the block's true one, so recovered audio may land one
    ///   or two frames off.
    ///
    /// The bound this always keeps is that a candidate must be a currently *missing* sequence
    /// number (`register.accepts`): recovery only ever fills a hole, and never overwrites a
    /// correctly received frame — the worst case above only reorders audio among frames that
    /// were all lost anyway. `carrier` is the packet the block arrived in; recovery is limited
    /// to `MAX_RED_RECOVERY_DEPTH` packets behind it.
    pub(crate) fn red_locate_seq(
        &self,
        carrier: SeqNo,
        pt: Pt,
        block_time: MediaTime,
        has_telephone_event: bool,
    ) -> Option<SeqNo> {
        let register = self.register.as_ref()?;
        let history = || self.red_history(pt, block_time.frequency());
        let block_time = block_time.numer();

        // A packet (received or already recovered) at exactly this time: nothing to recover.
        if history().any(|(_, t)| t == block_time) {
            return None;
        }

        let below = history()
            .filter(|(_, t)| *t < block_time)
            .max_by_key(|(s, _)| *s)?;
        let above = history()
            .filter(|(_, t)| *t > block_time)
            .min_by_key(|(s, _)| *s)?;

        let (l_seq, l_time) = (*below.0, below.1);
        let (u_seq, u_time) = (*above.0, above.1);

        // Bound the scan: the block must be within recovery depth of the carrier, which also
        // keeps `l_seq..u_seq` small. `checked_sub` guards a stream whose timestamps don't
        // follow its sequence numbers.
        let depth_ok = (*carrier)
            .checked_sub(l_seq)
            .is_some_and(|d| d <= MAX_RED_RECOVERY_DEPTH + 1);
        let span_seq = u_seq.checked_sub(l_seq)?;
        if span_seq <= 1 || u_seq > *carrier || !depth_ok {
            return None;
        }

        let mut missing = (l_seq + 1..u_seq)
            .map(SeqNo::from)
            .filter(|s| register.accepts(*s));

        let first = missing.next()?;
        let candidate = if missing.next().is_none() {
            // Exactly one hole between two received packets that bracket the block in time.
            first
        } else {
            if has_telephone_event {
                trace!("Skip ambiguous RED recovery across multiple audio/event losses");
                return None;
            }
            // Audio-only legacy best effort: assume uniform spacing across the gap.
            let span_time = u_time - l_time;
            if span_time % span_seq != 0 {
                return None;
            }
            let d = span_time / span_seq;
            let back = block_time - l_time;
            if d == 0 || back % d != 0 {
                return None;
            }
            let seq: SeqNo = (l_seq + back / d).into();
            if !register.accepts(seq) {
                return None;
            }
            seq
        };

        (*carrier)
            .checked_sub(*candidate)
            .is_some_and(|d| d <= MAX_RED_RECOVERY_DEPTH)
            .then_some(candidate)
    }

    /// Record that `seq_no` was rebuilt from RED redundancy. It was never on the wire, so it is
    /// not counted as received (reception reports still show the loss), but it must neither be
    /// NACKed nor recovered again.
    pub(crate) fn mark_red_recovered(&mut self, seq_no: SeqNo, pt: Pt, time: MediaTime) {
        if let Some(register) = &mut self.register {
            register.mark_recovered(seq_no);
        }
        self.remember_recent(seq_no, pt, time);
    }

    pub(crate) fn update_register(
        &mut self,
        now: Instant,
        header: &RtpHeader,
        params: &PayloadParams,
        is_repair: bool,
        seq_no: SeqNo,
    ) -> RegisterUpdateReceipt {
        self.last_used = now;

        let was_paused = self.paused;
        if was_paused {
            self.paused = false;
            self.need_paused_event = true;
        }
        self.check_paused_at = Some(now + self.pause_threshold);

        let register_ref = if is_repair {
            &mut self.register_rtx
        } else {
            &mut self.register
        };

        // Unwrap is OK because we always call extend_seq() for the same is_repair flag beforehand
        let register = register_ref.as_mut().unwrap();

        let clock_rate = params.spec().rtp_clock_rate();
        let is_event = params.spec().codec.is_telephone_event();
        let is_new_packet = if is_event {
            register.update_telephone_event(seq_no, now, header.timestamp, clock_rate.get())
        } else {
            register.update(seq_no, now, header.timestamp, clock_rate.get())
        };

        // Events can hold a tone's timestamp while audio advances, even at another clock rate.
        let previous_time = if is_event {
            self.event_times
                .get(&clock_rate.get())
                .map(|reference| reference.timestamp)
        } else {
            self.last_media_time
                .filter(|time| time.frequency() == clock_rate)
                .map(|time| time.numer())
        };

        // Calculate the extended timestamp
        let mut time_u32 = extend_u32(previous_time, header.timestamp);

        if was_paused && !is_event && Some(time_u32) < previous_time {
            // In 32-bit RTP timestamps, adding 2^31 (MAX/2) flips to the other half of timestamp space
            // This forces extend_u32 to produce a value in the next cycle
            const HALF_CYCLE: u32 = 1u32 << 31;
            let adjusted_ts = header.timestamp.wrapping_add(HALF_CYCLE);

            // Recalculate extended timestamp with adjusted value
            let adjusted_time_u32 = extend_u32(previous_time, adjusted_ts);

            // If this adjusted timestamp moves time forward, use it
            if adjusted_time_u32 > previous_time.unwrap() {
                time_u32 = adjusted_time_u32;
            } else {
                // Fallback
                time_u32 = header.timestamp as u64;
            }
        }

        let time = MediaTime::new(time_u32, clock_rate);

        if !is_repair {
            self.last_time = Some(time);
            if is_event {
                let reference =
                    self.event_times
                        .entry(clock_rate.get())
                        .or_insert(EventTimeReference {
                            seq_no: None,
                            timestamp: time_u32,
                        });
                if reference.seq_no.is_none_or(|previous| seq_no > previous) {
                    reference.seq_no = Some(seq_no);
                    reference.timestamp = time_u32;
                }
            } else {
                self.last_media_time = Some(time);
            }
            if is_new_packet && params.spec().codec.is_audio() {
                self.remember_recent(seq_no, params.pt(), time);
            }
        }

        RegisterUpdateReceipt {
            time,
            is_new_packet,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_rtp(
        &mut self,
        now: Instant,
        header: RtpHeader,
        payload: Arc<[u8]>,
        seq_no: SeqNo,
        time: MediaTime,
        wire_payload_len: usize,
    ) -> RtpPacket {
        let packet = self.make_rtp_packet(now, header, payload, seq_no, time);

        // `payload` may be narrower than what was on the wire (RED unwrapped to its primary
        // block); count what was received, matching the sender's egress accounting.
        self.stats.bytes += wire_payload_len as u64;
        self.stats.packets += 1;

        packet
    }

    /// Build an [`RtpPacket`] WITHOUT counting it in receive stats. Used for RFC 2198
    /// FEC-recovered packets, which were never received on the wire (the carrying packet's
    /// bytes are already counted by `handle_rtp`).
    pub(crate) fn make_rtp_packet(
        &mut self,
        now: Instant,
        header: RtpHeader,
        payload: Arc<[u8]>,
        seq_no: SeqNo,
        time: MediaTime,
    ) -> RtpPacket {
        trace!("Handle RTP: {:?}", header);

        let need_clock_rate = self.last_clock_rate.map(|(pt, _)| pt) != Some(header.payload_type);
        if need_clock_rate {
            self.last_clock_rate = Some((header.payload_type, time.frequency()));

            // If we get an SR before the first packet, we update the potential clock rate.
            if let Some(i) = &mut self.sender_info {
                i.info.rtp_time = MediaTime::new(i.info.rtp_time.numer(), time.frequency());
            }
        }

        RtpPacket {
            seq_no,
            time,
            header,
            payload,
            vp8_patch: None,
            nackable: false,
            last_sender_info: self.sender_info.as_ref().map(|l| l.info),
            timestamp: now,
        }
    }

    /// Rewrites the header to be the un-RTX'd original packet, and returns
    /// `data` with the original sequence number prefix stripped.
    pub(crate) fn un_rtx<'a>(&self, header: &mut RtpHeader, data: &'a [u8], pt: Pt) -> &'a [u8] {
        let mut orig_seq_no_16 = 0;

        let n = RtpHeader::read_original_sequence_number(data, &mut orig_seq_no_16);

        trace!(
            "Repaired seq no {} -> {}",
            header.sequence_number, orig_seq_no_16
        );

        header.sequence_number = orig_seq_no_16;

        header.ssrc = self.ssrc;
        header.payload_type = pt;
        header.ext_vals.rid = header.ext_vals.rid_repair.take();

        &data[n..]
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

    pub(crate) fn need_rr(&self, now: Instant, intervals: RtcpReportIntervals) -> bool {
        if self.ssrc.is_probe() {
            return false;
        }

        now >= self.receiver_report_at(intervals)
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
            let report = &rr.reports[rr.reports.len() - 1];
            self.stats.update_loss(report.fraction_lost);
            self.stats.jitter = report.jitter;
        }

        let xr = self.create_extended_receiver_report(now, sender_ssrc);

        trace!(
            "Created feedback RR/XR ({:?}): {:?} {:?}",
            self.midrid, rr, xr
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
            let t64 = self
                .sender_info
                .as_ref()
                .map_or(0u64, |l| l.info.ntp_time.as_ntp_64());

            (t64 >> 16) as u32
        };

        // The delay, expressed in units of 1/65_536 seconds, between
        // receiving the last SR packet from source SSRC_n and sending this
        // reception report block.  If no SR packet has been received yet
        // from SSRC_n, the DLSR field is set to zero.
        report.last_sr_delay = if let Some(l) = self.sender_info.as_ref() {
            let t = l.received_at;
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

    fn create_extended_receiver_report(&self, now: Instant, sender_ssrc: Ssrc) -> ExtendedReport {
        // we only want to report our time to measure RTT,
        // the source will answer with Dlrr feedback, allowing us to calculate RTT
        let block = ReportBlock::Rrtr(Rrtr {
            ntp_time: now.to_system_time(),
        });
        ExtendedReport {
            ssrc: sender_ssrc,
            blocks: vec![block],
        }
    }

    pub(crate) fn nack_enabled(&self) -> bool {
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

            trace!("Created feedback NACK: {:?}", nack);
            feedback.push_back(Rtcp::Nack(nack));
            self.stats.nacks += 1;
        }

        Some(())
    }

    pub(crate) fn visit_stats(&self, snapshot: &mut StatsSnapshot, now: Instant) {
        if self.ssrc.is_probe() {
            return;
        }

        self.stats
            .fill(snapshot, self.midrid, self.sender_info.as_ref(), now);
    }

    pub(crate) fn poll_paused(&mut self) -> Option<StreamPaused> {
        if self.ssrc.is_probe() {
            return None;
        }

        if !self.need_paused_event {
            return None;
        }

        self.need_paused_event = false;

        debug!(
            "{} StreamRx with {:?} and SSRC: {}",
            if self.paused { "Paused" } else { "Unpaused" },
            self.midrid,
            self.ssrc
        );

        Some(StreamPaused {
            ssrc: self.ssrc,
            mid: self.midrid.mid(),
            rid: self.midrid.rid(),
            paused: self.paused,
        })
    }

    /// Poll the most recent sender info and when it was received
    pub(crate) fn poll_sender_info(&mut self) -> Option<(SenderInfo, Instant)> {
        let i = self.sender_info.as_mut()?;
        if i.emitted {
            return None;
        }

        i.emitted = true;

        Some((i.info, i.received_at))
    }

    pub(crate) fn reset_buffers(&mut self, max_seq_lookup: impl Fn(Ssrc) -> Option<SeqNo>) {
        if let Some(r) = &mut self.register {
            r.clear(max_seq_lookup(self.ssrc));
        }

        if let Some(r) = &mut self.register_rtx {
            r.clear(self.rtx.and_then(max_seq_lookup));
        }
        self.pending_request_keyframe = None;
    }

    #[must_use]
    pub(crate) fn change_ssrc(&mut self, ssrc: Ssrc) -> bool {
        // Avoid flapping
        if ssrc == self.ssrc || Some(ssrc) == self.previous_ssrc {
            return false;
        }

        debug!(
            "Change main SSRC: {} -> {} {:?}",
            self.ssrc, ssrc, self.midrid
        );

        // Remember which was the previous in case a stray packet turns up
        // so do we don't go "backwards".
        self.previous_ssrc = Some(self.ssrc);
        self.ssrc = ssrc;

        // Reset all SSRC-specific state
        self.register = None;
        self.red_recent.clear();
        self.last_time = None;
        self.last_media_time = None;
        self.event_times.clear();
        self.last_clock_rate = None;
        self.sender_info = None;
        self.last_receiver_report = already_happened();
        self.fir_seq_no = 0;
        self.pending_request_keyframe = None;
        self.pending_request_remb = None;
        self.reset_roc = None;

        // Note: We don't reset the RTX register here, as the RTX SSRC is managed separately
        // via maybe_reset_rtx() and is not directly tied to the main SSRC change.

        true
    }

    pub(crate) fn maybe_reset_rtx(&mut self, rtx: Ssrc) {
        if let Some(current) = self.rtx {
            if current == rtx {
                return;
            }

            debug!(
                "Change RTX SSRC {} -> {} for main SSRC: {} {:?}",
                current, rtx, self.ssrc, self.midrid
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
        self.red_recent.clear();
        for reference in self.event_times.values_mut() {
            reference.seq_no = None;
        }
        self.reset_roc = Some(roc);
    }

    pub(crate) fn is_midrid(&self, midrid: MidRid) -> bool {
        midrid.special_equals(&self.midrid)
    }
}

impl StreamRxStats {
    fn update_loss(&mut self, fraction_lost: u8) {
        self.loss = Some(fraction_lost as f32 / u8::MAX as f32)
    }

    pub(crate) fn fill(
        &self,
        snapshot: &mut StatsSnapshot,
        midrid: MidRid,
        sender_info: Option<&LastSenderInfo>,
        now: Instant,
    ) {
        if self.bytes == 0 {
            return;
        }

        let stats = MediaIngressStats {
            mid: midrid.mid(),
            rid: midrid.rid(),
            bytes: self.bytes,
            packets: self.packets,
            firs: self.firs,
            plis: self.plis,
            nacks: self.nacks,
            jitter: self.jitter,
            rtt: self.rtt,
            loss: self.loss,
            timestamp: now,
            remote: sender_info.map(|l| RemoteEgressStats {
                bytes: l.info.sender_octet_count as u64,
                packets: l.info.sender_packet_count as u64,
            }),
        };

        // Several SSRCs can back a given (mid, rid) tuple. For example, Firefox creates new SSRCs
        // when a Transceiver transitions from send -> inactive -> send. In order to continue
        // correctly reporting stats for this (mid, rid) pair we need to merge the stats across all
        // the SSRCs that have been used.
        snapshot
            .ingress
            .entry(midrid)
            .and_modify(|s| s.merge_by_mid_rid(&stats))
            .or_insert(stats);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RegisterUpdateReceipt {
    pub time: MediaTime,
    pub is_new_packet: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{Codec, CodecSpec};

    fn params(codec: Codec, pt: u8, clock_rate: Frequency) -> PayloadParams {
        PayloadParams::new(
            pt.into(),
            None,
            CodecSpec {
                codec,
                clock_rate,
                channels: None,
                format: Default::default(),
            },
        )
    }

    fn locate_seq(stream: &StreamRx, carrier: u64, time: u64) -> Option<SeqNo> {
        stream.red_locate_seq(
            carrier.into(),
            111.into(),
            MediaTime::new(time, Frequency::FORTY_EIGHT_KHZ),
            false,
        )
    }

    fn receive_packet(
        stream: &mut StreamRx,
        params: &PayloadParams,
        seq: u16,
        timestamp: u32,
    ) -> RegisterUpdateReceipt {
        let header = RtpHeader {
            payload_type: params.pt(),
            sequence_number: seq,
            timestamp,
            ssrc: stream.ssrc(),
            ..Default::default()
        };
        let seq_no = stream.extend_seq(&header, false, |_| None);
        stream.update_register(already_happened(), &header, params, false, seq_no)
    }

    #[test]
    fn paused_timestamp_repair_moves_time_forward() {
        let now = already_happened();
        let mut stream = StreamRx::new(7.into(), MidRid("mid".into(), None), false);
        let previous_time = 1;
        stream.last_time = Some(MediaTime::new(previous_time, Frequency::NINETY_KHZ));
        stream.last_media_time = stream.last_time;
        stream.paused = true;

        let header = RtpHeader {
            payload_type: Pt::new_with_value(96),
            sequence_number: 42,
            timestamp: 0,
            ssrc: 7.into(),
            ..Default::default()
        };

        let seq_no = stream.extend_seq(&header, false, |_| None);
        let params = params(Codec::Vp8, 96, Frequency::NINETY_KHZ);
        let receipt = stream.update_register(now, &header, &params, false, seq_no);

        assert!(
            receipt.time.numer() > previous_time,
            "expected repaired media time to move forward"
        );
        assert!(!stream.paused);
    }

    #[test]
    fn delayed_event_after_pause_keeps_its_original_timestamp() {
        let mut stream = StreamRx::new(7.into(), MidRid("mid".into(), None), false);
        let event = params(Codec::TelephoneEvent, 126, Frequency::EIGHT_KHZ);
        receive_packet(&mut stream, &event, 100, 10000);
        receive_packet(&mut stream, &event, 102, 20000);
        stream.paused = true;
        let late = receive_packet(&mut stream, &event, 101, 10000);
        assert_eq!(late.time, MediaTime::new(10000, Frequency::EIGHT_KHZ));
        let reference = stream.event_times.get(&8000).unwrap();
        assert_eq!(reference.seq_no, Some(102.into()));
        assert_eq!(reference.timestamp, 20000);
    }

    #[test]
    fn event_reports_with_a_fixed_timestamp_update_rtcp_jitter() {
        let start = Instant::now();
        let mut stream = StreamRx::new(7.into(), MidRid("mid".into(), None), false);
        let event = params(Codec::TelephoneEvent, 126, Frequency::EIGHT_KHZ);
        for index in 0..2 {
            let header = RtpHeader {
                payload_type: event.pt(),
                sequence_number: 100 + index,
                timestamp: 10000,
                ssrc: stream.ssrc(),
                ..Default::default()
            };
            let seq = stream.extend_seq(&header, false, |_| None);
            stream.update_register(
                start + Duration::from_millis(index as u64 * 20),
                &header,
                &event,
                false,
                seq,
            );
        }
        assert_eq!(
            stream
                .register
                .as_mut()
                .unwrap()
                .reception_report()
                .unwrap()
                .jitter,
            10
        );
    }

    #[test]
    fn event_clock_references_survive_switches_and_sequence_resets() {
        let mut stream = StreamRx::new(7.into(), MidRid("mid".into(), None), false);
        let narrow = params(Codec::TelephoneEvent, 126, Frequency::EIGHT_KHZ);
        let wide = params(Codec::TelephoneEvent, 110, Frequency::FORTY_EIGHT_KHZ);
        receive_packet(&mut stream, &narrow, 100, u32::MAX - 159);
        receive_packet(&mut stream, &narrow, 101, 0);
        receive_packet(&mut stream, &wide, 102, 48000);
        let next = receive_packet(&mut stream, &narrow, 103, 160);
        assert_eq!(next.time.numer(), (1_u64 << 32) + 160);
        stream.reset_roc(0);
        let next = receive_packet(&mut stream, &narrow, 1, 320);
        assert_eq!(next.time.numer(), (1_u64 << 32) + 320);
        assert_eq!(
            stream.event_times.get(&8000).unwrap().seq_no,
            Some(1.into())
        );
        assert!(stream.change_ssrc(8.into()));
        assert!(stream.event_times.is_empty());
        let restarted = receive_packet(&mut stream, &narrow, 1, 0);
        assert_eq!(restarted.time.numer(), 0);
    }

    /// Feed packets `(seq, rtp_time)` into a fresh stream, as received on the wire.
    fn stream_with(packets: &[(u16, u32)]) -> StreamRx {
        let mut stream = StreamRx::new(7.into(), MidRid("mid".into(), None), false);
        let params = params(Codec::Opus, 111, Frequency::FORTY_EIGHT_KHZ);
        for (seq, ts) in packets {
            receive_packet(&mut stream, &params, *seq, *ts);
        }
        stream
    }

    #[test]
    fn red_history_excludes_events_and_other_payload_clocks() {
        let mut stream = stream_with(&[(10, 0)]);
        let event_params = params(Codec::TelephoneEvent, 126, Frequency::EIGHT_KHZ);
        receive_packet(&mut stream, &event_params, 12, 960);
        assert_eq!(stream.red_recent.len(), 1);
        assert_eq!(stream.register.as_ref().unwrap().max_seq(), Some(12.into()));

        let audio_params = params(Codec::Opus, 111, Frequency::FORTY_EIGHT_KHZ);
        receive_packet(&mut stream, &audio_params, 13, 1920);
        // Equal timestamp numerators in another PT or clock domain are not duplicates.
        stream.remember_recent(
            9.into(),
            0.into(),
            MediaTime::new(960, Frequency::EIGHT_KHZ),
        );
        stream.remember_recent(
            8.into(),
            111.into(),
            MediaTime::new(960, Frequency::EIGHT_KHZ),
        );
        assert_eq!(
            stream.red_locate_seq(
                13.into(),
                111.into(),
                MediaTime::new(960, Frequency::FORTY_EIGHT_KHZ),
                true,
            ),
            Some(11.into())
        );
    }

    #[test]
    fn red_locate_seq_does_not_interpolate_when_events_can_be_lost() {
        let stream = stream_with(&[(10, 0), (14, 3840)]);
        for time in [960, 1920, 2880] {
            assert_eq!(
                stream.red_locate_seq(
                    14.into(),
                    111.into(),
                    MediaTime::new(time, Frequency::FORTY_EIGHT_KHZ),
                    true,
                ),
                None
            );
        }
    }

    #[test]
    fn red_timestamp_extension_survives_sequence_reset() {
        let mut stream = stream_with(&[(10, u32::MAX - 959), (11, 0)]);
        let audio_params = params(Codec::Opus, 111, Frequency::FORTY_EIGHT_KHZ);
        stream.reset_roc(1);
        assert!(stream.red_recent.is_empty());
        let receipt = receive_packet(&mut stream, &audio_params, 12, 960);
        assert_eq!(receipt.time.numer(), (1_u64 << 32) + 960);

        let event_params = params(Codec::TelephoneEvent, 126, Frequency::EIGHT_KHZ);
        receive_packet(&mut stream, &event_params, 13, 8000);
        assert!(stream.change_ssrc(8.into()));
        assert!(stream.red_recent.is_empty());
        assert!(stream.last_media_time.is_none());
        assert!(stream.event_times.is_empty());
    }

    #[test]
    fn red_locate_seq_single_hole_regardless_of_frame_duration() {
        // 20 ms frames, then a 40 ms frame at seq 12, then 20 ms again. Seq 13 lost.
        let stream = stream_with(&[(10, 0), (11, 960), (12, 1920), (14, 4800)]);

        // Block at the time of seq 13 (1920 + 1920): the only hole between 12 and 14.
        assert_eq!(locate_seq(&stream, 14, 3840), Some(13.into()));
    }

    #[test]
    fn red_locate_seq_several_holes_need_uniform_spacing() {
        // Audio-only, fixed-ptime assumption: 10 and 14 bracket three lost frames.
        let stream = stream_with(&[(10, 0), (14, 3840)]);
        assert_eq!(locate_seq(&stream, 14, 960), Some(11.into()));
        assert_eq!(locate_seq(&stream, 14, 1920), Some(12.into()));
        assert_eq!(locate_seq(&stream, 14, 2880), Some(13.into()));
        // Not on a slot: skip rather than guess.
        assert_eq!(locate_seq(&stream, 14, 1000), None);

        // Same holes, but one of the lost frames was longer (span not a multiple): every block
        // is skipped, none is misplaced.
        let stream = stream_with(&[(10, 0), (14, 4800)]);
        for t in [960, 1920, 2880, 3840] {
            assert_eq!(locate_seq(&stream, 14, t), None, "time {t}");
        }
    }

    #[test]
    fn red_locate_seq_rejects_known_and_recovered_frames() {
        let mut stream = stream_with(&[(10, 0), (14, 3840)]);

        // A block for a frame we already have is not a recovery.
        assert_eq!(locate_seq(&stream, 14, 0), None);

        // Once recovered, the seq is neither a hole nor NACKed, and a later block for the same
        // frame is rejected instead of being pushed into a neighbouring hole.
        stream.mark_red_recovered(
            12.into(),
            111.into(),
            MediaTime::new(1920, Frequency::FORTY_EIGHT_KHZ),
        );
        assert_eq!(locate_seq(&stream, 14, 1920), None);
        assert!(!stream.is_new_packet(false, 12.into()));
        let nacked: Vec<SeqNo> = stream
            .register
            .as_mut()
            .unwrap()
            .nack_report()
            .into_iter()
            .flatten()
            .flat_map(|n| {
                n.reports
                    .iter()
                    .flat_map(|r| r.into_iter(10.into()))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(nacked, vec![11.into(), 13.into()]);

        // The remaining holes are still found (11 and 13 are single-hole brackets now).
        assert_eq!(locate_seq(&stream, 14, 960), Some(11.into()));
        assert_eq!(locate_seq(&stream, 14, 2880), Some(13.into()));
    }

    #[test]
    fn red_locate_seq_limits_recovery_depth() {
        let mut packets = vec![(10u16, 0u32)];
        // Seq 11 lost, then 12..=30 received at 20 ms.
        packets.extend((12..=30u16).map(|s| (s, (s as u32 - 10) * 960)));
        let stream = stream_with(&packets);
        assert_eq!(locate_seq(&stream, 30, 960), None);
        assert_eq!(locate_seq(&stream, 19, 960), Some(11.into()));
    }

    #[test]
    fn receiver_report_uses_supplied_intervals() {
        let mut stream = StreamRx::new(7.into(), MidRid("mid".into(), None), false);
        let now = Instant::now();
        stream.last_receiver_report = now;

        assert_eq!(
            stream.receiver_report_at(RtcpReportIntervals {
                audio: Duration::from_millis(750),
                video: Duration::from_millis(500),
            }),
            now + Duration::from_millis(750)
        );
    }
}
