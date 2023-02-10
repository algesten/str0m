use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use net_::{Id, DATAGRAM_MTU};
use packet::{DepacketizingBuffer, Packetized, PacketizingBuffer};
use rtp::{Extensions, Fir, FirEntry, NackEntry, Pli, Rtcp};
use rtp::{RtcpFb, RtpHeader, SdesType};
use rtp::{SeqNo, SRTP_BLOCK_SIZE, SRTP_OVERHEAD};

pub use packet::RtpMeta;
pub use rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid, Ssrc};
pub use sdp::{Codec, FormatParams};

use sdp::{MediaLine, MediaType, Msid, Simulcast as SdpSimulcast};

use crate::change::AddMedia;
use crate::stats::StatsSnapshot;
use crate::util::already_happened;
use crate::RtcError;

use super::receiver::ReceiverSource;
use super::sender::SenderSource;
use super::{CodecConfig, KeyframeRequestKind, MediaData, MediaKind, PayloadParams, Writer};

pub(crate) trait Source {
    fn ssrc(&self) -> Ssrc;
    fn rid(&self) -> Option<Rid>;
    #[must_use]
    fn set_rid(&mut self, rid: Rid) -> bool;
    fn is_rtx(&self) -> bool;
    fn repairs(&self) -> Option<Ssrc>;
    #[must_use]
    fn set_repairs(&mut self, ssrc: Ssrc) -> bool;
}

// How often we remove unused senders/receivers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

// Time between regular receiver reports.
// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
// Should technically be 4 seconds according to spec, but libWebRTC
// expects video to be every second, and audio every 5 seconds.
const RR_INTERVAL_VIDEO: Duration = Duration::from_millis(1000);
const RR_INTERVAL_AUDIO: Duration = Duration::from_millis(5000);

fn rr_interval(audio: bool) -> Duration {
    if audio {
        RR_INTERVAL_AUDIO
    } else {
        RR_INTERVAL_VIDEO
    }
}
#[derive(Debug)]
pub(crate) struct MLine {
    /// Three letter identifier of this m-line.
    mid: Mid,

    /// The index of this media line in the Session::media Vec.
    index: usize,

    /// Unique CNAME for use in Sdes RTCP packets.
    ///
    /// This is for _outgoing_ SDP. Incoming CNAME can be
    /// found in the `ssrc_info_rx`.
    cname: String,

    /// "Stream and track" identifiers.
    ///
    /// This is for _outgoing_ SDP. Incoming Msid details
    /// can be found in the `ssrc_info_rx`.
    msid: Msid,

    /// Audio or video.
    kind: MediaKind,

    /// The extensions for this m-line.
    exts: Extensions,

    /// Current media direction.
    ///
    /// Can be altered via negotiation.
    dir: Direction,

    /// Negotiated codec parameters.
    ///
    /// The PT information from SDP.
    params: Vec<PayloadParams>,

    /// Receiving sources (SSRC).
    ///
    /// These are created first time we observe the SSRC in an incoming RTP packet.
    /// Each source keeps track of packet loss, nack, reports etc. Receiving sources are
    /// cleaned up when we haven't received any data for the SSRC for a while.
    sources_rx: Vec<ReceiverSource>,

    /// Sender sources (SSRC).
    ///
    /// Created when we configure new m-lines via Changes API.
    sources_tx: Vec<SenderSource>,

    /// Last time we ran cleanup.
    last_cleanup: Instant,

    /// Last time we produced regular feedback (SR/RR).
    last_regular_feedback: Instant,

    /// Buffers for incoming data.
    ///
    /// Video samples are often fragmented over several RTP packets. These buffers reassembles
    /// the incoming RTP to full samples.
    buffers_rx: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,

    /// Buffers for outgoing data.
    ///
    /// When writing a sample we create a number of RTP packets to send. These buffers have the
    /// individual RTP data payload ready to send.
    buffers_tx: HashMap<Pt, PacketizingBuffer>,

    /// Queued resends.
    ///
    /// These have been scheduled via nacks.
    resends: VecDeque<Resend>,

    /// Whether the media line needs to be advertised in an event.
    pub(crate) need_open_event: bool,

    // Whether the media line needs to be notified of a change with an event.
    pub(crate) need_changed_event: bool,

    /// If we receive an rtcp request for a keyframe, this holds what kind.
    keyframe_request_rx: Option<(Option<Rid>, KeyframeRequestKind)>,

    /// If we are to send an rtcp request for a keyframe, this holds what kind.
    keyframe_request_tx: Option<(Ssrc, KeyframeRequestKind)>,

    /// Simulcast configuration, if set.
    simulcast: Option<SdpSimulcast>,

    /// Sources are kept in "mirrored pairs", i.e. if we have a ReceiverSource
    /// with Ssrc A and Rid B, there should be an equivalent SenderSource with Ssrc C and Rid B.
    equalize_sources: bool,

    /// Upon SDP negotiation set whether nack is enabled for this m-line.
    enable_nack: bool,
}

struct NextPacket<'a> {
    pt: Pt,
    pkt: &'a Packetized,
    ssrc: Ssrc,
    seq_no: SeqNo,
    orig_seq_no: Option<SeqNo>,
}

impl MLine {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn cname(&self) -> &str {
        &self.cname
    }

    pub fn set_cname(&mut self, cname: String) {
        self.cname = cname;
    }

    pub fn msid(&self) -> &Msid {
        &self.msid
    }

    pub fn set_msid(&mut self, msid: Msid) {
        self.msid = msid;
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub fn set_exts(&mut self, exts: Extensions) {
        if self.exts != exts {
            info!("Set {:?} extensions: {:?}", self.mid, exts);
            self.exts = exts;
        }
    }

    pub fn exts(&self) -> &Extensions {
        &self.exts
    }

    pub fn direction(&self) -> Direction {
        self.dir
    }

    fn codec_by_pt(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|c| c.pt() == pt)
    }

    pub fn payload_params(&self) -> &[PayloadParams] {
        &self.params
    }

    pub fn match_params(&self, params: PayloadParams) -> Option<Pt> {
        let c = self
            .params
            .iter()
            .max_by_key(|p| p.match_score(params.inner()))?;
        c.match_score(params.inner())?; // avoid None, which isn't a match.
        Some(c.pt())
    }

    pub fn writer(&mut self, pt: Pt) -> Writer<'_> {
        Writer {
            m_line: self,
            pt,
            rid: None,
            ext_vals: ExtensionValues::default(),
        }
    }

    /// Write to the packetizer.
    pub fn write(
        &mut self,
        pt: Pt,
        wallclock: Instant,
        ts: MediaTime,
        data: &[u8],
        rid: Option<Rid>,
        ext_vals: ExtensionValues,
    ) -> Result<usize, RtcError> {
        if !self.dir.is_sending() {
            return Err(RtcError::NotSendingDirection(self.dir));
        }

        let codec = { self.codec_by_pt(pt).map(|p| p.codec()) };

        let codec = match codec {
            Some(v) => v,
            None => return Err(RtcError::UnknownPt(pt)),
        };

        // The SSRC is figured out given the simulcast level.
        let tx = get_source_tx(&mut self.sources_tx, rid, false).ok_or(RtcError::NoSenderSource)?;

        let ssrc = tx.ssrc();
        tx.update_clocks(ts, wallclock);

        let buf = self.buffers_tx.entry(pt).or_insert_with(|| {
            let max_retain = if codec.is_audio() { 4096 } else { 2048 };
            PacketizingBuffer::new(codec.into(), max_retain)
        });

        trace!("Write to packetizer time: {:?} bytes: {}", ts, data.len());
        let mut mtu: usize = DATAGRAM_MTU - SRTP_OVERHEAD;
        // align to SRTP block size to minimize padding needs
        mtu = mtu - mtu % SRTP_BLOCK_SIZE;
        if let Err(e) = buf.push_sample(ts, data, ssrc, rid, ext_vals, mtu) {
            return Err(RtcError::Packet(self.mid, pt, e));
        };

        Ok(buf.free())
    }

    pub fn is_request_keyframe_possible(&self, kind: KeyframeRequestKind) -> bool {
        // TODO: It's possible to have different set of feedback enabled for different
        // payload types. I.e. we could have FIR enabled for H264, but not for VP8.
        // We might want to make this check more fine grained by testing which PT is
        // in "active use" right now.
        self.params.iter().any(|r| match kind {
            KeyframeRequestKind::Pli => r.inner().fb_pli,
            KeyframeRequestKind::Fir => r.inner().fb_fir,
        })
    }

    pub fn request_keyframe(
        &mut self,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) -> Result<(), RtcError> {
        if !self.is_request_keyframe_possible(kind) {
            return Err(RtcError::FeedbackNotEnabled(kind));
        }

        let rx = self
            .sources_rx
            .iter()
            .find(|s| s.rid() == rid && !s.is_rtx())
            .ok_or(RtcError::NoReceiverSource(rid))?;

        if let Some(rid) = rid {
            info!(
                "Request keyframe ({:?}, {:?}) SSRC: {}",
                kind,
                rid,
                rx.ssrc()
            );
        } else {
            info!("Request keyframe ({:?}) SSRC: {}", kind, rx.ssrc());
        }
        self.keyframe_request_tx = Some((rx.ssrc(), kind));

        Ok(())
    }

    pub fn poll_packet(
        &mut self,
        now: Instant,
        exts: &Extensions,
        twcc: &mut u64,
        buf: &mut Vec<u8>,
    ) -> Option<(RtpHeader, SeqNo)> {
        let mid = self.mid;

        let next = if let Some(next) = self.poll_packet_resend(now) {
            next
        } else if let Some(next) = self.poll_packet_regular(now) {
            next
        } else {
            return None;
        };

        let mut header = RtpHeader {
            payload_type: next.pt,
            sequence_number: *next.seq_no as u16,
            timestamp: next.pkt.ts.numer() as u32,
            ssrc: next.ssrc,
            ext_vals: next.pkt.exts,
            ..Default::default()
        };
        // ::new(next.pt, next.seq_no, next.pkt.ts, next.ssrc);
        header.marker = next.pkt.last;

        // We can fill out as many values we want here, only the negotiated ones will
        // be used when writing the RTP packet.
        //
        // These need to match `Extension::is_supported()` so we are sending what we are
        // declaring we support.
        header.ext_vals.abs_send_time = Some(now.into());
        header.ext_vals.mid = Some(mid);
        header.ext_vals.transport_cc = Some(*twcc as u16);
        *twcc += 1;

        buf.resize(2000, 0);
        let header_len = header.write_to(buf, exts);
        assert!(header_len % 4 == 0, "RTP header must be multiple of 4");
        header.header_len = header_len;

        let mut body_out = &mut buf[header_len..];

        // For resends, the original seq_no is inserted before the payload.
        if let Some(orig_seq_no) = next.orig_seq_no {
            let n = RtpHeader::write_original_sequence_number(body_out, orig_seq_no);
            body_out = &mut body_out[n..];
        }

        let body_len = next.pkt.data.len();
        body_out[..body_len].copy_from_slice(&next.pkt.data);

        // pad for SRTP
        let pad_len = RtpHeader::pad_packet(&mut buf[..], header_len, body_len, SRTP_BLOCK_SIZE);

        buf.truncate(header_len + body_len + pad_len);

        Some((header, next.seq_no))
    }

    fn poll_packet_resend(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        loop {
            let resend = self.resends.pop_front()?;

            // If there is no buffer for this resend, we skip to next. This is
            // a weird situation though, since it means the other side sent a nack for
            // an SSRC that matched this Media, but didnt match a buffer_tx.
            let buffer = match self.buffers_tx.values().find(|p| p.has_ssrc(resend.ssrc)) {
                Some(v) => v,
                None => continue,
            };

            // The seq_no could simply be too old to exist in the buffer, in which
            // case we will not do a resend.
            let pkt = match buffer.get(resend.seq_no) {
                Some(v) => v,
                None => continue,
            };

            // The send source, to get a contiguous seq_no for the resend.
            // Audio should not be resent, so this also gates whether we are doing resends at all.
            let source = match get_source_tx(&mut self.sources_tx, pkt.rid, true) {
                Some(v) => v,
                None => continue,
            };

            source.update_packet_counts(pkt.data.len() as u64, true);

            let seq_no = source.next_seq_no(now);

            // The resend ssrc. This would correspond to the RTX PT for video.
            let ssrc_rtx = source.ssrc();

            let orig_seq_no = Some(resend.seq_no);

            // Check that our internal state of organizing SSRC for senders is correct.
            assert_eq!(pkt.ssrc, resend.ssrc);
            assert_eq!(source.repairs(), Some(resend.ssrc));

            return Some(NextPacket {
                pt: resend.pt,
                pkt,
                ssrc: ssrc_rtx,
                seq_no,
                orig_seq_no,
            });
        }
    }

    fn poll_packet_regular(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        // exit via ? here is ok since that means there is nothing to send.
        let (pt, pkt) = next_send_buffer(&mut self.buffers_tx)?;

        let source = self
            .sources_tx
            .iter_mut()
            .find(|s| s.ssrc() == pkt.ssrc)
            .expect("SenderSource for packetized write");

        source.update_packet_counts(pkt.data.len() as u64, false);

        let seq_no = source.next_seq_no(now);
        pkt.seq_no = Some(seq_no);

        Some(NextPacket {
            pt,
            pkt,
            ssrc: pkt.ssrc,
            seq_no,
            orig_seq_no: None,
        })
    }

    pub fn get_or_create_source_rx(&mut self, ssrc: Ssrc) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|r| r.ssrc() == ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.equalize_sources = true;
            self.sources_rx.push(ReceiverSource::new(ssrc));
            self.sources_rx.last_mut().unwrap()
        }
    }

    pub fn get_or_create_source_tx(&mut self, ssrc: Ssrc) -> &mut SenderSource {
        let maybe_idx = self.sources_tx.iter().position(|r| r.ssrc() == ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_tx[idx]
        } else {
            self.equalize_sources = true;
            self.sources_tx.push(SenderSource::new(ssrc));
            self.sources_tx.last_mut().unwrap()
        }
    }

    pub fn set_equalize_sources(&mut self) {
        self.equalize_sources = true;
    }

    pub fn equalize_sources(&self) -> bool {
        self.equalize_sources
    }

    pub fn do_equalize_sources(&mut self, new_ssrc: &mut impl Iterator<Item = Ssrc>) {
        while self.sources_rx.len() < self.sources_tx.len() {
            let ssrc = new_ssrc.next().unwrap();
            self.get_or_create_source_rx(ssrc);
        }
        while self.sources_tx.len() < self.sources_rx.len() {
            let ssrc = new_ssrc.next().unwrap();
            self.get_or_create_source_tx(ssrc);
        }

        // Now there should be equal amount of receivers/senders.

        let mut txs: Vec<_> = self
            .sources_tx
            .iter_mut()
            .map(|t| t as &mut dyn Source)
            .collect();

        let mut rxs: Vec<_> = self
            .sources_rx
            .iter_mut()
            .map(|t| t as &mut dyn Source)
            .collect();

        fn equalize(from: &[&mut dyn Source], to: &mut [&mut dyn Source]) {
            for i in 0..from.len() {
                let rx = &from[i];
                if let Some(rid) = rx.rid() {
                    let _ = to[i].set_rid(rid);
                }
                if let Some(repairs) = rx.repairs() {
                    let j = from.iter().position(|s| s.ssrc() == repairs);
                    if let Some(j) = j {
                        let ssrc_tx = to[j].ssrc();
                        let _ = to[i].set_repairs(ssrc_tx);
                    }
                }
            }
        }

        // Now propagated rid/repairs both ways, but let rxs be dominant, so do rx -> tx first.
        equalize(&rxs, &mut txs);
        equalize(&txs, &mut rxs);

        self.equalize_sources = false;
    }

    pub fn get_params(&self, header: &RtpHeader) -> Option<&PayloadParams> {
        let pt = header.payload_type;
        self.params
            .iter()
            .find(|p| p.inner().codec.pt == pt || p.inner().resend == Some(pt))
    }

    pub fn has_nack(&mut self) -> bool {
        if !self.enable_nack {
            return false;
        }
        self.sources_rx
            .iter_mut()
            .filter(|s| !s.is_rtx())
            .any(|s| s.has_nack())
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        // TODO(martin): more cleanup
        self.last_cleanup = now;
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        Some(self.cleanup_at())
    }

    fn cleanup_at(&self) -> Instant {
        self.last_cleanup + CLEANUP_INTERVAL
    }

    pub fn source_tx_ssrcs(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.sources_tx.iter().map(|s| s.ssrc())
    }

    pub fn maybe_create_keyframe_request(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        let Some((ssrc, kind)) = self.keyframe_request_tx.take() else {
            return;
        };

        // Unwrap is ok, because MediaWriter ensures the ReceiverSource exists.
        let rx = self
            .sources_rx
            .iter_mut()
            .find(|s| s.ssrc() == ssrc)
            .unwrap();

        rx.update_with_keyframe_request(kind);

        match kind {
            KeyframeRequestKind::Pli => feedback.push_back(Rtcp::Pli(Pli { sender_ssrc, ssrc })),
            KeyframeRequestKind::Fir => feedback.push_back(Rtcp::Fir(Fir {
                sender_ssrc,
                reports: FirEntry {
                    ssrc,
                    seq_no: rx.next_fir_seq_no(),
                }
                .into(),
            })),
        }
    }

    /// Creates sender info and receiver reports for all senders/receivers
    pub fn maybe_create_regular_feedback(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        if now < self.regular_feedback_at() {
            return None;
        }

        // Since we're making new sender/receiver reports, clear out previous.
        feedback.retain(|r| !matches!(r, Rtcp::SenderReport(_) | Rtcp::ReceiverReport(_)));

        if self.dir.is_sending() {
            for s in &mut self.sources_tx {
                let sr = s.create_sender_report(now);
                let ds = s.create_sdes(&self.cname);

                debug!("Created feedback SR: {:?}", sr);
                feedback.push_back(Rtcp::SenderReport(sr));
                feedback.push_back(Rtcp::SourceDescription(ds));
            }
        }

        if self.dir.is_receiving() {
            for s in &mut self.sources_rx {
                let mut rr = s.create_receiver_report(now);
                rr.sender_ssrc = sender_ssrc;

                debug!("Created feedback RR: {:?}", rr);
                feedback.push_back(Rtcp::ReceiverReport(rr));

                let er = s.create_extended_receiver_report(now);
                debug!("Created feedback extended receiver report: {:?}", er);
                feedback.push_back(Rtcp::ExtendedReport(er));
            }
        }

        // Update timestamp to move time when next is created.
        self.last_regular_feedback = now;

        Some(())
    }

    /// Creates nack reports for receivers, if needed.
    pub fn create_nack(&mut self, sender_ssrc: Ssrc, feedback: &mut VecDeque<Rtcp>) {
        if !self.enable_nack {
            return;
        }
        for s in &mut self.sources_rx {
            if s.is_rtx() {
                continue;
            }
            if let Some(mut nack) = s.create_nack() {
                nack.sender_ssrc = sender_ssrc;
                debug!("Created feedback NACK: {:?}", nack);
                feedback.push_back(Rtcp::Nack(nack));
                s.update_with_nack();
            }
        }
    }

    /// Appply incoming RTCP feedback.
    pub fn handle_rtcp_fb(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        debug!("Handle RTCP feedback: {:?}", fb);

        if fb.is_for_rx() {
            self.handle_rtcp_fb_rx(now, fb)?;
        } else {
            self.handle_rtcp_fb_tx(now, fb)?;
        }

        Some(())
    }

    pub fn handle_rtcp_fb_rx(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        let ssrc = fb.ssrc();

        let source_rx = self.sources_rx.iter_mut().find(|s| s.ssrc() == ssrc)?;

        source_rx.update_with_feedback(&fb, now);

        use RtcpFb::*;
        match fb {
            SourceDescription(v) => {
                for (sdes, st) in v.values {
                    if sdes == SdesType::CNAME {
                        if st.is_empty() {
                            // In simulcast, chrome doesn't send the SSRC lines, but
                            // expects us to infer that from rtp headers. It does
                            // however send the SourceDescription RTCP with an empty
                            // string CNAME. ¯\_(ツ)_/¯
                            return None;
                        }

                        // Here we _could_ check CNAME here matches something. But
                        // CNAMEs are a bit unfashionable with the WebRTC spec people.
                        return None;
                    }
                }
            }
            Goodbye(_v) => {
                // For some reason, Chrome sends a Goodbye on every SDP negotation for all active
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

        Some(())
    }

    pub fn handle_rtcp_fb_tx(&mut self, _now: Instant, fb: RtcpFb) -> Option<()> {
        let ssrc = fb.ssrc();

        let source_tx = self.sources_tx.iter_mut().find(|s| s.ssrc() == ssrc)?;

        source_tx.update_with_feedback(&fb);

        use RtcpFb::*;
        match fb {
            ReceptionReport(v) => {
                // TODO: What to do with these?
                trace!("Handle reception report: {:?}", v);
            }
            Nack(ssrc, list) => {
                let entries = list.into_iter();
                self.handle_nack(ssrc, entries)?;
            }
            Pli(_) => self.keyframe_request_rx = Some((source_tx.rid(), KeyframeRequestKind::Pli)),
            Fir(_) => self.keyframe_request_rx = Some((source_tx.rid(), KeyframeRequestKind::Fir)),
            Twcc(_) => unreachable!("TWCC should be handled on session level"),
            _ => {}
        }

        Some(())
    }

    pub fn apply_changes(
        &mut self,
        m: &MediaLine,
        config: &CodecConfig,
        session_exts: &Extensions,
    ) {
        // Nack enabled
        {
            let enabled = m.rtp_params().iter().any(|p| p.fb_nack);
            if enabled && !self.enable_nack {
                debug!("Enable NACK feedback ({:?})", self.mid);
                self.enable_nack = true;
            }
        }

        // Directional changes
        {
            // All changes come from the other side, either via an incoming OFFER
            // or a ANSWER from our OFFER. Either way, the direction is inverted to
            // how we have it locally.
            let new_dir = m.direction().invert();
            if self.dir != new_dir {
                debug!(
                    "Mid ({}) change direction: {} -> {}",
                    self.mid, self.dir, new_dir
                );

                self.need_changed_event = true;

                let was_receiving = self.dir.is_receiving();
                let was_sending = self.dir.is_sending();
                let is_receiving = new_dir.is_receiving();
                let is_sending = new_dir.is_sending();

                self.dir = new_dir;

                if was_receiving && !is_receiving {
                    // Receive buffers are dropped straight away.
                    self.clear_receive_buffers();
                }
                if !was_sending && is_sending {
                    // Dump the buffers when we are about to start sending. We don't do this
                    // on sending -> not, because we want to keep the buffer to answer straggle nacks.
                    self.clear_send_buffers();
                }
            }
        }

        // Changes in PT
        {
            let params: Vec<PayloadParams> = m
                .rtp_params()
                .into_iter()
                .map(PayloadParams::new)
                .filter(|m| config.matches(m))
                .collect();
            let mut new_pts = HashSet::new();

            for p_new in params {
                new_pts.insert(p_new.pt());

                if let Some(p_old) = self.codec_by_pt(p_new.pt()) {
                    if *p_old != p_new {
                        debug!("Ignore change in mid ({}) for pt: {}", self.mid, p_new.pt());
                    }
                } else {
                    debug!("Ignoring new pt ({}) in mid: {}", p_new.pt(), self.mid);
                }
            }

            self.params.retain(|p| {
                let keep = new_pts.contains(&p.pt());

                if !keep {
                    debug!("Mid ({}) remove pt: {}", self.mid, p.pt());
                }

                keep
            });
        }

        // Update the extensions
        {
            let mut exts = Extensions::new();
            for x in m.extmaps() {
                exts.set_mapping(x);
            }
            exts.keep_same(session_exts);
            self.set_exts(exts);
        }

        // SSRC changes
        // This will always be for ReceiverSource since any incoming a=ssrc line will be
        // about the remote side's SSRC.
        {
            let infos = m.ssrc_info();
            for info in infos {
                let rx = self.get_or_create_source_rx(info.ssrc);

                if let Some(repairs) = info.repair {
                    if rx.set_repairs(repairs) {
                        self.set_equalize_sources();
                    }
                }
            }
        }

        // Simulcast configuration
        if let Some(s) = m.simulcast() {
            if s.is_munged {
                warn!("Not supporting simulcast via munging SDP");
            } else if self.simulcast().is_none() {
                // Invert before setting, since it has a recv and send config.
                self.set_simulcast(s.invert());
            }
        }
    }

    pub fn has_ssrc_rx(&self, ssrc: Ssrc) -> bool {
        self.sources_rx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub fn has_ssrc_tx(&self, ssrc: Ssrc) -> bool {
        self.sources_tx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub fn get_buffer_rx(
        &mut self,
        pt: Pt,
        rid: Option<Rid>,
        codec: Codec,
    ) -> &mut DepacketizingBuffer {
        self.buffers_rx
            .entry((pt, rid))
            .or_insert_with(|| DepacketizingBuffer::new(codec.into(), 100))
    }

    pub fn poll_keyframe_request(&mut self) -> Option<(Option<Rid>, KeyframeRequestKind)> {
        self.keyframe_request_rx.take()
    }

    pub fn poll_sample(&mut self) -> Option<Result<MediaData, RtcError>> {
        for ((pt, rid), buf) in &mut self.buffers_rx {
            if let Some(r) = buf.pop() {
                let codec = *self.params.iter().find(|c| c.pt() == *pt)?;
                return Some(
                    r.map(|dep| MediaData {
                        mid: self.mid,
                        pt: *pt,
                        rid: *rid,
                        params: codec,
                        time: dep.time,
                        network_time: dep.meta[0].received,
                        contiguous: dep.contiguous,
                        data: dep.data,
                        ext_vals: dep.meta[0].header.ext_vals,
                        meta: dep.meta,
                    })
                    .map_err(|e| RtcError::Packet(self.mid, *pt, e)),
                );
            }
        }
        None
    }

    pub fn handle_nack(
        &mut self,
        ssrc: Ssrc,
        entries: impl Iterator<Item = NackEntry>,
    ) -> Option<()> {
        // Figure out which packetizing buffer has been used to send the entries that been nack'ed.
        let (pt, buffer) = self.buffers_tx.iter_mut().find(|(_, p)| p.has_ssrc(ssrc))?;

        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = buffer.first_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Schedule all resends. They will be handled on next poll_packet
        self.resends.extend(iter.map(|seq_no| Resend {
            ssrc,
            pt: *pt,
            seq_no,
        }));

        Some(())
    }

    pub fn clear_send_buffers(&mut self) {
        self.buffers_tx.clear();
    }

    pub fn clear_receive_buffers(&mut self) {
        self.buffers_rx.clear();
    }

    pub fn regular_feedback_at(&self) -> Instant {
        self.last_regular_feedback + rr_interval(self.kind == MediaKind::Audio)
    }

    pub fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub fn set_simulcast(&mut self, s: SdpSimulcast) {
        info!("Set simulcast: {:?}", s);
        self.simulcast = Some(s);
    }

    pub fn ssrc_rx_for_rid(&self, repairs: Rid) -> Option<Ssrc> {
        self.sources_rx
            .iter()
            .find(|r| r.rid() == Some(repairs))
            .map(|r| r.ssrc())
    }

    /// The number of SSRC required to equalize the senders/receivers.
    pub fn equalize_requires_ssrcs(&self) -> usize {
        (self.sources_tx.len() as isize - self.sources_rx.len() as isize).unsigned_abs()
    }

    pub fn visit_stats(&self, now: Instant, snapshot: &mut StatsSnapshot) {
        for s in &self.sources_rx {
            s.visit_stats(now, self.mid, snapshot);
        }
        for s in &self.sources_tx {
            s.visit_stats(now, self.mid, snapshot);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    pub ssrc: Ssrc,
    pub pt: Pt,
    pub seq_no: SeqNo,
}

fn next_send_buffer(
    buffers_tx: &mut HashMap<Pt, PacketizingBuffer>,
) -> Option<(Pt, &mut Packetized)> {
    for (pt, buf) in buffers_tx {
        if let Some(pkt) = buf.poll_next() {
            assert!(pkt.seq_no.is_none());
            return Some((*pt, pkt));
        }
    }
    None
}

impl Default for MLine {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
            cname: Id::<20>::random().to_string(),
            msid: Msid {
                stream_id: Id::<30>::random().to_string(),
                track_id: Id::<30>::random().to_string(),
            },
            kind: MediaKind::Video,
            exts: Extensions::new(),
            dir: Direction::SendRecv,
            params: vec![],
            sources_rx: vec![],
            sources_tx: vec![],
            last_cleanup: already_happened(),
            last_regular_feedback: already_happened(),
            buffers_rx: HashMap::new(),
            buffers_tx: HashMap::new(),
            resends: VecDeque::new(),
            need_open_event: true,
            need_changed_event: false,
            keyframe_request_rx: None,
            keyframe_request_tx: None,
            simulcast: None,
            equalize_sources: false,
            enable_nack: false,
        }
    }
}

impl MLine {
    pub fn from_remote_media_line(l: &MediaLine, index: usize, exts: Extensions) -> Self {
        MLine {
            mid: l.mid(),
            index,
            // These two are not reflected back, and thus added by add_pending_changes().
            // cname,
            // msid,
            kind: l.typ.clone().into(),
            exts,
            dir: l.direction().invert(), // remote direction is reverse.
            params: l.rtp_params().into_iter().map(PayloadParams::new).collect(),
            ..Default::default()
        }
    }

    // Going from AddMedia to Media is for m-lines that are pending in a Change and are sent
    // in the offer to the other side.
    pub fn from_add_media(a: AddMedia, exts: Extensions) -> Self {
        let mut media = MLine {
            mid: a.mid,
            index: a.index,
            cname: a.cname,
            msid: a.msid,
            kind: a.kind,
            exts,
            dir: a.dir,
            params: a.params,
            equalize_sources: true,
            ..Default::default()
        };

        for (ssrc, repairs) in a.ssrcs {
            let tx = media.get_or_create_source_tx(ssrc);
            if let Some(repairs) = repairs {
                if tx.set_repairs(repairs) {
                    media.set_equalize_sources();
                }
            }
        }

        media
    }
}

impl From<MediaType> for MediaKind {
    fn from(v: MediaType) -> Self {
        match v {
            MediaType::Audio => MediaKind::Audio,
            MediaType::Video => MediaKind::Video,
            _ => panic!("Not MediaType::Audio or Video"),
        }
    }
}

/// Separate in wait for polonius.
fn get_source_tx(
    sources_tx: &mut [SenderSource],
    rid: Option<Rid>,
    is_rtx: bool,
) -> Option<&mut SenderSource> {
    sources_tx
        .iter_mut()
        .find(|s| rid == s.rid() && is_rtx == s.repairs().is_some())
}
