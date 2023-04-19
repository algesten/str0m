use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::dtls::KeyingMaterial;
use crate::format::{Codec, CodecConfig};
use crate::io::{DatagramSend, DATAGRAM_MTU, DATAGRAM_MTU_WARN};
use crate::media::{MediaAdded, MediaChanged, Source};
use crate::packet::{
    LeakyBucketPacer, NullPacer, Pacer, PacerImpl, RtpMeta, SendSideBandwithEstimator,
};
use crate::rtp::{extend_u16, RtpHeader, SessionId, TwccRecvRegister, TwccSendRegister};
use crate::rtp::{extend_u32, SRTCP_OVERHEAD};
use crate::rtp::{Bitrate, ExtensionMap, MediaTime, Mid, Rtcp, RtcpFb};
use crate::rtp::{SrtpContext, SrtpKey, Ssrc};
use crate::stats::StatsSnapshot;
use crate::util::{already_happened, not_happening, Soonest};
use crate::{net, KeyframeRequest, MediaData};
use crate::{RtcConfig, RtcError};

use super::{MediaInner, PolledPacket};

/// Minimum time we delay between sending nacks. This should be
/// set high enough to not cause additional problems in very bad
/// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Delay between reports of TWCC. This is deliberately very low.
const TWCC_INTERVAL: Duration = Duration::from_millis(100);

/// Amend to the current_bitrate value.
const PACING_FACTOR: f64 = 1.1;

/// Amount of deviation needed to emit a new BWE value. This is to reduce
/// the total number BWE events to only fire when there is a substantial change.
const ESTIMATE_TOLERANCE: f64 = 0.05;

pub(crate) struct Session {
    id: SessionId,

    // These fields are pub to allow session_sdp.rs modify them.
    // Notice the fields are maybe not in m-line index order since the app
    // might be spliced in somewhere.
    medias: Vec<MediaInner>,

    /// The app m-line. Spliced into medias above.
    app: Option<(Mid, usize)>,

    reordering_size_audio: usize,
    reordering_size_video: usize,

    /// Extension mappings are _per BUNDLE_, but we can only have one a=group BUNDLE
    /// in WebRTC (one ice connection), so they are effectively per session.
    pub exts: ExtensionMap,
    pub codec_config: CodecConfig,

    /// Internally all ReceiverSource and SenderSource are identified by mid/ssrc.
    /// This map helps denormalize to that form. Sender and Receiver are mixed in
    /// this map since Ssrc should never clash.
    source_keys: HashMap<Ssrc, (Mid, Ssrc)>,

    /// This is the first ever discovered remote media. We use that for
    /// special cases like the media SSRC in TWCC feedback.
    first_ssrc_remote: Option<Ssrc>,

    /// This is the first ever discovered local media. We use this for many
    /// feedback cases where we need a "sender SSRC".
    first_ssrc_local: Option<Ssrc>,

    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    last_nack: Instant,
    last_twcc: Instant,
    feedback: VecDeque<Rtcp>,
    twcc: u64,
    twcc_rx_register: TwccRecvRegister,
    twcc_tx_register: TwccSendRegister,

    bwe: Option<Bwe>,

    enable_twcc_feedback: bool,

    /// A pacer for sending RTP at specific rate.
    pacer: PacerImpl,

    // temporary buffer when getting the next (unencrypted) RTP packet from Media line.
    poll_packet_buf: Vec<u8>,

    pub ice_lite: bool,

    /// Whether we are running in RTP-mode.
    rtp_mode: bool,
}

#[allow(clippy::large_enum_variant)]
pub enum MediaEvent {
    Data(MediaData),
    Changed(MediaChanged),
    Error(RtcError),
    Added(MediaAdded),
    KeyframeRequest(KeyframeRequest),
    EgressBitrateEstimate(Bitrate),
}

impl Session {
    pub fn new(config: &RtcConfig) -> Self {
        let mut id = SessionId::new();
        // Max 2^62 - 1: https://bugzilla.mozilla.org/show_bug.cgi?id=861895
        const MAX_ID: u64 = 2_u64.pow(62) - 1;
        while *id > MAX_ID {
            id = (*id >> 1).into();
        }
        let (pacer, bwe) = if let Some(rate) = config.bwe_initial_bitrate {
            let pacer = PacerImpl::LeakyBucket(LeakyBucketPacer::new(rate * PACING_FACTOR * 2.0));

            let send_side_bwe = SendSideBandwithEstimator::new(rate);
            let bwe = Bwe {
                bwe: send_side_bwe,
                desired_bitrate: Bitrate::ZERO,
                current_bitrate: rate,

                last_emitted_estimate: Bitrate::ZERO,
            };

            (pacer, Some(bwe))
        } else {
            (PacerImpl::Null(NullPacer::default()), None)
        };

        Session {
            id,
            medias: vec![],
            app: None,
            reordering_size_audio: config.reordering_size_audio,
            reordering_size_video: config.reordering_size_video,
            exts: config.exts,
            codec_config: config.codec_config.clone(),
            source_keys: HashMap::new(),
            first_ssrc_remote: None,
            first_ssrc_local: None,
            srtp_rx: None,
            srtp_tx: None,
            last_nack: already_happened(),
            last_twcc: already_happened(),
            feedback: VecDeque::new(),
            twcc: 0,
            twcc_rx_register: TwccRecvRegister::new(100),
            twcc_tx_register: TwccSendRegister::new(1000),
            bwe,
            enable_twcc_feedback: false,
            pacer,
            poll_packet_buf: vec![0; 2000],
            ice_lite: config.ice_lite,

            rtp_mode: config.rtp_mode,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn set_app(&mut self, mid: Mid, index: usize) -> Result<(), String> {
        if let Some((mid_existing, index_existing)) = self.app {
            if mid_existing != mid {
                return Err(format!("App mid changed {} != {}", mid, mid_existing,));
            }
            if index_existing != index {
                return Err(format!("App index changed {} != {}", index, index_existing,));
            }
        } else {
            self.app = Some((mid, index));
        }
        Ok(())
    }

    pub fn app(&self) -> &Option<(Mid, usize)> {
        &self.app
    }

    pub fn media_by_mid(&self, mid: Mid) -> Option<&MediaInner> {
        self.medias.iter().find(|m| m.mid() == mid)
    }

    pub fn media_by_mid_mut(&mut self, mid: Mid) -> Option<&mut MediaInner> {
        self.medias.iter_mut().find(|m| m.mid() == mid)
    }

    pub fn exts(&self) -> &ExtensionMap {
        &self.exts
    }

    pub fn codec_config(&self) -> &CodecConfig {
        &self.codec_config
    }

    pub fn set_keying_material(&mut self, mat: KeyingMaterial, active: bool) {
        // Whether we're active or passive determines if we use the left or right
        // hand side of the key material to derive input/output.
        let left = active;

        let key_rx = SrtpKey::new(&mat, !left);
        let ctx_rx = SrtpContext::new(key_rx);
        self.srtp_rx = Some(ctx_rx);

        let key_tx = SrtpKey::new(&mat, left);
        let ctx_tx = SrtpContext::new(key_tx);
        self.srtp_tx = Some(ctx_tx);
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), RtcError> {
        for m in &mut self.medias {
            m.handle_timeout(now)?;
        }

        let sender_ssrc = self.first_ssrc_local();

        if let Some(twcc_at) = self.twcc_at() {
            if now >= twcc_at {
                self.create_twcc_feedback(sender_ssrc, now);
            }
        }

        for m in &mut self.medias {
            m.maybe_create_keyframe_request(sender_ssrc, &mut self.feedback);
        }

        if now >= self.regular_feedback_at() {
            for m in &mut self.medias {
                m.maybe_create_regular_feedback(now, sender_ssrc, &mut self.feedback);
            }
        }

        if let Some(nack_at) = self.nack_at() {
            if now >= nack_at {
                self.last_nack = now;
                for m in &mut self.medias {
                    m.create_nack(sender_ssrc, &mut self.feedback);
                }
            }
        }

        let iter = self
            .medias
            .iter_mut()
            .map(|m| m.buffers_tx_queue_state(now));
        if let Some(padding_request) = self.pacer.handle_timeout(now, iter) {
            let media = self
                .media_by_mid_mut(padding_request.mid)
                .expect("media for service padding request");

            media.generate_padding(now, padding_request.padding);
        }
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.handle_timeout(now);
        }

        Ok(())
    }

    fn create_twcc_feedback(&mut self, sender_ssrc: Ssrc, now: Instant) -> Option<()> {
        self.last_twcc = now;
        let mut twcc = self.twcc_rx_register.build_report(DATAGRAM_MTU - 100)?;

        // These SSRC are on medial level, but twcc is on session level,
        // we fill in the first discovered media SSRC in each direction.
        twcc.sender_ssrc = sender_ssrc;
        twcc.ssrc = self.first_ssrc_remote();

        debug!("Created feedback TWCC: {:?}", twcc);
        self.feedback.push_front(Rtcp::Twcc(twcc));
        Some(())
    }

    pub fn handle_receive(&mut self, now: Instant, r: net::Receive) {
        self.do_handle_receive(now, r);
    }

    fn do_handle_receive(&mut self, now: Instant, r: net::Receive) -> Option<()> {
        use crate::io::DatagramRecv::*;
        match r.contents {
            Rtp(buf) => {
                if let Some(header) = RtpHeader::parse(buf, &self.exts) {
                    self.handle_rtp(now, header, buf);
                    self.equalize_sources();
                } else {
                    trace!("Failed to parse RTP header");
                }
            }
            Rtcp(buf) => {
                // According to spec, the outer enclosing SRTCP packet should always be a SR or RR,
                // even if it's irrelevant and empty.
                // In practice I'm not sure that is happening, because libWebRTC hates empty packets.
                self.handle_rtcp(now, buf)?;
            }
            _ => {}
        }

        Some(())
    }

    fn mid_and_ssrc_for_header(&mut self, header: &RtpHeader) -> Option<(Mid, Ssrc)> {
        let ssrc = header.ssrc;

        // A direct hit on SSRC is to prefer. The idea is that mid/rid are only sent
        // for the initial x seconds and then we start using SSRC only instead.
        if let Some(r) = self.source_keys.get(&ssrc) {
            return Some(*r);
        }

        // The receiver/source might already exist in some Media.
        let maybe_mid = self
            .medias
            .iter()
            .find(|m| m.has_ssrc_rx(ssrc))
            .map(|m| m.mid());

        if let Some(mid) = maybe_mid {
            // SSRC is mapped to a Sender/Receiver in this media. Make an entry for it.
            self.source_keys.insert(ssrc, (mid, ssrc));

            return Some((mid, ssrc));
        }

        // The RTP header extension for mid might give us a clue.
        if let Some(mid) = header.ext_vals.mid {
            // Ensure media for this mid exists.
            let m_exists = self.medias.iter().any(|m| m.mid() == mid);

            if m_exists {
                // Insert an entry so we can look up on SSRC alone later.
                self.source_keys.insert(ssrc, (mid, ssrc));
                return Some((mid, ssrc));
            }
        }

        // No way to map this RtpHeader.
        None
    }

    fn handle_rtp(&mut self, now: Instant, header: RtpHeader, buf: &[u8]) {
        // const INGRESS_PACKET_LOSS_PERCENT: u16 = 5;
        // if header.sequence_number % (100 / INGRESS_PACKET_LOSS_PERCENT) == 0 {
        //     return;
        // }

        trace!("Handle RTP: {:?}", header);
        if let Some(transport_cc) = header.ext_vals.transport_cc {
            let prev = self.twcc_rx_register.max_seq();
            let extended = extend_u16(Some(*prev), transport_cc);
            self.twcc_rx_register.update_seq(extended.into(), now);
        }

        // Look up mid/ssrc for this header.
        let Some((mid, ssrc)) = self.mid_and_ssrc_for_header(&header) else {
            trace!("Unable to map RTP header to media: {:?}", header);
            return;
        };

        // mid_and_ssrc_for_header guarantees media for this mid exists.
        let media = self
            .medias
            .iter_mut()
            .find(|m| m.mid() == mid)
            .expect("media for mid");

        let srtp = match self.srtp_rx.as_mut() {
            Some(v) => v,
            None => {
                trace!("Rejecting SRTP while missing SrtpContext");
                return;
            }
        };
        let clock_rate = match media.get_params(header.payload_type) {
            Some(v) => v.spec().clock_rate,
            None => {
                trace!("No codec params for {:?}", header.payload_type);
                return;
            }
        };

        // Figure out which SSRC the repairs header points out. This is here because of borrow
        // checker ordering.
        let ssrc_repairs = header
            .ext_vals
            .rid_repair
            .and_then(|repairs| media.ssrc_rx_for_rid(repairs));

        let source = media.get_or_create_source_rx(ssrc);

        let mut media_need_check_source = false;
        if let Some(rid) = header.ext_vals.rid {
            if source.set_rid(rid) {
                media_need_check_source = true;
            }
        }
        if let Some(repairs) = ssrc_repairs {
            if source.set_repairs(repairs) {
                media_need_check_source = true;
            }
        }

        // Gymnastics to appease the borrow checker.
        let source = if media_need_check_source {
            media.set_equalize_sources();
            media.get_or_create_source_rx(ssrc)
        } else {
            source
        };

        let mut rid = source.rid();
        let seq_no = source.update(now, &header, clock_rate);

        let is_rtx = source.is_rtx();

        let mut data = match srtp.unprotect_rtp(buf, &header, *seq_no) {
            Some(v) => v,
            None => {
                trace!("Failed to unprotect SRTP");
                return;
            }
        };

        // For RTX we copy the header and modify the sequencer number to be that of the repaired stream.
        let mut header = header.clone();

        // This seq_no is the lengthened original seq_no for RTX stream, and just straight up
        // lengthened seq_no for non-rtx.
        let seq_no = if is_rtx {
            let mut orig_seq_16 = 0;

            // Not sure why we receive these initial packets with just nulls for the RTX.
            if RtpHeader::is_rtx_null_packet(&data) {
                trace!("Drop RTX null packet");
                return;
            }

            let n = RtpHeader::read_original_sequence_number(&data, &mut orig_seq_16);
            data.drain(0..n);
            trace!(
                "Repaired seq no {} -> {}",
                header.sequence_number,
                orig_seq_16
            );
            header.sequence_number = orig_seq_16;
            if let Some(repairs_rid) = header.ext_vals.rid_repair {
                rid = Some(repairs_rid);
            }

            let repaired_ssrc = match source.repairs() {
                Some(v) => v,
                None => {
                    trace!("Can't find repaired SSRC for: {}", header.ssrc);
                    return;
                }
            };
            trace!("Repaired {:?} -> {:?}", header.ssrc, repaired_ssrc);
            header.ssrc = repaired_ssrc;

            let repaired_source = media.get_or_create_source_rx(repaired_ssrc);
            if rid.is_none() && repaired_source.rid().is_some() {
                rid = repaired_source.rid();
            }
            let orig_seq_no = repaired_source.update(now, &header, clock_rate);

            let params = media.get_params(header.payload_type).unwrap();
            if let Some(pt) = params.resend() {
                header.payload_type = pt;
            }

            orig_seq_no
        } else {
            if self.first_ssrc_remote.is_none() {
                info!("First remote SSRC: {}", ssrc);
                self.first_ssrc_remote = Some(ssrc);
            }

            seq_no
        };

        // Parameters using the PT in the header. This will return the same CodecParams
        // instance regardless of whether this being a resend PT or not.
        // unwrap: is ok because we checked above.
        let params = media.get_params(header.payload_type).unwrap();

        // This is the "main" PT and it will differ to header.payload_type if this is a resend.
        let pt = params.pt();
        let codec = if self.rtp_mode {
            Codec::Null
        } else {
            params.spec().codec
        };

        if !media.direction().is_receiving() {
            // Not adding unless we are supposed to be receiving.
            return;
        }

        // Buffers are unique per media (since PT is unique per media).
        // The hold_back should be configured from param.spec().codec to
        // avoid the null codec.
        let hold_back = if params.spec().codec.is_audio() {
            self.reordering_size_audio
        } else {
            self.reordering_size_video
        };
        let buf_rx = media.get_buffer_rx(pt, rid, codec, hold_back);

        let prev_time = buf_rx.max_time().map(|t| t.numer() as u64);
        let extended = extend_u32(prev_time, header.timestamp);
        let time = MediaTime::new(extended as i64, clock_rate as i64);

        let meta = RtpMeta::new(now, time, seq_no, header);

        // here we have incoming and depacketized data before it may be dropped at buffer.push()
        let bytes_rx = data.len();

        // In RTP mode we want to retain the header. After srtp_unprotect, we need to
        // recombine the header + the decrypted payload.
        if self.rtp_mode {
            // Write header after the body. This shouldn't allocate since
            // unprotect_rtp() call above should allocate enough space for the header.
            data.extend_from_slice(&buf[..meta.header.header_len]);
            // Rotate so header is before body.
            data.rotate_right(meta.header.header_len);
        };

        buf_rx.push(meta, data);

        // TODO: is there a nicer way to make borrow-checker happy ?
        // this should go away with the refactoring of the entire handle_rtp() function
        let source = media.get_or_create_source_rx(ssrc);
        source.update_packet_counts(bytes_rx as u64);
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let unprotected = srtp.unprotect_rtcp(buf)?;

        let feedback = Rtcp::read_packet(&unprotected);

        for fb in RtcpFb::from_rtcp(feedback) {
            if let RtcpFb::Twcc(twcc) = fb {
                debug!("Handle TWCC: {:?}", twcc);
                let range = self.twcc_tx_register.apply_report(twcc, now);

                if let Some(bwe) = &mut self.bwe {
                    let records = range.and_then(|range| self.twcc_tx_register.send_records(range));

                    if let Some(records) = records {
                        bwe.update(records, now);
                    }
                }
                // Not in the above if due to lifetime issues, still okay because the method
                // doesn't do anything when BWE isn't configured.
                self.configure_pacer();

                return Some(());
            }

            let media = self.medias.iter_mut().find(|m| {
                if fb.is_for_rx() {
                    m.has_ssrc_rx(fb.ssrc())
                } else {
                    m.has_ssrc_tx(fb.ssrc())
                }
            });
            if let Some(media) = media {
                media.handle_rtcp_fb(now, fb);
            } else {
                // This is not necessarily a fault when starting a new track.
                trace!("No media for feedback: {:?}", fb);
            }
        }

        Some(())
    }

    /// Whenever there are changes to ReceiverSource/SenderSource, we need to ensure the
    /// receivers are matched to senders. This ensure the setup is correct.
    pub fn equalize_sources(&mut self) {
        let required_ssrcs: usize = self
            .medias
            .iter()
            .map(|m| m.equalize_requires_ssrcs())
            .sum();

        // This will contain enough new SSRC to equalize the receiver/senders.
        let mut new_ssrcs = Vec::with_capacity(required_ssrcs);

        loop {
            if new_ssrcs.len() == required_ssrcs {
                break;
            }
            let ssrc = self.new_ssrc();

            // There's an outside chance we randomize the same number twice.
            if !new_ssrcs.contains(&ssrc) {
                self.set_first_ssrc_local(ssrc);
                new_ssrcs.push(ssrc);
            }
        }

        let mut new_ssrcs = new_ssrcs.into_iter();

        for m in &mut self.medias {
            if !m.equalize_sources() {
                continue;
            }

            m.do_equalize_sources(&mut new_ssrcs);
        }
    }

    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        if let Some(bitrate_estimate) = self.bwe.as_mut().and_then(|bwe| bwe.poll_estimate()) {
            return Some(MediaEvent::EgressBitrateEstimate(bitrate_estimate));
        }

        // If we're not ready to flow media, don't send any events.
        if !self.ready_for_srtp() {
            return None;
        }

        for media in &mut self.medias {
            if media.need_open_event {
                media.need_open_event = false;

                return Some(MediaEvent::Added(MediaAdded {
                    mid: media.mid(),
                    kind: media.kind(),
                    direction: media.direction(),
                    simulcast: media.simulcast().map(|s| s.clone().into()),
                }));
            }

            if media.need_changed_event {
                media.need_changed_event = false;
                return Some(MediaEvent::Changed(MediaChanged {
                    mid: media.mid(),
                    direction: media.direction(),
                }));
            }

            if let Some((rid, kind)) = media.poll_keyframe_request() {
                return Some(MediaEvent::KeyframeRequest(KeyframeRequest {
                    mid: media.mid(),
                    rid,
                    kind,
                }));
            }

            if let Some(r) = media.poll_sample() {
                match r {
                    Ok(v) => return Some(MediaEvent::Data(v)),
                    Err(e) => return Some(MediaEvent::Error(e)),
                }
            }
        }

        None
    }

    fn ready_for_srtp(&self) -> bool {
        self.srtp_rx.is_some() && self.srtp_tx.is_some()
    }

    pub fn poll_datagram(&mut self, now: Instant) -> Option<net::DatagramSend> {
        // Time must have progressed forward from start value.
        if now == already_happened() {
            return None;
        }

        let x = None
            .or_else(|| self.poll_feedback())
            .or_else(|| self.poll_packet(now));

        if let Some(x) = &x {
            if x.len() > DATAGRAM_MTU_WARN {
                warn!("RTP above MTU {}: {}", DATAGRAM_MTU_WARN, x.len());
            }
        }

        x
    }

    fn poll_feedback(&mut self) -> Option<net::DatagramSend> {
        if self.feedback.is_empty() {
            return None;
        }

        const ENCRYPTABLE_MTU: usize = DATAGRAM_MTU - SRTCP_OVERHEAD - 14;
        assert!(ENCRYPTABLE_MTU % 4 == 0);

        let mut data = vec![0_u8; ENCRYPTABLE_MTU];

        let len = Rtcp::write_packet(&mut self.feedback, &mut data);

        if len == 0 {
            return None;
        }

        data.truncate(len);

        let srtp = self.srtp_tx.as_mut()?;
        let protected = srtp.protect_rtcp(&data);

        assert!(
            protected.len() < DATAGRAM_MTU,
            "Encrypted SRTCP should be less than MTU"
        );

        Some(protected.into())
    }

    fn poll_packet(&mut self, now: Instant) -> Option<DatagramSend> {
        let srtp_tx = self.srtp_tx.as_mut()?;

        // Figure out which, if any, queue to poll
        let mid = self.pacer.poll_queue()?;

        // NB: Cannot use media_index_mut here due to borrowing woes around self, need split
        // borrowing.
        let media = self
            .medias
            .iter_mut()
            .find(|m| m.mid() == mid)
            .expect("index is media");

        let buf = &mut self.poll_packet_buf;

        let twcc_seq = self.twcc;

        if let Some(polled_packet) = media.poll_packet(now, &self.exts, &mut self.twcc, buf) {
            let PolledPacket {
                header,
                twcc_seq_no,
                is_padding,
                payload_size,
            } = polled_packet;

            trace!(payload_size, is_padding, "Poll RTP: {:?}", header);

            #[cfg(feature = "_internal_dont_use_log_stats")]
            {
                let kind = if is_padding { "padding" } else { "media" };

                crate::log_stat!("PACKET_SENT", header.ssrc, payload_size, kind);
            }

            self.pacer.register_send(now, payload_size.into(), mid);
            let protected = srtp_tx.protect_rtp(buf, &header, *twcc_seq_no);

            self.twcc_tx_register
                .register_seq(twcc_seq.into(), now, payload_size);

            return Some(protected.into());
        }

        None
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let media = self
            .medias
            .iter_mut()
            .filter_map(|m| m.poll_timeout())
            .min();
        let regular_at = Some(self.regular_feedback_at());
        let nack_at = self.nack_at();
        let twcc_at = self.twcc_at();
        let pacing_at = self.pacer.poll_timeout();
        let bwe_at = self.bwe.as_ref().map(|bwe| bwe.poll_timeout());

        let timeout = (media, "media")
            .soonest((regular_at, "regular"))
            .soonest((nack_at, "nack"))
            .soonest((twcc_at, "twcc"))
            .soonest((pacing_at, "pacing"))
            .soonest((bwe_at, "bwe"));

        // trace!("poll_timeout soonest is: {}", timeout.1);

        timeout.0
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.medias.iter().any(|m| m.mid() == mid)
    }

    /// Test if the ssrc is known in the session at all, as sender or receiver.
    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        self.medias
            .iter()
            .any(|m| m.has_ssrc_rx(ssrc) || m.has_ssrc_tx(ssrc))
    }

    fn regular_feedback_at(&self) -> Instant {
        self.medias
            .iter()
            .map(|m| m.regular_feedback_at())
            .min()
            .unwrap_or_else(not_happening)
    }

    fn nack_at(&mut self) -> Option<Instant> {
        let need_nack = self.medias.iter_mut().any(|s| s.has_nack());

        if need_nack {
            Some(self.last_nack + NACK_MIN_INTERVAL)
        } else {
            None
        }
    }

    fn twcc_at(&self) -> Option<Instant> {
        let is_receiving = self.medias.iter().any(|m| m.direction().is_receiving());
        if is_receiving && self.enable_twcc_feedback && self.twcc_rx_register.has_unreported() {
            Some(self.last_twcc + TWCC_INTERVAL)
        } else {
            None
        }
    }

    pub fn new_ssrc(&self) -> Ssrc {
        loop {
            let ssrc: Ssrc = (rand::random::<u32>()).into();
            if !self.has_ssrc(ssrc) {
                break ssrc;
            }
        }
    }

    fn first_ssrc_remote(&self) -> Ssrc {
        self.first_ssrc_remote.unwrap_or_else(|| 0.into())
    }

    fn first_ssrc_local(&self) -> Ssrc {
        self.first_ssrc_local.unwrap_or_else(|| 0.into())
    }

    pub fn set_first_ssrc_local(&mut self, ssrc: Ssrc) {
        if self.first_ssrc_local.is_none() {
            info!("First local SSRC: {}", ssrc);
            self.first_ssrc_local = Some(ssrc);
        }
    }

    pub fn enable_twcc_feedback(&mut self) {
        if !self.enable_twcc_feedback {
            debug!("Enable TWCC feedback");
            self.enable_twcc_feedback = true;
        }
    }

    pub fn visit_stats(&mut self, now: Instant, snapshot: &mut StatsSnapshot) {
        for media in &mut self.medias {
            media.visit_stats(now, snapshot)
        }
        snapshot.tx = snapshot.egress.values().map(|s| s.bytes).sum();
        snapshot.rx = snapshot.ingress.values().map(|s| s.bytes).sum();
        snapshot.bwe_tx = self.bwe.as_ref().and_then(|bwe| bwe.last_estimate());
    }

    pub fn set_bwe_current_bitrate(&mut self, current_bitrate: Bitrate) {
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.current_bitrate = current_bitrate;
            self.configure_pacer();
        }
    }

    pub fn set_bwe_desired_bitrate(&mut self, desired_bitrate: Bitrate) {
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.desired_bitrate = desired_bitrate;
            self.configure_pacer();
        }
    }

    pub fn line_count(&self) -> usize {
        self.medias.len() + if self.app.is_some() { 1 } else { 0 }
    }

    pub fn add_media(&mut self, mut media: MediaInner) {
        media.rtp_mode = self.rtp_mode;
        self.medias.push(media);
    }

    pub fn medias(&self) -> &[MediaInner] {
        &self.medias
    }

    fn configure_pacer(&mut self) {
        let Some(bwe) = self.bwe.as_ref() else {
            return;
        };

        let padding_rate = bwe
            .last_estimate()
            .map(|estimate| estimate.min(bwe.desired_bitrate))
            .unwrap_or(Bitrate::ZERO);

        self.pacer.set_padding_rate(padding_rate);

        // We pad up to the pacing rate, therefore we need to increase pacing if the estimate, and
        // thus the padding rate, exceeds the current bitrate adjusted with the pacing factor.
        // Otherwise we can have a case where the current bitrate is 250Kbit/s resulting in a
        // pacing rate of 275KBit/s which means we'll only ever pad about 25Kbit/s. If the estimate
        // is actually 600Kbit/s we need to use that for the pacing rate to ensure we send as much as
        // we think the link capacity can sustain, if not the estimate is a lie.
        let pacing_rate = (bwe.current_bitrate * PACING_FACTOR).max(padding_rate);
        self.pacer.set_pacing_rate(pacing_rate);
    }
}

struct Bwe {
    bwe: SendSideBandwithEstimator,
    desired_bitrate: Bitrate,
    current_bitrate: Bitrate,

    last_emitted_estimate: Bitrate,
}

impl Bwe {
    fn handle_timeout(&mut self, now: Instant) {
        self.bwe.handle_timeout(now);
    }

    pub(crate) fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t crate::rtp::TwccSendRecord>,
        now: Instant,
    ) {
        self.bwe.update(records, now);
    }

    fn poll_estimate(&mut self) -> Option<Bitrate> {
        let estimate = self.bwe.last_estimate()?;

        let min = self.last_emitted_estimate * (1.0 - ESTIMATE_TOLERANCE);
        let max = self.last_emitted_estimate * (1.0 + ESTIMATE_TOLERANCE);

        if estimate < min || estimate > max {
            self.last_emitted_estimate = estimate;
            Some(estimate)
        } else {
            // Estimate is within tolerances.
            None
        }
    }

    fn poll_timeout(&self) -> Instant {
        self.bwe.poll_timeout()
    }

    fn last_estimate(&self) -> Option<Bitrate> {
        self.bwe.last_estimate()
    }
}
