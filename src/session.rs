use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::bwe::BweKind;
use crate::crypto::SrtpProfile;
use crate::crypto::{KeyingMaterial, SrtpCrypto};
use crate::format::CodecConfig;
use crate::format::PayloadParams;
use crate::io::{DatagramSend, DATAGRAM_MTU, DATAGRAM_MTU_WARN};
use crate::media::KeyframeRequestKind;
use crate::media::Media;
use crate::media::{MediaAdded, MediaChanged};
use crate::packet::SendSideBandwithEstimator;
use crate::packet::{LeakyBucketPacer, NullPacer, Pacer, PacerImpl};
use crate::rtp::{Extension, RawPacket};
use crate::rtp_::Direction;
use crate::rtp_::MidRid;
use crate::rtp_::Pt;
use crate::rtp_::SeqNo;
use crate::rtp_::SRTCP_OVERHEAD;
use crate::rtp_::{extend_u16, RtpHeader, SessionId, TwccRecvRegister, TwccSendRegister};
use crate::rtp_::{Bitrate, ExtensionMap, Mid, Rtcp, RtcpFb};
use crate::rtp_::{SrtpContext, Ssrc};
use crate::stats::StatsSnapshot;
use crate::streams::{RtpPacket, Streams};
use crate::util::{already_happened, not_happening, Soonest};
use crate::Event;
use crate::{net, Reason};
use crate::{RtcConfig, RtcError};

/// Minimum time we delay between sending nacks. This should be
/// set high enough to not cause additional problems in very bad
/// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(33);

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
    pub medias: Vec<Media>,

    // The actual RTP encoded streams.
    pub streams: Streams,

    /// The app m-line. Spliced into medias above.
    app: Option<(Mid, usize)>,

    reordering_size_audio: usize,
    reordering_size_video: usize,
    pub send_buffer_audio: usize,
    pub send_buffer_video: usize,

    /// Extension mappings are _per BUNDLE_, but we can only have one a=group BUNDLE
    /// in WebRTC (one ice connection), so they are effectively per session.
    pub exts: ExtensionMap,

    // Configuration of how we are sending/receiving media.
    pub codec_config: CodecConfig,

    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    last_nack: Instant,
    last_twcc: Instant,
    twcc: u64,
    twcc_rx_register: TwccRecvRegister,
    twcc_tx_register: TwccSendRegister,
    max_rx_seq_lookup: HashMap<Ssrc, SeqNo>,

    bwe: Option<Bwe>,

    enable_twcc_feedback: bool,

    /// A pacer for sending RTP at specific rate.
    pacer: PacerImpl,

    // temporary buffer when getting the next (unencrypted) RTP packet from Media line.
    poll_packet_buf: Vec<u8>,

    // Next packet for RtpPacket event.
    pending_packet: Option<RtpPacket>,

    pub ice_lite: bool,

    /// Whether we are running in RTP-mode.
    pub rtp_mode: bool,

    feedback_tx: VecDeque<Rtcp>,
    feedback_rx: VecDeque<Rtcp>,

    raw_packets: Option<VecDeque<Box<RawPacket>>>,
}

impl Session {
    pub fn new(config: &RtcConfig) -> Self {
        let mut id = SessionId::new();
        // Max 2^62 - 1: https://bugzilla.mozilla.org/show_bug.cgi?id=861895
        const MAX_ID: u64 = 2_u64.pow(62) - 1;
        while *id > MAX_ID {
            id = (*id >> 1).into();
        }
        let (pacer, bwe) = if let Some(config) = &config.bwe_config {
            let rate = config.initial_bitrate;
            let pacer = PacerImpl::LeakyBucket(LeakyBucketPacer::new(rate * PACING_FACTOR * 2.0));

            let send_side_bwe = SendSideBandwithEstimator::new(rate, config.enable_loss_controller);
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

        let enable_stats = config.stats_interval.is_some();

        Session {
            id,
            medias: vec![],
            streams: Streams::new(enable_stats),
            app: None,
            reordering_size_audio: config.reordering_size_audio,
            reordering_size_video: config.reordering_size_video,
            send_buffer_audio: config.send_buffer_audio,
            send_buffer_video: config.send_buffer_video,
            exts: config.exts.clone(),

            // Both sending and receiving starts from the configured codecs.
            // These can then be changed in the SDP OFFER/ANSWER dance.
            codec_config: config.codec_config.clone(),

            srtp_rx: None,
            srtp_tx: None,
            last_nack: already_happened(),
            last_twcc: already_happened(),
            twcc: 0,
            twcc_rx_register: TwccRecvRegister::new(100),
            twcc_tx_register: TwccSendRegister::new(1000),
            max_rx_seq_lookup: HashMap::new(),
            bwe,
            enable_twcc_feedback: false,
            pacer,
            poll_packet_buf: vec![0; 2000],
            pending_packet: None,
            ice_lite: config.ice_lite,
            rtp_mode: config.rtp_mode,
            feedback_tx: VecDeque::new(),
            feedback_rx: VecDeque::new(),
            raw_packets: if config.enable_raw_packets {
                Some(VecDeque::new())
            } else {
                None
            },
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

    pub fn set_keying_material(
        &mut self,
        mat: KeyingMaterial,
        srtp_crypto: &SrtpCrypto,
        srtp_profile: SrtpProfile,
        active: bool,
    ) {
        // TODO: rename this to `initialise_srtp_context`?
        // Whether we're active or passive determines if we use the left or right
        // hand side of the key material to derive input/output.
        let left = active;

        self.srtp_rx = Some(SrtpContext::new(srtp_crypto, srtp_profile, &mat, !left));
        self.srtp_tx = Some(SrtpContext::new(srtp_crypto, srtp_profile, &mat, left));
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), RtcError> {
        // Payload any waiting samples
        self.do_payload()?;

        let sender_ssrc = self.streams.first_ssrc_local();

        let do_nack = now >= self.nack_at().unwrap_or(not_happening());

        self.streams.handle_timeout(
            now,
            sender_ssrc,
            do_nack,
            &self.medias,
            &self.codec_config,
            &mut self.feedback_tx,
        );

        if do_nack {
            self.last_nack = now;
        }

        self.update_queue_state(now);

        if let Some(twcc_at) = self.twcc_at() {
            if now >= twcc_at {
                self.create_twcc_feedback(sender_ssrc, now);
            }
        }

        if let Some(bwe) = self.bwe.as_mut() {
            bwe.handle_timeout(now);
        }

        Ok(())
    }

    fn update_queue_state(&mut self, now: Instant) {
        let iter = self.streams.streams_tx().map(|m| m.queue_state(now));

        let Some(padding_request) = self.pacer.handle_timeout(now, iter) else {
            return;
        };

        let stream = self
            .streams
            .stream_tx_by_midrid(padding_request.midrid)
            .expect("pacer to use an existing stream");

        stream.generate_padding(padding_request.padding);
    }

    fn create_twcc_feedback(&mut self, sender_ssrc: Ssrc, now: Instant) -> Option<()> {
        self.last_twcc = now;
        let mut twcc = self.twcc_rx_register.build_report(DATAGRAM_MTU - 100)?;

        // These SSRC are on media level, but twcc is on session level,
        // we fill in the first discovered media SSRC in each direction.
        twcc.sender_ssrc = sender_ssrc;
        twcc.ssrc = self.streams.first_ssrc_remote();

        trace!("Created feedback TWCC: {:?}", twcc);
        self.feedback_tx.push_front(Rtcp::Twcc(twcc));
        Some(())
    }

    pub fn handle_rtp_receive(&mut self, now: Instant, message: &[u8]) {
        let Some(header) = RtpHeader::parse(message, &self.exts) else {
            trace!("Failed to parse RTP header");
            return;
        };

        self.handle_rtp(now, header, message);
    }

    pub fn handle_rtcp_receive(&mut self, now: Instant, message: &[u8]) {
        // According to spec, the outer enclosing SRTCP packet should always be a SR or RR,
        // even if it's irrelevant and empty.
        // In practice I'm not sure that is happening, because libWebRTC hates empty packets.
        self.handle_rtcp(now, message);
    }

    fn mid_and_ssrc_for_header(&mut self, now: Instant, header: &RtpHeader) -> Option<(Mid, Ssrc)> {
        let ssrc_header = header.ssrc;

        if let Some(r) = self.streams.mid_ssrc_rx_by_ssrc_or_rtx(now, ssrc_header) {
            return Some(r);
        }

        // Attempt to dynamically map this header to some Media/ReceiveStream.
        self.map_dynamic(header);

        // The dynamic mapping might have added an entry by now.
        self.streams.mid_ssrc_rx_by_ssrc_or_rtx(now, ssrc_header)
    }

    fn map_dynamic(&mut self, header: &RtpHeader) {
        // There are two strategies for dynamically mapping SSRC. Both use the RTP "mid"
        // header extension.
        // A) Mid+Rid - used when doing simulcast. Rid points out which
        //              simulcast layer is in use. There is a separate header
        //              to indicate repair (RTX) stream.
        // B) Mid+PT - when not doing simulcast, the PT identifies whether
        //             this is a repair stream.

        let Some(mid) = header.ext_vals.mid else {
            return;
        };
        let rid = header.ext_vals.rid.or(header.ext_vals.rid_repair);

        // The media the mid points out. Bail if the mid points to something
        // we don't know about.
        let Some(media) = self.medias.iter_mut().find(|m| m.mid() == mid) else {
            return;
        };

        // Figure out which payload the PT maps to. Either main or RTX.
        let maybe_payload = self
            .codec_config
            .iter()
            .find(|p| p.pt() == header.payload_type || p.resend() == Some(header.payload_type));

        // If we don't find it, bail out.
        let Some(payload) = maybe_payload else {
            return;
        };

        if let Some(rid) = rid {
            // Case A - use the rid_repair header to identify RTX.
            let is_main = header.ext_vals.rid.is_some();

            let midrid = MidRid(mid, Some(rid));

            self.streams
                .map_dynamic_by_rid(header.ssrc, midrid, media, *payload, is_main);
        } else {
            // Case B - the payload type identifies RTX.
            let is_main = payload.pt() == header.payload_type;

            let midrid = MidRid(mid, None);

            self.streams
                .map_dynamic_by_pt(header.ssrc, midrid, media, *payload, is_main);
        }
    }

    pub(crate) fn handle_rtp(&mut self, now: Instant, mut header: RtpHeader, buf: &[u8]) {
        // Rewrite absolute-send-time (if present) to be relative to now.
        header.ext_vals.update_absolute_send_time(now);

        trace!("Handle RTP: {:?}", header);

        // The ssrc is the _main_ ssrc (no the rtx, that might be in the header).
        let Some((mid, ssrc)) = self.mid_and_ssrc_for_header(now, &header) else {
            debug!("No mid/SSRC for header: {:?}", header);
            return;
        };

        let srtp = match self.srtp_rx.as_mut() {
            Some(v) => v,
            None => {
                trace!("Rejecting SRTP while missing SrtpContext");
                return;
            }
        };

        // Both of these unwraps are fine because mid_and_ssrc_for_header guarantees it.
        let media = self.medias.iter_mut().find(|m| m.mid() == mid).unwrap();
        let stream = self.streams.stream_rx(&ssrc).unwrap();

        let params = match main_payload_params(&self.codec_config, header.payload_type) {
            Some(p) => p,
            None => {
                trace!(
                    "No payload params could be found (main or RTX) for {:?}",
                    header.payload_type
                );
                return;
            }
        };
        let clock_rate = params.spec().clock_rate;
        let pt = params.pt();
        let is_repair = pt != header.payload_type;

        let max_seq_lookup = make_max_seq_lookup(&self.max_rx_seq_lookup);

        // is_repair controls whether update is updating the main register or the RTX register.
        // Either way we get a seq_no_outer which is used to decrypt the SRTP.
        let mut seq_no = stream.extend_seq(&header, is_repair, max_seq_lookup);

        if !stream.is_new_packet(is_repair, seq_no) {
            // Dupe packet. This could be a potential SRTP replay attack, which means
            // we should not spend any CPU cycles towards decrypting it.
            trace!(
                "Ignoring dupe packet mid: {} seq_no: {} is_repair: {}",
                mid,
                seq_no,
                is_repair
            );
            return;
        }

        let mut data = match srtp.unprotect_rtp(buf, &header, *seq_no) {
            Some(v) => v,
            None => {
                trace!(
                    "Failed to unprotect SRTP for SSRC: {} pt: {}  mid: {} \
                    rid: {:?} seq_no: {} is_repair: {}",
                    header.ssrc,
                    pt,
                    stream.mid(),
                    stream.rid(),
                    seq_no,
                    is_repair
                );
                return;
            }
        };

        if header.has_padding && !RtpHeader::unpad_payload(&mut data) {
            // Unpadding failed. Broken data?
            trace!("unpadding of unprotected payload failed");
            return;
        }

        if let Some(raw_packets) = &mut self.raw_packets {
            raw_packets.push_back(Box::new(RawPacket::RtpRx(header.clone(), data.clone())));
        }

        // Mark as received for TWCC purposes
        if let Some(transport_cc) = header.ext_vals.transport_cc {
            let prev = self.twcc_rx_register.max_seq();
            let extended = extend_u16(Some(*prev), transport_cc);
            self.twcc_rx_register.update_seq(extended.into(), now);
        }

        // Store largest seen seq_no for the SSRC. This is used in case we get SSRC changes
        // like A -> B -> A. When we go back to A, we must keep the ROC.
        update_max_seq(&mut self.max_rx_seq_lookup, header.ssrc, seq_no);

        // Register reception in nack registers.
        let receipt_outer = stream.update_register(now, &header, clock_rate, is_repair, seq_no);

        // RTX packets must be rewritten to be a normal packet. This only changes the
        // the seq_no, however MediaTime might be different when interpreted against the
        // the "main" register.
        let receipt = if is_repair {
            // Drop RTX packets that are just empty padding. The payload here
            // is empty because we would have done RtpHeader::unpad_payload above.
            // For unpausing, it's enough with the stream.update() already done above.
            if data.is_empty() {
                return;
            }

            // Rewrite the header, and removes the resent seq_no from the body.
            stream.un_rtx(&mut header, &mut data, pt);

            let max_seq_lookup = make_max_seq_lookup(&self.max_rx_seq_lookup);

            // Header has changed, which means we extend a new seq_no. This time
            // without is_repair since this is the wrapped resend. This is the
            // extended number of the main stream.
            seq_no = stream.extend_seq(&header, false, max_seq_lookup);

            // header.ssrc is changed by un_rtx() above to be main SSRC.
            update_max_seq(&mut self.max_rx_seq_lookup, header.ssrc, seq_no);

            // Now update the "main" register with the repaired packet info.
            stream.update_register(now, &header, clock_rate, false, seq_no)
        } else {
            // This is not RTX, the outer seq and time is what we use. The first
            // stream.update will have updated the main register.
            receipt_outer
        };

        let packet = stream.handle_rtp(now, header, data, seq_no, receipt.time);

        if self.rtp_mode {
            // In RTP mode, we store the packet temporarily here for the next poll_output().
            // However only if this is a packet not seen before. This filters out spurious
            // resends for padding.
            if receipt.is_new_packet {
                self.pending_packet = Some(packet);
            }
        } else {
            // In non-RTP mode, we let the Media use a Depayloader.
            media.depayload(
                stream.rid(),
                packet,
                self.reordering_size_audio,
                self.reordering_size_video,
                &self.codec_config,
            );
        }
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp: &mut SrtpContext = self.srtp_rx.as_mut()?;
        let unprotected = srtp.unprotect_rtcp(buf)?;

        Rtcp::read_packet(&unprotected, &mut self.feedback_rx);
        let mut need_configure_pacer = false;

        if let Some(raw_packets) = &mut self.raw_packets {
            for fb in &self.feedback_rx {
                raw_packets.push_back(Box::new(RawPacket::RtcpRx(fb.clone())));
            }
        }

        for fb in RtcpFb::from_rtcp(self.feedback_rx.drain(..)) {
            if let RtcpFb::Twcc(twcc) = fb {
                trace!("Handle TWCC: {:?}", twcc);
                let maybe_records = self.twcc_tx_register.apply_report(twcc, now);

                if let (Some(maybe_records), Some(bwe)) = (maybe_records, &mut self.bwe) {
                    bwe.update(maybe_records, now);
                }
                need_configure_pacer = true;

                // The funky thing about TWCC reports is that they are never stapled
                // together with other RTCP packet. If they were though, we want to
                // handle more packets.
                continue;
            }

            if fb.is_for_rx() {
                let Some(stream) = self.streams.stream_rx(&fb.ssrc()) else {
                    continue;
                };
                stream.handle_rtcp(now, fb);
            } else {
                let Some(stream) = self.streams.stream_tx(&fb.ssrc()) else {
                    continue;
                };
                stream.handle_rtcp(now, fb);
            }
        }

        // Not in the above if due to lifetime issues, still okay because the method
        // doesn't do anything when BWE isn't configured.
        if need_configure_pacer {
            self.configure_pacer();
        }

        Some(())
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        if let Some(bitrate_estimate) = self.bwe.as_mut().and_then(|bwe| bwe.poll_estimate()) {
            return Some(Event::EgressBitrateEstimate(BweKind::Twcc(
                bitrate_estimate,
            )));
        }

        // If we're not ready to flow media, don't send any events.
        if !self.ready_for_srtp() {
            return None;
        }

        if let Some(raw_packets) = &mut self.raw_packets {
            if let Some(p) = raw_packets.pop_front() {
                return Some(Event::RawPacket(p));
            }
        }

        // This must be before pending_packet.take() since we need to emit the unpaused event
        // before the first packet causing the unpause.
        if let Some(paused) = self.streams.poll_stream_paused() {
            return Some(Event::StreamPaused(paused));
        }

        if self.rtp_mode {
            if let Some(packet) = self.pending_packet.take() {
                return Some(Event::RtpPacket(packet));
            }
        }

        if let Some(req) = self.streams.poll_keyframe_request() {
            return Some(Event::KeyframeRequest(req));
        }

        if let Some((mid, bitrate)) = self.streams.poll_remb_request() {
            return Some(Event::EgressBitrateEstimate(BweKind::Remb(mid, bitrate)));
        }

        for media in &mut self.medias {
            if media.need_open_event {
                media.need_open_event = false;

                return Some(Event::MediaAdded(MediaAdded {
                    mid: media.mid(),
                    kind: media.kind(),
                    direction: media.direction(),
                    simulcast: media.simulcast().map(|s| s.clone().into()),
                }));
            }

            if media.need_changed_event {
                media.need_changed_event = false;
                return Some(Event::MediaChanged(MediaChanged {
                    mid: media.mid(),
                    direction: media.direction(),
                }));
            }
        }

        None
    }

    pub fn poll_event_fallible(&mut self) -> Result<Option<Event>, RtcError> {
        // Not relevant in rtp_mode, where the packets are picked up by poll_event().
        if self.rtp_mode {
            return Ok(None);
        }

        for media in &mut self.medias {
            if let Some(e) = media.poll_sample(&self.codec_config)? {
                return Ok(Some(Event::MediaData(e)));
            }
        }

        Ok(None)
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
            // In RTP mode we trust the API user feeds the RTP packet sizes they
            // need for the MTU they are targeting. This warning is only for when
            // str0m does the RTP packetization.
            if !self.rtp_mode && x.len() > DATAGRAM_MTU_WARN {
                warn!("RTP above MTU {}: {}", DATAGRAM_MTU_WARN, x.len());
            }
        }

        x
    }

    /// To be called in lieu of [`Self::poll_datagram`] when the owner is not in a position to transmit any
    /// generated feedback, and thus such feedback should be dropped.
    pub fn clear_feedback(&mut self) {
        self.feedback_rx.clear();
        self.feedback_tx.clear();
    }

    fn poll_feedback(&mut self) -> Option<net::DatagramSend> {
        if self.feedback_tx.is_empty() {
            return None;
        }

        // Round to nearest multiple of 4 bytes.
        const ENCRYPTABLE_MTU: usize = (DATAGRAM_MTU - SRTCP_OVERHEAD) & !3;
        assert!(ENCRYPTABLE_MTU % 4 == 0);

        let mut data = vec![0_u8; ENCRYPTABLE_MTU];

        let mut raw_packets = self.raw_packets.as_mut();
        let output = move |fb| {
            if let Some(raw_packets) = &mut raw_packets {
                raw_packets.push_back(Box::new(RawPacket::RtcpTx(fb)));
            }
        };

        let len = Rtcp::write_packet(&mut self.feedback_tx, &mut data, output);

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
        let midrid = self.pacer.poll_queue()?;
        let media = self
            .medias
            .iter()
            .find(|m| m.mid() == midrid.mid())
            .expect("index is media");

        let buf = &mut self.poll_packet_buf;
        let twcc_seq = self.twcc;

        let stream = self.streams.stream_tx_by_midrid(midrid)?;

        let params = &self.codec_config;
        let exts = media.remote_extmap();

        // TWCC might not be enabled for this m-line. Firefox do use TWCC, but not
        // for audio. This is indiciated via the SDP.
        let twcc_enabled = exts.id_of(Extension::TransportSequenceNumber).is_some();
        let twcc = twcc_enabled.then_some(&mut self.twcc);

        let receipt = stream.poll_packet(now, exts, twcc, params, buf)?;

        let PacketReceipt {
            header,
            seq_no,
            is_padding,
            payload_size,
        } = receipt;

        trace!(payload_size, is_padding, "Poll RTP: {:?}", header);

        #[cfg(feature = "_internal_dont_use_log_stats")]
        {
            let kind = if is_padding { "padding" } else { "media" };

            crate::log_stat!("PACKET_SENT", header.ssrc, payload_size, kind);
        }

        self.pacer.register_send(now, payload_size.into(), midrid);

        if let Some(raw_packets) = &mut self.raw_packets {
            raw_packets.push_back(Box::new(RawPacket::RtpTx(header.clone(), buf.clone())));
        }

        let protected = srtp_tx.protect_rtp(buf, &header, *seq_no);

        if twcc_enabled {
            self.twcc_tx_register
                .register_seq(twcc_seq.into(), now, payload_size);
        }

        // Technically we should wait for the next handle_timeout, but this speeds things up a bit
        // avoiding an extra poll_timeout.
        self.update_queue_state(now);

        Some(protected.into())
    }

    pub fn poll_timeout(&mut self) -> (Option<Instant>, Reason) {
        let feedback_at = self.regular_feedback_at();
        let nack_at = self.nack_at();
        let twcc_at = self.twcc_at();
        let pacing_at = self.pacer.poll_timeout();
        let packetize_at = self.medias.iter().flat_map(|m| m.poll_timeout()).next();
        let bwe_at = self.bwe.as_ref().map(|bwe| bwe.poll_timeout());
        let paused_at = self.paused_at();
        let send_stream_at = self.streams.send_stream();

        (feedback_at, Reason::Feedback)
            .soonest((nack_at, Reason::Nack))
            .soonest((twcc_at, Reason::Twcc))
            .soonest((pacing_at, Reason::Pacing))
            .soonest((packetize_at, Reason::Packetize))
            .soonest((bwe_at, Reason::Bwe))
            .soonest((paused_at, Reason::PauseCheck))
            .soonest((send_stream_at, Reason::SendStream))
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.medias.iter().any(|m| m.mid() == mid)
    }

    fn regular_feedback_at(&self) -> Option<Instant> {
        self.streams.regular_feedback_at()
    }

    fn paused_at(&self) -> Option<Instant> {
        self.streams.paused_at()
    }

    fn nack_at(&mut self) -> Option<Instant> {
        if !self.streams.any_nack_enabled() {
            return None;
        }

        Some(self.last_nack + NACK_MIN_INTERVAL)
    }

    fn twcc_at(&self) -> Option<Instant> {
        let is_receiving = self.streams.is_receiving();
        if is_receiving && self.enable_twcc_feedback && self.twcc_rx_register.has_unreported() {
            Some(self.last_twcc + TWCC_INTERVAL)
        } else {
            None
        }
    }

    pub fn enable_twcc_feedback(&mut self) {
        if !self.enable_twcc_feedback {
            debug!("Enable TWCC feedback");
            self.enable_twcc_feedback = true;
        }
    }

    pub fn visit_stats(&mut self, now: Instant, snapshot: &mut StatsSnapshot) {
        for stream in self.streams.streams_tx() {
            stream.visit_stats(snapshot, now);
        }

        for stream in self.streams.streams_rx() {
            stream.visit_stats(snapshot, now);
        }

        snapshot.tx = snapshot.egress.values().map(|s| s.bytes).sum();
        snapshot.rx = snapshot.ingress.values().map(|s| s.bytes).sum();
        snapshot.bwe_tx = self.bwe.as_ref().and_then(|bwe| bwe.last_estimate());

        snapshot.egress_loss_fraction = self.twcc_tx_register.loss(Duration::from_secs(1), now);
        snapshot.rtt = self.twcc_tx_register.rtt();
        snapshot.ingress_loss_fraction = self.twcc_rx_register.loss();
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

    pub fn reset_bwe(&mut self, init_bitrate: Bitrate) {
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.reset(init_bitrate);
        }
    }

    pub fn line_count(&self) -> usize {
        self.medias.len() + if self.app.is_some() { 1 } else { 0 }
    }

    pub fn add_media(&mut self, media: Media) {
        self.medias.push(media);
    }

    pub fn medias(&self) -> &[Media] {
        &self.medias
    }

    pub fn remove_media(&mut self, mid: Mid) {
        self.medias.retain(|media| media.mid() != mid);
        self.streams.remove_streams_by_mid(mid);
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

    pub fn media_by_mid(&self, mid: Mid) -> Option<&Media> {
        self.medias.iter().find(|m| m.mid() == mid)
    }

    pub fn media_by_mid_mut(&mut self, mid: Mid) -> Option<&mut Media> {
        self.medias.iter_mut().find(|m| m.mid() == mid)
    }

    fn do_payload(&mut self) -> Result<(), RtcError> {
        for m in &mut self.medias {
            m.do_payload(&mut self.streams, &self.codec_config)?;
        }

        Ok(())
    }

    pub fn set_direction(&mut self, mid: Mid, direction: Direction) -> bool {
        let Some(media) = self.media_by_mid_mut(mid) else {
            return false;
        };
        let old_dir = media.direction();
        if old_dir == direction {
            return false;
        }

        media.set_direction(direction);

        if old_dir.is_sending() && !direction.is_sending() {
            self.streams.reset_buffers_tx(mid);
        }

        let max_seq_lookup = make_max_seq_lookup(&self.max_rx_seq_lookup);
        if old_dir.is_receiving() && !direction.is_receiving() {
            self.streams.reset_buffers_rx(mid, max_seq_lookup);
        }

        true
    }

    pub fn is_request_keyframe_possible(&self, kind: KeyframeRequestKind) -> bool {
        // TODO: It's possible to have different set of feedback enabled for different
        // payload types. I.e. we could have FIR enabled for H264, but not for VP8.
        // We might want to make this check more fine grained by testing which PT is
        // in "active use" right now.
        self.codec_config.iter().any(|r| match kind {
            KeyframeRequestKind::Pli => r.fb_pli,
            KeyframeRequestKind::Fir => r.fb_fir,
        })
    }

    /// Checks whether the SRTP contexts are up.
    pub fn is_connected(&self) -> bool {
        self.srtp_rx.is_some() && self.srtp_tx.is_some()
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

    fn reset(&mut self, init_bitrate: Bitrate) {
        self.bwe.reset(init_bitrate);
    }

    fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t crate::rtp_::TwccSendRecord>,
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

pub struct PacketReceipt {
    pub header: RtpHeader,
    pub seq_no: SeqNo,
    pub is_padding: bool,
    pub payload_size: usize,
}

/// Find the PayloadParams for the given Pt, either when the Pt is the main Pt for the Codec or
/// when it's the RTX Pt.
fn main_payload_params(c: &CodecConfig, pt: Pt) -> Option<&PayloadParams> {
    c.iter().find(|p| (p.pt == pt || p.resend == Some(pt)))
}

fn make_max_seq_lookup(map: &HashMap<Ssrc, SeqNo>) -> impl Fn(Ssrc) -> Option<SeqNo> + '_ {
    |ssrc| map.get(&ssrc).cloned()
}

fn update_max_seq(map: &mut HashMap<Ssrc, SeqNo>, ssrc: Ssrc, seq_no: SeqNo) {
    let current = map.entry(ssrc).or_insert(seq_no);
    if seq_no > *current {
        *current = seq_no;
    }
}
