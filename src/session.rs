use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::Event;
use crate::bwe::BweKind;
use crate::bwe_::{Bwe, BweLogEvent};
use crate::config::KeyingMaterial;
use crate::crypto::CryptoProvider;
use crate::crypto::dtls::SrtpProfile;
use crate::format::CodecConfig;
use crate::format::PayloadParams;
use crate::format::Vp9PacketizerMode;
use crate::io::{DATAGRAM_MTU, DATAGRAM_MTU_WARN, DatagramSend};
use crate::media::Media;
use crate::media::{KeyframeRequestKind, MID_PROBE};
use crate::media::{MediaAdded, MediaChanged};
use crate::pacer::PacerControl;
use crate::pacer::{Pacer, PacerImpl};
use crate::rtp::{Extension, RawPacket};
use crate::rtp_::Direction;
use crate::rtp_::MidRid;
use crate::rtp_::Pt;
use crate::rtp_::SRTCP_OVERHEAD;
use crate::rtp_::SeqNo;
use crate::rtp_::{Bitrate, ExtensionMap, Mid, Rtcp, RtcpFb};
use crate::rtp_::{RtpHeader, SessionId, TwccPacketId, extend_u16};
use crate::rtp_::{SrtpContext, Ssrc};
use crate::rtp_::{TwccRecvRegister, TwccSendRegister};
use crate::stats::StatsSnapshot;
use crate::streams::{RtpPacket, Streams};
use crate::util::{Soonest, already_happened, not_happening};
use crate::rtc_event_log::RtcEventLogCollector;
use crate::{Reason, net};
use crate::{RtcConfig, RtcError};

/// Minimum time we delay between sending nacks. This should be
/// set high enough to not cause additional problems in very bad
/// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(33);

/// Delay between reports of TWCC. This is deliberately very low.
const TWCC_INTERVAL: Duration = Duration::from_millis(50);

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

    // Payload params for SSRC 0 BWE probes.
    // Lazy init when we see the PT.
    probe_payload_params: Option<PayloadParams>,

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
    pacer_control: PacerControl,

    // temporary buffer when getting the next (unencrypted) RTP packet from Media line.
    poll_packet_buf: Vec<u8>,

    // Next packet for RtpPacket event.
    pending_packet: Option<RtpPacket>,

    // Whether we sent a single outgoing RTP packet.
    packet_first_sent: bool,

    pub ice_lite: bool,

    /// Whether we are running in RTP-mode.
    pub rtp_mode: bool,

    /// VP9 packetizer mode.
    vp9_packetizer_mode: Vp9PacketizerMode,

    feedback_tx: VecDeque<Rtcp>,
    feedback_rx: VecDeque<Rtcp>,

    raw_packets: Option<VecDeque<Box<RawPacket>>>,

    /// RTC event log collector. None when event logging is not enabled.
    event_log: Option<RtcEventLogCollector>,

    /// Last known "now" for use in contexts where `now` is not passed as a parameter.
    /// Updated by `handle_timeout()` and `new()`.
    last_now: Instant,

    #[cfg(feature = "_internal_test_exports")]
    pending_probe: Option<crate::bwe_::ProbeClusterConfig>,
}

impl Session {
    pub fn new(config: &RtcConfig, now: Instant) -> Self {
        let mut id = SessionId::new();
        // Max 2^62 - 1: https://bugzilla.mozilla.org/show_bug.cgi?id=861895
        const MAX_ID: u64 = 2_u64.pow(62) - 1;
        while *id > MAX_ID {
            id = (*id >> 1).into();
        }
        let (pacer, bwe) = if let Some(config) = &config.bwe_config {
            let rate = config.initial_bitrate;
            let pacer = PacerImpl::leaky_bucket(rate * 2.0);
            let bwe = Bwe::new(rate);
            (pacer, Some(bwe))
        } else {
            (PacerImpl::null(), None)
        };

        let enable_stats = config.stats_interval.is_some();

        let mut session = Session {
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
            probe_payload_params: None,

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
            pacer_control: PacerControl::new(),
            poll_packet_buf: vec![0; 2000],
            pending_packet: None,
            packet_first_sent: false,
            ice_lite: config.ice_lite,
            rtp_mode: config.rtp_mode,
            vp9_packetizer_mode: config.vp9_packetizer_mode,
            feedback_tx: VecDeque::new(),
            feedback_rx: VecDeque::new(),
            raw_packets: if config.enable_raw_packets {
                Some(VecDeque::new())
            } else {
                None
            },
            event_log: if config.enable_rtc_event_log {
                let interval = config.rtc_event_log_interval;
                Some(if let Some(interval) = interval {
                    RtcEventLogCollector::new(now, interval)
                } else {
                    RtcEventLogCollector::with_defaults(now)
                })
            } else {
                None
            },
            last_now: now,
            #[cfg(feature = "_internal_test_exports")]
            pending_probe: None,
        };

        // Activate BWE event logging if both BWE and event log are enabled.
        if session.event_log.is_some() {
            if let Some(bwe) = &mut session.bwe {
                bwe.set_event_log_active(true);
            }
        }

        session
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn stop_rtc_event_log(&mut self, now: Instant) {
        if let Some(log) = &mut self.event_log {
            log.finish(now);
        }
        // Keep event_log alive so pending_output can be drained via poll_event().
        // It will be set to None after all data is drained, or the caller can
        // simply let Rtc drop.
    }

    /// Drain pending event log data. Used by poll_output even when Rtc is not alive,
    /// so EndLogEvent bytes queued by stop_rtc_event_log() can still be delivered.
    pub fn poll_event_log(&mut self) -> Option<Vec<u8>> {
        self.event_log.as_mut().and_then(|log| log.poll())
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
        crypto: &CryptoProvider,
        srtp_profile: SrtpProfile,
        active: bool,
    ) {
        // TODO: rename this to `initialise_srtp_context`?
        // Whether we're active or passive determines if we use the left or right
        // hand side of the key material to derive input/output.
        let left = active;

        self.srtp_rx = Some(SrtpContext::new(crypto, srtp_profile, &mat, !left));
        self.srtp_tx = Some(SrtpContext::new(crypto, srtp_profile, &mat, left));
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), RtcError> {
        self.last_now = now;

        // Payload any waiting frames
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

        self.handle_timeout_bwe(now);

        // Flush event log if interval elapsed or buffer full
        if let Some(log) = &mut self.event_log {
            log.flush(now);
        }

        Ok(())
    }

    fn handle_timeout_bwe(&mut self, now: Instant) {
        let Some(bwe) = self.bwe.as_mut() else {
            return;
        };

        // We can only run probes after first packet is sent and there
        // are any queues that can handle padding requests.
        let do_probe = self.packet_first_sent && self.pacer.has_padding_queue();

        if let Some(probe_config) = bwe.handle_timeout(now, do_probe) {
            // Only start the probe in the pacer if the estimator accepted it.
            if bwe.start_probe(probe_config, now) {
                // Log probe cluster created for event log.
                if let Some(log) = &mut self.event_log {
                    log.record_probe_cluster_created(
                        now,
                        *probe_config.cluster() as u32,
                        probe_config.target_bitrate().as_u64() as u32,
                        probe_config.min_packet_count() as u32,
                    );
                }

                #[cfg(feature = "_internal_test_exports")]
                {
                    self.pending_probe = Some(probe_config);
                }
                self.pacer.start_probe(probe_config);
            }
        }

        // Drain BWE log events (ALR state changes, probe failures from expired probes).
        self.drain_bwe_log_events(now);

        // Check if active probe just completed
        if let Some(cluster_id) = self.pacer.check_probe_complete(now) {
            // bwe field is still available since we only borrow self.bwe
            if let Some(bwe) = self.bwe.as_mut() {
                bwe.end_probe(now, cluster_id);
            }
        }
    }

    /// Drain buffered BWE log events and forward them to the event log collector.
    fn drain_bwe_log_events(&mut self, now: Instant) {
        let (Some(bwe), Some(log)) = (self.bwe.as_mut(), self.event_log.as_mut()) else {
            return;
        };

        for event in bwe.drain_log_events() {
            match event {
                BweLogEvent::DelayBased {
                    bitrate_bps,
                    detector_state,
                } => {
                    log.record_delay_based_bwe(now, bitrate_bps, detector_state);
                }
                BweLogEvent::LossBased {
                    bitrate_bps,
                    fraction_loss,
                    total_packets,
                } => {
                    log.record_loss_based_bwe(now, bitrate_bps, fraction_loss, total_packets);
                }
                BweLogEvent::ProbeSuccess { id, bitrate_bps } => {
                    log.record_probe_cluster_success(now, id, bitrate_bps);
                }
                BweLogEvent::ProbeFailure { id, reason } => {
                    log.record_probe_cluster_failure(now, id, reason);
                }
                BweLogEvent::AlrState { in_alr } => {
                    log.record_alr_state(now, in_alr);
                }
            }
        }
    }

    /// Record stream configs for a media mid into the event log.
    ///
    /// Called when a `MediaAdded` event is about to be emitted, so the streams
    /// for this mid are already set up.
    pub(crate) fn record_stream_configs_for_mid(&mut self, mid: Mid) {
        if self.event_log.is_none() {
            return;
        }

        let Some(media) = self.medias.iter().find(|m| m.mid() == mid) else {
            return;
        };
        let is_audio = media.kind().is_audio();
        let exts = media.remote_extmap().clone();

        // Collect TX stream SSRCs (uses &self on streams).
        let tx_ssrcs = self.streams.ssrcs_tx(mid);

        // Collect RX stream SSRCs. ssrcs_rx doesn't exist, so iterate manually.
        let rx_ssrcs: Vec<(Ssrc, Option<Ssrc>)> = self
            .streams
            .streams_rx_by_mid(mid)
            .map(|s| (s.ssrc(), s.rtx()))
            .collect();

        let local_ssrc = *self.streams.first_ssrc_local();

        let log = self.event_log.as_mut().unwrap();
        let now = self.last_now;

        for (ssrc, rtx) in &tx_ssrcs {
            if is_audio {
                log.record_audio_send_stream_config(now, **ssrc, &exts);
            } else {
                log.record_video_send_stream_config(
                    now,
                    **ssrc,
                    rtx.map(|r| *r),
                    &exts,
                );
            }
        }

        for (remote_ssrc, rtx) in &rx_ssrcs {
            if is_audio {
                log.record_audio_recv_stream_config(
                    now,
                    **remote_ssrc,
                    local_ssrc,
                    &exts,
                );
            } else {
                log.record_video_recv_stream_config(
                    now,
                    **remote_ssrc,
                    local_ssrc,
                    rtx.map(|r| *r),
                    &exts,
                );
            }
        }
    }

    /// Record a single receive stream config into the event log.
    pub(crate) fn record_recv_stream_config(
        &mut self,
        is_audio: bool,
        remote_ssrc: u32,
        rtx_ssrc: Option<u32>,
        exts: &ExtensionMap,
    ) {
        if self.event_log.is_none() {
            return;
        }
        let local_ssrc = *self.streams.first_ssrc_local();
        let now = self.last_now;
        let log = self.event_log.as_mut().unwrap();
        if is_audio {
            log.record_audio_recv_stream_config(now, remote_ssrc, local_ssrc, exts);
        } else {
            log.record_video_recv_stream_config(now, remote_ssrc, local_ssrc, rtx_ssrc, exts);
        }
    }

    /// Record a single send stream config into the event log.
    pub(crate) fn record_send_stream_config(
        &mut self,
        is_audio: bool,
        ssrc: u32,
        rtx_ssrc: Option<u32>,
        exts: &ExtensionMap,
    ) {
        let Some(log) = &mut self.event_log else {
            return;
        };
        let now = self.last_now;
        if is_audio {
            log.record_audio_send_stream_config(now, ssrc, exts);
        } else {
            log.record_video_send_stream_config(now, ssrc, rtx_ssrc, exts);
        }
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
        if let Some(r) = self.streams.mid_ssrc_rx_by_ssrc_or_rtx(now, ssrc_header) {
            return Some(r);
        }

        // SSRC 0 is used for non-media BWE probes from libwebrtc.
        // These probes need TWCC feedback but don't carry actual media.
        if ssrc_header.is_probe() {
            return self.ensure_probe_stream(header.payload_type);
        }

        None
    }

    /// Creates the probe stream on-demand for handling SSRC 0 BWE probes.
    ///
    /// No Media is created since probes don't carry real media - they only need
    /// SRTP decryption and TWCC feedback.
    fn ensure_probe_stream(&mut self, pt: Pt) -> Option<(Mid, Ssrc)> {
        let ssrc: Ssrc = 0.into();
        let midrid = MidRid(MID_PROBE, None);

        // Add PayloadParams for this PT if not already configured.
        // Probes may use different PTs, so we add them as we see them.
        self.probe_payload_params = Some(PayloadParams::new_probe(pt));

        // Create the stream with NACK suppressed (probes don't need retransmission)
        self.streams.expect_stream_rx(ssrc, None, midrid, true);

        Some((MID_PROBE, ssrc))
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

        // mid_and_ssrc_for_header guarantees stream exists.
        // Media may not exist for internal probe streams (SSRC 0).
        let stream = self.streams.stream_rx(&ssrc).unwrap();

        let maybe_params = if ssrc.is_probe() {
            self.probe_payload_params.as_ref()
        } else {
            main_payload_params(&self.codec_config, header.payload_type)
        };

        let params = match maybe_params {
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
                mid, seq_no, is_repair
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

        // Record incoming RTP for event log (before unpad/un_rtx, header as on-the-wire)
        if let Some(log) = &mut self.event_log {
            let padding_size = if header.has_padding && !data.is_empty() {
                data[data.len() - 1] as usize
            } else {
                0
            };
            let rtx_osn = if is_repair && data.len() >= padding_size + 2 {
                Some(u16::from_be_bytes([data[0], data[1]]))
            } else {
                None
            };
            // payload_size = total decrypted data minus padding
            // (includes RTX OSN prefix for RTX packets, matching Chrome behavior)
            let payload_size = data.len().saturating_sub(padding_size);
            log.record_incoming_rtp(now, &header, payload_size, padding_size, rtx_osn);
        }

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
            let extended = extend_u16(prev.map(|s| *s), transport_cc);
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

        // Probe packets (SSRC 0) contain only padding, no real media to process
        if ssrc.is_probe() {
            return;
        }

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
            // unwrap is fine because mid_and_ssrc_for_header guarantees it.
            let media = self.medias.iter_mut().find(|m| m.mid() == mid).unwrap();
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

        // Record incoming RTCP for event log (raw bytes, before parsing)
        if let Some(log) = &mut self.event_log {
            log.record_incoming_rtcp(now, &unprotected);
        }

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

        // Drain BWE log events after the feedback loop completes.
        // This is safe since TWCC reports are never stapled with other RTCP.
        self.drain_bwe_log_events(now);

        // Not in the above if due to lifetime issues, still okay because the method
        // doesn't do anything when BWE isn't configured.
        if need_configure_pacer {
            self.configure_pacer();
        }

        Some(())
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        #[cfg(feature = "_internal_test_exports")]
        {
            if let Some(probe) = self.pending_probe.take() {
                return Some(Event::Probe(probe));
            }
        }

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
            if paused.paused {
                if let Some(media) = self.medias.iter_mut().find(|m| m.mid() == paused.mid) {
                    // Drop held partial depacketizer state so pre-pause fragments can't
                    // complete into stale MediaData after the stream resumes.
                    media.reset_depayloaders_for_rid(paused.rid);
                }
            }
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

        if let Some(report) = self.streams.poll_sender_feedback() {
            return Some(Event::SenderFeedback(report));
        }

        if let Some((mid, bitrate)) = self.streams.poll_remb_request() {
            return Some(Event::EgressBitrateEstimate(BweKind::Remb(mid, bitrate)));
        }

        // Check for MediaAdded events first, then MediaChanged. This intentionally
        // prioritizes open events over change events across all medias (the original
        // single-loop checked per-media in iteration order; the split is needed to
        // release the mutable borrow on self.medias before record_stream_configs).
        let media_added = self
            .medias
            .iter_mut()
            .find(|m| m.need_open_event)
            .map(|media| {
                media.need_open_event = false;
                (
                    media.mid(),
                    media.kind(),
                    media.direction(),
                    media.simulcast().map(|s| s.clone().into()),
                )
            });
        if let Some((mid, kind, direction, simulcast)) = media_added {
            return Some(Event::MediaAdded(MediaAdded {
                mid,
                kind,
                direction,
                simulcast,
            }));
        }

        let media_changed = self
            .medias
            .iter_mut()
            .find(|m| m.need_changed_event)
            .map(|media| {
                media.need_changed_event = false;
                (media.mid(), media.direction())
            });
        if let Some((mid, direction)) = media_changed {
            return Some(Event::MediaChanged(MediaChanged { mid, direction }));
        }

        // Event log data — polled LAST (bulk, non-urgent)
        if let Some(log) = &mut self.event_log {
            if let Some(data) = log.poll() {
                return Some(Event::RtcEventLog(data));
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
            .or_else(|| self.poll_feedback(now))
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

    fn poll_feedback(&mut self, now: Instant) -> Option<net::DatagramSend> {
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

        // Record outgoing RTCP for event log (raw bytes, before SRTP protect)
        if let Some(log) = &mut self.event_log {
            log.record_outgoing_rtcp(now, &data);
        }

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
        // The cluster_id is captured by the pacer at poll time, before register_send() might clear it
        let (midrid, cluster_id) = self.pacer.poll_queue()?;
        let Some(media) = self.medias.iter().find(|m| m.mid() == midrid.mid()) else {
            trace!("Pacer pointed to mid {} which has no media", midrid.mid());
            return None;
        };

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
            rtx_original_seq_no,
        } = receipt;

        trace!(payload_size, is_padding, "Poll RTP: {:?}", header);

        #[cfg(feature = "_internal_dont_use_log_stats")]
        {
            let kind = if is_padding { "padding" } else { "media" };

            crate::log_stat!("PACKET_SENT", header.ssrc, payload_size, kind);
        }

        self.pacer.register_send(now, payload_size.into(), midrid);

        // Record outgoing RTP for event log (before SRTP protect, cheap Vec::push)
        if let Some(log) = &mut self.event_log {
            let probe_id = cluster_id.map(|c| *c as i32);
            let rtx_osn = rtx_original_seq_no.map(|s| *s as u16);
            log.record_outgoing_rtp(now, &header, payload_size, probe_id, rtx_osn);
        }

        if let Some(raw_packets) = &mut self.raw_packets {
            raw_packets.push_back(Box::new(RawPacket::RtpTx(header.clone(), buf.clone())));
        }

        let protected = srtp_tx.protect_rtp(buf, &header, *seq_no);

        if twcc_enabled {
            let packet_id = if let Some(cluster) = cluster_id {
                TwccPacketId::with_cluster(twcc_seq, cluster)
            } else {
                TwccPacketId::new(twcc_seq)
            };
            self.twcc_tx_register
                .register_seq(packet_id, now, payload_size);
        }

        // Update BWE subsystem
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.on_media_sent(payload_size.into(), is_padding, now);
        }

        if !self.packet_first_sent {
            self.packet_first_sent = true;
        }

        Some(protected.into())
    }

    pub fn poll_timeout(&mut self) -> (Option<Instant>, Reason) {
        let feedback_at = self.regular_feedback_at();
        let nack_at = self.nack_at();
        let twcc_at = self.twcc_at();
        let pacing_at = self.pacer.poll_timeout();
        let packetize_at = self.medias.iter().flat_map(|m| m.poll_timeout()).next();
        let paused_at = self.paused_at();
        let send_stream_at = self.streams.send_stream();

        // Gives us built-in reason
        let bwe_at = self
            .bwe
            .as_ref()
            .map(|bwe| bwe.poll_timeout())
            // We should never see this reason.
            .unwrap_or((None, Reason::BweDelayControl));

        let event_log_at = self.event_log.as_ref().and_then(|log| log.poll_timeout());

        (feedback_at, Reason::Feedback)
            .soonest((nack_at, Reason::Nack))
            .soonest((twcc_at, Reason::Twcc))
            .soonest(pacing_at)
            .soonest((packetize_at, Reason::Packetize))
            .soonest((paused_at, Reason::PauseCheck))
            .soonest((send_stream_at, Reason::SendStream))
            .soonest(bwe_at)
            .soonest((event_log_at, Reason::EventLog))
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

    pub fn set_bwe_desired_bitrate(&mut self, desired_bitrate: Bitrate) {
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.set_desired_bitrate(desired_bitrate);
            self.configure_pacer();
        }
    }

    pub fn reset_bwe(&mut self, init_bitrate: Bitrate) {
        if let Some(bwe) = self.bwe.as_mut() {
            bwe.reset(init_bitrate);
        }
    }

    #[allow(dead_code)]
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
        let Some(bwe) = self.bwe.as_mut() else {
            return;
        };

        let Some(current_estimate) = bwe.last_estimate() else {
            // No estimate yet, no padding
            return;
        };
        let is_overuse = bwe.is_overusing();

        let has_active_media = self.has_active_outgoing_media();

        // Calculate pacing and padding rates
        let result = self
            .pacer_control
            .calculate(has_active_media, current_estimate, is_overuse);

        self.pacer.set_padding_rate(result.padding_rate);
        self.pacer.set_pacing_rate(result.pacing_rate);
    }

    fn has_active_outgoing_media(&self) -> bool {
        self.medias
            .iter()
            .any(|m| m.direction().is_sending() && !m.disabled())
    }

    pub fn media_by_mid(&self, mid: Mid) -> Option<&Media> {
        self.medias.iter().find(|m| m.mid() == mid)
    }

    pub fn media_by_mid_mut(&mut self, mid: Mid) -> Option<&mut Media> {
        self.medias.iter_mut().find(|m| m.mid() == mid)
    }

    fn do_payload(&mut self) -> Result<(), RtcError> {
        for m in &mut self.medias {
            m.do_payload(
                &mut self.streams,
                &self.codec_config,
                self.vp9_packetizer_mode,
            )?;
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

    pub fn stop_media(&mut self, mid: Mid) -> bool {
        let Some(media) = self.media_by_mid_mut(mid) else {
            return false;
        };
        if media.disabled() {
            return false;
        }

        media.mark_stopped();
        self.set_direction(mid, Direction::Inactive);

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

pub struct PacketReceipt {
    pub header: RtpHeader,
    pub seq_no: SeqNo,
    pub is_padding: bool,
    pub payload_size: usize,
    /// For RTX resends, the original sequence number being retransmitted.
    pub rtx_original_seq_no: Option<SeqNo>,
}

/// Find the PayloadParams for the given Pt, either when the Pt is the main Pt for the Codec or
/// when it's the RTX Pt.
fn main_payload_params(c: &CodecConfig, pt: Pt) -> Option<&PayloadParams> {
    c.iter().find(|p| p.pt == pt || p.resend == Some(pt))
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
