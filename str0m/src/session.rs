use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use dtls::KeyingMaterial;
use net_::{DatagramSend, DATAGRAM_MTU};
use packet::RtpMeta;
use rtp::SRTCP_OVERHEAD;
use rtp::{extend_seq, Direction, RtpHeader, SessionId, TwccRecvRegister, TwccSendRegister};
use rtp::{Extensions, MediaTime, Mid, Rtcp, RtcpFb};
use rtp::{SrtpContext, SrtpKey, Ssrc};

use crate::media::{App, CodecConfig, MediaKind, Source};
use crate::session_sdp::AsMediaLine;
use crate::util::{already_happened, not_happening, Soonest};
use crate::RtcError;
use crate::{net, KeyframeRequest, MediaData};

use super::Media;

// Minimum time we delay between sending nacks. This should be
// set high enough to not cause additional problems in very bad
// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(250);

// Delay between reports of TWCC. This is deliberately very low.
const TWCC_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct Session {
    id: SessionId,

    // these fields are pub to allow session_sdp.rs modify them.
    pub media: Vec<MediaOrApp>,
    /// Extension mappings are _per BUNDLE_, but we can only have one a=group BUNDLE
    /// in WebRTC (one ice connection), so they are effetively per session.
    pub exts: Extensions,
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
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum MediaOrApp {
    Media(Media),
    App(App),
}

impl MediaOrApp {
    pub fn as_media(&self) -> Option<&Media> {
        match self {
            MediaOrApp::Media(m) => Some(m),
            MediaOrApp::App(_) => None,
        }
    }

    pub fn as_media_mut(&mut self) -> Option<&mut Media> {
        match self {
            MediaOrApp::Media(m) => Some(m),
            MediaOrApp::App(_) => None,
        }
    }
}

pub enum MediaEvent {
    Data(MediaData),
    Error(RtcError),
    Open(Mid, MediaKind, Direction),
    KeyframeRequest(KeyframeRequest),
}

impl Session {
    pub fn new(codec_config: CodecConfig) -> Self {
        let mut id = SessionId::new();
        // Max 2^62 - 1: https://bugzilla.mozilla.org/show_bug.cgi?id=861895
        const MAX_ID: u64 = 2_u64.pow(62) - 1;
        while *id > MAX_ID {
            id = (*id >> 1).into();
        }
        Session {
            id,
            media: vec![],
            exts: Extensions::default_mappings(),
            codec_config: codec_config.init(),
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
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn media(&mut self) -> impl Iterator<Item = &mut Media> {
        self.media.iter_mut().filter_map(|m| match m {
            MediaOrApp::Media(m) => Some(m),
            MediaOrApp::App(_) => None,
        })
    }

    pub fn app(&mut self) -> Option<&mut App> {
        self.media.iter_mut().find_map(|m| match m {
            MediaOrApp::Media(_) => None,
            MediaOrApp::App(a) => Some(a),
        })
    }

    pub fn get_media(&mut self, mid: Mid) -> Option<&mut Media> {
        self.media().find(|m| m.mid() == mid)
    }

    pub fn exts(&self) -> &Extensions {
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

    pub fn handle_timeout(&mut self, now: Instant) {
        for m in &mut self.media() {
            m.handle_timeout(now);
        }

        let sender_ssrc = self.first_ssrc_local();

        if let Some(twcc_at) = self.twcc_at() {
            if now >= twcc_at {
                self.create_twcc_feedback(sender_ssrc, now);
            }
        }

        for m in only_media_mut(&mut self.media) {
            m.maybe_create_keyframe_request(sender_ssrc, &mut self.feedback);
        }

        if now >= self.regular_feedback_at() {
            for m in only_media_mut(&mut self.media) {
                m.maybe_create_regular_feedback(now, sender_ssrc, &mut self.feedback);
            }
        }

        if let Some(nack_at) = self.nack_at() {
            if now >= nack_at {
                self.last_nack = now;
                for m in only_media_mut(&mut self.media) {
                    m.create_nack(sender_ssrc, &mut self.feedback);
                }
            }
        }
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
        use net::DatagramRecv::*;
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
        let maybe_mid = only_media(&self.media)
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
            let m_exists = only_media(&self.media).any(|m| m.mid() == mid);

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
        trace!("Handle RTP: {:?}", header);
        if let Some(transport_cc) = header.ext_vals.transport_cc {
            let prev = self.twcc_rx_register.max_seq();
            let extended = extend_seq(Some(*prev), transport_cc);
            self.twcc_rx_register.update_seq(extended.into(), now);
        }

        // Look up mid/ssrc for this header.
        let Some((mid, ssrc)) = self.mid_and_ssrc_for_header(&header) else {
            trace!("Unable to map RTP header to media: {:?}", header);
            return;
        };

        // mid_and_ssrc_for_header guarantees media for this mid exists.
        let media = only_media_mut(&mut self.media)
            .find(|m| m.mid() == mid)
            .expect("media for mid");

        let srtp = match self.srtp_rx.as_mut() {
            Some(v) => v,
            None => {
                trace!("Rejecting SRTP while missing SrtpContext");
                return;
            }
        };
        let clock_rate = match media.get_params(&header) {
            Some(v) => v.clock_rate(),
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

        let rid = source.rid();
        let seq_no = source.update(now, &header, clock_rate);

        let is_rtx = source.is_rtx();

        // The first few packets, the source is in "probabtion". However for rtx,
        // we let them straight through, since it would be weird to require probabtion
        // time for resends (they are not contiguous) in the receiver register.
        if !is_rtx && !source.is_valid() {
            trace!("Source is not (yet) valid, probably probation");
            return;
        }

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

            let repaired_ssrc = match source.repairs() {
                Some(v) => v,
                None => {
                    trace!("Can't find repaired SSRC for: {}", header.ssrc);
                    return;
                }
            };
            trace!("Repaired {:?} -> {:?}", header.ssrc, repaired_ssrc);
            header.ssrc = repaired_ssrc;

            let source = media.get_or_create_source_rx(ssrc);
            let orig_seq_no = source.update(now, &header, clock_rate);

            if !source.is_valid() {
                trace!("Repaired source is not (yet) valid, probably probation");
                return;
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
        let params = media.get_params(&header).unwrap();

        // This is the "main" PT and it will differ to header.payload_type if this is a resend.
        let pt = params.pt();
        let codec = params.codec();

        let time = MediaTime::new(header.timestamp as i64, clock_rate as i64);

        if !media.direction().is_receiving() {
            // Not adding unless we are supposed to be receiving.
            return;
        }

        // Buffers are unique per m-line (since PT is unique per m-line).
        let buf = media.get_buffer_rx(pt, rid, codec);

        let meta = RtpMeta::new(now, time, seq_no, header);
        trace!("Add to buffer {:?}", meta);
        buf.push(meta, data);
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let unprotected = srtp.unprotect_rtcp(buf)?;

        let feedback = Rtcp::read_packet(&unprotected);

        for fb in RtcpFb::from_rtcp(feedback) {
            if let RtcpFb::Twcc(twcc) = fb {
                self.twcc_tx_register.apply_report(twcc, now);
                return Some(());
            }

            let media = self.media().find(|m| {
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
        let required_ssrcs: usize = only_media(&self.media)
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

        for m in only_media_mut(&mut self.media) {
            if !m.equalize_sources() {
                continue;
            }

            m.do_equalize_sources(&mut new_ssrcs);
        }
    }

    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        for media in self.media() {
            if media.need_open_event {
                media.need_open_event = false;
                return Some(MediaEvent::Open(
                    media.mid(),
                    media.kind(),
                    media.direction(),
                ));
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

    pub fn poll_datagram(&mut self, now: Instant) -> Option<net::DatagramSend> {
        // Time must have progressed forward from start value.
        if now == already_happened() {
            return None;
        }

        let feedback = self.poll_feedback();
        if feedback.is_some() {
            return feedback;
        }

        let packet = self.poll_packet(now);
        if packet.is_some() {
            return packet;
        }

        None
    }

    fn poll_feedback(&mut self) -> Option<net::DatagramSend> {
        if self.feedback.is_empty() {
            return None;
        }

        const ENCRYPTABLE_MTU: usize = DATAGRAM_MTU - SRTCP_OVERHEAD;
        assert!(ENCRYPTABLE_MTU % 4 == 0);

        let mut data = vec![0_u8; ENCRYPTABLE_MTU];

        let len = Rtcp::write_packet(&mut self.feedback, &mut data);
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

        for m in only_media_mut(&mut self.media) {
            let twcc_seq = self.twcc;
            if let Some((header, buf, seq_no)) = m.poll_packet(now, &self.exts, &mut self.twcc) {
                self.twcc_tx_register.register_seq(twcc_seq.into(), now);
                let protected = srtp_tx.protect_rtp(&buf, &header, *seq_no);
                return Some(protected.into());
            }
        }

        None
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let media_at = self.media().filter_map(|m| m.poll_timeout()).min();
        let regular_at = Some(self.regular_feedback_at());
        let nack_at = self.nack_at();
        let twcc_at = self.twcc_at();

        let timeout = (media_at, "media")
            .soonest((regular_at, "regular"))
            .soonest((nack_at, "nack"))
            .soonest((twcc_at, "twcc"));

        // trace!("poll_timeout soonest is: {}", timeout.1);

        timeout.0
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.media.iter().any(|m| m.mid() == mid)
    }

    /// Test if the ssrc is known in the session at all, as sender or receiver.
    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        only_media(&self.media).any(|m| m.has_ssrc_rx(ssrc) || m.has_ssrc_tx(ssrc))
    }

    fn regular_feedback_at(&self) -> Instant {
        only_media(&self.media)
            .map(|m| m.regular_feedback_at())
            .min()
            .unwrap_or_else(not_happening)
    }

    fn nack_at(&mut self) -> Option<Instant> {
        let need_nack = self.media().any(|s| s.has_nack());

        if need_nack {
            Some(self.last_nack + NACK_MIN_INTERVAL)
        } else {
            None
        }
    }

    fn twcc_at(&self) -> Option<Instant> {
        if self.twcc_rx_register.has_unreported() {
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
}

// Helper while waiting for polonius.
pub(crate) fn only_media(media: &[MediaOrApp]) -> impl Iterator<Item = &Media> {
    media.iter().filter_map(|m| m.as_media())
}

// Helper while waiting for polonius.
pub(crate) fn only_media_mut(media: &mut [MediaOrApp]) -> impl Iterator<Item = &mut Media> {
    media.iter_mut().filter_map(|m| m.as_media_mut())
}
