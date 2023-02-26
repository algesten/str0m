use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use dtls::KeyingMaterial;
use net_::{DatagramSend, DATAGRAM_MTU, DATAGRAM_MTU_WARN};
use packet::{NullPacer, Pacer, PacerImpl, PollOutcome, RtpMeta};
use rtp_::SRTCP_OVERHEAD;
use rtp_::{extend_seq, RtpHeader, SessionId, TwccRecvRegister, TwccSendRegister};
use rtp_::{Extensions, MediaTime, Mid, Rtcp, RtcpFb};
use rtp_::{SrtpContext, SrtpKey, Ssrc};

use crate::media::{App, CodecConfig, MediaAdded, MediaChanged, Source};
use crate::session_sdp::AsMediaLine;
use crate::stats::StatsSnapshot;
use crate::util::{already_happened, not_happening, Soonest};
use crate::RtcError;
use crate::{net, KeyframeRequest, MediaData};

use super::MLine;

// Minimum time we delay between sending nacks. This should be
// set high enough to not cause additional problems in very bad
// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(100);

// Delay between reports of TWCC. This is deliberately very low.
const TWCC_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct Session {
    id: SessionId,

    // these fields are pub to allow session_sdp.rs modify them.
    pub m_lines: Vec<MLineOrApp>,
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

    enable_twcc_feedback: bool,

    /// A pacer for sending RTP at specific rate.
    pacer: PacerImpl,

    // temporary buffer when getting the next (unencrypted) RTP packet from Media line.
    poll_packet_buf: Vec<u8>,

    pub ice_lite: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum MLineOrApp {
    /// A regular m-line with media.
    MLine(MLine),
    /// An app m-line for SCTP association.
    App(App),
}

impl MLineOrApp {
    pub fn as_m_line(&self) -> Option<&MLine> {
        match self {
            MLineOrApp::MLine(m) => Some(m),
            MLineOrApp::App(_) => None,
        }
    }

    pub fn as_m_line_mut(&mut self) -> Option<&mut MLine> {
        match self {
            MLineOrApp::MLine(m) => Some(m),
            MLineOrApp::App(_) => None,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum MediaEvent {
    Data(MediaData),
    Changed(MediaChanged),
    Error(RtcError),
    Added(MediaAdded),
    KeyframeRequest(KeyframeRequest),
}

impl Session {
    pub fn new(codec_config: CodecConfig, ice_lite: bool) -> Self {
        let mut id = SessionId::new();
        // Max 2^62 - 1: https://bugzilla.mozilla.org/show_bug.cgi?id=861895
        const MAX_ID: u64 = 2_u64.pow(62) - 1;
        while *id > MAX_ID {
            id = (*id >> 1).into();
        }
        let pacer = PacerImpl::Null(NullPacer::default());

        Session {
            id,
            m_lines: vec![],
            exts: Extensions::default_mappings(),
            codec_config,
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
            // Enough to accurately measure received bandwidths up to 20Mbit/s, assuming an average
            // packet size of 1000 bytes.
            twcc_tx_register: TwccSendRegister::new(2500),
            enable_twcc_feedback: false,
            pacer,
            poll_packet_buf: vec![0; 2000],
            ice_lite,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn m_lines(&mut self) -> impl Iterator<Item = &mut MLine> {
        self.m_lines.iter_mut().filter_map(|m| match m {
            MLineOrApp::MLine(m) => Some(m),
            MLineOrApp::App(_) => None,
        })
    }

    pub fn app(&mut self) -> Option<&mut App> {
        self.m_lines.iter_mut().find_map(|m| match m {
            MLineOrApp::MLine(_) => None,
            MLineOrApp::App(a) => Some(a),
        })
    }

    pub fn m_line_by_mid_mut(&mut self, mid: Mid) -> Option<&mut MLine> {
        self.m_lines().find(|m| m.mid() == mid)
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
        for m in &mut self.m_lines() {
            m.handle_timeout(now);
        }

        let sender_ssrc = self.first_ssrc_local();

        if let Some(twcc_at) = self.twcc_at() {
            if now >= twcc_at {
                self.create_twcc_feedback(sender_ssrc, now);
            }
        }

        for m in only_m_line_mut(&mut self.m_lines) {
            m.maybe_create_keyframe_request(sender_ssrc, &mut self.feedback);
        }

        if now >= self.regular_feedback_at() {
            for m in only_m_line_mut(&mut self.m_lines) {
                m.maybe_create_regular_feedback(now, sender_ssrc, &mut self.feedback);
            }
        }

        if let Some(nack_at) = self.nack_at() {
            if now >= nack_at {
                self.last_nack = now;
                for m in only_m_line_mut(&mut self.m_lines) {
                    m.create_nack(sender_ssrc, &mut self.feedback);
                }
            }
        }

        update_queue_states(now, &mut self.m_lines, &mut self.pacer);
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
        let maybe_mid = only_m_line(&self.m_lines)
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
            let m_exists = only_m_line(&self.m_lines).any(|m| m.mid() == mid);

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
            let extended = extend_seq(Some(*prev), transport_cc);
            self.twcc_rx_register.update_seq(extended.into(), now);
        }

        // Look up mid/ssrc for this header.
        let Some((mid, ssrc)) = self.mid_and_ssrc_for_header(&header) else {
            trace!("Unable to map RTP header to media: {:?}", header);
            return;
        };

        // mid_and_ssrc_for_header guarantees media for this mid exists.
        let m_line = only_m_line_mut(&mut self.m_lines)
            .find(|m| m.mid() == mid)
            .expect("m-line for mid");

        let srtp = match self.srtp_rx.as_mut() {
            Some(v) => v,
            None => {
                trace!("Rejecting SRTP while missing SrtpContext");
                return;
            }
        };
        let clock_rate = match m_line.get_params(header.payload_type) {
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
            .and_then(|repairs| m_line.ssrc_rx_for_rid(repairs));

        let source = m_line.get_or_create_source_rx(ssrc);

        let mut m_line_need_check_source = false;
        if let Some(rid) = header.ext_vals.rid {
            if source.set_rid(rid) {
                m_line_need_check_source = true;
            }
        }
        if let Some(repairs) = ssrc_repairs {
            if source.set_repairs(repairs) {
                m_line_need_check_source = true;
            }
        }

        // Gymnastics to appease the borrow checker.
        let source = if m_line_need_check_source {
            m_line.set_equalize_sources();
            m_line.get_or_create_source_rx(ssrc)
        } else {
            source
        };

        let mut rid = source.rid();
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

            let repaired_source = m_line.get_or_create_source_rx(repaired_ssrc);
            if rid.is_none() && repaired_source.rid().is_some() {
                rid = repaired_source.rid();
            }
            let orig_seq_no = repaired_source.update(now, &header, clock_rate);
            let source = m_line.get_or_create_source_rx(ssrc);

            if !source.is_valid() {
                trace!("Repaired source is not (yet) valid, probably probation");
                return;
            }

            let params = m_line.get_params(header.payload_type).unwrap();
            if let Some(pt) = params.pt_rtx() {
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
        let params = m_line.get_params(header.payload_type).unwrap();

        // This is the "main" PT and it will differ to header.payload_type if this is a resend.
        let pt = params.pt();
        let codec = params.codec();

        let time = MediaTime::new(header.timestamp as i64, clock_rate as i64);

        if !m_line.direction().is_receiving() {
            // Not adding unless we are supposed to be receiving.
            return;
        }

        // Buffers are unique per m-line (since PT is unique per m-line).
        let buf = m_line.get_buffer_rx(pt, rid, codec);

        let meta = RtpMeta::new(now, time, seq_no, header);

        // here we have incoming and depacketized data before it may be dropped at buffer.push()
        let bytes_rx = data.len();

        buf.push(meta, data);

        // TODO: is there a nicer way to make borrow-checker happy ?
        // this should go away with the refactoring of the entire handle_rtp() function
        let source = m_line.get_or_create_source_rx(ssrc);
        source.update_packet_counts(bytes_rx as u64);
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let unprotected = srtp.unprotect_rtcp(buf)?;

        let feedback = Rtcp::read_packet(&unprotected);

        for fb in RtcpFb::from_rtcp(feedback) {
            if let RtcpFb::Twcc(twcc) = fb {
                debug!("Handle TWCC: {:?}", twcc);
                self.twcc_tx_register.apply_report(twcc, now);
                return Some(());
            }

            let m_line = self.m_lines().find(|m| {
                if fb.is_for_rx() {
                    m.has_ssrc_rx(fb.ssrc())
                } else {
                    m.has_ssrc_tx(fb.ssrc())
                }
            });
            if let Some(m_line) = m_line {
                m_line.handle_rtcp_fb(now, fb);
            } else {
                // This is not necessarily a fault when starting a new track.
                trace!("No m-line for feedback: {:?}", fb);
            }
        }

        Some(())
    }

    /// Whenever there are changes to ReceiverSource/SenderSource, we need to ensure the
    /// receivers are matched to senders. This ensure the setup is correct.
    pub fn equalize_sources(&mut self) {
        let required_ssrcs: usize = only_m_line(&self.m_lines)
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

        for m in only_m_line_mut(&mut self.m_lines) {
            if !m.equalize_sources() {
                continue;
            }

            m.do_equalize_sources(&mut new_ssrcs);
        }
    }

    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        for m_line in self.m_lines() {
            if m_line.need_open_event {
                m_line.need_open_event = false;

                return Some(MediaEvent::Added(MediaAdded {
                    mid: m_line.mid(),
                    kind: m_line.kind(),
                    direction: m_line.direction(),
                    simulcast: m_line.simulcast().map(|s| s.clone().into()),
                }));
            }

            if m_line.need_changed_event {
                m_line.need_changed_event = false;
                return Some(MediaEvent::Changed(MediaChanged {
                    mid: m_line.mid(),
                    direction: m_line.direction(),
                }));
            }

            if let Some((rid, kind)) = m_line.poll_keyframe_request() {
                return Some(MediaEvent::KeyframeRequest(KeyframeRequest {
                    mid: m_line.mid(),
                    rid,
                    kind,
                }));
            }

            if let Some(r) = m_line.poll_sample() {
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
        let queue_id = match self.pacer.poll_action() {
            PollOutcome::PollQueue(queue_id) => queue_id,
            PollOutcome::Nothing => {
                return None;
            }
        };

        // NB: Cannot use mline_index_mut here due to borrowing woes around self, need split
        // borrowing.
        let mline = self.m_lines[queue_id.as_usize()]
            .as_m_line_mut()
            .expect("index is MLine");
        let buf = &mut self.poll_packet_buf;

        let twcc_seq = self.twcc;
        if let Some((header, seq_no)) = mline.poll_packet(now, &self.exts, &mut self.twcc, buf) {
            trace!("Poll RTP: {:?}", header);

            self.pacer.register_send(now, buf.len().into(), queue_id);
            let protected = srtp_tx.protect_rtp(buf, &header, *seq_no);

            self.twcc_tx_register
                .register_seq(twcc_seq.into(), now, protected.len());

            return Some(protected.into());
        }

        None
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let m_line_at = self.m_lines().filter_map(|m| m.poll_timeout()).min();
        let regular_at = Some(self.regular_feedback_at());
        let nack_at = self.nack_at();
        let twcc_at = self.twcc_at();
        let pacing_at = self.pacer.poll_timeout();

        let timeout = (m_line_at, "m_line")
            .soonest((regular_at, "regular"))
            .soonest((nack_at, "nack"))
            .soonest((twcc_at, "twcc"))
            .soonest((pacing_at, "pacing"));

        // trace!("poll_timeout soonest is: {}", timeout.1);

        timeout.0
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.m_lines.iter().any(|m| m.mid() == mid)
    }

    /// Test if the ssrc is known in the session at all, as sender or receiver.
    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        only_m_line(&self.m_lines).any(|m| m.has_ssrc_rx(ssrc) || m.has_ssrc_tx(ssrc))
    }

    fn regular_feedback_at(&self) -> Instant {
        only_m_line(&self.m_lines)
            .map(|m| m.regular_feedback_at())
            .min()
            .unwrap_or_else(not_happening)
    }

    fn nack_at(&mut self) -> Option<Instant> {
        let need_nack = self.m_lines().any(|s| s.has_nack());

        if need_nack {
            Some(self.last_nack + NACK_MIN_INTERVAL)
        } else {
            None
        }
    }

    fn twcc_at(&self) -> Option<Instant> {
        let is_receiving = only_m_line(&self.m_lines).any(|m| m.direction().is_receiving());
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

    pub(crate) fn enable_twcc_feedback(&mut self) {
        if !self.enable_twcc_feedback {
            debug!("Enable TWCC feedback");
            self.enable_twcc_feedback = true;
        }
    }

    pub fn visit_stats(&mut self, now: Instant, snapshot: &mut StatsSnapshot) {
        for m_line in self.m_lines() {
            m_line.visit_stats(now, snapshot)
        }
        snapshot.tx = snapshot.egress.values().map(|s| s.bytes).sum();
        snapshot.rx = snapshot.ingress.values().map(|s| s.bytes).sum();
    }

    pub fn m_line_by_index(&self, index: usize) -> &MLine {
        self.m_lines[index].as_m_line().expect("index is MLine")
    }

    pub fn m_line_by_index_mut(&mut self, index: usize) -> &mut MLine {
        self.m_lines[index].as_m_line_mut().expect("index is MLine")
    }
}

fn update_queue_states(now: Instant, m_lines: &mut [MLineOrApp], pacer: &mut PacerImpl) {
    let iter = only_m_line_mut(m_lines).map(|m| m.buffers_tx_queue_state(now));
    pacer.handle_timeout(now, iter);
}

// Helper while waiting for polonius.
pub(crate) fn only_m_line(m_lines: &[MLineOrApp]) -> impl Iterator<Item = &MLine> {
    m_lines.iter().filter_map(|m| m.as_m_line())
}

// Helper while waiting for polonius.
pub(crate) fn only_m_line_mut(m_lines: &mut [MLineOrApp]) -> impl Iterator<Item = &mut MLine> {
    m_lines.iter_mut().filter_map(|m| m.as_m_line_mut())
}
