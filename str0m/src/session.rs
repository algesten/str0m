use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dtls::KeyingMaterial;
use net_::{DatagramSend, DATAGRAM_MTU};
use packet::RtpMeta;
use rtp::{extend_seq, RtpHeader, SessionId, TwccRecvRegister, TwccSendRegister};
use rtp::{Extensions, MediaTime, Mid, ReceiverReport, ReportList, Rtcp, RtcpFb};
use rtp::{SrtpContext, SrtpKey, Ssrc};
use rtp::{SRTCP_BLOCK_SIZE, SRTCP_OVERHEAD};

use crate::media::CodecConfig;
use crate::session_sdp::AsMediaLine;
use crate::util::{already_happened, not_happening, Soonest};
use crate::RtcError;
use crate::{net, MediaData};

use super::{Channel, Media};

// Minimum time we delay between sending nacks. This should be
// set high enough to not cause additional problems in very bad
// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(250);

// Delay between reports of TWCC. This is deliberately very low.
const TWCC_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct Session {
    id: SessionId,

    // these fields are pub to allow session_sdp.rs modify them.
    pub media: Vec<MediaOrChannel>,
    pub exts: Extensions,
    pub codec_config: CodecConfig,

    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    last_nack: Instant,
    last_twcc: Instant,
    feedback: VecDeque<Rtcp>,
    twcc: u64,
    twcc_rx_register: TwccRecvRegister,
    twcc_tx_register: TwccSendRegister,
}

#[derive(Debug)]
pub enum MediaOrChannel {
    Media(Media),
    Channel(Channel),
}

impl MediaOrChannel {
    pub fn as_media(&self) -> Option<&Media> {
        match self {
            MediaOrChannel::Media(m) => Some(m),
            MediaOrChannel::Channel(_) => None,
        }
    }

    pub fn as_media_mut(&mut self) -> Option<&mut Media> {
        match self {
            MediaOrChannel::Media(m) => Some(m),
            MediaOrChannel::Channel(_) => None,
        }
    }
}

pub enum MediaEvent {
    MediaData(MediaData),
    MediaError(RtcError),
}

impl Session {
    pub fn new() -> Self {
        Session {
            id: SessionId::new(),
            media: vec![],
            exts: Extensions::default_mappings(),
            codec_config: CodecConfig::default(),
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
            MediaOrChannel::Media(m) => Some(m),
            MediaOrChannel::Channel(_) => None,
        })
    }

    pub fn channels(&mut self) -> impl Iterator<Item = &mut Channel> {
        self.media.iter_mut().filter_map(|m| match m {
            MediaOrChannel::Media(_) => None,
            MediaOrChannel::Channel(c) => Some(c),
        })
    }

    pub fn get_media(&mut self, mid: Mid) -> Option<&mut Media> {
        self.media().find(|m| m.mid() == mid)
    }

    pub fn get_channel(&mut self, mid: Mid) -> Option<&mut Channel> {
        self.channels().find(|m| m.mid() == mid)
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

        if now >= self.twcc_at() {
            self.create_twcc_feedback(now);
        }

        if now >= self.regular_feedback_at() {
            for m in only_media_mut(&mut self.media) {
                m.maybe_create_regular_feedback(now, &mut self.feedback);
            }
        }

        if let Some(nack_at) = self.nack_at() {
            if now >= nack_at {
                self.last_nack = now;
                for m in only_media_mut(&mut self.media) {
                    m.create_nack(&mut self.feedback);
                }
            }
        }
    }

    fn create_twcc_feedback(&mut self, now: Instant) -> Option<()> {
        self.last_twcc = now;
        let mut twcc = self.twcc_rx_register.build_report(DATAGRAM_MTU - 100)?;
        let first_ssrc = self.first_sender_ssrc()?;
        twcc.sender_ssrc = first_ssrc;
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

    fn handle_rtp(&mut self, now: Instant, header: RtpHeader, buf: &[u8]) {
        trace!("Handle RTP: {:?}", header);
        if let Some(transport_cc) = header.ext_vals.transport_cc {
            let prev = self.twcc_rx_register.max_seq();
            let extended = extend_seq(Some(*prev), transport_cc);
            self.twcc_rx_register.update_seq(extended.into(), now);
        }

        let mid_in = header.ext_vals.rtp_mid;
        let media = match only_media_mut(&mut self.media)
            .find(|m| m.has_ssrc_rx(header.ssrc) || Some(m.mid()) == mid_in)
        {
            Some(v) => v,
            None => {
                trace!("No Media for {:?} or {:?}", mid_in, header.ssrc);
                return;
            }
        };

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
        let is_rtx = media.is_rtx(header.ssrc);
        let source = media.get_source_rx(&header, is_rtx, now);
        let seq_no = source.update(now, &header, clock_rate);

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

            let repaired_ssrc = match media.get_repaired_rx_ssrc(header.ssrc) {
                Some(v) => v,
                None => {
                    trace!("Can't find repaired SSRC for: {}", header.ssrc);
                    return;
                }
            };
            trace!("Repaired {:?} -> {:?}", header.ssrc, repaired_ssrc);
            header.ssrc = repaired_ssrc;

            let source = media.get_source_rx(&header, false, now);
            let orig_seq_no = source.update(now, &header, clock_rate);

            if !source.is_valid() {
                trace!("Repaired source is not (yet) valid, probably probation");
                return;
            }

            orig_seq_no
        } else {
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
        let buf = media.get_buffer_rx(pt, codec);

        let meta = RtpMeta::new(now, time, seq_no, header);
        trace!("Add to buffer {:?}", meta);
        buf.push(meta, data);
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let unprotected = srtp.unprotect_rtcp(&buf)?;

        let feedback = Rtcp::read_packet(&unprotected);

        for fb in RtcpFb::from_rtcp(feedback) {
            if let RtcpFb::Twcc(twcc) = fb {
                self.twcc_tx_register.apply_report(twcc, now);
                return Some(());
            }

            let media = self.media().find(|m| m.has_ssrc_rx(fb.ssrc()));
            if let Some(media) = media {
                media.handle_rtcp_fb(now, fb);
            }
        }

        Some(())
    }

    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        for media in self.media() {
            if let Some(r) = media.poll_sample() {
                match r {
                    Ok(v) => return Some(MediaEvent::MediaData(v)),
                    Err(e) => return Some(MediaEvent::MediaError(e)),
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

        // The first RTCP packet must be SR or RR, since the sender SSRC is used for the
        // SRTCP encryption. If feedback is lacking such, we add a dummy RR.
        // If the self.feedback already contains an SR/RR it will be sorted to appear
        // at the front of the queue by Rtcp::write_packet below.
        self.maybe_insert_dummy_rr()?;

        // The encryptable "body" must be an even number of 16.
        const ENCRYPTABLE_MTU: usize =
            DATAGRAM_MTU - SRTCP_OVERHEAD - (DATAGRAM_MTU - SRTCP_OVERHEAD) % SRTCP_BLOCK_SIZE;

        let mut data = vec![0_u8; ENCRYPTABLE_MTU];

        assert!(
            data.len() % SRTCP_BLOCK_SIZE == 0,
            "RTCP buffer multiple of SRTCP block size",
        );

        let len = Rtcp::write_packet(&mut self.feedback, &mut data, SRTCP_BLOCK_SIZE);
        data.truncate(len);

        let srtp = self.srtp_tx.as_mut()?;
        let protected = srtp.protect_rtcp(&data);

        assert!(
            protected.len() < DATAGRAM_MTU,
            "Encrypted SRTCP should be less than MTU"
        );

        Some(net::DatagramSend::new(protected))
    }

    fn poll_packet(&mut self, now: Instant) -> Option<DatagramSend> {
        let srtp_tx = self.srtp_tx.as_mut()?;

        for m in only_media_mut(&mut self.media) {
            let twcc_seq = self.twcc;
            if let Some((header, buf, seq_no)) = m.poll_packet(now, &self.exts, &mut self.twcc) {
                self.twcc_tx_register.register_seq(twcc_seq.into(), now);
                let encrypted = srtp_tx.protect_rtp(&buf, &header, *seq_no);
                return Some(DatagramSend::new(encrypted));
            }
        }

        None
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let media_at = self.media().filter_map(|m| m.poll_timeout()).min();
        let regular_at = Some(self.regular_feedback_at());
        let nack_at = self.nack_at();
        let twcc_at = Some(self.twcc_at());

        media_at
            .soonest(regular_at)
            .soonest(nack_at)
            .soonest(twcc_at)
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.media.iter().any(|m| m.mid() == mid)
    }

    /// Test if the ssrc is known in the session at all, as sender or receiver.
    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        only_media(&self.media).any(|m| m.has_ssrc_rx(ssrc) || m.has_ssrc_tx(ssrc))
    }

    // pub fn handle_sctp(&mut self, sctp) {
    // }
    // pub fn poll_sctp(&mut self) -> Option<Sctp> {
    // }

    fn regular_feedback_at(&self) -> Instant {
        only_media(&self.media)
            .map(|m| m.regular_feedback_at())
            .min()
            .unwrap_or(not_happening())
    }

    fn nack_at(&mut self) -> Option<Instant> {
        let need_nack = self.media().any(|s| s.has_nack());

        if need_nack {
            Some(self.last_nack + NACK_MIN_INTERVAL)
        } else {
            None
        }
    }

    fn twcc_at(&self) -> Instant {
        self.last_twcc + TWCC_INTERVAL
    }

    /// Helper that ensures feedback has at least one SR/RR.
    #[must_use]
    pub fn maybe_insert_dummy_rr(&mut self) -> Option<()> {
        let has_sr_rr = self
            .feedback
            .iter()
            .any(|r| matches!(r, Rtcp::SenderReport(_) | Rtcp::ReceiverReport(_)));

        if has_sr_rr {
            return Some(());
        }

        // If we don't have any sender SSRC, we simply can't send feedback at this point.
        let first_ssrc = self.first_sender_ssrc()?;

        self.feedback
            .push_front(Rtcp::ReceiverReport(ReceiverReport {
                sender_ssrc: first_ssrc,
                reports: ReportList::new(),
            }));

        Some(())
    }

    fn first_sender_ssrc(&self) -> Option<Ssrc> {
        only_media(&self.media)
            .next()
            .and_then(|m| m.first_source_tx())
            .map(|s| s.ssrc())
    }

    pub fn new_ssrc(&self) -> Ssrc {
        loop {
            let ssrc: Ssrc = (rand::random::<u32>()).into();
            if !self.has_ssrc(ssrc) {
                break ssrc;
            }
        }
    }
}

// Helper while waiting for polonius.
pub(crate) fn only_media(media: &[MediaOrChannel]) -> impl Iterator<Item = &Media> {
    media.iter().filter_map(|m| m.as_media())
}

// Helper while waiting for polonius.
pub(crate) fn only_media_mut(media: &mut [MediaOrChannel]) -> impl Iterator<Item = &mut Media> {
    media.iter_mut().filter_map(|m| m.as_media_mut())
}
