use std::collections::VecDeque;
use std::convert::TryInto;
use std::time::{Duration, Instant};

use dtls::KeyingMaterial;
use net_::{DatagramSend, DATAGRAM_MTU};
use rtp::{extend_seq, RtcpHeader, RtpHeader, SessionId, TwccRegister};
use rtp::{Extensions, MediaTime, Mid, ReceiverReport, ReportList, Rtcp, RtcpFb};
use rtp::{RtcpType, SrtpContext, SrtpKey, Ssrc};
use rtp::{SRTCP_BLOCK_SIZE, SRTCP_OVERHEAD};
use sdp::{Answer, MediaLine, Offer, Sdp};

use crate::change::{Change, Changes};
use crate::media::CodecConfig;
use crate::session_sdp::AsMediaLine;
use crate::util::{already_happened, Soonest};
use crate::RtcError;
use crate::{net, MediaData};

use super::{Channel, Media};

// Time between regular receiver reports.
// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
const RR_INTERVAL: Duration = Duration::from_millis(4000);

// Minimum time we delay between sending nacks. This should be
// set high enough to not cause additional problems in very bad
// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct Session {
    id: SessionId,
    media: Vec<MediaOrChannel>,
    exts: Extensions,
    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    last_regular: Instant,
    last_nack: Instant,
    feedback: VecDeque<Rtcp>,
    codec_config: CodecConfig,
    twcc: u64,
    twcc_register: TwccRegister,
}

pub enum MediaOrChannel {
    Media(Media),
    Channel(Channel),
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
            srtp_rx: None,
            srtp_tx: None,
            last_regular: already_happened(),
            last_nack: already_happened(),
            feedback: VecDeque::new(),
            codec_config: CodecConfig::default(),
            twcc: 0,
            twcc_register: TwccRegister::new(100),
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

        if now >= self.regular_feedback_at() {
            info!("Create regular feedback");
            self.last_regular = now;
            for m in only_media_mut(&mut self.media) {
                m.create_regular_feedback(now, &mut self.feedback);
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
                let r: Result<RtcpHeader, &'static str> = buf.try_into();
                match r {
                    Ok(v) => {
                        // According to spec, the outer enclosing SRTCP packet should always be a SR or RR,
                        // even if it's irrelevant and empty.
                        use RtcpType::*;
                        let is_sr_rr = matches!(v.rtcp_type(), SenderReport | ReceiverReport);

                        if is_sr_rr {
                            // The header in SRTP is not interesting. It's just there to fulfil
                            // the RTCP protocol. If we fail to verify it, there packet was not
                            // welformed.
                            self.handle_rtcp(now, buf)?;
                        } else {
                            trace!("SRTCP is not SR or RR: {:?}", v.rtcp_type());
                        }
                    }
                    Err(e) => {
                        trace!("Failed to parse RTCP header: {}", e);
                    }
                }
            }
            _ => {}
        }

        Some(())
    }

    fn handle_rtp(&mut self, now: Instant, header: RtpHeader, buf: &[u8]) {
        trace!("Handle RTP: {:?}", header);
        if let Some(transport_cc) = header.ext_vals.transport_cc {
            let prev = self.twcc_register.max_seq();
            let extended = extend_seq(Some(*prev), transport_cc);
            self.twcc_register.update_seq(extended.into(), now);
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

        // Buffers are unique per m-line (since PT is unique per m-line).
        let buf = media.get_buffer_rx(pt, codec);

        trace!("Add to buffer {}", seq_no);
        buf.push(data, time, seq_no, header.marker);
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let unprotected = srtp.unprotect_rtcp(&buf)?;

        let feedback = Rtcp::read_packet(&unprotected);

        for fb in RtcpFb::from_rtcp(feedback) {
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

        Rtcp::write_packet(&mut self.feedback, &mut data, SRTCP_BLOCK_SIZE);

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
            if let Some((header, buf, seq_no)) = m.poll_packet(now, &self.exts, &mut self.twcc) {
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

        media_at.soonest(regular_at).soonest(nack_at)
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
        self.last_regular + RR_INTERVAL
    }

    fn nack_at(&mut self) -> Option<Instant> {
        let need_nack = self.media().any(|s| s.has_nack());

        if need_nack {
            Some(self.last_nack + NACK_MIN_INTERVAL)
        } else {
            None
        }
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
        let first_ssrc = self
            .media()
            .next()
            .and_then(|m| m.first_source_tx())
            .map(|s| s.ssrc())?;

        self.feedback
            .push_front(Rtcp::ReceiverReport(ReceiverReport {
                sender_ssrc: first_ssrc,
                reports: ReportList::new(),
            }));

        Some(())
    }

    pub fn apply_offer(&mut self, offer: Offer) -> Result<(), RtcError> {
        offer.assert_consistency()?;

        self.update_session_extmaps(&offer)?;

        let new_lines = self.sync_m_lines(&offer).map_err(RtcError::RemoteSdp)?;

        self.add_new_lines(&new_lines)
            .map_err(RtcError::RemoteSdp)?;

        // For new lines appearing in an offer, we just add the corresponding amount of SSRC
        // that we find in the incoming line. This is probably always correct. If there is simulcast
        // configured, we (probably) have simulcast in both directions. If we have RTX, we have it
        // in both directions.
        for l in &new_lines {
            let ssrcs: Vec<_> = l
                .ssrc_info()
                .iter()
                .map(|i| (self.new_ssrc(), i.repair.is_some()))
                .collect();

            let media = self
                .get_media(l.mid())
                .expect("Media to be added for new m-line");

            for (ssrc, is_rtx) in ssrcs {
                media.add_source_tx(ssrc, is_rtx);
            }
        }

        Ok(())
    }

    pub fn apply_answer(&mut self, pending: Changes, answer: Answer) -> Result<(), RtcError> {
        answer.assert_consistency()?;

        self.update_session_extmaps(&answer)?;

        let new_lines = self.sync_m_lines(&answer).map_err(RtcError::RemoteSdp)?;

        // The new_lines from the answer must correspond to what we sent in the offer.
        if let Some(err) = pending.ensure_correct_answer(&new_lines) {
            return Err(RtcError::RemoteSdp(err));
        }

        self.add_new_lines(&new_lines)
            .map_err(RtcError::RemoteSdp)?;

        // For pending AddMedia, we have outgoing SSRC communicated that needs to be added.
        for change in pending.0 {
            let add_media = match change {
                Change::AddMedia(v) => v,
                _ => continue,
            };

            let media = self
                .get_media(add_media.mid)
                .expect("Media to be added for pending mid");

            for (ssrc, is_rtx) in add_media.ssrcs {
                media.add_source_tx(ssrc, is_rtx);
            }
        }

        Ok(())
    }

    /// Compares m-lines in Sdp with that already in the session.
    ///
    /// * Existing m-lines can apply changes (such as direction change).
    /// * New m-lines are returned to the caller.
    fn sync_m_lines<'a>(&mut self, sdp: &'a Sdp) -> Result<Vec<&'a MediaLine>, String> {
        let mut new_lines = Vec::new();

        // SAFETY: CodecConfig is read only and not interfering with self.get_media.
        let config = unsafe {
            let ptr = &self.codec_config as *const CodecConfig;
            &*ptr
        };

        for (idx, m) in sdp.media_lines.iter().enumerate() {
            if let Some(media) = self.get_media(m.mid()) {
                if idx != media.index() {
                    return index_err(m.mid());
                }

                media.apply_changes(m, config);
            } else if let Some(chan) = self.get_channel(m.mid()) {
                if idx != chan.index() {
                    return index_err(m.mid());
                }

                chan.apply_changes(m);
            } else {
                new_lines.push(m);
            }
        }

        fn index_err<T>(mid: Mid) -> Result<T, String> {
            Err(format!("Changed order for m-line with mid: {}", mid))
        }

        Ok(new_lines)
    }

    /// Adds new m-lines as found in an offer or answer.
    fn add_new_lines(&mut self, new_lines: &[&MediaLine]) -> Result<(), String> {
        for m in new_lines {
            let idx = self.media.len();

            if m.typ.is_media() {
                let media = (*m, idx).into();
                self.media.push(MediaOrChannel::Media(media));

                let media = only_media_mut(&mut self.media).last().unwrap();
                media.apply_changes(m, &self.codec_config);
            } else if m.typ.is_channel() {
                let channel = (m.mid(), idx).into();
                self.media.push(MediaOrChannel::Channel(channel));

                let chan = self.channels().last().unwrap();
                chan.apply_changes(m);
            } else {
                return Err(format!(
                    "New m-line is neither media nor channel: {}",
                    m.mid()
                ));
            }
        }

        Ok(())
    }

    /// Update session level Extensions.
    fn update_session_extmaps(&mut self, sdp: &Sdp) -> Result<(), RtcError> {
        let extmaps = sdp
            .media_lines
            .iter()
            .map(|m| m.extmaps())
            .flatten()
            // Only keep supported extensions
            .filter(|x| x.ext.is_supported());

        for x in extmaps {
            self.exts.apply_mapping(&x);
        }

        Ok(())
    }

    /// Returns all media/channels as `AsMediaLine` trait.
    pub fn as_media_lines(&self) -> impl Iterator<Item = &dyn AsMediaLine> {
        self.media.iter().map(|m| m as &dyn AsMediaLine)
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
fn only_media(media: &[MediaOrChannel]) -> impl Iterator<Item = &Media> {
    media.iter().filter_map(|m| match m {
        MediaOrChannel::Media(m) => Some(m),
        MediaOrChannel::Channel(_) => None,
    })
}

// Helper while waiting for polonius.
fn only_media_mut(media: &mut [MediaOrChannel]) -> impl Iterator<Item = &mut Media> {
    media.iter_mut().filter_map(|m| match m {
        MediaOrChannel::Media(m) => Some(m),
        MediaOrChannel::Channel(_) => None,
    })
}

// * receiver register - handle_rtp
// * nack reporter     - handle_rtp  (poll_rtcp)
// * receiver reporter - handle_rtp  (poll_rtcp)
// * twcc reporter     - handle_rtp handle_rtcp (poll_rtcp)
// * depacketizer      - handle_rtp

// * packetizer        - write
// * send buffer       - write_rtp
// * nack responder    - handle_rtcp (poll_rtcp poll_rtp)
// * sender reporter   -             (poll_rtcp)
// * twcc generator    - handle_rtcp (poll_rtcp)
