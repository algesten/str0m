use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::time::{Duration, Instant};

use dtls::KeyingMaterial;
use net_::DATAGRAM_MTU;
use rtp::{Extensions, Mid, Rtcp, RtcpFb, RtcpHeader, RtpHeader, SessionId, SRTCP_BLOCK_SIZE};
use rtp::{RtcpType, SrtpContext, SrtpKey, Ssrc};
use rtp::{SRTCP_OVERHEAD_PREFIX, SRTCP_OVERHEAD_SUFFIX};
use sdp::Answer;

use crate::change::Changes;
use crate::net;
use crate::util::{already_happened, Soonest};
use crate::RtcError;

use super::{Channel, Media};

// Time between regular receiver reports.
// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
const RR_INTERVAL: Duration = Duration::from_millis(4000);

// Minimum time we delay between sending nacks. This should be
// set high enough to not cause additional problems in very bad
// network conditions.
const NACK_MIN_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct Session {
    pub id: SessionId,
    pub media: Vec<Media>,
    pub channels: Vec<Channel>,
    pub exts: Extensions,
    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    ssrc_map: HashMap<Ssrc, usize>,
    last_regular: Instant,
    last_nack: Instant,
    feedback: VecDeque<Rtcp>,
}

pub enum MediaEvent {
    //
}

impl Session {
    pub fn new() -> Self {
        Session {
            id: SessionId::new(),
            media: vec![],
            channels: vec![],
            exts: Extensions::new(),
            srtp_rx: None,
            srtp_tx: None,
            ssrc_map: HashMap::new(),
            last_regular: already_happened(),
            last_nack: already_happened(),
            feedback: VecDeque::new(),
        }
    }

    pub fn get_media(&mut self, mid: Mid) -> Option<&mut Media> {
        self.media.iter_mut().find(|m| m.mid() == mid)
    }

    pub fn get_channel(&mut self, mid: Mid) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|m| m.mid() == mid)
    }

    pub fn set_keying_material(&mut self, mat: KeyingMaterial) {
        let key_rx = SrtpKey::new(&mat, true);
        let ctx_rx = SrtpContext::new(key_rx);
        self.srtp_rx = Some(ctx_rx);

        let key_tx = SrtpKey::new(&mat, false);
        let ctx_tx = SrtpContext::new(key_tx);
        self.srtp_tx = Some(ctx_tx);
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        for m in &mut self.media {
            m.handle_timeout(now);
        }

        if now >= self.regular_feedback_at() {
            self.last_regular = now;
            for m in &mut self.media {
                m.create_regular_feedback(now, &mut self.feedback);
            }
        }

        if let Some(nack_at) = self.nack_at() {
            if now >= nack_at {
                self.last_nack = now;
                for m in &mut self.media {
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
                    self.handle_rtp(now, header, buf)?;
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

    fn handle_rtp(&mut self, now: Instant, header: RtpHeader, buf: &[u8]) -> Option<()> {
        let media = if let Some(idx) = self.ssrc_map.get(&header.ssrc) {
            // We know which Media this packet belongs to.
            &mut self.media[*idx]
        } else {
            fallback_match_media(&header, &mut self.media, &mut self.ssrc_map)?
        };

        let srtp = self.srtp_rx.as_mut()?;
        let clock_rate = media.get_params(&header)?.clock_rate();
        let source = media.get_source_rx(&header, now);
        let seq_no = source.update(now, &header, clock_rate);

        if source.is_valid() {
            let data = srtp.unprotect_rtp(buf, &header, *seq_no)?;
            let params = media.get_params(&header)?;
        }

        Some(())
    }

    fn handle_rtcp(&mut self, now: Instant, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let decrypted = srtp.unprotect_rtcp(&buf)?;

        let feedback = Rtcp::read_packet(&decrypted);

        for fb in RtcpFb::from_rtcp(feedback) {
            if let Some(idx) = self.ssrc_map.get(&fb.ssrc()) {
                let media = &mut self.media[*idx];
                media.handle_rtcp_fb(now, fb);
            }
        }

        Some(())
    }

    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        todo!()
    }

    pub fn poll_datagram(&mut self) -> Option<net::DatagramSend> {
        let feedback = self.poll_feedback();
        if feedback.is_some() {
            return feedback;
        }

        None
    }

    fn poll_feedback(&mut self) -> Option<net::DatagramSend> {
        if self.feedback.is_empty() {
            return None;
        }

        // The encryptable "body" must be an even number of 16.
        // For an mtu 1500, this works out as: 1500 - (1500 - 8 - 16) % 16 => 1496
        const ENCRYPTABLE_MTU: usize = DATAGRAM_MTU
            - (DATAGRAM_MTU - SRTCP_OVERHEAD_PREFIX - SRTCP_OVERHEAD_SUFFIX) % SRTCP_BLOCK_SIZE;

        let mut data = vec![0_u8; ENCRYPTABLE_MTU];
        let buf = &mut data[SRTCP_OVERHEAD_PREFIX..];

        // the bytes available while still fitting the srtp
        let len = buf.len() - SRTCP_OVERHEAD_SUFFIX;

        let mut buf = &mut buf[..len];
        assert!(
            buf.len() % SRTCP_BLOCK_SIZE == 0,
            "Multiple of SRTCP_BLOCK_SIZE"
        );

        Rtcp::write_packet(&mut self.feedback, &mut buf, SRTCP_BLOCK_SIZE);

        Some(net::DatagramSend::new(data))
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let media_at = self.media.iter_mut().filter_map(|m| m.poll_timeout()).min();
        let regular_at = Some(self.regular_feedback_at());
        let nack_at = self.nack_at();

        media_at.soonest(regular_at).soonest(nack_at)
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.media.iter().any(|m| m.mid() == mid)
    }

    pub fn apply_offer(&self, offer: sdp::Offer) -> Result<(), RtcError> {
        todo!()
    }

    pub fn apply_answer(&self, pending: Changes, answer: Answer) -> Result<(), RtcError> {
        todo!()
    }

    // pub fn handle_sctp(&mut self, sctp) {
    // }
    // pub fn poll_sctp(&mut self) -> Option<Sctp> {
    // }

    fn regular_feedback_at(&self) -> Instant {
        self.last_regular + RR_INTERVAL
    }

    fn nack_at(&mut self) -> Option<Instant> {
        let need_nack = self.media.iter_mut().any(|s| s.has_nack());

        if need_nack {
            Some(self.last_nack + NACK_MIN_INTERVAL)
        } else {
            None
        }
    }
}

/// Fallback strategy to match up packet with m-line.
fn fallback_match_media<'a>(
    header: &RtpHeader,
    media: &'a mut [Media],
    ssrc_map: &mut HashMap<Ssrc, usize>,
) -> Option<&'a mut Media> {
    // Attempt to match Mid in RTP header with our m-lines from SDP.
    let mid = header.ext_vals.rtp_mid?;
    let (idx, media) = media.iter_mut().enumerate().find(|(_, m)| m.mid() == mid)?;

    // Retain this association.
    ssrc_map.insert(header.ssrc, idx);

    Some(media)
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
