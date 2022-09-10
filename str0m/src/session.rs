use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::time::{Duration, Instant};

use dtls::KeyingMaterial;
use net_::DATAGRAM_MTU;
use rtp::{Extensions, MLineIdx, Mid, ReceiverReport, ReportList, Rtcp, RtcpFb};
use rtp::{RtcpHeader, RtpHeader, SessionId};
use rtp::{RtcpType, SrtpContext, SrtpKey, Ssrc};
use rtp::{SRTCP_BLOCK_SIZE, SRTCP_OVERHEAD_SUFFIX};
use sdp::{Answer, MediaLine, Offer, Sdp};

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
        let unprotected = srtp.unprotect_rtcp(&buf)?;

        let feedback = Rtcp::read_packet(&unprotected);

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

        // The first RTCP packet must be SR or RR, since the sender SSRC is used for the
        // SRTCP encryption. If feedback is lacking such, we add a dummy RR.
        // If the self.feedback already contains an SR/RR it will be sorted to appear
        // at the front of the queue by Rtcp::write_packet below.
        self.maybe_insert_dummy_rr()?;

        // The encryptable "body" must be an even number of 16.
        const ENCRYPTABLE_MTU: usize = DATAGRAM_MTU
            - SRTCP_OVERHEAD_SUFFIX
            - (DATAGRAM_MTU - SRTCP_OVERHEAD_SUFFIX) % SRTCP_BLOCK_SIZE;

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

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let media_at = self.media.iter_mut().filter_map(|m| m.poll_timeout()).min();
        let regular_at = Some(self.regular_feedback_at());
        let nack_at = self.nack_at();

        media_at.soonest(regular_at).soonest(nack_at)
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.media.iter().any(|m| m.mid() == mid)
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

    /// Helper that ensures feedback has at least one SR/RR.
    #[must_use]
    pub(crate) fn maybe_insert_dummy_rr(&mut self) -> Option<()> {
        let has_sr_rr = self
            .feedback
            .iter()
            .any(|r| matches!(r, Rtcp::SenderReport(_) | Rtcp::ReceiverReport(_)));

        if has_sr_rr {
            return Some(());
        }

        // If we don't have any sender SSRC, we simply can't send feedback at this point.
        let first_ssrc = self
            .media
            .first()
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

        todo!()
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

        todo!()
    }

    fn sync_m_lines<'a>(&mut self, sdp: &'a Sdp) -> Result<Vec<&'a MediaLine>, String> {
        let mut new_lines = Vec::new();

        for (idx, m) in sdp.media_lines.iter().enumerate() {
            if let Some(media) = self.get_media(m.mid()) {
                if idx != *media.m_line_idx() {
                    return index_err(m.mid());
                }

                media.apply_changes(m);
            } else if let Some(chan) = self.get_channel(m.mid()) {
                if idx != *chan.m_line_idx() {
                    return index_err(m.mid());
                }

                chan.apply_changes(m);
            } else {
                // We've checked all the index for all mids we've encountered so far.
                // Once we start finding mids that we haven't seen before, the index must also be new.
                let all_less = self.as_media_lines().all(|m| *m.index() < idx);

                if !all_less {
                    return Err(format!("New mid ({}) for m-line index: {}", m.mid(), idx));
                }

                new_lines.push(m);
            }
        }

        fn index_err<T>(mid: Mid) -> Result<T, String> {
            Err(format!("Changed order for m-line with mid: {}", mid))
        }

        Ok(new_lines)
    }

    fn add_new_lines(&mut self, new_lines: &[&MediaLine]) -> Result<(), String> {
        let index_start = self.as_media_lines().map(|m| *m.index()).max().unwrap_or(0);

        for (i, m) in new_lines.iter().enumerate() {
            let idx: MLineIdx = (index_start + i).into();

            if m.typ.is_media() {
                self.media.push((*m, idx).into());
                let media = self.media.last_mut().unwrap();

                media.apply_changes(m);
            } else if m.typ.is_channel() {
                self.channels.push((*m, idx).into());
                let chan = self.channels.last_mut().unwrap();

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
        let extmaps = sdp.media_lines.iter().map(|m| m.extmaps()).flatten();

        for x in extmaps {
            self.exts.apply_mapping(&x)?;
        }

        Ok(())
    }
}

/// Fallback strategy to match up packet with m-line.
fn fallback_match_media<'a>(
    header: &RtpHeader,
    media: &'a mut [Media],
    ssrc_map: &mut HashMap<Ssrc, usize>,
) -> Option<&'a mut Media> {
    // Match either by mid or ssrc, if present.
    let mid = header.ext_vals.rtp_mid;
    let ssrc = header.ssrc;

    let (idx, media) = media
        .iter_mut()
        .enumerate()
        .find(|(_, m)| m.contains_ssrc(ssrc) || Some(m.mid()) == mid)?;

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
