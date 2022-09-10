use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use rtp::{MLineIdx, Rtcp, RtcpFb, RtpHeader, Ssrc};

pub use rtp::{Direction, Mid, Pt};
pub use sdp::{Codec, FormatParams};
use sdp::{MediaLine, MediaType, SsrcInfo};

mod codec;
pub use codec::CodecParams;

mod channel;
pub use channel::Channel;

mod receiver;
use receiver::ReceiverSource;

mod sender;
use sender::SenderSource;

use crate::util::already_happened;

// How often we remove unused senders/receivers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

pub struct Media {
    mid: Mid,
    kind: MediaKind,
    m_line_idx: MLineIdx,
    dir: Direction,
    params: Vec<CodecParams>,
    sources_rx: Vec<ReceiverSource>,
    sources_tx: Vec<SenderSource>,
    last_cleanup: Instant,
    ssrc_info: Vec<SsrcInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Types of media.
pub enum MediaKind {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
}

impl Media {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub(crate) fn kind(&self) -> MediaKind {
        self.kind
    }

    pub(crate) fn m_line_idx(&self) -> MLineIdx {
        self.m_line_idx
    }

    pub fn direction(&self) -> Direction {
        self.dir
    }

    fn codec_by_pt(&self, pt: Pt) -> Option<&CodecParams> {
        self.params.iter().find(|c| c.pt() == pt)
    }

    pub fn codecs(&self) -> &[CodecParams] {
        &self.params
    }

    pub fn write(&mut self, pt: Pt, data: &[u8]) {
        //
    }

    pub(crate) fn get_source_rx(
        &mut self,
        header: &RtpHeader,
        now: Instant,
    ) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc() == header.ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            let mut new_source = ReceiverSource::new(header, now);

            // We might have info for this source already.
            for info in &self.ssrc_info {
                if new_source.matches_ssrc_info(info) {
                    new_source.set_ssrc_info(info);
                    break;
                }
            }

            self.sources_rx.push(new_source);
            self.sources_rx.last_mut().unwrap()
        }
    }

    pub(crate) fn get_params(&self, header: &RtpHeader) -> Option<&CodecParams> {
        let pt = header.payload_type;
        self.params
            .iter()
            .find(|p| p.inner().codec.pt == pt || p.inner().resend == Some(pt))
    }

    pub(crate) fn has_nack(&mut self) -> bool {
        self.sources_rx.iter_mut().any(|s| s.has_nack())
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if now >= self.cleanup_at() {
            self.last_cleanup = now;
            self.sources_rx.retain(|s| s.is_alive(now));
        }
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
        Some(self.cleanup_at())
    }

    fn cleanup_at(&self) -> Instant {
        self.last_cleanup + CLEANUP_INTERVAL
    }

    pub(crate) fn first_source_tx(&self) -> Option<&SenderSource> {
        self.sources_tx.first()
    }

    /// Creates sender info and receiver reports for all senders/receivers
    pub(crate) fn create_regular_feedback(
        &mut self,
        now: Instant,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        // If we don't have any sender sources, we can't create an SRTCP wrapper around the
        // feedback. This is because the SSRC is used to calculate the specific encryption key.
        // No sender SSRC, no encryption, no feedback possible.
        let first_ssrc = self.first_source_tx().map(|s| s.ssrc())?;

        for s in &mut self.sources_tx {
            let sr = s.create_sender_report(now);

            feedback.push_back(Rtcp::SenderReport(sr));
        }

        for s in &mut self.sources_rx {
            let mut rr = s.create_receiver_report(now);
            rr.sender_ssrc = first_ssrc;

            feedback.push_back(Rtcp::ReceiverReport(rr));
        }

        Some(())
    }

    /// Creates nack reports for receivers, if needed.
    pub(crate) fn create_nack(&mut self, feedback: &mut VecDeque<Rtcp>) {
        for s in &mut self.sources_rx {
            if let Some(nack) = s.create_nack() {
                feedback.push_back(nack);
            }
        }
    }

    /// Appply incoming RTCP feedback.
    pub(crate) fn handle_rtcp_fb(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        let source_rx = self.sources_rx.iter_mut().find(|s| s.ssrc() == fb.ssrc())?;

        use RtcpFb::*;
        match fb {
            SenderInfo(v) => source_rx.set_sender_info(now, v),
            ReceptionReport(_) => todo!(),
            SourceDescription(_) => todo!(),
            Goodbye(_) => todo!(),
            Nack(_, _) => todo!(),
            Pli(_) => todo!(),
            Fir(_) => todo!(),
        }

        Some(())
    }

    pub(crate) fn apply_changes(&mut self, m: &MediaLine) {
        // Directional changes
        {
            let new_dir = m.direction();
            if self.dir != new_dir {
                debug!(
                    "Mid ({}) change direction: {} -> {}",
                    self.mid, self.dir, new_dir
                );
                self.dir = new_dir;
            }
        }

        // Changes in PT
        {
            let params: Vec<CodecParams> = m.rtp_params().into_iter().map(|m| m.into()).collect();
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

        // SSRC changes
        {
            let infos = m.ssrc_info();

            // Might want to update the info field in any already initialized ReceiverSource.
            for info in &infos {
                for s in &mut self.sources_rx {
                    if s.matches_ssrc_info(info) {
                        s.set_ssrc_info(info);
                    }
                }
            }

            self.ssrc_info = infos;
        }
    }

    /// Check if SSRC been communicated in SDP either as main or repair SSRC.
    pub fn contains_ssrc(&self, ssrc: Ssrc) -> bool {
        self.ssrc_info
            .iter()
            .any(|i| i.ssrc == ssrc || i.repair == Some(ssrc))
    }
}

impl<'a> From<(&'a MediaLine, MLineIdx)> for Media {
    fn from((l, m_line_idx): (&'a MediaLine, MLineIdx)) -> Self {
        Media {
            mid: l.mid(),
            kind: l.typ.clone().into(),
            m_line_idx,
            dir: l.direction(),
            params: l.rtp_params().into_iter().map(|p| p.into()).collect(),
            sources_rx: vec![],
            sources_tx: vec![],
            last_cleanup: already_happened(),
            ssrc_info: vec![],
        }
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
