use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use net_::{DatagramSend, Id};
use packet::{DepacketizingBuffer, PacketError, PacketizingBuffer};
use rtp::{MLineIdx, MediaTime, Rtcp, RtcpFb, RtpHeader, Ssrc};

pub use rtp::{Direction, Mid, Pt};
pub use sdp::{Codec, FormatParams};
use sdp::{MediaLine, MediaType, Msid, SsrcInfo};

mod codec;
pub use codec::{CodecConfig, CodecParams};

mod channel;
pub use channel::Channel;

mod receiver;
use receiver::ReceiverSource;

mod sender;
use sender::SenderSource;

use crate::change::AddMedia;
use crate::util::already_happened;
use crate::RtcError;

// How often we remove unused senders/receivers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

/// Audio or video media.
///
/// An m-line in SDP.
pub struct Media {
    /// Three letter identifier of this m-line.
    mid: Mid,

    /// Unique CNAME for use in Sdes RTCP packets.
    ///
    /// This is for _outgoing_ SDP. Incoming CNAME ca be
    /// found in the `ssrc_info_rx`.
    cname: String,

    /// "Stream and track" identifiers.
    ///
    /// This is for _outgoing_ SDP. Incoming Msid details
    /// can be found in the `ssrc_info_rx`.
    msid: Msid,

    /// Audio eller video.
    kind: MediaKind,

    /// Index of m-line in SDP.
    m_line_idx: MLineIdx,

    /// Current media direction.
    ///
    /// Can be altered via negotiation.
    dir: Direction,

    /// Negotiated codec parameters.
    ///
    /// The PT information from SDP.
    params: Vec<CodecParams>,

    /// Receiving sources (SSRC).
    ///
    /// These are created first time we observe the SSRC in an incoming RTP packet.
    /// Each source keeps track of packet loss, nack, reports etc. Receiving sources are
    /// cleaned up when we haven't received any data for the SSRC for a while.
    sources_rx: Vec<ReceiverSource>,

    /// Sender sources (SSRC).
    ///
    /// Created when we configure new m-lines via Changes API.
    sources_tx: Vec<SenderSource>,

    /// Last time we ran cleanup.
    last_cleanup: Instant,

    /// SSRC information discovered in the SDP.
    ///
    /// This tells us which SSRC is resend (RTX) for which SSRC as well as the identifiers for
    /// WebRTC javascript API for MediaStream and Track (MediaStream and Track are not concepts
    /// we use in this crate).
    ssrc_info_rx: Vec<SsrcInfo>,

    /// Buffers for incoming data.
    ///
    /// Video samples are often fragmented over several RTP packets. These buffers reassembles
    /// the incoming RTP to full samples.
    buffers_rx: HashMap<Pt, DepacketizingBuffer>,

    /// Buffers for outgoing data.
    ///
    /// When writing a sample we create a number of RTP packets to send. These buffers have the
    /// individual RTP data payload ready to send.
    buffers_tx: HashMap<Pt, PacketizingBuffer>,
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

    pub(crate) fn cname(&self) -> &str {
        &self.cname
    }

    pub(crate) fn msid(&self) -> &Msid {
        &self.msid
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

    pub fn get_writer(&mut self, pt: Pt) -> MediaWriter<'_> {
        let codec = {
            self.codec_by_pt(pt)
                .map(|p| p.codec())
                .unwrap_or(Codec::Unknown)
        };

        MediaWriter {
            media: self,
            pt,
            codec,
        }
    }

    pub(crate) fn poll_datagram(&mut self) -> Option<DatagramSend> {
        for (pt, buf) in &mut self.buffers_tx {
            if let Some(pkt) = buf.poll_next() {
                // let header = RtpHeader::new(*pt, pkt.seq_no, pkt.ts, ssrc);
                //
            }
        }
        None
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
            for info in &self.ssrc_info_rx {
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

    pub(crate) fn source_tx_ssrcs(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.sources_tx.iter().map(|s| s.ssrc())
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

    pub(crate) fn apply_changes(&mut self, m: &MediaLine, config: &CodecConfig) {
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
            let params: Vec<CodecParams> = m
                .rtp_params()
                .into_iter()
                .map(|m| m.into())
                .filter(|m| config.matches(m))
                .collect();
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

            self.ssrc_info_rx = infos;
        }
    }

    /// Test if we know of this SSRC either via SDP or received packets.
    pub(crate) fn has_ssrc_rx(&self, ssrc: Ssrc) -> bool {
        let via_sdp = self
            .ssrc_info_rx
            .iter()
            .any(|i| i.ssrc == ssrc || i.repair == Some(ssrc));

        if via_sdp {
            return true;
        }

        // via received packets
        self.sources_rx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub(crate) fn has_ssrc_tx(&self, ssrc: Ssrc) -> bool {
        self.sources_tx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub(crate) fn get_buffer_rx(&mut self, pt: Pt, codec: Codec) -> &mut DepacketizingBuffer {
        self.buffers_rx
            .entry(pt)
            .or_insert_with(|| DepacketizingBuffer::new(codec.into()))
    }

    pub(crate) fn poll_sample(&mut self) -> Option<(Mid, Pt, Result<Vec<u8>, PacketError>)> {
        for (pt, buf) in &mut self.buffers_rx {
            match buf.emit_sample() {
                Ok(Some(v)) => return Some((self.mid, *pt, Ok(v))),
                Err(e) => return Some((self.mid, *pt, Err(e))),
                Ok(None) => continue,
            }
        }
        None
    }
}

impl<'a> From<(&'a MediaLine, MLineIdx)> for Media {
    fn from((l, m_line_idx): (&'a MediaLine, MLineIdx)) -> Self {
        Media {
            mid: l.mid(),
            cname: Id::<20>::random().to_string(),
            msid: Msid {
                stream_id: Id::<30>::random().to_string(),
                track_id: Id::<30>::random().to_string(),
            },
            kind: l.typ.clone().into(),
            m_line_idx,
            dir: l.direction(),
            params: l.rtp_params().into_iter().map(|p| p.into()).collect(),
            sources_rx: vec![],
            sources_tx: vec![],
            last_cleanup: already_happened(),
            ssrc_info_rx: vec![],
            buffers_rx: HashMap::new(),
            buffers_tx: HashMap::new(),
        }
    }
}

impl From<AddMedia> for Media {
    fn from(a: AddMedia) -> Self {
        let mut m = Media {
            mid: a.mid,
            cname: Id::<20>::random().to_string(),
            msid: a.msid,
            kind: a.kind,
            m_line_idx: 0.into(),
            dir: a.dir,
            params: a.params,
            sources_rx: vec![],
            sources_tx: vec![],
            last_cleanup: already_happened(),
            ssrc_info_rx: vec![],
            buffers_rx: HashMap::new(),
            buffers_tx: HashMap::new(),
        };

        for ssrc in a.ssrcs {
            m.sources_tx.push(SenderSource::new(ssrc));
        }

        m
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

pub struct MediaWriter<'a> {
    media: &'a mut Media,
    pt: Pt,
    codec: Codec,
}

impl MediaWriter<'_> {
    pub fn write(&mut self, ts: MediaTime, data: &[u8]) -> Result<(), RtcError> {
        let buf = self.media.buffers_tx.entry(self.pt).or_insert_with(|| {
            let max_retain = if self.codec.is_video() { 10 } else { 50 };
            PacketizingBuffer::new(self.codec.into(), max_retain)
        });

        // buf.push_sample(ts, data, xDATAGRAM_MTU)?;

        Ok(())
    }
}
