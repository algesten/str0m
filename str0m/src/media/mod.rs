use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use net_::{Id, DATAGRAM_MTU};
use packet::{DepacketizingBuffer, PacketError, Packetized, PacketizingBuffer};
use rtp::{Extensions, MediaTime, NackEntry, Rtcp, RtcpFb, RtpHeader, SeqNo, Ssrc, SRTP_OVERHEAD};

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

mod register;

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

    /// The index of this media line in the Session::media Vec.
    index: usize,

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

    /// Queued resends.
    ///
    /// These have been scheduled via nacks.
    resends: VecDeque<Resend>,
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

    pub fn index(&self) -> usize {
        self.index
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
        let codec = { self.codec_by_pt(pt).map(|p| p.codec()) };

        MediaWriter {
            media: self,
            pt,
            codec,
            sim_lvl: 0,
        }
    }

    pub(crate) fn poll_packet(
        &mut self,
        now: Instant,
        exts: &Extensions,
        twcc: &mut u64,
    ) -> Option<(RtpHeader, Vec<u8>, SeqNo)> {
        let (pt, pkt, ssrc, seq_no) = loop {
            if let Some(resend) = self.resends.pop_front() {
                // If there is no buffer for this resend, we loop to next. This is
                // a weird situation though, since it means the other side sent a nack for
                // an SSRC that matched this Media, but didnt match a buffer_tx.
                let buffer = match self.buffers_tx.values().find(|p| p.has_ssrc(resend.ssrc)) {
                    Some(v) => v,
                    None => continue,
                };

                // The seq_no could simply be too old to exist in the buffer, in which
                // case we will not do a resend.
                let pkt = match buffer.get(resend.seq_no) {
                    Some(v) => v,
                    None => continue,
                };

                let is_audio = self.kind == MediaKind::Audio;

                // The resend ssrc. This would correspond to the RTX PT for video.
                // Audio should not be resent, so this also gates whether we are doing resends at all.
                let ssrc_rtx =
                    match get_source_tx(&mut self.sources_tx, is_audio, pkt.sim_lvl, true)
                        .map(|tx| tx.ssrc())
                    {
                        Some(v) => v,
                        None => continue,
                    };

                break (resend.pt, pkt, ssrc_rtx, resend.seq_no);
            } else {
                // exit via ? here is ok since that means there is nothing to send.
                let (pt, pkt) = next_send_buffer(&mut self.buffers_tx)?;

                let tx = self
                    .sources_tx
                    .iter_mut()
                    .find(|s| s.ssrc() == pkt.ssrc)
                    .expect("SenderSource for packetized write");

                let seq_no = tx.next_seq_no(now);
                pkt.seq_no = Some(seq_no);

                break (pt, pkt, pkt.ssrc, seq_no);
            }
        };

        let mut header = RtpHeader::new(pt, seq_no, pkt.ts, ssrc);
        header.marker = pkt.last;

        header.ext_vals.abs_send_time = Some(now.into());
        header.ext_vals.rtp_mid = Some(self.mid);
        header.ext_vals.transport_cc = Some(*twcc as u16);
        *twcc += 1;

        let mut buf = Vec::with_capacity(DATAGRAM_MTU);
        let header_len = header.write_to(&mut buf, exts);
        assert!(header_len % 4 == 0, "RTP header must be multiple of 4");

        let data_out = &mut buf[header_len..];
        data_out[..pkt.data.len()].copy_from_slice(&pkt.data);

        Some((header, buf, seq_no))
    }

    pub(crate) fn get_source_rx(
        &mut self,
        header: &RtpHeader,
        is_rtx: bool,
        now: Instant,
    ) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc() == header.ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            info!(
                "New ReceiverSource for {:?} {:?}",
                header.ssrc, header.payload_type
            );

            let mut new_source = ReceiverSource::new(header, is_rtx, now);

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
        self.sources_rx
            .iter_mut()
            .filter(|s| !s.is_rtx())
            .any(|s| s.has_nack())
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        // TODO(martin): more cleanup
        self.last_cleanup = now;
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

            debug!("Created feedback SR: {:?}", sr);
            feedback.push_back(Rtcp::SenderReport(sr));
        }

        for s in &mut self.sources_rx {
            let mut rr = s.create_receiver_report(now);
            rr.sender_ssrc = first_ssrc;

            debug!("Created feedback RR: {:?}", rr);
            feedback.push_back(Rtcp::ReceiverReport(rr));
        }

        Some(())
    }

    /// Creates nack reports for receivers, if needed.
    pub(crate) fn create_nack(&mut self, feedback: &mut VecDeque<Rtcp>) {
        for s in &mut self.sources_rx {
            if s.is_rtx() {
                continue;
            }
            if let Some(nack) = s.create_nack() {
                debug!("Created feedback NACK {:?}", nack);
                feedback.push_back(nack);
            }
        }
    }

    /// Appply incoming RTCP feedback.
    pub(crate) fn handle_rtcp_fb(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        let ssrc = fb.ssrc();

        use RtcpFb::*;
        match fb {
            SenderInfo(v) => {
                let source_rx = self.sources_rx.iter_mut().find(|s| s.ssrc() == ssrc)?;
                source_rx.set_sender_info(now, v);
            }
            ReceptionReport(_) => todo!(),
            SourceDescription(v) => {
                error!("SourceDescription: {:?}", v);
            }
            Goodbye(v) => {
                error!("Goodbye: {:?}", v);
            }
            Nack(ssrc, list) => {
                let entries = list.into_iter();
                self.handle_nack(ssrc, entries)?;
            }
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

    pub(crate) fn add_source_tx(&mut self, ssrc: Ssrc, is_rtx: bool) {
        self.sources_tx.push(SenderSource::new(ssrc, is_rtx));
    }

    pub(crate) fn handle_nack(
        &mut self,
        ssrc: Ssrc,
        entries: impl Iterator<Item = NackEntry>,
    ) -> Option<()> {
        // Figure out which packetizing buffer has been used to send the entries that been nack'ed.
        let (pt, buffer) = self.buffers_tx.iter_mut().find(|(_, p)| p.has_ssrc(ssrc))?;

        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = buffer.first_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Schedule all resends. They will be handled on next poll_packet
        self.resends.extend(iter.map(|seq_no| Resend {
            ssrc,
            pt: *pt,
            seq_no,
        }));

        Some(())
    }

    pub(crate) fn is_rtx(&self, ssrc: Ssrc) -> bool {
        let is_rtx_rx = self.ssrc_info_rx.iter().any(|r| r.repair == Some(ssrc));
        if is_rtx_rx {
            return true;
        }

        let is_rtx_tx = self
            .sources_tx
            .iter()
            .find(|s| s.ssrc() == ssrc)
            .map(|s| s.is_rtx())
            .unwrap_or(false);

        is_rtx_tx
    }

    pub(crate) fn get_repaired_rx_ssrc(&self, ssrc: Ssrc) -> Option<Ssrc> {
        self.ssrc_info_rx
            .iter()
            .find(|r| r.repair == Some(ssrc))
            .map(|r| r.ssrc)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    pub ssrc: Ssrc,
    pub pt: Pt,
    pub seq_no: SeqNo,
}

fn next_send_buffer(
    buffers_tx: &mut HashMap<Pt, PacketizingBuffer>,
) -> Option<(Pt, &mut Packetized)> {
    for (pt, buf) in buffers_tx {
        if let Some(pkt) = buf.poll_next() {
            assert!(pkt.seq_no.is_none());
            return Some((*pt, pkt));
        }
    }
    None
}

impl Default for Media {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
            cname: Id::<20>::random().to_string(),
            msid: Msid {
                stream_id: Id::<30>::random().to_string(),
                track_id: Id::<30>::random().to_string(),
            },
            kind: MediaKind::Video,
            dir: Direction::SendRecv,
            params: vec![],
            sources_rx: vec![],
            sources_tx: vec![],
            last_cleanup: already_happened(),
            ssrc_info_rx: vec![],
            buffers_rx: HashMap::new(),
            buffers_tx: HashMap::new(),
            resends: VecDeque::new(),
        }
    }
}

// Going from an incoming m-line in an SDP, this is used to create new Media.
impl<'a> From<(&'a MediaLine, usize)> for Media {
    fn from((l, index): (&'a MediaLine, usize)) -> Self {
        Media {
            mid: l.mid(),
            index,
            kind: l.typ.clone().into(),
            dir: l.direction(),
            ssrc_info_rx: l.ssrc_info(),
            params: l.rtp_params().into_iter().map(|p| p.into()).collect(),
            ..Default::default()
        }
    }
}

// Going from AddMedia to Media is for m-lines that are pending in a Change and are sent
// in the offer to the other side.
impl From<AddMedia> for Media {
    fn from(a: AddMedia) -> Self {
        let sources_tx = a
            .ssrcs
            .into_iter()
            .map(|(s, r)| SenderSource::new(s, r))
            .collect();
        Media {
            mid: a.mid,
            index: a.index,
            msid: a.msid,
            kind: a.kind,
            dir: a.dir,
            params: a.params,
            sources_tx,
            ..Default::default()
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

pub struct MediaWriter<'a> {
    media: &'a mut Media,
    pt: Pt,
    codec: Option<Codec>,
    sim_lvl: usize,
}

impl MediaWriter<'_> {
    pub fn write(&mut self, ts: MediaTime, data: &[u8]) -> Result<(), RtcError> {
        let codec = match self.codec {
            Some(v) => v,
            None => return Err(RtcError::UnknownPt(self.pt)),
        };

        let is_audio = self.media.kind == MediaKind::Audio;

        // The SSRC is figured out given the simulcast level.
        let tx = get_source_tx(&mut self.media.sources_tx, is_audio, self.sim_lvl, false)
            .ok_or(RtcError::NoSenderSource(self.sim_lvl))?;

        let ssrc = tx.ssrc();

        let buf = self.media.buffers_tx.entry(self.pt).or_insert_with(|| {
            let max_retain = if codec.is_audio() { 50 } else { 10 };
            PacketizingBuffer::new(codec.into(), max_retain)
        });

        buf.push_sample(ts, data, ssrc, self.sim_lvl, DATAGRAM_MTU - SRTP_OVERHEAD)?;

        Ok(())
    }
}

/// Get the SenderSource by providing simulcast level and maybe reset.
///
/// Separte in wait for polonius.
fn get_source_tx(
    sources_tx: &mut Vec<SenderSource>,
    is_audio: bool,
    level: usize,
    resend: bool,
) -> Option<&mut SenderSource> {
    let (per_level, resend_offset) = if is_audio { (1, 0) } else { (2, 1) };

    let idx = level * per_level + if resend { resend_offset } else { 0 };

    sources_tx.get_mut(idx)
}
