use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use crate::error::RtpError;
use crate::media::KeyframeRequestKind;
use crate::rtp::ExtensionMap;
use crate::rtp::Pt;
use crate::rtp::RtpHeader;
use crate::rtp::SeqNo;
use crate::rtp::Ssrc;
use crate::session::PacketReceipt;
use crate::util::already_happened;
use crate::RtcError;

use self::receive::{StreamRx, StreamRxStats};
use self::send::{StreamTx, StreamTxStats};

mod receive;
mod register;
mod rtx_cache;
mod send;

// Time between regular receiver reports.
// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
// Should technically be 4 seconds according to spec, but libWebRTC
// expects video to be every second, and audio every 5 seconds.
const RR_INTERVAL_VIDEO: Duration = Duration::from_millis(1000);
const RR_INTERVAL_AUDIO: Duration = Duration::from_millis(5000);

fn rr_interval(audio: bool) -> Duration {
    if audio {
        RR_INTERVAL_AUDIO
    } else {
        RR_INTERVAL_VIDEO
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StreamPacket {
    /// Extended sequence number to avoid having to deal with ROC.
    pub seq_no: SeqNo,

    /// Parsed rtp header.
    pub header: RtpHeader,

    /// RTP packet data, including header and padding.
    ///
    /// To get only the payload data, see [`payload()`].
    pub data: Vec<u8>,

    /// Whether this packet can be nacked. This is always false for audio,
    /// but might also be false for discardable frames when using temporal encoding
    /// as in a VP8 simulcast situation.
    pub nackable: bool,

    /// This timestamp has nothing to do with RTP itself. For outgoing packets, this is when
    /// the packet was first handed over to str0m and enqueued in the outgoing send buffers.
    /// For incoming packets it's the time we received the network packet.
    pub timestamp: Instant,

    /// If we are to resend this packet, which pt to use.
    pub rtx_pt: Option<Pt>,
}

impl StreamPacket {
    /// Only the RTP payload, without header and padding.
    pub fn payload(&self) -> &[u8] {
        self.header.payload_of(&self.data)
    }
}

/// Holder of incoming/outgoing encoded streams.
///
/// Each encoded stream is uniquely identified by an SSRC. The concept of mid/rid sits on the Media
/// level together with the ability to translate a mid/rid to an encoded stream.
#[derive(Debug, Default)]
pub struct Streams {
    /// All incoming encoded streams.
    streams_rx: HashMap<Ssrc, StreamRx>,

    /// All outgoing encoded streams.
    streams_tx: HashMap<Ssrc, StreamTx>,
}

impl Streams {
    /// Allow incoming traffic from remote peer for the given SSRC.
    ///
    /// The first time we ever discover a new SSRC, we emit the [`Event::RtpData`] with the bool flag
    /// `initial: true`. No more packets will be handled unless we call `allow_stream_rx` for the incoming
    /// SSRC.
    ///
    /// Can be called multiple times if the `rtx` is discovered later via RTP header extensions.
    pub fn expect_stream_rx(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>) {
        let stream = self
            .streams_rx
            .entry(ssrc)
            .or_insert_with(|| StreamRx::new(ssrc));

        if let Some(rtx) = rtx {
            stream.set_rtx_ssrc(rtx);
        }
    }

    pub(crate) fn stats_rx(&self, ssrc: Ssrc) -> Option<&StreamRxStats> {
        self.streams_rx.get(&ssrc).map(|s| s.stats())
    }

    pub(crate) fn stats_tx(&self, ssrc: Ssrc) -> Option<&StreamTxStats> {
        self.streams_tx.get(&ssrc).map(|s| s.stats())
    }

    /// Request a keyframe for an incoming encoded stream.
    ///
    /// * SSRC the identifier of the remote encoded stream to request a keyframe for.
    /// * kind PLI or FIR.
    pub fn request_keyframe(
        &mut self,
        ssrc: Ssrc,
        kind: KeyframeRequestKind,
    ) -> Result<(), RtcError> {
        let stream = self
            .streams_rx
            .get_mut(&ssrc)
            .ok_or_else(|| RtcError::NoReceiverSource(None))?;

        stream.request_keyframe(kind);

        Ok(())
    }

    /// Declare the intention to send data using the given SSRC.
    ///
    /// * The resend RTX is optional but necessary to do resends. str0m does not do
    ///   resends without RTX.
    ///
    /// Can be called multiple times without changing any internal state. However
    /// the RTX value is only picked up the first ever time we see a new SSRC.
    pub fn declare_stream_tx(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>) {
        let stream = self
            .streams_tx
            .entry(ssrc)
            .or_insert_with(|| StreamTx::new(ssrc, rtx));

        assert_eq!(stream.rtx(), rtx);
    }

    /// Write RTP packet to a send stream.
    ///
    /// The `packet` argument is expected to be a complete RTP packet from _some other source_ that isn't
    /// this instance of Rtc. Thus the RTP packet's SSRC, PT, sequence number, TWCC, etc are expected to be
    /// wrong and will be rewritten to be correct for communicating with the remote peer this Rtc instance
    /// is connected to.
    ///
    /// * `packet` RTP packet, including header and padding that will be rewritten.
    /// * `seq_no` Sequence number to use for this packet. Overwrites the header.
    /// * `exts` Extension map necessary to understand the extensions in the packet. Some values
    ///          such as audio activity, color space, rotation etc are not rewritten but copied
    ///          over to the outgoing.
    /// * `ssrc` The outgoing SSRC. This will be rewritten in the packet.
    /// * `pt` The outgoing payload type (PT). This will be rewritten in the packet.
    /// * `rtx_pt` The PT to use if we are using RTX. This requires the stream_tx to be declared with RTX.
    /// * `wallclock` Real world time that corresponds to the media time in the RTP packet. For an SFU,
    ///               this can be hard to know, since RTP packets typically only contain the media
    ///               time (RTP time). In the simplest SFU setup, the wallclock could simply be the
    ///               arrival time of the incoming RTP data. For better synchronization the SFU
    ///               probably needs to weigh in clock drifts and data provided via the statistics, receiver
    ///               reports etc.
    /// * `nackable` Whether we should respond this packet for incoming NACK from the remote peer. For
    ///              audio this is always false. For temporal encoded video, some packets are discardable
    ///              and this flag should be set accordingly.
    pub fn write_rtp(
        &mut self,
        // Params about the incoming data.
        packet: &[u8],
        seq_no: SeqNo,
        exts: &ExtensionMap,
        // Params about the outgoing data.
        ssrc: Ssrc,
        pt: Pt,
        rtx_pt: Option<Pt>,
        wallclock: Instant,
        nackable: bool,
    ) -> Result<(), RtcError> {
        let mut header =
            RtpHeader::parse(packet, exts).ok_or_else(|| RtcError::Rtp(RtpError::ParseHeader))?;

        // Set as much as possible. The rest will be done on poll_packet().
        header.ssrc = ssrc;
        header.payload_type = pt;
        header.sequence_number = *seq_no as u16;

        let packet = StreamPacket {
            seq_no,
            header,
            data: packet.to_vec(),
            nackable,
            timestamp: already_happened(), // Updated on first ever poll_output.
            rtx_pt,
        };

        let stream = self
            .streams_tx
            .get_mut(&ssrc)
            .ok_or_else(|| RtcError::NoSenderSource)?;

        if stream.rtx().is_some() && rtx_pt.is_none() {
            return Err(RtcError::ResendRequiresRtxPt);
        }

        stream.enqueue(packet);

        Ok(())
    }

    pub(crate) fn poll_packet(
        &mut self,
        now: Instant,
        exts: &ExtensionMap,
        twcc: &mut u64,
        buf: &mut Vec<u8>,
    ) -> Option<PacketReceipt> {
        for stream in self.streams_tx.values_mut() {
            let Some(packet) = stream.poll_packet(now, exts, twcc, buf) else {
                continue;

            };
            return Some(packet);
        }
        None
    }

    pub(crate) fn regular_feedback_at(&self) -> Option<Instant> {
        let r = self.streams_rx.values().map(|s| s.receiver_report_at());
        let s = self.streams_tx.values().map(|s| s.sender_report_at());
        r.chain(s).min()
    }

    pub(crate) fn need_nack(&self) -> bool {
        self.streams_tx.values().any(|s| s.need_nack())
    }

    pub(crate) fn is_receiving(&self) -> bool {
        !self.streams_rx.is_empty()
    }
}
