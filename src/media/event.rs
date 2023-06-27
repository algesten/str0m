use std::ops::RangeInclusive;
use std::time::Instant;

use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid, SeqNo, Ssrc};
use crate::sdp::Simulcast as SdpSimulcast;

use super::PayloadParams;
use crate::format::CodecExtra;

pub use crate::packet::MediaKind;

impl From<SdpSimulcast> for Simulcast {
    fn from(s: SdpSimulcast) -> Self {
        let send = s
            .send
            .iter()
            .flat_map(|s| s.iter().map(|s| s.as_stream_id().0.as_ref()))
            .map(Rid::from)
            .collect();

        let recv = s
            .recv
            .iter()
            .flat_map(|s| s.iter().map(|s| s.as_stream_id().0.as_ref()))
            .map(Rid::from)
            .collect();

        Simulcast { send, recv }
    }
}

/// A new media appeared in an Rtc session.
///
/// This event fires both for negotations triggered by a remote or local offer.
///
/// Does not fire for application media (data channel).
#[derive(Debug, PartialEq, Eq)]
pub struct MediaAdded {
    /// Identifier of the new media.
    pub mid: Mid,

    /// The kind of media carried.
    pub kind: MediaKind,

    /// Current direction.
    pub direction: Direction,

    /// If simulcast is configured, this holds the Rids.
    ///
    /// `a=simulcast:send h;l`
    pub simulcast: Option<Simulcast>,
}

/// A change happening during an SDP re-negotation.
///
/// This event fires both for re-negotations triggered by a remote or local offer.
///
/// Does not fire for application media (data channel).
#[derive(Debug, PartialEq, Eq)]
pub struct MediaChanged {
    /// Identifier of the new media.
    pub mid: Mid,

    /// Current direction.
    pub direction: Direction,
}

/// Simplified information about the simulcast config from SDP.
///
/// The [full spec][1] covers many cases that are not used by simple simulcast.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-sdp-simulcast-14
#[derive(Debug, PartialEq, Eq)]
pub struct Simulcast {
    /// The RID used for sending simulcast.
    pub send: Vec<Rid>,
    /// The RID used for receiving simulcast.
    pub recv: Vec<Rid>,
}

/// Video or audio data from the remote peer.
///
/// This is obtained via [`Event::MediaData`][crate::Event::MediaData].
#[derive(PartialEq, Eq)]
pub struct MediaData {
    /// Identifier of the media in the session this media belongs to.
    pub mid: Mid,

    /// Payload type (PT) tells which negotiated codec is being used. Each media
    /// can carry different codecs, the payload type can theoretically change
    /// from one packet to the next.
    pub pt: Pt,

    /// Rtp Stream Id (RID) identifies an RTP stream without referring to its
    /// Synchronization Source (SSRC).
    ///
    /// This is a newer standard that is sometimes used in WebRTC to identify
    /// a stream. Specifically when using Simulcast in Chrome.
    pub rid: Option<Rid>,

    /// Parameters for the codec. This is used to match incoming PT to outgoing PT.
    pub params: PayloadParams,

    /// The RTP media time of this packet. Media time is described as a nominator/denominator
    /// quantity. The nominator is the timestamp field from the RTP header, the denominator
    /// depends on whether this is an audio or video packet.
    ///
    /// For audio the timebase is 48kHz for video it is 90kHz.
    pub time: MediaTime,

    /// The time of the [`Input::Receive`][crate::Input::Receive] that caused this MediaData.
    ///
    /// In simple SFU setups this can be used as wallclock for [`Writer::write`][crate::media::Writer].
    pub network_time: Instant,

    /// The (RTP) sequence numbers that made up this data.
    pub seq_range: RangeInclusive<SeqNo>,

    /// Whether the data is contiguous from the one just previously emitted. If this is false,
    /// we got an interruption in RTP packets, and the data may or may not be usable in a decoder
    /// without requesting a new keyframe.
    ///
    /// For audio this flag most likely doesn't matter.
    pub contiguous: bool,

    /// The actual packet data a.k.a Sample.
    ///
    /// Bigger samples don't fit in one UDP packet, thus WebRTC RTP is chopping up codec
    /// transmission units into smaller parts.
    ///
    /// This data is a full depacketized Sample.
    pub data: Vec<u8>,

    /// RTP header extensions for this media data. This is taken from the
    /// first RTP header.
    pub ext_vals: ExtensionValues,

    /// Additional codec specific information
    pub codec_extra: CodecExtra,
}

/// When using "RTP mode", represents an RTP packet that has been received.
/// It will sit in buffers until poll_output() is called.
#[derive(Debug, PartialEq, Eq)]
pub struct RtpPacketReceived {
    /// Roughly identifies a "Media Source" in RFC7656 taxonomy.
    /// In practice, it's what you think of as a "stream" of audio or video.
    /// Determined by either the MID header extension or SSRC.
    pub mid: Mid,

    /// Identifies an "Encoded Stream" in RFC7656 taxonomy.
    /// In practice, it's what you think of as a simulcast layer.
    /// Determined by either the RID header extensions or SSRC.
    /// Only used with simulcast video.
    pub rid: Option<Rid>,

    /// Identifies the "RTP stream" in RFC7656 taxonomy.
    /// In practice, it's either the primary or RTX part of a simulcast layer
    /// (or of a "stream" if not using simulcast)
    /// Determined by the RTP header.
    /// If the packet received is an RTX packet, this is the original SSRC.
    pub ssrc: Ssrc,

    /// The RTP sequence number, determined by expanding the the sequence number in the RTP header.
    /// (keeping track of the rollover count or ROC)
    /// If the packet received is an RTX packet, this is the original sequence number.
    pub sequence_number: SeqNo,

    /// The RTP media time of this packet, expanded from timestamp in RTP header,
    /// and with the clock rate of the payload type.
    /// Determined by expanding the timestamp in the RTP header.
    pub timestamp: MediaTime,

    /// The RTP payload type, determined by the RTP header.
    /// If the packet received is an RTX packet, this is the original payload type.
    pub payload_type: Pt,

    /// The RTP marker bit.  Means different things for different payload types.
    pub marker: bool,

    /// The RTP header extensions
    pub header_extensions: ExtensionValues,

    /// The RTP payload.  Often contains a codec-specific header.
    pub payload: Vec<u8>,
}

/// When using "RTP mode", represents an RTP packet to send.
/// It will sit in buffers until the pacer wants to send it.
#[derive(Debug)]
pub struct RtpPacketToSend {
    /// Roughly identifies a "Media Source" in RFC7656 taxonomy.
    /// In practice, it's what you think of as a "stream" of audio or video.
    pub mid: Mid,

    /// Identifies the "RTP stream" in RFC7656 taxonomy.
    pub ssrc: Ssrc,

    /// The RTP sequence number, which must be untruncated because it will
    /// be used as part of the nonce for SRTP.
    /// You must not reuse an (ssrc, seq_no) pair.
    pub sequence_number: SeqNo,

    /// The RTP timestamp.  A truncated value is OK.  The receiver will expand it.
    pub timestamp: u32,

    /// The RTP payload type.  Must be in the range 0..=127.
    pub payload_type: Pt,

    /// The RTP marker bit.
    pub marker: bool,

    /// The RTP header extensions.  Should not contain header extensions associated with
    /// congestion control, such as transport-cc and abs-send-time, which will be filled
    /// in automatically before sending.
    pub header_extensions: ExtensionValues,

    /// The RTP payload.  Often contains a codec-specific header.
    pub payload: Vec<u8>,
}

/// Details for an incoming a keyframe request (PLI or FIR).
///
/// This is obtained via the [`Event::KeyframeRequest`][crate::Event::KeyframeRequest].
///
/// Sending a keyframe request is done via [`Media::request_keyframe()`][crate::media::Media].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyframeRequest {
    /// The media identifier this keyframe request is for.
    pub mid: Mid,

    /// Rid the keyframe request is for. Relevant when doing simulcast.
    pub rid: Option<Rid>,

    /// The kind of keyframe request (PLI or FIR).
    pub kind: KeyframeRequestKind,
}

/// Type of keyframe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyframeRequestKind {
    /// Picture Loss Indiciation (PLI) is a less severe keyframe request that can be
    /// automatically generated by an SFU or by the end peer.
    Pli,

    /// Full Intra Request (FIR) is a more severe keyframe request that should only
    /// be used when it's impossible for an end peer to show a video stream.
    Fir,
}
