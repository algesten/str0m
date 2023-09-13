use std::fmt;
use std::ops::RangeInclusive;
use std::time::Instant;

use crate::packet::MediaKind;
use crate::rtp_::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid, SenderInfo, SeqNo};
use crate::sdp::Simulcast as SdpSimulcast;

use super::PayloadParams;
use crate::format::CodecExtra;

impl From<SdpSimulcast> for Simulcast {
    fn from(s: SdpSimulcast) -> Self {
        let send = s.send.iter().map(|r| r.0.as_ref()).map(Rid::from).collect();
        let recv = s.recv.iter().map(|r| r.0.as_ref()).map(Rid::from).collect();

        Simulcast { send, recv }
    }
}

/// A new media appeared in an Rtc session.
///
/// This event fires both for negotiations triggered by a remote or local offer.
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

/// A change happening during an SDP re-negotiation.
///
/// This event fires both for re-negotiations triggered by a remote or local offer.
///
/// Does not fire for application media (data channel).
#[derive(Debug, PartialEq, Eq)]
pub struct MediaChanged {
    /// Identifier of the media.
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

    /// The time of the [`Input::Receive`][crate::Input::Receive] of the first packet that caused this MediaData.
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
    /// This data is a full depayloaded Sample.
    pub data: Vec<u8>,

    /// RTP header extensions for this media data. This is taken from the
    /// first RTP header.
    pub ext_vals: ExtensionValues,

    /// Additional codec specific information
    pub codec_extra: CodecExtra,

    /// Sender information from the most recent Sender Report(SR).
    ///
    /// If no Sender Report(SR) has been received this is [`None`].
    pub last_sender_info: Option<SenderInfo>,
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
    /// Picture Loss Indication (PLI) is a less severe keyframe request that can be
    /// automatically generated by an SFU or by the end peer.
    Pli,

    /// Full Intra Request (FIR) is a more severe keyframe request that should only
    /// be used when it's impossible for an end peer to show a video stream.
    Fir,
}

impl fmt::Debug for MediaData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaData")
            .field("mid", &self.mid)
            .field("pt", &self.pt)
            .field("rid", &self.rid)
            .field("time", &self.time)
            .field("len", &self.data.len())
            .finish()
    }
}
