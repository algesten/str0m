use std::any::Any;
use std::any::TypeId;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::hash::BuildHasherDefault;
use std::hash::Hasher;
use std::panic::UnwindSafe;
use std::str::from_utf8;
use std::sync::Arc;

use super::mtime::MediaTime;
use super::{Mid, Rid};

/// RTP header extensions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Extension {
    /// <http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time>
    AbsoluteSendTime,
    /// <urn:ietf:params:rtp-hdrext:ssrc-audio-level>
    AudioLevel,
    /// <urn:ietf:params:rtp-hdrext:toffset>
    ///
    /// Use when a RTP packet is delayed by a send queue to indicate an offset in the "transmitter".
    /// It effectively means we can set a timestamp offset exactly when the UDP packet leaves the
    /// server.
    TransmissionTimeOffset,
    /// <urn:3gpp:video-orientation>
    VideoOrientation,
    /// <http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01>
    TransportSequenceNumber,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/playout-delay>
    PlayoutDelay,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/video-content-type>
    VideoContentType,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/video-timing>
    VideoTiming,
    /// <urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id>
    ///
    /// UTF8 encoded identifier for the RTP stream. Not the same as SSRC, this is is designed to
    /// avoid running out of SSRC for very large sessions.
    RtpStreamId,
    /// <urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id>
    ///
    /// UTF8 encoded identifier referencing another RTP stream's RtpStreamId. If we see
    /// this extension type, we know the stream is a repair stream.
    RepairedRtpStreamId,
    /// <urn:ietf:params:rtp-hdrext:sdes:mid>
    RtpMid,
    /// <http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07>
    FrameMarking,
    /// <http://www.webrtc.org/experiments/rtp-hdrext/color-space>
    ColorSpace,

    /// Not recognized URI, but it could still be user parseable.
    #[doc(hidden)]
    UnknownUri(String, Arc<dyn ExtensionSerializer>),
}

// TODO: think this through. Is it unwind safe?
impl UnwindSafe for Extension {}

/// Trait for parsing/writing user RTP header extensions.
pub trait ExtensionSerializer: Debug + Send + Sync + 'static {
    /// Write the extension to the buffer of bytes. Must return the number
    /// of bytes written. This can be 0 if the extension could not be serialized.
    fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> usize;

    /// Parse a value and put it in the [`ExtensionValues::user_values`] field.
    fn parse_value(&self, buf: &[u8], ev: &mut ExtensionValues) -> bool;

    /// Tell if this extension should be used for video media.
    fn is_video(&self) -> bool;

    /// Tell if this extension should be used for audio media.
    fn is_audio(&self) -> bool;
}

/// This is a placeholder value for when the Extension URI are parsed in an SDP OFFER/ANSWER.
/// The trait write_to() and parse_value() should never be called (that would be a bug).
#[derive(Debug)]
struct SdpUnknownUri;

impl ExtensionSerializer for SdpUnknownUri {
    // If an unreachable happens, it's a bug.
    fn write_to(&self, _buf: &mut [u8], _ev: &ExtensionValues) -> usize {
        unreachable!("Incorrect ExtensionSerializer::write_to")
    }
    fn parse_value(&self, _buf: &[u8], _ev: &mut ExtensionValues) -> bool {
        unreachable!("Incorrect ExtensionSerializer::parse_value")
    }
    fn is_video(&self) -> bool {
        unreachable!("Incorrect ExtensionSerializer::is_video")
    }
    fn is_audio(&self) -> bool {
        unreachable!("Incorrect ExtensionSerializer::is_audio")
    }
}

/// Mapping of extension URI to our enum
const EXT_URI: &[(Extension, &str)] = &[
    (
        Extension::AbsoluteSendTime,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    ),
    (
        Extension::AudioLevel,
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
    ),
    (
        Extension::TransmissionTimeOffset,
        "urn:ietf:params:rtp-hdrext:toffset",
    ),
    (
        Extension::VideoOrientation, //
        "urn:3gpp:video-orientation",
    ),
    (
        Extension::TransportSequenceNumber,
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
    (
        Extension::PlayoutDelay,
        "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
    ),
    (
        Extension::VideoContentType,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type",
    ),
    (
        Extension::VideoTiming,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
    ),
    (
        Extension::RtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    ),
    (
        Extension::RepairedRtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ),
    (
        Extension::RtpMid, //
        "urn:ietf:params:rtp-hdrext:sdes:mid",
    ),
    (
        Extension::FrameMarking,
        "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07",
    ),
    (
        Extension::ColorSpace,
        "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
    ),
];

impl Extension {
    /// Parses an extension from a URI. This only happens for incoming SDP OFFER/ANSWER
    /// while the corresponding Extension with a potential ExtensionSerializer is
    /// in Rtc::session.
    pub(crate) fn from_sdp_uri(uri: &str) -> Self {
        for (t, spec) in EXT_URI.iter() {
            if *spec == uri {
                return t.clone();
            }
        }

        Extension::UnknownUri(uri.to_string(), Arc::new(SdpUnknownUri))
    }

    /// Extension for a uri not handled by str0m itself.
    pub fn with_serializer(uri: &str, s: impl ExtensionSerializer) -> Self {
        Extension::UnknownUri(uri.to_string(), Arc::new(s))
    }

    /// Represents the extension as an URI.
    pub fn as_uri(&self) -> &str {
        for (t, spec) in EXT_URI.iter() {
            if t == self {
                return spec;
            }
        }

        if let Extension::UnknownUri(uri, _) = self {
            return uri;
        }

        "unknown"
    }

    pub(crate) fn is_serialized(&self) -> bool {
        if let Self::UnknownUri(_, s) = self {
            // Check if this Arc contains the SdpUnknownUri.
            let is_sdp = (s as &(dyn Any + 'static))
                .downcast_ref::<SdpUnknownUri>()
                .is_some();

            // If it is the SdpUnknownUri, we are not serializing. If this happens,
            // it's probably a bug. The only way to construct SdpUnknownUri is via SDP,
            // but those values are only for Eq-comparison vs the values in Session.
            // The SdpUnknownUri should not even try to be serialized.
            if is_sdp {
                panic!("is_serialized on SdpUnkownUri, this is a bug");
            }
        }
        true
    }

    fn is_audio(&self) -> bool {
        use Extension::*;

        if let UnknownUri(_, serializer) = self {
            return serializer.is_audio();
        }

        matches!(
            self,
            RtpStreamId
                | RepairedRtpStreamId
                | RtpMid
                | AbsoluteSendTime
                | AudioLevel
                | TransportSequenceNumber
                | TransmissionTimeOffset
                | PlayoutDelay
        )
    }

    fn is_video(&self) -> bool {
        use Extension::*;

        if let UnknownUri(_, serializer) = self {
            return serializer.is_video();
        }

        matches!(
            self,
            RtpStreamId
                | RepairedRtpStreamId
                | RtpMid
                | AbsoluteSendTime
                | VideoOrientation
                | TransportSequenceNumber
                | TransmissionTimeOffset
                | PlayoutDelay
                | VideoContentType
                | VideoTiming
                | FrameMarking
                | ColorSpace
        )
    }
}

// As of 2022-09-28, for audio google chrome offers these.
// "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level"
// "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
// "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
// "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid"
//
// For video these.
// "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
// "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
// "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid"
// "a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay"
// "a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type"
// "a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing"
// "a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space"
// "a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
// "a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
// "a=extmap:13 urn:3gpp:video-orientation"
// "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset"

/// Mapping between RTP extension id to what extension that is.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtensionMap([Option<MapEntry>; 14]); // index 0 is extmap:1.

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    ext: Extension,
    locked: bool,
}

impl ExtensionMap {
    /// Create an empty map.
    pub fn empty() -> Self {
        ExtensionMap(std::array::from_fn(|_| None))
    }

    /// Creates a map with the "standard" mappings.
    ///
    /// The standard are taken from Chrome.
    pub fn standard() -> Self {
        let mut exts = Self::empty();

        exts.set(1, Extension::AudioLevel);
        exts.set(2, Extension::AbsoluteSendTime);
        exts.set(3, Extension::TransportSequenceNumber);
        exts.set(4, Extension::RtpMid);
        // exts.set_mapping(&ExtMap::new(8, Extension::ColorSpace));
        exts.set(10, Extension::RtpStreamId);
        exts.set(11, Extension::RepairedRtpStreamId);
        exts.set(13, Extension::VideoOrientation);

        exts
    }

    pub(crate) fn clear(&mut self) {
        for i in &mut self.0 {
            *i = None;
        }
    }

    /// Set a mapping for an extension.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn set(&mut self, id: u8, ext: Extension) {
        if id < 1 || id > 14 {
            debug!("Set RTP extension out of range 1-14: {}", id);
            return;
        }
        let idx = id as usize - 1;

        let m = MapEntry { ext, locked: false };

        self.0[idx] = Some(m);
    }

    /// Look up the extension for the id.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn lookup(&self, id: u8) -> Option<&Extension> {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1].as_ref().map(|m| &m.ext)
        } else {
            debug!("Lookup RTP extension out of range 1-14: {}", id);
            None
        }
    }

    /// Finds the id for an extension (if mapped).
    ///
    /// The returned id will be 1-based.
    pub fn id_of(&self, e: Extension) -> Option<u8> {
        self.0
            .iter()
            .position(|x| x.as_ref().map(|e| &e.ext) == Some(&e))
            .map(|p| p as u8 + 1)
    }

    /// Returns an iterator over the elements of the extension map
    ///
    /// Filtering them based on the provided `audio` flag
    pub fn iter(&self, audio: bool) -> impl Iterator<Item = (u8, &Extension)> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
            .filter(move |(_, e)| {
                if audio {
                    e.ext.is_audio()
                } else {
                    e.ext.is_video()
                }
            })
            .map(|(i, e)| ((i + 1) as u8, &e.ext))
    }

    pub(crate) fn cloned_with_type(&self, audio: bool) -> Self {
        let mut x = ExtensionMap::empty();
        for (id, ext) in self.iter(audio) {
            x.set(id, ext.clone());
        }
        x
    }

    // https://tools.ietf.org/html/rfc5285
    pub(crate) fn parse(&self, mut buf: &[u8], ext_vals: &mut ExtensionValues) {
        loop {
            if buf.is_empty() {
                return;
            }

            if buf[0] == 0 {
                // padding
                buf = &buf[1..];
                continue;
            }

            let id = buf[0] >> 4;
            let len = (buf[0] & 0xf) as usize + 1;
            buf = &buf[1..];

            if id == 15 {
                // If the ID value 15 is
                // encountered, its length field should be ignored, processing of the
                // entire extension should terminate at that point, and only the
                // extension elements present prior to the element with ID 15
                // considered.
                return;
            }

            if buf.len() < len {
                trace!("Not enough type ext len: {} < {}", buf.len(), len);
                return;
            }

            let ext_buf = &buf[..len];
            if let Some(ext) = self.lookup(id) {
                ext.parse_value(ext_buf, ext_vals);
            }

            buf = &buf[len..];
        }
    }

    pub(crate) fn write_to(&self, ext_buf: &mut [u8], ev: &ExtensionValues) -> usize {
        let orig_len = ext_buf.len();
        let mut b = ext_buf;

        for (idx, x) in self.0.iter().enumerate() {
            if let Some(v) = x {
                if let Some(n) = v.ext.write_to(&mut b[1..], ev) {
                    assert!(n <= 16);
                    assert!(n > 0);
                    b[0] = (idx as u8 + 1) << 4 | (n as u8 - 1);
                    b = &mut b[1 + n..];
                }
            }
        }

        orig_len - b.len()
    }

    pub(crate) fn remap(&mut self, remote_exts: &[(u8, &Extension)]) {
        // Match remote numbers and lock down those we see for the first time.
        for (id, ext) in remote_exts {
            self.swap(*id, ext);
        }
    }

    fn swap(&mut self, id: u8, ext: &Extension) {
        if id < 1 || id > 14 {
            return;
        }

        // Mapping goes from 0 to 13.
        let new_index = id as usize - 1;

        let Some(old_index) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, m)| m.as_ref().map(|m| &m.ext) == Some(ext))
            .map(|(i, _)| i)
        else {
            return;
        };

        // Unwrap OK because index is checking just above.
        let old = self.0[old_index].as_mut().unwrap();

        let is_change = new_index != old_index;

        // If either audio or video is locked, we got a previous extmap negotiation.
        if is_change && old.locked {
            warn!(
                "Extmap locked by previous negotiation. Ignore change: {} -> {}",
                old_index, new_index
            );
            return;
        }

        // Locking must be done regardless of whether there was an actual change.
        old.locked = true;

        if !is_change {
            return;
        }

        self.0.swap(old_index, new_index);
    }
}

const FIXED_POINT_6_18: i64 = 262_144; // 2 ^ 18

impl Extension {
    pub(crate) fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> Option<usize> {
        use Extension::*;
        match self {
            AbsoluteSendTime => {
                // 24 bit fixed point 6 bits for seconds, 18 for the decimals.
                // wraps around at 64 seconds.
                let v = ev.abs_send_time?.rebase(FIXED_POINT_6_18);
                let time_24 = v.numer() as u32;
                buf[..3].copy_from_slice(&time_24.to_be_bytes()[1..]);
                Some(3)
            }
            AudioLevel => {
                let v1 = ev.audio_level?;
                let v2 = ev.voice_activity?;
                buf[0] = if v2 { 0x80 } else { 0 } | (-(0x7f & v1) as u8);
                Some(1)
            }
            TransmissionTimeOffset => {
                let v = ev.tx_time_offs?;
                buf[..4].copy_from_slice(&v.to_be_bytes());
                Some(4)
            }
            VideoOrientation => {
                let v = ev.video_orientation?;
                buf[0] = v as u8;
                Some(1)
            }
            TransportSequenceNumber => {
                let v = ev.transport_cc?;
                buf[..2].copy_from_slice(&v.to_be_bytes());
                Some(2)
            }
            PlayoutDelay => {
                let v1 = ev.play_delay_min?.rebase(100);
                let v2 = ev.play_delay_max?.rebase(100);
                let min = (v1.numer() & 0xfff) as u32;
                let max = (v2.numer() & 0xfff) as u32;
                buf[0] = (min >> 4) as u8;
                buf[1] = (min << 4) as u8 | (max >> 8) as u8;
                buf[2] = max as u8;
                Some(3)
            }
            VideoContentType => {
                let v = ev.video_content_type?;
                buf[0] = v;
                Some(1)
            }
            VideoTiming => {
                let v = ev.video_timing?;
                buf[0] = v.flags;
                buf[1..3].copy_from_slice(&v.encode_start.to_be_bytes());
                buf[3..5].copy_from_slice(&v.encode_finish.to_be_bytes());
                buf[5..7].copy_from_slice(&v.packetize_complete.to_be_bytes());
                buf[7..9].copy_from_slice(&v.last_left_pacer.to_be_bytes());
                // Reserved for network
                buf[9..11].copy_from_slice(&0_u16.to_be_bytes());
                buf[11..13].copy_from_slice(&0_u16.to_be_bytes());
                Some(13)
            }
            RtpStreamId => {
                let v = ev.rid?;
                let l = v.as_bytes().len();
                buf[..l].copy_from_slice(v.as_bytes());
                Some(l)
            }
            RepairedRtpStreamId => {
                let v = ev.rid_repair?;
                let l = v.as_bytes().len();
                buf[..l].copy_from_slice(v.as_bytes());
                Some(l)
            }
            RtpMid => {
                let v = ev.mid?;
                let l = v.as_bytes().len();
                buf[..l].copy_from_slice(v.as_bytes());
                Some(l)
            }
            FrameMarking => {
                let v = ev.frame_mark?;
                buf[..4].copy_from_slice(&v.to_be_bytes());
                Some(4)
            }
            ColorSpace => {
                // TODO HDR color space
                None
            }
            UnknownUri(_, serializer) => {
                let n = serializer.write_to(buf, ev);

                if n == 0 {
                    None
                } else {
                    Some(n)
                }
            }
        }
    }

    pub(crate) fn parse_value(&self, buf: &[u8], ev: &mut ExtensionValues) -> Option<()> {
        use Extension::*;
        match self {
            // 3
            AbsoluteSendTime => {
                // fixed point 6.18
                if buf.len() < 3 {
                    return None;
                }
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                ev.abs_send_time = Some(MediaTime::new(time_24 as i64, FIXED_POINT_6_18));
            }
            // 1
            AudioLevel => {
                if buf.is_empty() {
                    return None;
                }
                ev.audio_level = Some(-(0x7f & buf[0] as i8));
                ev.voice_activity = Some(buf[0] & 0x80 > 0);
            }
            // 3
            TransmissionTimeOffset => {
                if buf.len() < 4 {
                    return None;
                }
                ev.tx_time_offs = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            // 1
            VideoOrientation => {
                if buf.is_empty() {
                    return None;
                }
                ev.video_orientation = Some(super::ext::VideoOrientation::from(buf[0] & 3));
            }
            // 2
            TransportSequenceNumber => {
                if buf.len() < 2 {
                    return None;
                }
                ev.transport_cc = Some(u16::from_be_bytes([buf[0], buf[1]]));
            }
            // 3
            PlayoutDelay => {
                if buf.len() < 3 {
                    return None;
                }
                let min = (buf[0] as u32) << 4 | (buf[1] as u32) >> 4;
                let max = ((buf[1] & 0xf) as u32) << 8 | buf[2] as u32;
                ev.play_delay_min = Some(MediaTime::new(min as i64, 100));
                ev.play_delay_max = Some(MediaTime::new(max as i64, 100));
            }
            // 1
            VideoContentType => {
                if buf.is_empty() {
                    return None;
                }
                ev.video_content_type = Some(buf[0]);
            }
            // 13
            VideoTiming => {
                if buf.len() < 9 {
                    return None;
                }
                ev.video_timing = Some(self::VideoTiming {
                    flags: buf[0],
                    encode_start: u16::from_be_bytes([buf[1], buf[2]]),
                    encode_finish: u16::from_be_bytes([buf[3], buf[4]]),
                    packetize_complete: u16::from_be_bytes([buf[5], buf[6]]),
                    last_left_pacer: u16::from_be_bytes([buf[7], buf[8]]),
                    //  9 - 10 // reserved for network
                    // 11 - 12 // reserved for network
                });
            }
            RtpStreamId => {
                let s = from_utf8(buf).ok()?;
                ev.rid = Some(s.into());
            }
            RepairedRtpStreamId => {
                let s = from_utf8(buf).ok()?;
                ev.rid_repair = Some(s.into());
            }
            RtpMid => {
                let s = from_utf8(buf).ok()?;
                ev.mid = Some(s.into());
            }
            FrameMarking => {
                if buf.len() < 4 {
                    return None;
                }
                ev.frame_mark = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            ColorSpace => {
                // TODO HDR color space
            }
            UnknownUri(_, serializer) => {
                let success = serializer.parse_value(buf, ev);
                if !success {
                    return None;
                }
            }
        }

        Some(())
    }
}

/// Values in an RTP header extension.
///
/// This is metadata that is available also without decrypting the SRTP packets.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExtensionValues {
    /// Audio level is measured in negative decibel. 0 is max and a "normal" value might be -30.
    pub audio_level: Option<i8>,

    /// Indication that there is sound from a voice.
    pub voice_activity: Option<bool>,

    /// Tell a receiver what rotation a video need to replay correctly.
    pub video_orientation: Option<VideoOrientation>,

    // The values below are considered internal until we have a reason to expose them.
    // Generally we want to avoid expose experimental features unless there are strong
    // reasons to do so.
    #[doc(hidden)]
    pub video_content_type: Option<u8>, // 0 = unspecified, 1 = screenshare
    #[doc(hidden)]
    pub tx_time_offs: Option<u32>,
    #[doc(hidden)]
    pub abs_send_time: Option<MediaTime>,
    #[doc(hidden)]
    pub transport_cc: Option<u16>, // (buf[0] << 8) | buf[1];
    #[doc(hidden)]
    // https://webrtc.googlesource.com/src/+/refs/heads/master/docs/native-code/rtp-hdrext/playout-delay
    pub play_delay_min: Option<MediaTime>,
    #[doc(hidden)]
    pub play_delay_max: Option<MediaTime>,
    #[doc(hidden)]
    pub video_timing: Option<VideoTiming>,
    #[doc(hidden)]
    pub rid: Option<Rid>,
    #[doc(hidden)]
    pub rid_repair: Option<Rid>,
    #[doc(hidden)]
    pub mid: Option<Mid>,
    #[doc(hidden)]
    pub frame_mark: Option<u32>,

    /// User values for [`ExtensionSerializer`] to parse into and write from.
    pub user_values: UserExtensionValues,
}

/// Space for storing user extension values via [`ExtensionSerializer`].
#[derive(Clone, Default)]
pub struct UserExtensionValues {
    map: Option<AnyMap>,
}

// The "AnyMap" idea is borrowed from the http crate but replacing Box for Any.
type AnyMap = HashMap<TypeId, Arc<dyn Any + Send + Sync>, BuildHasherDefault<IdHasher>>;

// No point in hashing the TypeId, since it is already unique.
#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("TypeId calls write_u64");
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

// TODO: I don't see a good way of comparing this. Is there one?
impl PartialEq for UserExtensionValues {
    fn eq(&self, other: &Self) -> bool {
        let (Some(m1), Some(m2)) = (&self.map, &other.map) else {
            return self.map.is_none() == other.map.is_none();
        };

        for k1 in m1.keys() {
            if !m2.contains_key(k1) {
                return false;
            }
        }

        for k2 in m2.keys() {
            if !m1.contains_key(k2) {
                return false;
            }
        }

        true
    }
}

impl Eq for UserExtensionValues {}

impl UserExtensionValues {
    /// Set a user extension value.
    ///
    /// This uses the type of the value as "key", i.e. it can only hold a single
    /// per type. The user should make a wrapper type for the extension they want
    /// to parse/write.
    ///
    /// ```
    /// # use str0m::rtp::ExtensionValues;
    /// let mut exts = ExtensionValues::default();
    ///
    /// #[derive(Debug, PartialEq, Eq)]
    /// struct MySpecialType(u8);
    ///
    /// exts.user_values.set(MySpecialType(42));
    /// ```
    pub fn set<T: Send + Sync + 'static>(&mut self, val: T) {
        self.map
            .get_or_insert_with(HashMap::default)
            .insert(TypeId::of::<T>(), Arc::new(val));
    }

    /// Get a user extension value (by type).
    /// ```
    /// # use str0m::rtp::ExtensionValues;
    /// let mut exts = ExtensionValues::default();
    ///
    /// #[derive(Debug, PartialEq, Eq)]
    /// struct MySpecialType(u8);
    ///
    /// exts.user_values.set(MySpecialType(42));
    ///
    /// let v = exts.user_values.get::<MySpecialType>();
    ///
    /// assert_eq!(v, Some(&MySpecialType(42)));
    /// ```
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .as_ref()
            .and_then(|map| map.get(&TypeId::of::<T>()))
            // unwrap here is OK because TypeId::of::<T> is guaranteed to be unique
            .map(|boxed| (&**boxed as &(dyn Any + 'static)).downcast_ref().unwrap())
    }
}

impl UnwindSafe for UserExtensionValues {}

impl fmt::Debug for ExtensionValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionValues {{")?;

        if let Some(t) = self.mid {
            write!(f, " mid: {t}")?;
        }
        if let Some(t) = self.rid {
            write!(f, " rid: {t}")?;
        }
        if let Some(t) = self.rid_repair {
            write!(f, " rid_repair: {t}")?;
        }
        if let Some(t) = self.abs_send_time {
            write!(f, " abs_send_time: {:?}", t)?;
        }
        if let Some(t) = self.voice_activity {
            write!(f, " voice_activity: {t}")?;
        }
        if let Some(t) = self.audio_level {
            write!(f, " audio_level: {t}")?;
        }
        if let Some(t) = self.tx_time_offs {
            write!(f, " tx_time_offs: {t}")?;
        }
        if let Some(t) = self.video_orientation {
            write!(f, " video_orientation: {t:?}")?;
        }
        if let Some(t) = self.transport_cc {
            write!(f, " transport_cc: {t}")?;
        }
        if let Some(t) = self.play_delay_min {
            write!(f, " play_delay_min: {}", t.as_seconds())?;
        }
        if let Some(t) = self.play_delay_max {
            write!(f, " play_delay_max: {}", t.as_seconds())?;
        }
        if let Some(t) = self.video_content_type {
            write!(f, " video_content_type: {t}")?;
        }
        if let Some(t) = &self.video_timing {
            write!(f, " video_timing: {t:?}")?;
        }
        if let Some(t) = &self.frame_mark {
            write!(f, " frame_mark: {t}")?;
        }

        write!(f, " }}")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoTiming {
    // 0x01 = extension is set due to timer.
    // 0x02 - extension is set because the frame is larger than usual.
    pub flags: u8,
    pub encode_start: u16,
    pub encode_finish: u16,
    pub packetize_complete: u16,
    pub last_left_pacer: u16,
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Extension::*;
        write!(
            f,
            "{}",
            match self {
                AbsoluteSendTime => "abs-send-time",
                AudioLevel => "ssrc-audio-level",
                TransmissionTimeOffset => "toffset",
                VideoOrientation => "video-orientation",
                TransportSequenceNumber => "transport-wide-cc",
                PlayoutDelay => "playout-delay",
                VideoContentType => "video-content-type",
                VideoTiming => "video-timing",
                RtpStreamId => "rtp-stream-id",
                RepairedRtpStreamId => "repaired-rtp-stream-id",
                RtpMid => "mid",
                FrameMarking => "frame-marking07",
                ColorSpace => "color-space",
                UnknownUri(uri, _) => uri,
            }
        )
    }
}

impl fmt::Debug for ExtensionMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extensions(")?;
        let joined = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.as_ref().map(|v| (i + 1, v)))
            .map(|(i, v)| format!("{}={}", i, v.ext))
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{joined}")?;
        write!(f, ")")?;
        Ok(())
    }
}

/// How the video is rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoOrientation {
    /// Not rotated.
    Deg0 = 0,
    /// 90 degress clockwise.
    Deg90 = 3,
    /// Upside down.
    Deg180 = 2,
    /// 90 degrees counter clockwise.
    Deg270 = 1,
}

impl From<u8> for VideoOrientation {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Deg270,
            2 => Self::Deg180,
            3 => Self::Deg90,
            _ => Self::Deg0,
        }
    }
}

impl PartialEq for Extension {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Extension::AbsoluteSendTime, Extension::AbsoluteSendTime) => true,
            (Extension::AudioLevel, Extension::AudioLevel) => true,
            (Extension::TransmissionTimeOffset, Extension::TransmissionTimeOffset) => true,
            (Extension::VideoOrientation, Extension::VideoOrientation) => true,
            (Extension::TransportSequenceNumber, Extension::TransportSequenceNumber) => true,
            (Extension::PlayoutDelay, Extension::PlayoutDelay) => true,
            (Extension::VideoContentType, Extension::VideoContentType) => true,
            (Extension::VideoTiming, Extension::VideoTiming) => true,
            (Extension::RtpStreamId, Extension::RtpStreamId) => true,
            (Extension::RepairedRtpStreamId, Extension::RepairedRtpStreamId) => true,
            (Extension::RtpMid, Extension::RtpMid) => true,
            (Extension::FrameMarking, Extension::FrameMarking) => true,
            (Extension::ColorSpace, Extension::ColorSpace) => true,
            (Extension::UnknownUri(uri1, _), Extension::UnknownUri(uri2, _)) => uri1 == uri2,
            _ => false,
        }
    }
}

impl Eq for Extension {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn abs_send_time() {
        let mut exts = ExtensionMap::empty();
        exts.set(4, Extension::AbsoluteSendTime);
        let ev = ExtensionValues {
            abs_send_time: Some(MediaTime::new(1, FIXED_POINT_6_18)),
            ..Default::default()
        };

        let mut buf = vec![0_u8; 8];
        exts.write_to(&mut buf[..], &ev);

        let mut ev2 = ExtensionValues::default();
        exts.parse(&buf, &mut ev2);

        assert_eq!(ev.abs_send_time, ev2.abs_send_time);
    }

    #[test]
    fn playout_delay() {
        let mut exts = ExtensionMap::empty();
        exts.set(2, Extension::PlayoutDelay);
        let ev = ExtensionValues {
            play_delay_min: Some(MediaTime::new(100, 100)),
            play_delay_max: Some(MediaTime::new(200, 100)),
            ..Default::default()
        };

        let mut buf = vec![0_u8; 8];
        exts.write_to(&mut buf[..], &ev);

        let mut ev2 = ExtensionValues::default();
        exts.parse(&buf, &mut ev2);

        assert_eq!(ev.play_delay_min, ev2.play_delay_min);
        assert_eq!(ev.play_delay_max, ev2.play_delay_max);
    }

    #[test]
    fn remap_exts_audio() {
        use Extension::*;

        let mut e1 = ExtensionMap::standard();
        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);

        println!("{:?}", e1.iter(false).collect::<Vec<_>>());

        e1.remap(&e2.iter(true).collect::<Vec<_>>());

        // e1 should have adjusted the TransportSequenceNumber for audio
        assert_eq!(
            e1.iter(true).collect::<Vec<_>>(),
            vec![
                (1, &AudioLevel),
                (2, &AbsoluteSendTime),
                (4, &RtpMid),
                (10, &RtpStreamId),
                (11, &RepairedRtpStreamId),
                (14, &TransportSequenceNumber)
            ]
        );

        // e1 should have adjusted the TransportSequenceNumber for vudeo
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![
                (2, &AbsoluteSendTime),
                (4, &RtpMid),
                (10, &RtpStreamId),
                (11, &RepairedRtpStreamId),
                (13, &VideoOrientation),
                (14, &TransportSequenceNumber),
            ]
        );
    }

    #[test]
    fn remap_exts_video() {
        use Extension::*;

        let mut e1 = ExtensionMap::empty();
        e1.set(3, TransportSequenceNumber);
        e1.set(4, VideoOrientation);
        e1.set(5, VideoContentType);
        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);
        e2.set(12, VideoOrientation);

        e1.remap(&e2.iter(false).collect::<Vec<_>>());

        // e1 should have adjusted to e2.
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![
                (5, &VideoContentType),
                (12, &VideoOrientation),
                (14, &TransportSequenceNumber)
            ]
        );
    }

    #[test]
    fn remap_exts_swaparoo() {
        use Extension::*;

        let mut e1 = ExtensionMap::empty();
        e1.set(12, TransportSequenceNumber);
        e1.set(14, VideoOrientation);
        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);
        e2.set(12, VideoOrientation);

        e1.remap(&e2.iter(false).collect::<Vec<_>>());

        // just make sure the logic isn't wrong for 12-14 -> 14-12
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![(12, &VideoOrientation), (14, &TransportSequenceNumber)]
        );
    }

    #[test]
    fn remap_exts_illegal() {
        use Extension::*;

        let mut e1 = ExtensionMap::empty();
        e1.set(12, TransportSequenceNumber);
        e1.set(14, VideoOrientation);

        let mut e2 = ExtensionMap::empty();
        e2.set(14, TransportSequenceNumber);
        e2.set(12, VideoOrientation);

        let mut e3 = ExtensionMap::empty();
        // Illegal change of already negotiated/locked number
        e3.set(1, TransportSequenceNumber);
        e3.set(12, AudioLevel); // change of type for existing.

        // First apply e2
        e1.remap(&e2.iter(false).collect::<Vec<_>>());

        println!("{:#?}", e1.0);
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![(12, &VideoOrientation), (14, &TransportSequenceNumber)]
        );

        // Now attempt e3
        e1.remap(&e3.iter(true).collect::<Vec<_>>());

        println!("{:#?}", e1.0);
        // At this point we should have not allowed the change, but remain as it was in first apply.
        assert_eq!(
            e1.iter(false).collect::<Vec<_>>(),
            vec![(12, &VideoOrientation), (14, &TransportSequenceNumber)]
        );
    }
}
