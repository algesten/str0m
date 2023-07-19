use std::fmt;
use std::str::from_utf8;

use super::mtime::MediaTime;
use super::{Mid, Rid};

/// RTP header extensions.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    /// Not recognized URI
    UnknownUri,
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
    /// Parses an extension from a URI.
    pub fn from_uri(uri: &str) -> Self {
        for (t, spec) in EXT_URI.iter() {
            if *spec == uri {
                return *t;
            }
        }

        trace!("Unknown a=extmap uri: {}", uri);

        Extension::UnknownUri
    }

    /// Represents the extension as an URI.
    pub fn as_uri(&self) -> &'static str {
        for (t, spec) in EXT_URI.iter() {
            if t == self {
                return spec;
            }
        }
        "unknown"
    }

    pub(crate) fn is_serialized(&self) -> bool {
        *self != Extension::UnknownUri
    }

    fn is_audio(&self) -> bool {
        use Extension::*;
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExtensionMap([Option<Extension>; 14]);

impl ExtensionMap {
    /// Create an empty map.
    pub fn empty() -> Self {
        ExtensionMap([None; 14])
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
        self.0[idx] = Some(ext);
    }

    pub(crate) fn keep_same(&mut self, other: &ExtensionMap) {
        for i in 0..14 {
            if self.0[i] != other.0[i] {
                self.0[i] = None;
            }
        }
    }

    pub(crate) fn apply(&mut self, id: u8, ext: Extension) {
        if id < 1 || id > 14 {
            return;
        }

        // Mapping goes from 0 to 13.
        let new_index = id as usize - 1;

        let Some(old_index) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, m)| **m == Some(ext))
            .map(|(i, _)| i) else {
                return;
            };

        if new_index == old_index {
            return;
        }

        // swap them
        self.0[old_index] = self.0[new_index].take();
        self.0[new_index] = Some(ext);
    }

    /// Look up the extension for the id.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn lookup(&self, id: u8) -> Option<Extension> {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1]
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
            .position(|x| *x == Some(e))
            .map(|p| p as u8 + 1)
    }

    /// Returns an iterator over the elements of the extension map.
    pub fn iter(&self, audio: bool) -> impl Iterator<Item = (u8, Extension)> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
            .filter(move |(_, e)| if audio { e.is_audio() } else { e.is_video() })
            .map(|(i, e)| ((i + 1) as u8, *e))
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
                if let Some(n) = v.write_to(&mut b[1..], ev) {
                    assert!(n <= 16);
                    assert!(n > 0);
                    b[0] = (idx as u8 + 1) << 4 | (n as u8 - 1);
                    b = &mut b[1 + n..];
                }
            }
        }

        orig_len - b.len()
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
                todo!()
            }
            UnknownUri => {
                // do nothing
                todo!()
            }
        }
    }

    pub(crate) fn parse_value(&self, buf: &[u8], v: &mut ExtensionValues) -> Option<()> {
        use Extension::*;
        match self {
            // 3
            AbsoluteSendTime => {
                // fixed point 6.18
                if buf.len() < 3 {
                    return None;
                }
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                v.abs_send_time = Some(MediaTime::new(time_24 as i64, FIXED_POINT_6_18));
            }
            // 1
            AudioLevel => {
                if buf.is_empty() {
                    return None;
                }
                v.audio_level = Some(-(0x7f & buf[0] as i8));
                v.voice_activity = Some(buf[0] & 0x80 > 0);
            }
            // 3
            TransmissionTimeOffset => {
                if buf.len() < 4 {
                    return None;
                }
                v.tx_time_offs = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            // 1
            VideoOrientation => {
                if buf.is_empty() {
                    return None;
                }
                v.video_orientation = Some(super::ext::VideoOrientation::from(buf[0] & 3));
            }
            // 2
            TransportSequenceNumber => {
                if buf.len() < 2 {
                    return None;
                }
                v.transport_cc = Some(u16::from_be_bytes([buf[0], buf[1]]));
            }
            // 3
            PlayoutDelay => {
                if buf.len() < 3 {
                    return None;
                }
                let min = (buf[0] as u32) << 4 | (buf[1] as u32) >> 4;
                let max = ((buf[1] & 0xf) as u32) << 8 | buf[2] as u32;
                v.play_delay_min = Some(MediaTime::new(min as i64, 100));
                v.play_delay_max = Some(MediaTime::new(max as i64, 100));
            }
            // 1
            VideoContentType => {
                if buf.is_empty() {
                    return None;
                }
                v.video_content_type = Some(buf[0]);
            }
            // 13
            VideoTiming => {
                if buf.len() < 9 {
                    return None;
                }
                v.video_timing = Some(self::VideoTiming {
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
                v.rid = Some(s.into());
            }
            RepairedRtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.rid_repair = Some(s.into());
            }
            RtpMid => {
                let s = from_utf8(buf).ok()?;
                v.mid = Some(s.into());
            }
            FrameMarking => {
                if buf.len() < 4 {
                    return None;
                }
                v.frame_mark = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            ColorSpace => {
                // TODO HDR color space
            }
            UnknownUri => {
                // ignore
            }
        }

        Some(())
    }
}

/// Values in an RTP header extension.
///
/// This is metadata that is available also without decrypting the SRTP packets.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
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
}

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
                UnknownUri => "unknown-uri",
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn abs_send_time() {
        let mut exts = ExtensionMap::empty();
        exts.0[3] = Some(Extension::AbsoluteSendTime);
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
        exts.0[1] = Some(Extension::PlayoutDelay);
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
}

impl fmt::Debug for ExtensionMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extensions(")?;
        let joined = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.map(|v| (i + 1, v)))
            .map(|(i, v)| format!("{i}={v}"))
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
