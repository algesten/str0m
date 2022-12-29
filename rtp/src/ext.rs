use std::fmt;
use std::str::from_utf8;

use crate::mtime::MediaTime;
use crate::{Direction, Mid, Rid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtMap {
    pub id: u8,                       // 1-14 inclusive, 0 and 15 are reserved.
    pub direction: Option<Direction>, // recvonly, sendrecv, sendonly, inactive
    pub ext: Extension,
}

impl ExtMap {
    pub fn new(id: u8, ext: Extension) -> Self {
        ExtMap {
            id,
            direction: None,
            ext,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Extension {
    AbsoluteSendTime,
    AudioLevel,
    /// Use when a RTP packet is delayed by a send queue to indicate an offset in the "transmitter".
    /// It effectively means we can set a timestamp offset exactly when the UDP packet leaves the
    /// server.
    TransmissionTimeOffset,
    VideoOrientation,
    TransportSequenceNumber,
    PlayoutDelay,
    VideoContentType,
    VideoTiming,
    /// UTF8 encoded identifier for the RTP stream. Not the same as SSRC, this is is designed to
    /// avoid running out of SSRC for very large sessions.
    RtpStreamId,
    /// UTF8 encoded identifier referencing another RTP stream's RtpStreamId. If we see
    /// this extension type, we know the stream is a repair stream.
    RepairedRtpStreamId,
    RtpMid,
    FrameMarking,
    ColorSpace,
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
    pub fn from_uri(uri: &str) -> Self {
        for (t, spec) in EXT_URI.iter() {
            if *spec == uri {
                return *t;
            }
        }

        trace!("Unknown a=extmap uri: {}", uri);

        Extension::UnknownUri
    }

    pub fn as_uri(&self) -> &'static str {
        for (t, spec) in EXT_URI.iter() {
            if t == self {
                return spec;
            }
        }
        "unknown"
    }

    pub fn is_serialized(&self) -> bool {
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
pub struct Extensions([Option<Extension>; 14]);

impl Extensions {
    pub fn new() -> Self {
        Extensions([None; 14])
    }

    pub fn default_mappings() -> Extensions {
        let mut exts = Self::new();

        exts.set_mapping(ExtMap::new(2, Extension::AbsoluteSendTime));
        exts.set_mapping(ExtMap::new(3, Extension::TransportSequenceNumber));
        exts.set_mapping(ExtMap::new(4, Extension::RtpMid));
        // exts.set_mapping(&ExtMap::new(8, Extension::ColorSpace));
        exts.set_mapping(ExtMap::new(10, Extension::RtpStreamId));
        exts.set_mapping(ExtMap::new(11, Extension::RepairedRtpStreamId));
        exts.set_mapping(ExtMap::new(13, Extension::VideoOrientation));

        exts
    }

    pub fn set_mapping(&mut self, x: ExtMap) {
        let new_index = x.id as usize - 1;
        self.0[new_index] = Some(x.ext);
    }

    pub fn keep_same(&mut self, other: &Extensions) {
        for i in 0..14 {
            if self.0[i] != other.0[i] {
                self.0[i] = None;
            }
        }
    }

    pub fn apply_mapping(&mut self, x: &ExtMap) {
        if x.id < 1 && x.id > 14 {
            return;
        }

        // Mapping goes from 0 to 13.
        let new_index = x.id as usize - 1;

        let Some(old_index) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, m)| **m == Some(x.ext))
            .map(|(i, _)| i) else {
                return;
            };

        if new_index == old_index {
            return;
        }

        // swap them
        self.0[old_index] = self.0[new_index].take();
        self.0[new_index] = Some(x.ext);
    }

    pub fn lookup(&self, id: u8) -> Option<Extension> {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1]
        } else {
            debug!("Lookup RTP extension out of range 1-14: {}", id);
            None
        }
    }

    pub fn into_extmap(&self, audio: bool) -> impl Iterator<Item = ExtMap> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
            .filter(move |(_, e)| if audio { e.is_audio() } else { e.is_video() })
            .map(|(i, e)| ExtMap {
                id: (i + 1) as u8,
                direction: None,
                ext: *e,
            })
    }

    // https://tools.ietf.org/html/rfc5285
    pub fn parse(&self, mut buf: &[u8], ext_vals: &mut ExtensionValues) {
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

    pub fn write_to(&self, ext_buf: &mut [u8], ev: &ExtensionValues) -> usize {
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
    pub fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> Option<usize> {
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
                let v = ev.video_orient?;
                buf[0] = v & 3;
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
                let v = ev.video_c_type?;
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

    pub fn parse_value(&self, buf: &[u8], v: &mut ExtensionValues) -> Option<()> {
        use Extension::*;
        match self {
            // 3
            AbsoluteSendTime => {
                // fixed point 6.18
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                v.abs_send_time = Some(MediaTime::new(time_24 as i64, FIXED_POINT_6_18));
            }
            // 1
            AudioLevel => {
                v.audio_level = Some(-(0x7f & buf[0] as i8));
                v.voice_activity = Some(buf[0] & 0x80 > 0);
            }
            // 3
            TransmissionTimeOffset => {
                v.tx_time_offs = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            // 1
            VideoOrientation => {
                v.video_orient = Some(buf[0] & 3);
            }
            // 2
            TransportSequenceNumber => {
                v.transport_cc = Some(u16::from_be_bytes([buf[0], buf[1]]));
            }
            // 3
            PlayoutDelay => {
                let min = (buf[0] as u32) << 4 | (buf[1] as u32) >> 4;
                let max = ((buf[1] & 0xf) as u32) << 8 | buf[2] as u32;
                v.play_delay_min = Some(MediaTime::new(min as i64, 100));
                v.play_delay_max = Some(MediaTime::new(max as i64, 100));
            }
            // 1
            VideoContentType => {
                v.video_c_type = Some(buf[0]);
            }
            // 13
            VideoTiming => {
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

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExtensionValues {
    pub abs_send_time: Option<MediaTime>,
    pub voice_activity: Option<bool>,
    pub audio_level: Option<i8>,
    pub tx_time_offs: Option<u32>,
    pub video_orient: Option<u8>,  // TODO map out values buf[0] & 3;
    pub transport_cc: Option<u16>, // (buf[0] << 8) | buf[1];
    // https://webrtc.googlesource.com/src/+/refs/heads/master/docs/native-code/rtp-hdrext/playout-delay
    pub play_delay_min: Option<MediaTime>,
    pub play_delay_max: Option<MediaTime>,
    pub video_c_type: Option<u8>, // 0 = unspecified, 1 = screenshare
    pub video_timing: Option<VideoTiming>,
    pub rid: Option<Rid>,
    pub rid_repair: Option<Rid>,
    pub mid: Option<Mid>,
    pub frame_mark: Option<u32>,
}

impl fmt::Debug for ExtensionValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionValues {{")?;

        if let Some(t) = self.mid {
            write!(f, " mid: {}", t)?;
        }
        if let Some(t) = self.rid {
            write!(f, " rid: {}", t)?;
        }
        if let Some(t) = self.rid_repair {
            write!(f, " rid_repair: {}", t)?;
        }
        if let Some(t) = self.abs_send_time {
            write!(f, " abs_send_time: {}", t.as_seconds())?;
        }
        if let Some(t) = self.voice_activity {
            write!(f, " voice_activity: {}", t)?;
        }
        if let Some(t) = self.audio_level {
            write!(f, " audio_level: {}", t)?;
        }
        if let Some(t) = self.tx_time_offs {
            write!(f, " tx_time_offs: {}", t)?;
        }
        if let Some(t) = self.video_orient {
            write!(f, " video_orient: {}", t)?;
        }
        if let Some(t) = self.transport_cc {
            write!(f, " transport_cc: {}", t)?;
        }
        if let Some(t) = self.play_delay_min {
            write!(f, " play_delay_min: {}", t.as_seconds())?;
        }
        if let Some(t) = self.play_delay_max {
            write!(f, " play_delay_max: {}", t.as_seconds())?;
        }
        if let Some(t) = self.video_c_type {
            write!(f, " video_c_type: {}", t)?;
        }
        if let Some(t) = &self.video_timing {
            write!(f, " video_timing: {:?}", t)?;
        }
        if let Some(t) = &self.frame_mark {
            write!(f, " frame_mark: {}", t)?;
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
        let mut exts = Extensions::new();
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
        let mut exts = Extensions::new();
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

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extensions(")?;
        let joined = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.map(|v| (i + 1, v)))
            .map(|(i, v)| format!("{}={}", i, v))
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", joined)?;
        write!(f, ")")?;
        Ok(())
    }
}
