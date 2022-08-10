use std::fmt;
use std::str::from_utf8;

use crate::mtime::MediaTime;
use crate::{Direction, RtpError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtMap {
    pub id: u8,                       // 1-14 inclusive, 0 and 15 are reserved.
    pub direction: Option<Direction>, // recvonly, sendrecv, sendonly, inactive
    pub ext: Extension,
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

    pub fn is_supported(&self) -> bool {
        use Extension::*;
        match self {
            // These seem to be the bare minimum to get Chrome
            // to send RTP for a simulcast video
            RtpStreamId => true,
            RepairedRtpStreamId => true,
            RtpMid => true,
            AbsoluteSendTime => true,
            VideoOrientation => true,
            AudioLevel => true,

            // transport wide cc
            TransportSequenceNumber => true,

            TransmissionTimeOffset => false,
            PlayoutDelay => false,
            VideoContentType => false,
            VideoTiming => false,
            FrameMarking => false,
            ColorSpace => false,
            UnknownUri => false,
        }
    }

    pub fn is_serialized(&self) -> bool {
        *self != Extension::UnknownUri
    }
}

/// Mapping between RTP extension id to what extension that is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extensions([Option<Extension>; 14]);

impl Extensions {
    pub fn new() -> Self {
        Extensions([None; 14])
    }

    pub fn apply_mappings(&mut self, v: &[ExtMap]) -> Result<(), RtpError> {
        for x in v {
            if x.id >= 1 && x.id <= 14 {
                // Mapping goes from 0 to 13.
                let id = x.id as usize - 1;

                if let Some(v) = self.0[id] {
                    if v == x.ext {
                        // same mapping, nothing to do
                    } else {
                        // We assume that an ext-type mapping cannot be different within the context
                        // of one RTP session. If they are different, we have no strategy for parsing
                        // the mid from a RTP packet to match it up with an m-line (avoiding a=ssrc).
                        // If we see this error, we must make fallback strategies for how to match
                        // incoming RTP to a Media/IngressStream.
                        return Err(RtpError::ExtMapDiffers(v, x.ext));
                    }
                } else {
                    self.0[id] = Some(x.ext);
                }
            }
        }

        Ok(())
    }

    pub fn lookup(&self, id: u8) -> Option<Extension> {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1]
        } else {
            debug!("Lookup RTP extension out of range 1-14: {}", id);
            None
        }
    }
}

impl Extension {
    pub(crate) fn parse_value<'a>(&self, buf: &'a [u8], v: &mut ExtensionValues<'a>) -> Option<()> {
        use Extension::*;
        match self {
            // 3
            AbsoluteSendTime => {
                // fixed point 6.18
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                let time_fp = time_24 as f32 / (2 ^ 18) as f32;
                v.abs_send_time = Some(MediaTime::from_seconds(time_fp));
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
                let max = (buf[1] as u32) << 8 | buf[2] as u32;
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
                    encode_start: u32::from_be_bytes([0, 0, buf[1], buf[2]]),
                    encode_finish: u32::from_be_bytes([0, 0, buf[2], buf[3]]),
                    packetize_complete: u32::from_be_bytes([0, 0, buf[4], buf[5]]),
                    last_left_pacer: u32::from_be_bytes([0, 0, buf[6], buf[7]]),
                    //  8 -  9 // reserved for network
                    // 10 - 11 // reserved for network
                });
            }
            RtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.stream_id = Some(s);
            }
            RepairedRtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.rep_stream_id = Some(s);
            }
            RtpMid => {
                let s = from_utf8(buf).ok()?;
                v.rtp_mid = Some(s);
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

#[derive(Clone, Default)]
pub struct ExtensionValues<'a> {
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
    pub stream_id: Option<&'a str>,
    pub rep_stream_id: Option<&'a str>,
    pub rtp_mid: Option<&'a str>,
    pub frame_mark: Option<u32>,
}

impl<'a> fmt::Debug for ExtensionValues<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionValues {{")?;

        if let Some(t) = self.rtp_mid {
            write!(f, " mid: {}", t)?;
        }
        if let Some(t) = self.stream_id {
            write!(f, " stream_id: {}", t)?;
        }
        if let Some(t) = self.rep_stream_id {
            write!(f, " rep_stream_id: {}", t)?;
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
        if self.transport_cc.is_some() {
            write!(f, " transport_cc: TODO")?;
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
        if self.frame_mark.is_some() {
            write!(f, " frame_mark: TODO")?;
        }

        write!(f, " }}")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VideoTiming {
    // 0x01 = extension is set due to timer.
    // 0x02 - extension is set because the frame is larger than usual.
    pub flags: u8,
    pub encode_start: u32,
    pub encode_finish: u32,
    pub packetize_complete: u32,
    pub last_left_pacer: u32,
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
