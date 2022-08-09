use std::fmt;
use std::str::from_utf8;

use crate::mtime::MediaTime;
use crate::RtpError;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RtpExtensionType {
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
    UnknownExt,
}
/// Mapping of extension URI to our enum
const RTP_EXT_URI: &[(RtpExtensionType, &str)] = &[
    (
        RtpExtensionType::AbsoluteSendTime,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    ),
    (
        RtpExtensionType::AudioLevel,
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
    ),
    (
        RtpExtensionType::TransmissionTimeOffset,
        "urn:ietf:params:rtp-hdrext:toffset",
    ),
    (
        RtpExtensionType::VideoOrientation,
        "urn:3gpp:video-orientation",
    ),
    (
        RtpExtensionType::TransportSequenceNumber,
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
    (
        RtpExtensionType::PlayoutDelay,
        "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
    ),
    (
        RtpExtensionType::VideoContentType,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type",
    ),
    (
        RtpExtensionType::VideoTiming,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
    ),
    (
        RtpExtensionType::RtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    ),
    (
        RtpExtensionType::RepairedRtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ),
    (
        RtpExtensionType::RtpMid,
        "urn:ietf:params:rtp-hdrext:sdes:mid",
    ),
    (
        RtpExtensionType::FrameMarking,
        "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07",
    ),
    (
        RtpExtensionType::ColorSpace,
        "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
    ),
];

impl RtpExtensionType {
    pub fn from_uri(uri: &str) -> Self {
        for (t, spec) in RTP_EXT_URI.iter() {
            if *spec == uri {
                return *t;
            }
        }

        trace!("Unknown a=extmap uri: {}", uri);

        RtpExtensionType::UnknownUri
    }

    pub fn as_uri(&self) -> &'static str {
        for (t, spec) in RTP_EXT_URI.iter() {
            if t == self {
                return spec;
            }
        }
        "unknown"
    }

    pub fn is_supported(&self) -> bool {
        use RtpExtensionType::*;
        match self {
            // These 4 seem to be the bare minimum to get Chrome
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
            UnknownExt => false,
        }
    }

    pub fn is_filtered(&self) -> bool {
        use RtpExtensionType::*;
        matches!(self, UnknownUri | UnknownExt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtMap {
    pub id: u8,                    // 1-14 inclusive, 0 and 15 are reserved.
    pub direction: Option<String>, // recvonly, sendrecv, sendonly
    pub ext_type: RtpExtensionType,
    pub ext: Option<String>,
}

/// Mapping between RTP extension id to what extension that is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdToExtType([RtpExtensionType; 14]);

impl IdToExtType {
    pub fn new() -> Self {
        IdToExtType([RtpExtensionType::UnknownExt; 14])
    }

    pub fn apply_ext_map(&mut self, v: &[ExtMap]) -> Result<(), RtpError> {
        for x in v {
            if x.id >= 1 && x.id <= 14 {
                // Mapping goes from 0 to 13.
                let id = x.id as usize - 1;

                if self.0[id] == RtpExtensionType::UnknownExt {
                    self.0[id] = x.ext_type;
                } else if self.0[id] == x.ext_type {
                    // Same type
                } else {
                    // We assume that an ext-type mapping cannot be different within the context
                    // of one RTP session. If they are different, we have no strategy for parsing
                    // the mid from a RTP packet to match it up with an m-line (avoiding a=ssrc).
                    // If we see this error, we must make fallback strategies for how to match
                    // incoming RTP to a Media/IngressStream.
                    return Err(RtpError::ExtMapDiffers(self.0[id], x.ext_type));
                }
            }
        }

        Ok(())
    }

    pub fn lookup(&self, id: u8) -> RtpExtensionType {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1]
        } else {
            debug!("Lookup RTP extension out of range 1-14: {}", id);
            RtpExtensionType::UnknownExt
        }
    }
}

impl RtpExtensionType {
    pub(crate) fn parse_value<'a>(&self, buf: &'a [u8], v: &mut RtpExtValues<'a>) -> Option<()> {
        match self {
            // 3
            RtpExtensionType::AbsoluteSendTime => {
                // fixed point 6.18
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                let time_fp = time_24 as f32 / (2 ^ 18) as f32;
                v.abs_send_time = Some(MediaTime::from_seconds(time_fp));
            }
            // 1
            RtpExtensionType::AudioLevel => {
                v.audio_level = Some(-(0x7f & buf[0] as i8));
                v.voice_activity = Some(buf[0] & 0x80 > 0);
            }
            // 3
            RtpExtensionType::TransmissionTimeOffset => {
                v.tx_time_offs = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            // 1
            RtpExtensionType::VideoOrientation => {
                v.video_orient = Some(buf[0] & 3);
            }
            // 2
            RtpExtensionType::TransportSequenceNumber => {
                v.transport_cc = Some(u16::from_be_bytes([buf[0], buf[1]]));
            }
            // 3
            RtpExtensionType::PlayoutDelay => {
                let min = (buf[0] as u32) << 4 | (buf[1] as u32) >> 4;
                let max = (buf[1] as u32) << 8 | buf[2] as u32;
                v.play_delay_min = Some(MediaTime::new(min as i64, 100));
                v.play_delay_max = Some(MediaTime::new(max as i64, 100));
            }
            // 1
            RtpExtensionType::VideoContentType => {
                v.video_c_type = Some(buf[0]);
            }
            // 13
            RtpExtensionType::VideoTiming => {
                v.video_timing = Some(VideoTiming {
                    flags: buf[0],
                    encode_start: u32::from_be_bytes([0, 0, buf[1], buf[2]]),
                    encode_finish: u32::from_be_bytes([0, 0, buf[2], buf[3]]),
                    packetize_complete: u32::from_be_bytes([0, 0, buf[4], buf[5]]),
                    last_left_pacer: u32::from_be_bytes([0, 0, buf[6], buf[7]]),
                    //  8 -  9 // reserved for network
                    // 10 - 11 // reserved for network
                })
            }
            RtpExtensionType::RtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.stream_id = Some(s);
            }
            RtpExtensionType::RepairedRtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.rep_stream_id = Some(s);
            }
            RtpExtensionType::RtpMid => {
                let s = from_utf8(buf).ok()?;
                v.rtp_mid = Some(s);
            }
            RtpExtensionType::FrameMarking => {
                v.frame_mark = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            RtpExtensionType::ColorSpace => {
                // TODO HDR color space
            }
            RtpExtensionType::UnknownUri | RtpExtensionType::UnknownExt => {
                // ignore
            }
        }

        Some(())
    }
}

#[derive(Clone, Default)]
pub struct RtpExtValues<'a> {
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

impl<'a> fmt::Debug for RtpExtValues<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RtpExtValues {{")?;

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

impl<'a> RtpExtValues<'a> {
    //
}

#[derive(Debug, Clone)]
pub struct VideoTiming {
    // 0x01 = extension is set due to timer.
    // 0x02 - extension is set because the frame is larger than usual.
    flags: u8,
    encode_start: u32,
    encode_finish: u32,
    packetize_complete: u32,
    last_left_pacer: u32,
}

impl fmt::Display for RtpExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RtpExtensionType::AbsoluteSendTime => "abs-send-time",
                RtpExtensionType::AudioLevel => "ssrc-audio-level",
                RtpExtensionType::TransmissionTimeOffset => "toffset",
                RtpExtensionType::VideoOrientation => "video-orientation",
                RtpExtensionType::TransportSequenceNumber => "transport-wide-cc",
                RtpExtensionType::PlayoutDelay => "playout-delay",
                RtpExtensionType::VideoContentType => "video-content-type",
                RtpExtensionType::VideoTiming => "video-timing",
                RtpExtensionType::RtpStreamId => "rtp-stream-id",
                RtpExtensionType::RepairedRtpStreamId => "repaired-rtp-stream-id",
                RtpExtensionType::RtpMid => "mid",
                RtpExtensionType::FrameMarking => "frame-marking07",
                RtpExtensionType::ColorSpace => "color-space",
                RtpExtensionType::UnknownUri => "unknown-uri",
                RtpExtensionType::UnknownExt => "unknown-ext",
            }
        )
    }
}
