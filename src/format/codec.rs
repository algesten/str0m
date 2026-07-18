use serde::{Deserialize, Serialize};
use std::fmt;

use crate::packet::MediaKind;
use crate::rtp_::Frequency;

use super::format_params::FormatParams;

/// Codec specification
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecSpec {
    /// The codec identifier.
    pub codec: Codec,

    /// Clock rate of the codec.
    pub clock_rate: Frequency,

    /// Number of audio channels (if any).
    pub channels: Option<u8>,

    /// Codec specific format parameters. This might carry additional config for
    /// things like h264.
    pub format: FormatParams,
}

impl CodecSpec {
    /// The RTP clock rate used on the wire for this codec.
    ///
    /// For most codecs this is the same as [`CodecSpec::clock_rate`]. G722 is a
    /// special case: although the codec samples audio at 16 kHz, its RTP timestamp
    /// clock is 8000 Hz (to remain backwards compatible with RFC 1890, which
    /// incorrectly used this value). str0m treats G722 as a 16 kHz codec everywhere
    /// user facing, and only maps to 8 kHz when converting to and from RTP timestamps
    /// (and in the SDP `a=rtpmap` line).
    ///
    /// See RFC 3551 §4.5.2 and
    /// <https://en.wikipedia.org/wiki/RTP_payload_formats#cite_note-55>
    pub(crate) fn rtp_clock_rate(&self) -> Frequency {
        if self.codec == Codec::G722 {
            Frequency::EIGHT_KHZ
        } else {
            self.clock_rate
        }
    }
}

/// Known codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Codec {
    Opus,
    PCMU,
    PCMA,
    G722,
    /// Comfort Noise payload, per RFC 3389.
    ComfortNoise,
    H264,
    // TODO show this when we support h265.
    #[doc(hidden)]
    H265,
    /// H266/VVC.
    H266,
    Vp8,
    Vp9,
    // TODO show this when we support Av1.
    #[doc(hidden)]
    Av1,
    /// Technically not a codec, but used in places where codecs go
    /// in `a=rtpmap` lines.
    #[doc(hidden)]
    Rtx,
    /// For RTP mode. No codec.
    #[doc(hidden)]
    Null,
    #[doc(hidden)]
    Unknown,
}

#[cfg(feature = "drv")]
crate::drv_identity_copy!(Codec, CodecSpec);

impl Codec {
    /// Tells if codec is audio.
    pub fn is_audio(&self) -> bool {
        use Codec::*;
        matches!(self, Opus | PCMU | PCMA | G722 | ComfortNoise)
    }

    /// Tells if codec is video.
    pub fn is_video(&self) -> bool {
        use Codec::*;
        matches!(self, H266 | H265 | H264 | Vp8 | Vp9 | Av1)
    }

    /// Audio/Video.
    pub fn kind(&self) -> MediaKind {
        if self.is_audio() {
            MediaKind::Audio
        } else {
            MediaKind::Video
        }
    }
}

impl<'a> From<&'a str> for Codec {
    fn from(v: &'a str) -> Self {
        let lc = v.to_ascii_lowercase();
        match &lc[..] {
            "opus" => Codec::Opus,
            "pcmu" => Codec::PCMU,
            "pcma" => Codec::PCMA,
            "g722" => Codec::G722,
            "cn" => Codec::ComfortNoise,
            "h264" => Codec::H264,
            "h265" => Codec::H265,
            "h266" => Codec::H266,
            "vp8" => Codec::Vp8,
            "vp9" => Codec::Vp9,
            "av1" => Codec::Av1,
            "rtx" => Codec::Rtx, // resends
            _ => Codec::Unknown,
        }
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Codec::Opus => write!(f, "opus"),
            Codec::PCMU => write!(f, "PCMU"),
            Codec::PCMA => write!(f, "PCMA"),
            Codec::G722 => write!(f, "G722"),
            Codec::ComfortNoise => write!(f, "CN"),
            Codec::H264 => write!(f, "H264"),
            Codec::H265 => write!(f, "H265"),
            Codec::H266 => write!(f, "H266"),
            Codec::Vp8 => write!(f, "VP8"),
            Codec::Vp9 => write!(f, "VP9"),
            Codec::Av1 => write!(f, "AV1"),
            Codec::Rtx => write!(f, "rtx"),
            Codec::Null => write!(f, "null"),
            Codec::Unknown => write!(f, "unknown"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::format::FormatParams;
    use crate::rtp_::{Frequency, MediaTime};

    fn g722_spec() -> CodecSpec {
        CodecSpec {
            codec: Codec::G722,
            clock_rate: Frequency::SIXTEEN_KHZ,
            channels: None,
            format: FormatParams::default(),
        }
    }

    #[test]
    fn g722_is_audio_and_parses() {
        assert!(Codec::G722.is_audio());
        assert!(!Codec::G722.is_video());
        assert_eq!(Codec::from("G722"), Codec::G722);
        assert_eq!(Codec::from("g722"), Codec::G722);
        assert_eq!(Codec::G722.to_string(), "G722");
    }

    #[test]
    fn comfort_noise_is_audio_and_parses() {
        assert!(Codec::ComfortNoise.is_audio());
        assert!(!Codec::ComfortNoise.is_video());
        assert_eq!(Codec::from("CN"), Codec::ComfortNoise);
        assert_eq!(Codec::from("cn"), Codec::ComfortNoise);
        assert_eq!(Codec::ComfortNoise.to_string(), "CN");
    }

    #[test]
    fn g722_rtp_clock_rate_is_8khz() {
        let spec = g722_spec();
        // User facing clock rate is 16 kHz ...
        assert_eq!(spec.clock_rate, Frequency::SIXTEEN_KHZ);
        // ... but the RTP wire clock rate is 8 kHz (RFC 3551).
        assert_eq!(spec.rtp_clock_rate(), Frequency::EIGHT_KHZ);
    }

    #[test]
    fn g722_16khz_media_time_halves_on_the_wire() {
        // 20 ms of 16 kHz audio is 320 samples. On the wire the RTP timestamp must
        // advance by 160 (8000 Hz clock), i.e. the 16 kHz media time is halved when
        // converted to an RTP timestamp.
        let spec = g722_spec();
        let media_time = MediaTime::new(320, spec.clock_rate);
        let wire = media_time.rebase(spec.rtp_clock_rate());
        assert_eq!(wire.numer(), 160);
    }

    #[test]
    fn non_g722_rtp_clock_rate_equals_clock_rate() {
        let spec = CodecSpec {
            codec: Codec::Opus,
            clock_rate: Frequency::FORTY_EIGHT_KHZ,
            channels: Some(2),
            format: FormatParams::default(),
        };
        assert_eq!(spec.rtp_clock_rate(), Frequency::FORTY_EIGHT_KHZ);
    }
}
