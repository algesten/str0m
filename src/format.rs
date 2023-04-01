//! Media formats and parameters

use std::collections::HashMap;
use std::fmt;

use crate::media::MediaKind;
use crate::rtp::Pt;
use crate::sdp;

/// Group of parameters for a payload type (PT).
///
/// In the SDP a payload type has a number of associated parameters. See example below:
///
/// ```text
/// a=rtpmap:96 H264/90000
/// a=rtcp-fb:96 goog-remb
/// a=rtcp-fb:96 transport-cc
/// a=rtcp-fb:96 ccm fir
/// a=rtcp-fb:96 nack
/// a=rtcp-fb:96 nack pli
/// a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadParams {
    /// The payload type that groups these parameters.
    pub(crate) pt: Pt,

    /// Whether these parameters are repairing some other set of parameters.
    /// This is used to, via PT, separate RTX resend streams from the main stream.
    pub(crate) resend: Option<Pt>,

    /// The codec with settings for this group of parameters.
    pub(crate) spec: CodecSpec,

    /// Whether the payload use the TWCC feedback mechanic.
    pub(crate) fb_transport_cc: bool,

    /// Whether the payload uses NACK to request resends.
    pub(crate) fb_nack: bool,

    /// Whether the payload uses the PLI (Picture Loss Indication) mechanic.
    pub(crate) fb_pli: bool,

    /// Whether the payload uses the FIR (Full Intra Request) mechanic.
    pub(crate) fb_fir: bool,

    /// Internal field whether the payload is matched to the remote. This is used in SDP
    /// negotiation.
    pub(crate) pt_matched_to_remote: bool,
}

/// Codec specification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecSpec {
    /// The codec identifier.
    pub codec: Codec,

    /// Clock rate of the codec.
    pub clock_rate: u32,

    /// Number of audio channels (if any).
    pub channels: Option<u8>,

    /// Codec specific format parameters. This might carry additional config for
    /// things like h264.
    pub format: FormatParams,
}

/// Known codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Codec {
    Opus,
    H264,
    // TODO show this when we support h265.
    #[doc(hidden)]
    H265,
    Vp8,
    Vp9,
    // TODO show this when we support Av1.
    #[doc(hidden)]
    Av1,
    /// Technically not a codec, but used in places where codecs go
    /// in `a=rtpmap` lines.
    #[doc(hidden)]
    Rtx,
    #[doc(hidden)]
    Unknown,
}

/// Codec specific format parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FormatParams {
    /// Opus specific parameter.
    ///
    /// The minimum duration of media represented by a packet.
    pub min_p_time: Option<u8>,

    /// Opus specific parameter.
    ///
    /// Specifies that the decoder can do Opus in-band FEC
    pub use_inband_fec: Option<bool>,

    /// Whether h264 sending media encoded at a different level in the offerer-to-answerer
    /// direction than the level in the answerer-to-offerer direction, is allowed.
    pub level_asymmetry_allowed: Option<bool>,

    /// What h264 packetization mode is used.
    ///
    /// * 0 - single nal.
    /// * 1 - STAP-A, FU-A is allowed. Non-interleaved.
    pub packetization_mode: Option<u8>,

    /// H264 profile level.
    ///
    /// * 42 00 1f - 4200=baseline (B)              1f=level 3.1
    /// * 42 e0 1f - 42e0=constrained baseline (CB) 1f=level 3.1
    /// * 4d 00 1f - 4d00=main (M)                  1f=level 3.1
    /// * 64 00 1f - 6400=high (H)                  1f=level 3.1
    pub profile_level_id: Option<u32>,

    /// VP9 profile id.
    pub profile_id: Option<u32>,
}

/// Session config for all codecs.
#[derive(Debug, Clone, Default)]
pub struct CodecConfig {
    configs: Vec<PayloadParams>,
}

impl PayloadParams {
    /// Creates new payload params.
    ///
    /// * `pt` is the payload type RTP mapping in the session.
    /// * `resend` is the payload type used for (RTX) resend channel.
    /// * `spec` configures details about the codec.
    pub fn new(pt: Pt, resend: Option<Pt>, spec: CodecSpec) -> Self {
        let is_video = spec.codec.is_video();

        PayloadParams {
            pt,
            resend,

            spec,

            // Both audio and video use TWCC
            fb_transport_cc: true,

            // Only true for video.
            fb_fir: is_video,
            fb_nack: is_video,
            fb_pli: is_video,

            pt_matched_to_remote: false,
        }
    }

    /// The payload type that groups these parameters.
    pub fn pt(&self) -> Pt {
        self.pt
    }

    /// Whether these parameters are repairing some other set of parameters.
    /// This is used to, via PT, separate RTX resend streams from the main stream.
    pub fn resend(&self) -> Option<Pt> {
        self.resend
    }

    /// The codec with settings for this group of parameters.
    pub fn spec(&self) -> CodecSpec {
        self.spec
    }

    pub(crate) fn match_score(&self, o: &PayloadParams) -> Option<usize> {
        // we don't want to compare PT
        let c0 = self.spec;
        let c1 = o.spec;

        if c0 == c1 {
            return Some(100);
        } else {
            // TODO: fuzzy matching.
        }

        // No match
        None
    }

    fn update_pt(&mut self, media_pts: &[PayloadParams]) -> Option<(Pt, Pt)> {
        let first = media_pts
            .iter()
            .find(|p| self.match_score(p) == Some(100))?;

        let remote_pt = first.pt;

        if self.pt_matched_to_remote {
            // just verify it's still the same.
            if self.pt != remote_pt {
                warn!("Remote PT changed {} => {}", self.pt, remote_pt);
            }

            None
        } else {
            let replaced = self.pt;

            // Lock down the PT
            self.pt = remote_pt;
            self.pt_matched_to_remote = true;

            Some((remote_pt, replaced))
        }
    }
}

impl CodecConfig {
    /// Creates a new empty config.
    pub fn new() -> Self {
        CodecConfig::default()
    }

    /// Creates a new config with all default configurations enabled.
    pub fn new_with_defaults() -> Self {
        let mut c = Self::new();
        c.add_default_opus();

        c.add_default_vp8();
        c.add_default_h264();
        // c.add_default_av1();
        c.add_default_vp9();

        c
    }

    /// Clear all configured configs.
    pub fn clear(&mut self) {
        self.configs.clear();
    }

    pub(crate) fn matches(&self, c: &PayloadParams) -> bool {
        self.configs.iter().any(|x| x.spec == c.spec)
    }

    /// Manually configure a payload type.
    pub fn add_config(
        &mut self,
        pt: Pt,
        resend: Option<Pt>,
        codec: Codec,
        clock_rate: u32,
        channels: Option<u8>,
        format: FormatParams,
    ) {
        let (fb_transport_cc, fb_fir, fb_nack, fb_pli, resend) = if codec.is_video() {
            (true, true, true, true, resend)
        } else {
            (true, false, false, false, None)
        };

        let p = PayloadParams {
            pt,
            spec: CodecSpec {
                codec,
                clock_rate,
                channels,
                format,
            },
            resend,
            fb_transport_cc,
            fb_fir,
            fb_nack,
            fb_pli,
            pt_matched_to_remote: false,
        };

        self.configs.push(p);
    }

    /// Convenience for adding a h264 payload type.
    pub fn add_h264(
        &mut self,
        pt: Pt,
        resend: Option<Pt>,
        packetization_mode: bool,
        profile_level_id: u32,
    ) {
        self.add_config(
            pt,
            resend,
            Codec::H264,
            90_000,
            None,
            FormatParams {
                level_asymmetry_allowed: Some(true),
                packetization_mode: if packetization_mode { Some(1) } else { Some(0) },
                profile_level_id: Some(profile_level_id),
                ..Default::default()
            },
        )
    }

    /// Add a default OPUS payload type.
    pub fn add_default_opus(&mut self) {
        self.add_config(
            111.into(),
            None,
            Codec::Opus,
            48_000,
            Some(2),
            FormatParams {
                min_p_time: Some(10),
                use_inband_fec: Some(true),
                ..Default::default()
            },
        )
    }

    /// Add a default VP8 payload type.
    pub fn add_default_vp8(&mut self) {
        self.add_config(
            96.into(),
            Some(97.into()),
            Codec::Vp8,
            90_000,
            None,
            FormatParams::default(),
        )
    }

    /// Add a default H264 payload type.
    pub fn add_default_h264(&mut self) {
        const PARAMS: &[(u8, u8, bool, u32)] = &[
            (127, 121, true, 0x42001f),
            (125, 107, false, 0x42001f),
            (108, 109, true, 0x42e01f),
            (124, 120, false, 0x42e01f),
            (123, 119, true, 0x4d001f),
            (35, 36, false, 0x4d001f),
            (114, 115, true, 0x64001f),
        ];

        for p in PARAMS {
            self.add_h264(p.0.into(), Some(p.1.into()), p.2, p.3)
        }
    }

    // TODO: AV1 depacketizer/packetizer.
    //
    // /// Add a default AV1 payload type.
    // pub fn add_default_av1(&mut self) {
    //     self.add_config(
    //         41.into(),
    //         Some(42.into()),
    //         Codec::Av1,
    //         90_000,
    //         None,
    //         FormatParams::default(),
    //     )
    // }

    /// Add a default VP9 payload type.
    pub fn add_default_vp9(&mut self) {
        self.add_config(
            98.into(),
            Some(99.into()),
            Codec::Vp9,
            90_000,
            None,
            FormatParams {
                profile_id: Some(0),
                ..Default::default()
            },
        );
        self.add_config(
            100.into(),
            Some(101.into()),
            Codec::Vp9,
            90_000,
            None,
            FormatParams {
                profile_id: Some(2),
                ..Default::default()
            },
        );
    }

    pub(crate) fn all_for_kind(&self, kind: MediaKind) -> impl Iterator<Item = &PayloadParams> {
        self.configs.iter().filter(move |params| {
            if kind == MediaKind::Video {
                params.spec.codec.is_video()
            } else {
                params.spec.codec.is_audio()
            }
        })
    }

    pub(crate) fn update_pts(&mut self, m: &sdp::MediaLine) {
        let pts = m.rtp_params();
        let mut replaceds = Vec::with_capacity(pts.len());
        let mut assigneds = HashMap::with_capacity(pts.len());

        for (i, p) in self.configs.iter_mut().enumerate() {
            if let Some((assigned, replaced)) = p.update_pt(&pts[..]) {
                replaceds.push(replaced);
                assigneds.insert(assigned, i);
            }
        }

        // Need to adjust potentially clashes introduced by assigning pts from the medias.
        for (i, p) in self.configs.iter_mut().enumerate() {
            if let Some(index) = assigneds.get(&p.pt) {
                if i != *index {
                    // This PT has been reassigned. This unwrap is ok
                    // because we can't have replaced something without
                    // also get the old PT out.
                    let r = replaceds.pop().unwrap();
                    p.pt = r;
                }
            }
        }
    }
}

impl fmt::Display for FormatParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self
            .to_format_param()
            .into_iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(";");
        write!(f, "{s}")
    }
}

impl Codec {
    /// Tells if codec is audio.
    pub fn is_audio(&self) -> bool {
        use Codec::*;
        matches!(self, Opus)
    }

    /// Tells if codec is video.
    pub fn is_video(&self) -> bool {
        use Codec::*;
        matches!(self, H264 | Vp8 | Vp9 | Av1)
    }
}

impl<'a> From<&'a str> for Codec {
    fn from(v: &'a str) -> Self {
        let lc = v.to_ascii_lowercase();
        match &lc[..] {
            "opus" => Codec::Opus,
            "h264" => Codec::H264,
            "h265" => Codec::H265,
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
            Codec::H264 => write!(f, "H264"),
            Codec::H265 => write!(f, "H265"),
            Codec::Vp8 => write!(f, "VP8"),
            Codec::Vp9 => write!(f, "VP9"),
            Codec::Av1 => write!(f, "AV1"),
            Codec::Rtx => write!(f, "rtx"),
            Codec::Unknown => write!(f, "unknown"),
        }
    }
}
