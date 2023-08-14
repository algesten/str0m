//! Media formats and parameters

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::RangeInclusive;

use crate::packet::MediaKind;
use crate::rtp_::Pt;
use crate::sdp::FormatParam;

// These really don't belong anywhere, but I guess they're kind of related
// to codecs etc.
pub use crate::packet::{CodecExtra, Vp8CodecExtra};

/// Session config for all codecs.
#[derive(Debug, Clone, Default)]
pub struct CodecConfig {
    params: Vec<PayloadParams>,
}

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
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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

    /// Whether the payload is locked by negotiation or can still be debated.
    ///
    /// If we make an OFFER or ANSWER and the direction is sendrecv/recvonly, the parameters are locked
    /// can't be further changed. If we make an OFFER for a sendonly, the parameters are only proposed
    /// and don't lock.
    pub(crate) locked: bool,
}

// we don't want to compare "locked"
impl PartialEq for PayloadParams {
    fn eq(&self, other: &Self) -> bool {
        self.pt == other.pt
            && self.resend == other.resend
            && self.spec == other.spec
            && self.fb_transport_cc == other.fb_transport_cc
            && self.fb_nack == other.fb_nack
            && self.fb_pli == other.fb_pli
            && self.fb_fir == other.fb_fir
    }
}

impl Eq for PayloadParams {}

/// Codec specification
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// For RTP mode. No codec.
    #[doc(hidden)]
    Null,
    #[doc(hidden)]
    Unknown,
}

/// Codec specific format parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
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

            locked: false,
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

    /// Sets whether the payload use the TWCC feedback mechanic.
    pub fn set_fb_transport_cc(&mut self, fb_transport_cc: bool) {
        self.fb_transport_cc = fb_transport_cc
    }

    /// Whether the payload use the TWCC feedback mechanic.
    pub fn fb_transport_cc(&self) -> bool {
        self.fb_transport_cc
    }

    /// Sets whether the payload uses NACK to request resends.
    pub fn set_fb_nack(&mut self, fb_nack: bool) {
        self.fb_nack = fb_nack
    }

    /// Whether the payload uses NACK to request resends.
    pub fn fb_nack(&self) -> bool {
        self.fb_nack
    }

    /// Set whether the payload uses the PLI (Picture Loss Indication) mechanic.
    pub fn set_fb_pli(&mut self, fb_pli: bool) {
        self.fb_pli = fb_pli
    }

    /// Whether the payload uses the PLI (Picture Loss Indication) mechanic.
    pub fn fb_pli(&self) -> bool {
        self.fb_pli
    }

    /// Set whether the payload uses the FIR (Full Intra Request) mechanic.
    pub fn set_fb_fir(&mut self, fb_fir: bool) {
        self.fb_fir = fb_fir
    }

    /// Whether the payload uses the FIR (Full Intra Request) mechanic.
    pub fn fb_fir(&self) -> bool {
        self.fb_fir
    }

    pub(crate) fn match_score(&self, o: &PayloadParams) -> Option<usize> {
        // we don't want to compare PT
        let c0 = self.spec;
        let c1 = o.spec;

        if c0 == c1 {
            // Exact match
            return Some(100);
        }

        // Attempt fuzzy matching, since we don't have an exact match
        if c0.codec != c1.codec || (c0.codec == Codec::Unknown && c1.codec == Codec::Unknown) {
            // Codecs must match
            return None;
        }

        if c0.clock_rate != c1.clock_rate {
            // Clock rates must match
            return None;
        }

        if c0.channels != c1.channels {
            // Channels must match
            return None;
        }

        if c0.codec.is_audio() && c0.codec == Codec::Opus {
            return Some(Self::match_opus_score(c0, c1));
        }

        // TODO: Fuzzy matching for any other audio codecs
        // TODO: Fuzzy matching for video

        None
    }

    fn match_opus_score(c0: CodecSpec, c1: CodecSpec) -> usize {
        let mut score: usize = 100;

        // If neither value is specified both sides should assume the default value, 3.
        let either_p_time_specified =
            c0.format.min_p_time.is_some() || c1.format.min_p_time.is_some();
        if either_p_time_specified && c0.format.min_p_time != c1.format.min_p_time {
            score = score.saturating_sub(1);
        }

        // If neither value is specified both sides should assume FEC is not used as this is
        // the default.
        let either_fec_specified =
            c0.format.use_inband_fec.is_some() || c1.format.use_inband_fec.is_some();

        if either_fec_specified && c0.format.use_inband_fec != c1.format.use_inband_fec {
            score = score.saturating_sub(2);
        }

        score
    }

    fn update_param(&mut self, remote_pts: &[PayloadParams], claimed: &mut [bool; 128]) {
        let Some((first, _)) = remote_pts
            .iter()
            .filter_map(|p| self.match_score(p).map(|s| (p, s)))
            .max_by_key(|(_, s)| *s) else {
                return;
            };

        let remote_pt = first.pt;
        let remote_rtx = first.resend;

        if self.locked {
            // Just verify it's still the same. We should validate this in apply_offer/answer instead
            // of ever seeing this error message.
            if self.pt != remote_pt {
                warn!("Remote PT changed {} => {}", self.pt, remote_pt);
            }

            if self.resend != remote_rtx {
                warn!(
                    "Remote PT RTX changed {:?} => {:?}",
                    self.resend, remote_rtx
                );
            }
        } else {
            // Lock down the PT
            self.pt = remote_pt;
            self.resend = remote_rtx;
            self.locked = true;

            claimed.assert_claim_once(remote_pt);
            if let Some(rtx) = remote_rtx {
                claimed.assert_claim_once(rtx);
            }
        }
    }

    /// Exposed for integration tests.
    #[doc(hidden)]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl CodecConfig {
    /// Creates a new empty config.
    pub fn empty() -> Self {
        CodecConfig::default()
    }

    /// Creates a new config from payload params
    pub fn new_from_payload_params(payload_params: Vec<PayloadParams>) -> Self {
        CodecConfig {
            params: payload_params,
        }
    }

    /// Creates a new config with all default configurations enabled.
    pub fn new_with_defaults() -> Self {
        let mut c = Self::empty();
        c.enable_opus(true);

        c.enable_vp8(true);
        c.enable_h264(true);
        // c.add_default_av1();
        c.enable_vp9(true);

        c
    }

    /// Returns a reference to the payload parameters.
    pub fn params(&self) -> &[PayloadParams] {
        &self.params
    }

    /// Clear all configured configs.
    pub fn clear(&mut self) {
        self.params.clear();
    }

    pub(crate) fn matches(&self, c: &PayloadParams) -> bool {
        self.params.iter().any(|x| x.match_score(c).is_some())
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
        let (fb_transport_cc, fb_fir, fb_nack, fb_pli) = if codec.is_video() {
            (true, true, true, true)
        } else {
            (true, false, false, false)
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
            locked: false,
        };

        self.params.push(p);
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
    pub fn enable_opus(&mut self, enabled: bool) {
        self.params.retain(|c| c.spec.codec != Codec::Opus);
        if !enabled {
            return;
        }
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
    pub fn enable_vp8(&mut self, enabled: bool) {
        self.params.retain(|c| c.spec.codec != Codec::Vp8);
        if !enabled {
            return;
        }
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
    pub fn enable_h264(&mut self, enabled: bool) {
        self.params.retain(|c| c.spec.codec != Codec::H264);
        if !enabled {
            return;
        }
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
    pub fn enable_vp9(&mut self, enabled: bool) {
        self.params.retain(|c| c.spec.codec != Codec::Vp9);
        if !enabled {
            return;
        }
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

    /// Match the given parameters to the configured parameters.
    ///
    /// In a server scenario, a certain codec configuration might not have the same
    /// payload type (PT) for two different peers. We will have incoming data with one
    /// PT and need to match that against the PT of the outgoing.
    ///
    /// This call performs matching and if a match is found, returns the _local_ PT
    /// that can be used for sending media.
    pub fn match_params(&self, params: PayloadParams) -> Option<&PayloadParams> {
        let c = self.params.iter().max_by_key(|p| p.match_score(&params))?;
        c.match_score(&params)?; // avoid None, which isn't a match.
        Some(c)
    }

    /// Find a payload parameter using a finder function.
    pub fn find(&self, mut f: impl FnMut(&PayloadParams) -> bool) -> Option<&PayloadParams> {
        self.params.iter().find(move |p| f(p))
    }

    pub(crate) fn all_for_kind(&self, kind: MediaKind) -> impl Iterator<Item = &PayloadParams> {
        self.params.iter().filter(move |params| {
            if kind == MediaKind::Video {
                params.spec.codec.is_video()
            } else {
                params.spec.codec.is_audio()
            }
        })
    }

    pub(crate) fn update_params(&mut self, remote_params: &[PayloadParams]) {
        // 0-128 of "claimed" PTs. I.e. PTs that we already allocated to something.
        let mut claimed: [bool; 128] = [false; 128];

        // Make a pass with all that are definitely confirmed by the remote, since these can't change.
        for p in self.params.iter() {
            if !p.locked {
                continue;
            }

            claimed.assert_claim_once(p.pt);

            if let Some(rtx) = p.resend {
                claimed.assert_claim_once(rtx);
            }
        }

        // Now lock potential new parameters to remote.
        for p in self.params.iter_mut() {
            p.update_param(remote_params, &mut claimed);
        }

        const PREFERED_RANGES: &[RangeInclusive<usize>] = &[
            // Payload identifiers 96–127 are used for payloads defined dynamically during a session.
            96..=127,
            // "unassigned" ranged. note that RTCP packet type 207 (XR, Extended Reports) would be
            // indistinguishable from RTP payload types 79 with the marker bit set
            80..=95,
            77..=78,
            // reserved because RTCP packet types 200–204 would otherwise be indistinguishable from RTP payload types 72–76
            // 72..77,
            // lol range.
            35..=71,
        ];

        // Make a pass to reassign unconfirmed payloads that have PT which are now claimed.
        for p in self.params.iter_mut() {
            if p.locked {
                continue;
            }

            if claimed.is_claimed(p.pt) {
                let Some(pt) = claimed.find_unclaimed(PREFERED_RANGES) else {
                    // TODO: handle this gracefully.
                    panic!("Exhausted all PT ranges, inconsistent PayloadParam state");
                };

                info!("Reassigned PT {} => {}", p.pt, pt);
                p.pt = pt;

                claimed.assert_claim_once(pt);
            }

            let Some(rtx) = p.resend else {
                continue;
            };

            if claimed.is_claimed(rtx) {
                let Some(rtx) = claimed.find_unclaimed(PREFERED_RANGES) else {
                    // TODO: handle this gracefully.
                    panic!("Exhausted all PT ranges, inconsistent PayloadParam state");
                };

                info!("Reassigned RTX PT {:?} => {:?}", p.resend, rtx);
                p.resend = Some(rtx);

                claimed.assert_claim_once(rtx);
            }
        }
    }

    pub(crate) fn has_pt(&self, pt: Pt) -> bool {
        self.params.iter().any(|p| p.pt() == pt)
    }
}

trait Claimed {
    fn assert_claim_once(&mut self, pt: Pt);
    fn is_claimed(&self, pt: Pt) -> bool;
    fn find_unclaimed(&self, ranges: &[RangeInclusive<usize>]) -> Option<Pt>;
}

impl Claimed for [bool; 128] {
    fn assert_claim_once(&mut self, pt: Pt) {
        let idx = *pt as usize;
        assert!(!self[idx], "Pt locked multiple times: {}", pt);
        self[idx] = true;
    }
    fn is_claimed(&self, pt: Pt) -> bool {
        let idx = *pt as usize;
        self[idx]
    }
    fn find_unclaimed(&self, ranges: &[RangeInclusive<usize>]) -> Option<Pt> {
        for range in ranges {
            for i in range.clone() {
                if !self[i] {
                    let pt: Pt = (i as u8).into();
                    return Some(pt);
                }
            }
        }

        // Failed to find unclaimed PT.
        None
    }
}

impl FormatParams {
    /// Parse an fmtp line to create a FormatParams.
    ///
    /// Example `minptime=10;useinbandfec=1`.
    pub fn parse_line(line: &str) -> Self {
        let key_vals = line.split(';').filter_map(|pair| {
            let mut kv = pair.split('=');
            match (kv.next(), kv.next()) {
                (Some(k), Some(v)) => Some((k.trim(), v.trim())),
                _ => None,
            }
        });

        let mut p = FormatParams::default();

        for (k, v) in key_vals {
            let param = FormatParam::parse(k, v);
            p.set_param(&param);
        }

        p
    }

    pub(crate) fn set_param(&mut self, param: &FormatParam) {
        use FormatParam::*;
        match param {
            MinPTime(v) => self.min_p_time = Some(*v),
            UseInbandFec(v) => self.use_inband_fec = Some(*v),
            LevelAsymmetryAllowed(v) => self.level_asymmetry_allowed = Some(*v),
            PacketizationMode(v) => self.packetization_mode = Some(*v),
            ProfileLevelId(v) => self.profile_level_id = Some(*v),
            ProfileId(v) => self.profile_id = Some(*v),
            Apt(_) => {}
            Unknown => {}
        }
    }

    pub(crate) fn to_format_param(self) -> Vec<FormatParam> {
        use FormatParam::*;
        let mut r = Vec::with_capacity(5);

        if let Some(v) = self.min_p_time {
            r.push(MinPTime(v));
        }
        if let Some(v) = self.use_inband_fec {
            r.push(UseInbandFec(v));
        }
        if let Some(v) = self.level_asymmetry_allowed {
            r.push(LevelAsymmetryAllowed(v));
        }
        if let Some(v) = self.packetization_mode {
            r.push(PacketizationMode(v));
        }
        if let Some(v) = self.profile_level_id {
            r.push(ProfileLevelId(v));
        }
        if let Some(v) = self.profile_id {
            r.push(ProfileId(v));
        }

        r
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
            Codec::Null => write!(f, "null"),
            Codec::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::ops::Deref for CodecConfig {
    type Target = [PayloadParams];

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

impl std::ops::DerefMut for CodecConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.params
    }
}
