//! Media formats and parameters

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::RangeInclusive;

use crate::packet::MediaKind;
use crate::rtp_::Direction;
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

        if c0.codec == Codec::H264 {
            return Self::match_h264_score(c0, c1);
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

    fn match_h264_score(c0: CodecSpec, c1: CodecSpec) -> Option<usize> {
        // Default packetization mode is 0. https://www.rfc-editor.org/rfc/rfc6184#section-6.2
        let c0_packetization_mode = c0.format.packetization_mode.unwrap_or(0);
        let c1_packetization_mode = c1.format.packetization_mode.unwrap_or(0);

        if c0_packetization_mode != c1_packetization_mode {
            return None;
        }

        let c0_profile_level = c0
            .format
            .profile_level_id
            .map(|l| l.try_into().ok())
            .unwrap_or(Some(H264ProfileLevel::FALLBACK))?;
        let c1_profile_level = c1
            .format
            .profile_level_id
            .map(|l| l.try_into().ok())
            .unwrap_or(Some(H264ProfileLevel::FALLBACK))?;

        if c0_profile_level != c1_profile_level {
            return None;
        }

        Some(100)
    }

    fn update_param(
        &mut self,
        remote_pts: &[PayloadParams],
        claimed: &mut [bool; 128],
        warn_on_locked: bool,
    ) {
        let Some((first, _)) = remote_pts
            .iter()
            .filter_map(|p| self.match_score(p).map(|s| (p, s)))
            .max_by_key(|(_, s)| *s) else {
                return;
            };

        let remote_pt = first.pt;
        let remote_rtx = first.resend;

        if self.locked {
            // This can happen if the incoming PTs are suggestions (send-direction) rather than demanded
            // (receive-direction). We only want to warn if we get receive direction changes.
            if !warn_on_locked {
                return;
            }
            // Just verify it's still the same. We should validate this in apply_offer/answer instead
            // of ever seeing this error message.
            if self.pt != remote_pt {
                warn!("Ignore remote PT change {} => {}", self.pt, remote_pt);
            }

            if self.resend != remote_rtx {
                warn!(
                    "Ignore remote PT RTX change {:?} => {:?}",
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

    /// When we get remote payload parameters, we need to match differently depending on direction.
    pub(crate) fn sdp_match_remote(
        &self,
        remote_params: PayloadParams,
        remote_dir: Direction,
    ) -> Option<Pt> {
        // If we have no matching parameters locally, we can't accept the remote in any way.
        let our_params = self.match_params(remote_params)?;

        if remote_dir.sdp_is_receiving() {
            // The remote is talking about its own receive requirements. The PTs are not suggestions.
            Some(remote_params.pt())
        } else {
            // We can override the remote with our local config. We would have adjusted to
            // the remote earlier if we can.
            Some(our_params.pt())
        }
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

    pub(crate) fn update_params(&mut self, remote_params: &[PayloadParams], remote_dir: Direction) {
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
        //
        // If the remote is doing `SendOnly`, the PTs are suggestions, and we are allowed to
        // ANSWER with our own allocations as overrides. If SendRecv or RecvOnly, the remote
        // is talking about its own receiving capapbilities and we are not allowed to change it
        // in the ANSWER.
        let warn_on_locked = remote_dir.sdp_is_receiving();

        for p in self.params.iter_mut() {
            p.update_param(remote_params, &mut claimed, warn_on_locked);
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct H264ProfileLevel {
    profile: H264Profile,
    level_idc: H264LevelIdc,
}

impl H264ProfileLevel {
    // TODO: The default should really be Baseline and Level1
    // according to the spec: https://tools.ietf.org/html/rfc6184#section-8.1. However, libWebRTC
    // specifies Level3_1 to not break backwards compatibility and we copy them.
    // When libWebRTC updates we are probably safe to do the same.
    //
    // See: https://webrtc.googlesource.com/src/+/refs/heads/main/api/video_codecs/h264_profile_level_id.cc#182
    const FALLBACK: Self = Self {
        profile: H264Profile::Baseline,
        level_idc: H264LevelIdc::Level3_1,
    };

    /// Different combinations of profile-iop and profile-idc match to the same profile.
    /// See table 5 in https://www.rfc-editor.org/rfc/rfc6184#section-8.1
    ///
    /// The first value in each tuple is the profile that is matched if the profile-idc and the
    /// IOPPattern matches a given fmtp line.
    const PROFILES: &[(H264Profile, H264ProfileIdc, IOPPattern)] = &[
        // Constrained Baseline
        (
            H264Profile::ConstrainedBaseline,
            H264ProfileIdc::X42,
            IOPPattern::new(*b"x1xx0000"),
        ),
        (
            H264Profile::ConstrainedBaseline,
            H264ProfileIdc::X4D,
            IOPPattern::new(*b"1xxx0000"),
        ),
        (
            H264Profile::ConstrainedBaseline,
            H264ProfileIdc::X58,
            IOPPattern::new(*b"11xx0000"),
        ),
        // Baseline
        (
            H264Profile::Baseline,
            H264ProfileIdc::X42,
            IOPPattern::new(*b"x0xx0000"),
        ),
        (
            H264Profile::Baseline,
            H264ProfileIdc::X58,
            IOPPattern::new(*b"10xx0000"),
        ),
        // Main
        (
            H264Profile::Main,
            H264ProfileIdc::X4D,
            IOPPattern::new(*b"0x0x0000"),
        ),
        // Extended
        (
            H264Profile::Extended,
            H264ProfileIdc::X58,
            IOPPattern::new(*b"00xx0000"),
        ),
        // High(No constraints)
        (
            H264Profile::High,
            H264ProfileIdc::X64,
            IOPPattern::new(*b"00000000"),
        ),
        (
            H264Profile::High10,
            H264ProfileIdc::X6E,
            IOPPattern::new(*b"00000000"),
        ),
        (
            H264Profile::High422,
            H264ProfileIdc::X7A,
            IOPPattern::new(*b"00000000"),
        ),
        (
            H264Profile::High444Predictive,
            H264ProfileIdc::XF4,
            IOPPattern::new(*b"00000000"),
        ),
        // Intra profiles
        (
            H264Profile::High10Intra,
            H264ProfileIdc::X6E,
            IOPPattern::new(*b"00010000"),
        ),
        (
            H264Profile::High422Intra,
            H264ProfileIdc::X7A,
            IOPPattern::new(*b"00010000"),
        ),
        (
            H264Profile::High444Intra,
            H264ProfileIdc::XF4,
            IOPPattern::new(*b"00010000"),
        ),
        (
            H264Profile::CAVLC444Intra,
            H264ProfileIdc::X2C,
            IOPPattern::new(*b"00010000"),
        ),
    ];

    /// Construct a new H264ProfileLevel.
    ///
    /// Returns `Some(Self)` only if the provided parameters identify a valid profile.
    fn new(profile_idc: H264ProfileIdc, profile_iop: u8, level_idc: H264LevelIdc) -> Option<Self> {
        Self::PROFILES
            .iter()
            .find_map(|&(profile, expected_pidc, iop_pattern)| {
                // Profile IDC must match
                if expected_pidc != profile_idc {
                    return None;
                }
                // The profile-iop must match the pattern for the profile
                if !iop_pattern.matches(profile_iop) {
                    return None;
                }

                Some(Self { profile, level_idc })
            })
    }
}

impl TryFrom<u32> for H264ProfileLevel {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, ()> {
        const CONSTRAINT_SET3_FLAG: u8 = 0x10;

        let bytes = value.to_be_bytes();

        let profile_idc = bytes[1].try_into()?;
        let profile_iop = bytes[2];
        let mut profile_level = bytes[3].try_into()?;

        // When profile_idc is equal to 66, 77, or 88 (the Baseline, Main, or
        // Extended profile), level_idc is equal to 11, and bit 4
        // (constraint_set3_flag) of the profile-iop byte is equal to 1,
        // the default level is Level 1b.
        if [
            H264ProfileIdc::X42,
            H264ProfileIdc::X4D,
            H264ProfileIdc::X58,
        ]
        .contains(&profile_idc)
            && profile_level == H264LevelIdc::Level1
        {
            profile_level = if (profile_iop & CONSTRAINT_SET3_FLAG) != 0 {
                H264LevelIdc::Level1B
            } else {
                H264LevelIdc::Level1
            };
        }

        Self::new(profile_idc, profile_iop, profile_level).ok_or(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum H264Profile {
    Baseline,
    ConstrainedBaseline,
    Main,
    Extended,
    High,
    High10,
    High422,
    High444Predictive,
    High10Intra,
    High422Intra,
    High444Intra,
    CAVLC444Intra,
}

/// The various h264 profile_idc, not all of these have a name,
/// but they are a constrained portion of `u8`, hence an
/// enum to prevent using unspecified values.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum H264ProfileIdc {
    X2C = 44_u8,
    X42 = 66_u8, // B
    X4D = 77_u8, // M
    X58 = 88_u8, // E
    X64 = 100_u8,
    X6E = 110_u8,
    X7A = 122_u8,
    XF4 = 244_u8,
}

impl TryFrom<u8> for H264ProfileIdc {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if (Self::X2C as u8) == x => Ok(Self::X2C),
            x if (Self::X42 as u8) == x => Ok(Self::X42),
            x if (Self::X4D as u8) == x => Ok(Self::X4D),
            x if (Self::X58 as u8) == x => Ok(Self::X58),
            x if (Self::X64 as u8) == x => Ok(Self::X64),
            x if (Self::X6E as u8) == x => Ok(Self::X6E),
            x if (Self::X7A as u8) == x => Ok(Self::X7A),
            x if (Self::XF4 as u8) == x => Ok(Self::XF4),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone)]
struct IOPPattern {
    mask: u8,
    masked_value: u8,
}

impl IOPPattern {
    fn matches(&self, profile_iop: u8) -> bool {
        ((profile_iop ^ self.masked_value) & self.mask) == 0x0
    }

    const fn new(pattern: [u8; 8]) -> Self {
        const fn bit_to_mask_bit(pattern: [u8; 8], i: usize) -> u8 {
            let bit = pattern[7 - i];
            match bit {
                b'1' | b'0' => 0x1 << i,
                b'x' => 0x0 << i,
                _ => panic!("Invalid bit pattern in IOPPattern only ASCII 1, 0, and x are allowed"),
            }
        }

        const fn to_mask(pattern: [u8; 8]) -> u8 {
            bit_to_mask_bit(pattern, 7)
                | bit_to_mask_bit(pattern, 6)
                | bit_to_mask_bit(pattern, 5)
                | bit_to_mask_bit(pattern, 4)
                | bit_to_mask_bit(pattern, 3)
                | bit_to_mask_bit(pattern, 2)
                | bit_to_mask_bit(pattern, 1)
                | bit_to_mask_bit(pattern, 0)
        }

        const fn bit_to_mask_value_bit(pattern: [u8; 8], i: usize) -> u8 {
            let bit = pattern[7 - i];
            match bit {
                b'1' => 0x1 << i,
                b'x' | b'0' => 0x0 << i,
                _ => panic!("Invalid bit pattern in IOPPattern only ASCII 1, 0, and x are allowed"),
            }
        }

        const fn to_mask_value(pattern: [u8; 8]) -> u8 {
            bit_to_mask_value_bit(pattern, 7)
                | bit_to_mask_value_bit(pattern, 6)
                | bit_to_mask_value_bit(pattern, 5)
                | bit_to_mask_value_bit(pattern, 4)
                | bit_to_mask_value_bit(pattern, 3)
                | bit_to_mask_value_bit(pattern, 2)
                | bit_to_mask_value_bit(pattern, 1)
                | bit_to_mask_value_bit(pattern, 0)
        }
        let mask = to_mask(pattern);
        let masked_value = to_mask_value(pattern);

        Self { mask, masked_value }
    }
}

// Per libWebRTC
//     All values are equal to ten times the level number, except level 1b which is
//     special.
// Can't find the source for this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum H264LevelIdc {
    Level1B = 0_u8,
    Level1 = 10_u8,
    Level1_1 = 11_u8,
    Level1_2 = 12_u8,
    Level1_3 = 13_u8,
    Level2 = 20_u8,
    Level2_1 = 21_u8,
    Level2_2 = 22_u8,
    Level3 = 30_u8,
    Level3_1 = 31_u8,
    Level3_2 = 32_u8,
    Level4 = 40_u8,
    Level4_1 = 41_u8,
    Level4_2 = 42_u8,
    Level5 = 50_u8,
    Level5_1 = 51_u8,
    Level5_2 = 52_u8,
}

impl TryFrom<u8> for H264LevelIdc {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use H264LevelIdc::*;

        match value {
            x if (Level1B as u8) == x => Ok(Level1B),
            x if (Level1 as u8) == x => Ok(Level1),
            x if (Level1_1 as u8) == x => Ok(Level1_1),
            x if (Level1_2 as u8) == x => Ok(Level1_2),
            x if (Level1_3 as u8) == x => Ok(Level1_3),
            x if (Level2 as u8) == x => Ok(Level2),
            x if (Level2_1 as u8) == x => Ok(Level2_1),
            x if (Level2_2 as u8) == x => Ok(Level2_2),
            x if (Level3 as u8) == x => Ok(Level3),
            x if (Level3_1 as u8) == x => Ok(Level3_1),
            x if (Level3_2 as u8) == x => Ok(Level3_2),
            x if (Level4 as u8) == x => Ok(Level4),
            x if (Level4_1 as u8) == x => Ok(Level4_1),
            x if (Level4_2 as u8) == x => Ok(Level4_2),
            x if (Level5 as u8) == x => Ok(Level5),
            x if (Level5_1 as u8) == x => Ok(Level5_1),
            x if (Level5_2 as u8) == x => Ok(Level5_2),
            _ => Err(()),
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

#[cfg(test)]
mod test {
    use super::{Codec, CodecSpec, FormatParams, H264LevelIdc, IOPPattern, PayloadParams};

    #[test]
    fn test_iop_pattern_matching() {
        let all_any = IOPPattern::new(*b"xxxxxxxx");
        for x in 0..255 {
            assert!(all_any.matches(x));
        }

        let stripes = IOPPattern::new(*b"10101010");
        assert!(stripes.matches(0b1010_1010));
        assert!(!stripes.matches(0b1011_1010));

        let inverse_stripes = IOPPattern::new(*b"01010101");
        assert!(inverse_stripes.matches(0b0101_0101));
        assert!(!inverse_stripes.matches(0b0111_0001));

        let high_bits = IOPPattern::new(*b"1101xxxx");
        assert!(high_bits.matches(0b1101_0101));
        assert!(!high_bits.matches(0b1001_0101));

        let mid_bits = IOPPattern::new(*b"xx0110xx");
        assert!(mid_bits.matches(0b0101_1001));
        assert!(!mid_bits.matches(0b1000_1001));

        let only_ones = IOPPattern::new(*b"11111111");
        assert!(only_ones.matches(0b1111_1111));
        assert!(!only_ones.matches(0b1110_1111));

        let only_zeros = IOPPattern::new(*b"00000000");
        assert!(only_zeros.matches(0b0000_0000));
        assert!(!only_zeros.matches(0b0000_0010));

        let mixed_pattern = IOPPattern::new(*b"1x0x1x01");
        assert!(mixed_pattern.matches(0b11011001));
        assert!(!mixed_pattern.matches(0b11011011));

        let complex_pattern = IOPPattern::new(*b"1xx01x0x");
        assert!(complex_pattern.matches(0b10001001));
        assert!(!complex_pattern.matches(0b10101010));
    }

    fn h264_codec_spec(
        level_asymmetry_allowed: Option<bool>,
        packetization_mode: Option<u8>,
        profile_level_id: Option<u32>,
    ) -> CodecSpec {
        CodecSpec {
            codec: Codec::H264,
            clock_rate: 90000,
            channels: None,
            format: FormatParams {
                min_p_time: None,
                use_inband_fec: None,
                level_asymmetry_allowed,
                packetization_mode,
                profile_level_id,
                profile_id: None, // VP8
            },
        }
    }

    #[test]
    fn test_h264_profile_matching() {
        struct Case {
            c0: CodecSpec,
            c1: CodecSpec,
            must_match: bool,
            msg: &'static str,
        }

        let cases = [Case {
            c0: h264_codec_spec(None, None, Some(0x42E01F)),
            c1: h264_codec_spec(None, None, Some(0x4DA01F)),
            must_match: true,
            msg:
                "0x42A01F and 0x4DF01F should match, they are both constrained baseline subprofile",
        }, Case {
            c0: h264_codec_spec(None, None, Some(0x42E01F)),
            c1: h264_codec_spec(None, Some(1), Some(0x4DA01F)),
            must_match: false,
            msg:
                "0x42A01F and 0x4DF01F with differing packetization modes should not match",
        },  Case {
            c0: h264_codec_spec(None, Some(0), Some(0x422000)),
            c1: h264_codec_spec(None, None, Some(0x42B00A)),
            must_match: true,
            msg:
                "0x424000 and 0x42B00A should match because they are both the baseline subprofile and the level idc of 0x42F01F will be adjusted to Level1B because the constraint set 3 flag is set"
        }];

        for Case {
            c0,
            c1,
            must_match,
            msg,
        } in cases.into_iter()
        {
            let matched = PayloadParams::match_h264_score(c0, c1).is_some();
            assert_eq!(matched, must_match, "{msg}\nc0: {c0:#?}\nc1: {c1:#?}");
        }
    }
}
