use serde::{Deserialize, Serialize};
use std::fmt;

use crate::sdp::FormatParam;

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

    /// Opus specific parameter.
    ///
    /// Specifies that the decoder prefers DTX (Discontinuous Transmission) such that
    /// the packet rate is greatly lowered during periods of silence.
    pub use_dtx: Option<bool>,

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

    /// AV1 profile.
    ///
    /// Indicates the highest AV1 profile that may have been used to generate
    /// the bitstream or that the receiver supports. The range of possible values
    /// is identical to the seq_profile syntax element specified in AV1. If the
    /// parameter is not present, it MUST be inferred to be 0 ("Main" profile).
    ///
    /// 0  8-bit or 10-bit 4:2:0
    /// 1  8-bit or 10-bit 4:4:4
    /// 2  8-bit or 10-bit 4:2:2
    /// 2  12-bit          4:2:0, 4:2:2, 4:4:4
    pub profile: Option<u8>,

    /// AV1 level-idx.
    ///
    /// Indicates the highest AV1 level that may have been used to generate the
    /// bitstream or that the receiver supports. The range of possible values
    /// is identical to the seq_level_idx syntax element specified in AV1. If
    /// the parameter is not present, it MUST be inferred to be 5 (level 3.1).
    pub level_idx: Option<u8>,

    /// AV1 tier.
    ///
    /// Indicates the highest tier that may have been used to generate the  bitstream
    /// or that the receiver supports. The range of possible values is identical
    /// to the seq_tier syntax element specified in AV1. If the parameter is not
    /// present, the tier MUST be inferred to be 0.
    pub tier: Option<u8>,

    /// H.265/HEVC profile, tier, and level.
    ///
    /// Contains:
    /// * profile: Main, Main10, Main Still Picture, etc.
    /// * tier: Main or High.
    /// * level: 3.1, 4.0, 5.0, etc.
    ///
    /// See ITU-T H.265 Annex A for complete definitions.
    pub h265_profile_tier_level: Option<crate::packet::H265ProfileTierLevel>,
}

impl FormatParams {
    /// Parse an fmtp line to create a FormatParams.
    ///
    /// Example `minptime=10;useinbandfec=1`.
    pub fn parse_line(line: &str) -> Self {
        use crate::packet::H265ProfileTierLevel;
        use std::collections::HashMap;

        let key_vals: Vec<_> = line
            .split(';')
            .filter_map(|pair| {
                let mut kv = pair.split('=');
                match (kv.next(), kv.next()) {
                    (Some(k), Some(v)) => Some((k.trim().to_string(), v.trim().to_string())),
                    _ => None,
                }
            })
            .collect();

        let is_h265 = key_vals
            .iter()
            .any(|(k, _)| k == "tier-flag" || k == "level-id");

        let mut p = FormatParams::default();

        if is_h265 {
            let map: HashMap<String, String> = key_vals.into_iter().collect();
            if let Some(ptl) = H265ProfileTierLevel::from_fmtp(&map) {
                p.set_param(&FormatParam::H265ProfileTierLevel(ptl));
            }
            // Parse non-PTL parameters
            for (k, v) in map.iter() {
                if k != "profile-id" && k != "tier-flag" && k != "level-id" {
                    p.set_param(&FormatParam::parse(k, v));
                }
            }
        } else {
            for (k, v) in key_vals {
                p.set_param(&FormatParam::parse(&k, &v));
            }
        }

        p
    }

    pub(crate) fn set_param(&mut self, param: &FormatParam) {
        use FormatParam::*;
        match param {
            MinPTime(v) => self.min_p_time = Some(*v),
            UseInbandFec(v) => self.use_inband_fec = Some(*v),
            UseDtx(v) => self.use_dtx = Some(*v),
            LevelAsymmetryAllowed(v) => self.level_asymmetry_allowed = Some(*v),
            PacketizationMode(v) => self.packetization_mode = Some(*v),
            ProfileLevelId(v) => self.profile_level_id = Some(*v),
            ProfileId(v) => self.profile_id = Some(*v),
            Profile(v) => self.profile = Some(*v),
            LevelIdx(v) => self.level_idx = Some(*v),
            Tier(v) => self.tier = Some(*v),
            H265ProfileTierLevel(v) => self.h265_profile_tier_level = Some(*v),
            // H.265 individual params are only for SDP serialization, not for setting
            H265ProfileId(_) | H265TierFlag(_) | H265LevelId(_) => {}
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
        if let Some(v) = self.use_dtx {
            r.push(UseDtx(v));
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
        if let Some(v) = self.profile {
            r.push(Profile(v));
        }
        if let Some(v) = self.level_idx {
            r.push(LevelIdx(v));
        }
        if let Some(v) = self.tier {
            r.push(Tier(v));
        }
        // H.265 Profile/Tier/Level: Expand composite into three separate params for SDP.
        if let Some(ptl) = self.h265_profile_tier_level {
            r.push(H265ProfileId(ptl.profile_id()));
            r.push(H265TierFlag(ptl.tier_flag()));
            r.push(H265LevelId(ptl.level_id()));
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
