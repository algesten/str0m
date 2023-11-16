use crate::util::BitPattern;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct H264ProfileLevel {
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
    pub(crate) const FALLBACK: Self = Self {
        profile: H264Profile::Baseline,
        level_idc: H264LevelIdc::Level3_1,
    };

    /// Different combinations of profile-iop and profile-idc match to the same profile.
    /// See table 5 in https://www.rfc-editor.org/rfc/rfc6184#section-8.1
    ///
    /// The first value in each tuple is the profile that is matched if the profile-idc and the
    /// BitPattern matches a given fmtp line.
    const PROFILES: &'static [(H264Profile, H264ProfileIdc, BitPattern)] = &[
        // Constrained Baseline
        (
            H264Profile::ConstrainedBaseline,
            H264ProfileIdc::X42,
            BitPattern::new(*b"x1xx0000"),
        ),
        (
            H264Profile::ConstrainedBaseline,
            H264ProfileIdc::X4D,
            BitPattern::new(*b"1xxx0000"),
        ),
        (
            H264Profile::ConstrainedBaseline,
            H264ProfileIdc::X58,
            BitPattern::new(*b"11xx0000"),
        ),
        // Baseline
        (
            H264Profile::Baseline,
            H264ProfileIdc::X42,
            BitPattern::new(*b"x0xx0000"),
        ),
        (
            H264Profile::Baseline,
            H264ProfileIdc::X58,
            BitPattern::new(*b"10xx0000"),
        ),
        // Main
        (
            H264Profile::Main,
            H264ProfileIdc::X4D,
            BitPattern::new(*b"0x0x0000"),
        ),
        // Extended
        (
            H264Profile::Extended,
            H264ProfileIdc::X58,
            BitPattern::new(*b"00xx0000"),
        ),
        // High(No constraints)
        (
            H264Profile::High,
            H264ProfileIdc::X64,
            BitPattern::new(*b"00000000"),
        ),
        (
            H264Profile::High10,
            H264ProfileIdc::X6E,
            BitPattern::new(*b"00000000"),
        ),
        (
            H264Profile::High422,
            H264ProfileIdc::X7A,
            BitPattern::new(*b"00000000"),
        ),
        (
            H264Profile::High444Predictive,
            H264ProfileIdc::XF4,
            BitPattern::new(*b"00000000"),
        ),
        // Intra profiles
        (
            H264Profile::High10Intra,
            H264ProfileIdc::X6E,
            BitPattern::new(*b"00010000"),
        ),
        (
            H264Profile::High422Intra,
            H264ProfileIdc::X7A,
            BitPattern::new(*b"00010000"),
        ),
        (
            H264Profile::High444Intra,
            H264ProfileIdc::XF4,
            BitPattern::new(*b"00010000"),
        ),
        (
            H264Profile::CAVLC444Intra,
            H264ProfileIdc::X2C,
            BitPattern::new(*b"00010000"),
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

// Per libWebRTC
//     All values are equal to ten times the level number, except level 1b which is
//     special.
// Can't find the source for this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[rustfmt::skip]
enum H264LevelIdc {
    Level1B  = 0_u8,
    Level1   = 10_u8,
    Level1_1 = 11_u8,
    Level1_2 = 12_u8,
    Level1_3 = 13_u8,
    Level2   = 20_u8,
    Level2_1 = 21_u8,
    Level2_2 = 22_u8,
    Level3   = 30_u8,
    Level3_1 = 31_u8,
    Level3_2 = 32_u8,
    Level4   = 40_u8,
    Level4_1 = 41_u8,
    Level4_2 = 42_u8,
    Level5   = 50_u8,
    Level5_1 = 51_u8,
    Level5_2 = 52_u8,
}

impl TryFrom<u8> for H264LevelIdc {
    type Error = ();

    #[rustfmt::skip]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use H264LevelIdc::*;

        match value {
            x if (Level1B as u8)  == x => Ok(Level1B),
            x if (Level1 as u8)   == x => Ok(Level1),
            x if (Level1_1 as u8) == x => Ok(Level1_1),
            x if (Level1_2 as u8) == x => Ok(Level1_2),
            x if (Level1_3 as u8) == x => Ok(Level1_3),
            x if (Level2 as u8)   == x => Ok(Level2),
            x if (Level2_1 as u8) == x => Ok(Level2_1),
            x if (Level2_2 as u8) == x => Ok(Level2_2),
            x if (Level3 as u8)   == x => Ok(Level3),
            x if (Level3_1 as u8) == x => Ok(Level3_1),
            x if (Level3_2 as u8) == x => Ok(Level3_2),
            x if (Level4 as u8)   == x => Ok(Level4),
            x if (Level4_1 as u8) == x => Ok(Level4_1),
            x if (Level4_2 as u8) == x => Ok(Level4_2),
            x if (Level5 as u8)   == x => Ok(Level5),
            x if (Level5_1 as u8) == x => Ok(Level5_1),
            x if (Level5_2 as u8) == x => Ok(Level5_2),
            _ => Err(()),
        }
    }
}
