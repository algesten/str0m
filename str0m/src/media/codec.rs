use sdp::{CodecSpec, PayloadParams};

use rtp::Pt;
use sdp::{Codec, FormatParams};

use super::MediaKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecParams(PayloadParams);

impl CodecParams {
    pub fn pt(&self) -> Pt {
        self.0.codec.pt
    }

    pub fn pt_rtx(&self) -> Option<Pt> {
        self.0.resend
    }

    pub fn codec(&self) -> Codec {
        self.0.codec.codec
    }

    pub fn clock_rate(&self) -> u32 {
        self.0.codec.clock_rate
    }

    pub fn channels(&self) -> Option<u8> {
        self.0.codec.channels
    }

    pub fn fmtp(&self) -> &FormatParams {
        &self.0.fmtps
    }

    pub(crate) fn inner(&self) -> &PayloadParams {
        &self.0
    }

    pub(crate) fn match_score(&self, o: Self) -> usize {
        // we don't want to compare PT
        let pt = 0.into();
        let c0 = CodecSpec { pt, ..self.0.codec };
        let c1 = CodecSpec { pt, ..o.0.codec };

        if c0 == c1 && self.0.fmtps == o.0.fmtps {
            100
        } else {
            // TODO: fuzzy matching.
            0
        }
    }
}

impl From<PayloadParams> for CodecParams {
    fn from(p: PayloadParams) -> Self {
        CodecParams(p)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CodecConfig {
    configs: Vec<CodecParams>,
}

impl CodecConfig {
    pub fn new() -> Self {
        CodecConfig::default()
    }

    /// Add default config if none is set.
    pub(crate) fn init(mut self) -> Self {
        if self.configs.is_empty() {
            self.add_default_opus();

            self.add_default_vp8();
            self.add_default_h264();
            self.add_default_av1();
            self.add_default_vp9();
        }
        self
    }

    pub fn matches(&self, c: &CodecParams) -> bool {
        self.configs.iter().any(|x| {
            x.codec() == c.codec() && x.clock_rate() == c.clock_rate() && x.fmtp() == c.fmtp()
        })
    }

    pub fn add_config(
        &mut self,
        pt: Pt,
        resend: Option<Pt>,
        codec: Codec,
        clock_rate: u32,
        channels: Option<u8>,
        fmtps: FormatParams,
    ) {
        let (fb_transport_cc, fb_fir, fb_nack, fb_pli, resend) = if codec.is_video() {
            (true, true, true, true, resend)
        } else {
            (true, false, false, false, None)
        };

        let p = PayloadParams {
            codec: CodecSpec {
                pt,
                codec,
                clock_rate,
                channels,
            },
            fmtps,
            resend,
            fb_transport_cc,
            fb_fir,
            fb_nack,
            fb_pli,
        };

        self.configs.push(p.into());
    }

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

    pub fn add_default_av1(&mut self) {
        self.add_config(
            41.into(),
            Some(42.into()),
            Codec::Av1,
            90_000,
            None,
            FormatParams::default(),
        )
    }

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

    pub(crate) fn all_for_kind(&self, kind: MediaKind) -> impl Iterator<Item = &CodecParams> {
        self.configs.iter().filter(move |c| {
            if kind == MediaKind::Video {
                c.codec().is_video()
            } else {
                c.codec().is_audio()
            }
        })
    }
}
