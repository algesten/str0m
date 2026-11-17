use std::time::Duration;

use crate::Bitrate;
use crate::RtcConfig;
use crate::format::Codec;
use crate::packet::CodecDepacketizer;
use crate::rtp::{Extension, ExtensionMap};
use crate::rtp::{dependency_descriptor, vla};

use super::Rng;

pub fn random_depacketizer(rng: &mut Rng, codec: Codec) -> Option<CodecDepacketizer> {
    let mut depack: CodecDepacketizer = codec.into();
    match &mut depack {
        CodecDepacketizer::AmrWb(amr) => amr.octet_align = rng.bool()?,
        CodecDepacketizer::H265(h265) => h265.with_donl(rng.bool()?),
        CodecDepacketizer::H266(h266) => h266.with_donl(rng.bool()?),
        _ => {}
    }
    Some(depack)
}

pub fn random_extmap(rng: &mut Rng, to_set: usize) -> Option<ExtensionMap> {
    use Extension::*;
    let mut e = ExtensionMap::empty();
    for _ in 0..to_set {
        // ExtensionMap takes ids 1..=16. Above 14 needs the two-byte header form.
        let id = rng.u8(15)? + 1;
        let ext = match rng.u8(15)? {
            0 => AbsoluteSendTime,
            1 => AudioLevel,
            2 => TransmissionTimeOffset,
            3 => VideoOrientation,
            4 => TransportSequenceNumber,
            5 => PlayoutDelay,
            6 => VideoContentType,
            7 => VideoTiming,
            8 => RtpStreamId,
            9 => RepairedRtpStreamId,
            10 => RtpMid,
            11 => FrameMarking,
            12 => ColorSpace,
            13 => AbsoluteCaptureTime,
            14 => Extension::with_serializer(vla::URI, vla::Serializer),
            15 => Extension::with_serializer(
                dependency_descriptor::URI,
                dependency_descriptor::Serializer,
            ),
            _ => unreachable!(),
        };
        e.set(id, ext);
    }
    Some(e)
}

#[allow(unused)]
pub fn random_config(rng: &mut Rng) -> Option<RtcConfig> {
    let mut c = RtcConfig::new();
    c = c.set_extension_map(random_extmap(rng, 8)?);
    c = c.set_ice_lite(rng.bool()?);
    c = c.set_fingerprint_verification(rng.bool()?);
    c = c.clear_codecs();
    c = c.enable_opus(rng.bool()?, false);
    c = c.enable_h264(rng.bool()?);
    c = c.enable_vp8(rng.bool()?);
    c = c.enable_vp9(rng.bool()?);
    c = c.enable_av1(rng.bool()?);
    if rng.bool()? {
        rng.bool(); // consume one
        c = c.set_stats_interval(None);
    } else {
        let t = Duration::from_millis(rng.u64(10_000)?);
        c = c.set_stats_interval(Some(t));
    }
    if rng.bool()? {
        rng.bool();
        c = c.enable_bwe(None);
    } else {
        c = c.enable_bwe(Some(Bitrate::bps(rng.u64(u64::MAX)?)));
    }
    c = c.set_reordering_size_audio(rng.usize(usize::MAX)?);
    c = c.set_reordering_size_video(rng.usize(usize::MAX)?);
    c = c.set_send_buffer_audio(rng.usize(usize::MAX)?.saturating_add(1)); // panics if set to 0
    c = c.set_send_buffer_video(rng.usize(usize::MAX)?);
    c = c.set_rtp_mode(rng.bool()?);
    c = c.enable_raw_packets(rng.bool()?);
    Some(c)
}
