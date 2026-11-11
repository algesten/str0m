use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::media::{Direction, MediaKind};
use str0m::rtp::{Chromaticity, Extension, HdrMetadata, VideoColorSpace};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

#[test]
fn color_space_with_and_without_hdr() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        Peer::Left.span(),
        Rtc::builder()
            .set_extension(8, Extension::ColorSpace)
            .build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        Peer::Right.span(),
        Rtc::builder()
            .set_extension(8, Extension::ColorSpace)
            .build(now),
    );
    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;
    while !l.is_connected() || !r.is_connected() {
        progress(&mut l, &mut r)?;
    }
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;
    let hdr = HdrMetadata {
        luminance_max: 1000,
        luminance_min: 50,
        primary_red: Chromaticity { x: 34000, y: 16000 },
        primary_green: Chromaticity { x: 13250, y: 34500 },
        primary_blue: Chromaticity { x: 7500, y: 3000 },
        white_point: Chromaticity { x: 15635, y: 16450 },
        max_content_light_level: 1200,
        max_frame_average_light_level: 400,
    };
    let mut cs = VideoColorSpace {
        primaries: 9,
        transfer: 16,
        matrix: 9,
        range: 1,
        chroma_siting_horizontal: 1,
        chroma_siting_vertical: 2,
        hdr_metadata: None,
    };
    let pt = l.params_vp8().pt();
    for metadata in [None, Some(hdr), None] {
        cs.hdr_metadata = metadata;
        let before = r.events.len();
        for _ in 0..100 {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            l.writer(mid)
                .unwrap()
                .color_space(cs)
                .write(pt, wallclock, time, vec![0xaa; 5000])?;
            progress(&mut l, &mut r)?;
            if r.events[before..].iter().any(
                |(_, e)| matches!(e, Event::MediaData(d) if d.ext_vals.color_space == Some(cs)),
            ) {
                break;
            }
            if l.duration() > Duration::from_secs(10) {
                break;
            }
        }
        assert!(
            r.events[before..].iter().any(
                |(_, e)| matches!(e, Event::MediaData(d) if d.ext_vals.color_space == Some(cs))
            ),
            "missing {cs:?}"
        );
    }
    Ok(())
}

#[test]
fn no_mixed_extension_headers_without_sdp_negotiation() -> Result<(), RtcError> {
    extension_header_profiles(false, false)
}

#[test]
fn mixed_extension_headers_when_negotiated() -> Result<(), RtcError> {
    extension_header_profiles(true, false)
}

#[test]
fn no_mixed_extension_headers_when_offer_omits_it() -> Result<(), RtcError> {
    extension_header_profiles(false, true)
}

fn extension_header_profiles(allow_mixed: bool, strip_offer: bool) -> Result<(), RtcError> {
    use common::capture_rtp_profiles;
    use str0m::change::{SdpAnswer, SdpOffer};

    init_log();
    init_crypto_default();
    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        Peer::Left.span(),
        Rtc::builder()
            .set_extension(8, Extension::ColorSpace)
            .build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        Peer::Right.span(),
        Rtc::builder()
            .set_extension(8, Extension::ColorSpace)
            .build(now),
    );
    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let offer = if strip_offer {
        SdpOffer::from_sdp_string(
            &offer
                .to_sdp_string()
                .replace("a=extmap-allow-mixed\r\n", ""),
        )
        .unwrap()
    } else {
        offer
    };
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    if strip_offer {
        assert!(!answer.to_sdp_string().contains("a=extmap-allow-mixed"));
    }
    let answer = if !allow_mixed {
        SdpAnswer::from_sdp_string(
            &answer
                .to_sdp_string()
                .replace("a=extmap-allow-mixed\r\n", ""),
        )
        .unwrap()
    } else {
        SdpAnswer::from_sdp_string(&answer.to_sdp_string()).unwrap()
    };
    l.rtc.sdp_api().accept_answer(pending, answer)?;
    while !l.is_connected() || !r.is_connected() {
        progress(&mut l, &mut r)?;
    }
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;
    let pt = l.params_vp8().pt();
    let mut profiles = Vec::new();
    for hdr in [None, Some(HdrMetadata::default())] {
        let cs = VideoColorSpace {
            hdr_metadata: hdr,
            ..Default::default()
        };
        for _ in 0..100 {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            l.writer(mid)
                .unwrap()
                .color_space(cs)
                .write(pt, wallclock, time, vec![0xaa; 200])?;
            let got = capture_rtp_profiles(&mut l, &mut r)?;
            if !got.is_empty() {
                profiles.extend(got);
                break;
            }
        }
    }
    assert!(profiles.len() >= 2, "missing RTP packets: {profiles:?}");
    if allow_mixed {
        assert_eq!(profiles, [0xbede, 0x1000]);
    } else {
        assert!(
            profiles.iter().all(|p| *p == 0x1000),
            "RTP headers mixed without extmap-allow-mixed: {profiles:x?}"
        );
    }
    Ok(())
}
