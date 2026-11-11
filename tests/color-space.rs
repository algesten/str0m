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
            l.writer(mid).unwrap().color_space(cs.clone()).write(
                pt,
                wallclock,
                time,
                vec![0xaa; 5000],
            )?;
            progress(&mut l, &mut r)?;
            if r.events[before..].iter().any(
                |(_, e)| matches!(e, Event::MediaData(d) if d.ext_vals.color_space.as_deref() == Some(&cs)),
            ) {
                break;
            }
            if l.duration() > Duration::from_secs(10) {
                break;
            }
        }
        assert!(
            r.events[before..].iter().any(
                |(_, e)| matches!(e, Event::MediaData(d) if d.ext_vals.color_space.as_deref() == Some(&cs))
            ),
            "missing {cs:?}"
        );
    }
    Ok(())
}
