use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;
use tracing::info_span;

use str0m::format::Codec;
use str0m::media::rtp::RtpHeader;
use str0m::media::rtp::{Extension, ExtensionMap};
use str0m::media::{Direction, MediaKind};
use str0m::{Candidate, Event, Rtc, RtcError};

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn rtp_mode() -> Result<(), RtcError> {
    init_log();

    let rtc1 = Rtc::builder().set_rtp_mode(true).build();
    let rtc2 = Rtc::builder()
        .set_rtp_mode(true)
        // release packet straight away
        .set_reordering_size_audio(0)
        .build();

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.media(mid).unwrap().payload_params()[0];
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let mut exts = ExtensionMap::empty();
    exts.set(3, Extension::AudioLevel);

    let to_write: Vec<&[u8]> = vec![
        // 1
        &[
            //
            144, 33, 183, 152, 0, 0, 39, 16, 0, 0, 0, 44, 190, 222, 0, 1, 48, 170, 0, 0,
            // payload
            0x1, 0x2, 0x3, 0x4,
        ],
        // 3
        &[
            //
            144, 33, 183, 155, 0, 0, 54, 176, 0, 0, 0, 44, 190, 222, 0, 1, 48, 172, 0, 0,
            // payload
            0x9, 0xa, 0xb, 0xc,
        ],
        // 2
        &[
            //
            144, 161, 183, 153, 0, 0, 46, 224, 0, 0, 0, 44, 190, 222, 0, 1, 48, 171, 0, 0,
            // payload
            0x5, 0x6, 0x7, 0x8,
        ],
    ];

    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                l.media(mid)
                    .unwrap()
                    .writer(pt)
                    .write_rtp(wallclock, packet, &exts)?;
            }
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let media: Vec<_> = r
        .events
        .iter()
        .filter_map(|e| {
            if let Event::MediaData(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(media.len(), 3);

    // no change from standard above
    let exts = ExtensionMap::standard();

    let h0 = RtpHeader::parse(&media[0].data, &exts).unwrap();
    let h1 = RtpHeader::parse(&media[1].data, &exts).unwrap();
    let h2 = RtpHeader::parse(&media[2].data, &exts).unwrap();

    assert_eq!(h0.sequence_number, 47000);
    assert_eq!(h1.sequence_number, 47003);
    assert_eq!(h2.sequence_number, 47001);

    assert_eq!(h0.timestamp, 10000);
    assert_eq!(h1.timestamp, 14000);
    assert_eq!(h2.timestamp, 12000);

    assert_eq!(h0.ext_vals.audio_level, Some(-42));
    assert_eq!(h1.ext_vals.audio_level, Some(-44));
    assert_eq!(h2.ext_vals.audio_level, Some(-43));

    assert!(!h0.marker);
    assert!(!h1.marker);
    assert!(h2.marker);

    Ok(())
}
