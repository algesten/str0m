use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::Rtc;
use str0m::{Candidate, Event, RtcError};
use tracing::info_span;

mod common;
use common::vp8_data;
use common::{init_log, progress, TestRtc};

#[test]
pub fn contiguous_all_the_way() -> Result<(), RtcError> {
    init_log();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp")?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp")?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None);
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

    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    let data = vp8_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            progress(&mut l, &mut r)?;
        }

        let absolute = max + relative;

        let mut direct = l.direct_api();
        let tx = direct.stream_tx_by_mid(mid, None).unwrap();
        tx.write_rtp(
            pt,
            header.sequence_number(None),
            header.timestamp,
            absolute,
            header.marker,
            header.ext_vals,
            true,
            payload,
        )
        .unwrap();

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let iter = r.events.iter().filter_map(|(_, e)| {
        if let Event::MediaData(d) = e {
            Some(d)
        } else {
            None
        }
    });

    let mut count = 0;

    // Contiguous all the way through.
    for data in iter {
        println!("{:?} {:?}", data, data.seq_range);
        assert!(data.contiguous);
        count += 1;
    }

    // The last packet, 14362, is never flushed out because the depacketizer wants
    // to see the next packet before releasing.
    // We have 3 continuations and one last packet missing: 104 - 3 - 1 == 100
    assert_eq!(count, 100);

    Ok(())
}

#[test]
pub fn not_contiguous() -> Result<(), RtcError> {
    init_log();

    let mut l = TestRtc::new(info_span!("L"));

    // We need to lower the default reordering buffer size, or we won't make it
    // past the dropped packet.
    let rtc_r = Rtc::builder().set_reordering_size_video(5).build();

    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp")?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp")?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None);
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

    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    let data = vp8_data();

    for (relative, header, payload) in data {
        // Drop a random packet in the middle.
        if header.sequence_number == 14337 {
            continue;
        }

        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            progress(&mut l, &mut r)?;
        }

        let absolute = max + relative;

        let mut direct = l.direct_api();
        let tx = direct.stream_tx_by_mid(mid, None).unwrap();
        tx.write_rtp(
            pt,
            header.sequence_number(None),
            header.timestamp,
            absolute,
            header.marker,
            header.ext_vals,
            true,
            payload,
        )
        .unwrap();

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let iter = r.events.iter().filter_map(|(_, e)| {
        if let Event::MediaData(d) = e {
            Some(d)
        } else {
            None
        }
    });

    let mut count = 0;

    // Contiguous all the way through.
    for data in iter {
        count += 1;
        // We dropped packet 14337, which means its dependendant 14338 is not
        // emitted, and 14339 is emitted and marked as discontinuous.
        let assume_contiguous = !data.seq_range.contains(&14339.into());
        assert_eq!(assume_contiguous, data.contiguous);
    }

    // assert!(false);
    // We have 3 continuations, 2 missing packet (14337 14338), and one last
    // packet missing: 104 - 3 - 1 - 1 == 99
    assert_eq!(count, 98);

    Ok(())
}
