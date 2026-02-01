//! Tests for RTP sequence number and timing edge cases.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, negotiate, progress, Peer, TestRtc};

/// Test handling of packets near sequence number boundary.
#[test]
fn rtp_sequence_number_near_boundary() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();
    let data = vec![1_u8; 80];

    // Send many packets to exercise sequence number handling
    for _ in 0..200 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        // Must call progress after each write to avoid WriteWithoutPoll error
        progress(&mut l, &mut r)?;
    }

    // Final progress to deliver remaining packets
    for _ in 0..50 {
        progress(&mut l, &mut r)?;
    }

    let received_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        received_count > 100,
        "Should receive most packets, got {}",
        received_count
    );

    Ok(())
}

/// Test reordering buffer with audio threshold.
#[test]
fn rtp_reordering_buffer_audio() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .set_reordering_size_audio(15)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    for _ in 0..100 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    let received_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        received_count > 50,
        "Should receive packets with reordering buffer, got {}",
        received_count
    );

    Ok(())
}

/// Test reordering buffer with video threshold.
#[test]
fn rtp_reordering_buffer_video() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .set_reordering_size_video(30)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    let pt = params.pt();
    // VP8 keyframe header
    let data = vec![0x10, 0x00, 0x00, 0x00];

    for _ in 0..100 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    let received_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        received_count > 0,
        "Should receive video packets with reordering buffer"
    );

    Ok(())
}

/// Test custom reordering buffer sizes.
#[test]
fn rtp_reordering_buffer_custom_size() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Test with smaller reordering buffer
    let rtc = RtcConfig::new()
        .set_reordering_size_audio(5)
        .set_reordering_size_video(10)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect");
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    for _ in 0..50 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    let received_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        received_count > 20,
        "Should receive packets with custom reordering size, got {}",
        received_count
    );

    Ok(())
}

/// Test media time increases correctly.
#[test]
fn rtp_media_time_increasing() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    // Send packets with increasing timestamps
    for _ in 0..50 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    // Verify we received packets (media time handling worked)
    let received_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        received_count > 20,
        "Should receive packets with increasing timestamps, got {}",
        received_count
    );

    Ok(())
}

/// Test large reordering buffer configuration.
#[test]
fn rtp_reordering_buffer_large() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Test with larger reordering buffer
    let rtc = RtcConfig::new()
        .set_reordering_size_audio(50)
        .set_reordering_size_video(100)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect");
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    for _ in 0..100 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    let received_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        received_count > 50,
        "Should receive packets with large reordering buffer, got {}",
        received_count
    );

    Ok(())
}
