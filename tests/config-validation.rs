//! Tests for configuration edge cases and validation.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, negotiate, progress, Peer, TestRtc};

/// Test set_reordering_size_audio() and set_reordering_size_video() with custom sizes.
#[test]
fn config_reordering_size_custom() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .set_reordering_size_audio(20)
        .set_reordering_size_video(50)
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

    // Verify connection works with custom reordering sizes
    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    for _ in 0..10 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test enable_raw_packets(true) produces RawPacket events.
#[test]
fn config_raw_packets_enabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .enable_raw_packets(true)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);

    let rtc_r = RtcConfig::new()
        .enable_raw_packets(true)
        .build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

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

    // Clear previous events
    l.events.clear();
    r.events.clear();

    // Send some audio data
    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    for _ in 0..20 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    // Check for RawPacket events
    let raw_packet_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::RawPacket(_)))
        .count();

    assert!(
        raw_packet_count > 0,
        "Should have RawPacket events with enable_raw_packets(true)"
    );

    Ok(())
}

/// Test set_stats_interval with custom duration.
#[test]
fn config_stats_interval_custom() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let stats_interval = Duration::from_secs(1);
    let rtc = RtcConfig::new()
        .set_stats_interval(Some(stats_interval))
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);

    let rtc_r = RtcConfig::new()
        .set_stats_interval(Some(stats_interval))
        .build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

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

    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));

    // Run for 5 seconds to get multiple stats events
    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Should have multiple stats events with 1s interval over 5s
    let peer_stats_count = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::PeerStats(_)))
        .count();

    assert!(
        peer_stats_count >= 3,
        "Expected at least 3 PeerStats events with 1s interval over 5s, got {}",
        peer_stats_count
    );

    Ok(())
}

/// Test set_stats_interval(None) produces no stats events.
#[test]
fn config_stats_disabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .set_stats_interval(None)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);

    let rtc_r = RtcConfig::new()
        .set_stats_interval(None)
        .build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

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

    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));

    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
        if l.duration() > Duration::from_secs(3) {
            break;
        }
    }

    let peer_stats_count = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::PeerStats(_)))
        .count();

    assert_eq!(
        peer_stats_count, 0,
        "Should have no PeerStats events when stats disabled"
    );

    Ok(())
}

/// Test set_fingerprint_verification(false).
#[test]
fn config_fingerprint_verification_disabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .set_fingerprint_verification(false)
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);

    let rtc_r = RtcConfig::new()
        .set_fingerprint_verification(false)
        .build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        let _ = change.add_channel("test".into());
        change.apply().unwrap()
    });

    let answer = r.span.in_scope(|| r.rtc.sdp_api().accept_offer(offer))?;
    l.span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending, answer))?;

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect with fingerprint verification disabled");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test that RtcConfig can be cloned and used for multiple instances.
#[test]
fn config_clone_multiple_instances() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Create a config with custom settings (not ice_lite since both can't be ice_lite)
    let config = RtcConfig::new()
        .set_reordering_size_audio(20)
        .set_reordering_size_video(40);

    // Clone the config and create multiple instances
    let rtc1 = config.clone().build(Instant::now());
    let rtc2 = config.build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        let _ = change.add_channel("test".into());
        change.apply().unwrap()
    });

    let answer = r.span.in_scope(|| r.rtc.sdp_api().accept_offer(offer))?;
    l.span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending, answer))?;

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect with cloned config");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test set_send_buffer_audio and set_send_buffer_video configuration.
#[test]
fn config_send_buffer_sizes() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc = RtcConfig::new()
        .set_send_buffer_audio(100)
        .set_send_buffer_video(2000)
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

    // Connection should work with custom send buffer sizes
    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    for _ in 0..10 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    Ok(())
}
