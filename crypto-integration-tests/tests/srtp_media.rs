//! Integration test: SRTP encryption/decryption using Apple crypto provider.
//!
//! This test verifies that media is correctly encrypted and decrypted
//! using the Apple CommonCrypto SRTP implementation.

#![cfg(target_vendor = "apple")]

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, init_crypto, init_log, progress};

/// Test unidirectional audio transmission (SRTP encryption/decryption).
#[test]
pub fn srtp_unidirectional_audio() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Wait for connection
    loop {
        if l.is_connected() || r.is_connected() {
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

    // Send audio data
    let data = vec![0x42_u8; 80]; // 80 bytes of test data

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

    // Verify receiver got media
    let media_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        media_count > 100,
        "Expected at least 100 MediaData events, got {}",
        media_count
    );

    Ok(())
}

/// Test bidirectional audio transmission (SRTP in both directions).
#[test]
pub fn srtp_bidirectional_audio() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
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

    let params = l.params_opus();
    let pt = params.pt();

    let data_l = vec![0x11_u8; 80];
    let data_r = vec![0x22_u8; 80];

    loop {
        // L sends
        {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            l.writer(mid)
                .unwrap()
                .write(pt, wallclock, time, data_l.clone())?;
        }

        // R sends
        {
            let wallclock = r.start + r.duration();
            let time = l.duration().into();
            r.writer(mid)
                .unwrap()
                .write(pt, wallclock, time, data_r.clone())?;
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Verify L received from R
    let media_count_l = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        media_count_l > 50,
        "L expected at least 50 MediaData events, got {}",
        media_count_l
    );

    // Verify R received from L
    let media_count_r = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        media_count_r > 50,
        "R expected at least 50 MediaData events, got {}",
        media_count_r
    );

    Ok(())
}

/// Test video transmission (larger payloads).
#[test]
pub fn srtp_video_transmission() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
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

    // Simulate video frame data (larger than audio)
    let frame_data = vec![0xAB_u8; 1200];

    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, frame_data.clone())?;

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let media_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        media_count > 50,
        "Expected at least 50 video MediaData events, got {}",
        media_count
    );

    Ok(())
}
