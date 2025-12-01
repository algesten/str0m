//! Security-focused integration tests for Apple crypto provider.
//!
//! These tests verify security properties like replay protection and
//! fingerprint verification.

#![cfg(target_vendor = "apple")]

use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, RawPacket, SeqNo, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, connect_with_wrong_fingerprint, init_crypto, init_log};
use common::{progress, progress_with_replay};

const EXPECTED_PACKETS: usize = 50;
const REPLAY_PER_PACKET: usize = 5;

/// Test SRTP replay attack protection in RTP mode.
///
/// Sends each packet multiple times and verifies that only the original
/// packets are accepted (replay duplicates are discarded).
#[test]
pub fn srtp_replay_attack_protection() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_l_r();
    let mid = "aud".into();

    let ssrc_tx: Ssrc = 42.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();
    let mut write_at = l.last + Duration::from_millis(20);
    let mut seq_no: SeqNo = 0_u64.into();
    let mut time = 0;
    let mut send_count = 0;
    const TIME_INTERVAL: u32 = 960;

    // Process the DTLS Handshake first, before we start duplicating SRTP packets
    progress_with_replay(&mut l, &mut r, 1)?;

    loop {
        if l.start + l.duration() > write_at && send_count < EXPECTED_PACKETS {
            seq_no.inc();
            time += TIME_INTERVAL;
            write_at = l.last + Duration::from_millis(20);
            let wallclock = l.start + l.duration();
            let mut direct = l.direct_api();
            let stream = direct.stream_tx(&ssrc).unwrap();
            let exts = ExtensionValues {
                audio_level: Some(-42),
                voice_activity: Some(false),
                ..Default::default()
            };

            stream
                .write_rtp(
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![1, 3, 3, 7],
                )
                .expect("clean write");
            send_count += 1;
        }

        // Each packet is sent REPLAY_PER_PACKET times
        progress_with_replay(&mut l, &mut r, REPLAY_PER_PACKET)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Count raw RTP packets received
    let rtp_raw_rx: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Some(RawPacket::RtpRx(header, payload)) = e.as_raw_packet() {
                Some((header, payload))
            } else {
                None
            }
        })
        .collect();

    // Despite sending each packet REPLAY_PER_PACKET times,
    // we should only receive EXPECTED_PACKETS unique packets
    assert_eq!(
        rtp_raw_rx.len(),
        EXPECTED_PACKETS,
        "Replay attack protection failed: received {} packets but expected {}",
        rtp_raw_rx.len(),
        EXPECTED_PACKETS
    );

    // Also verify via RtpPacket events
    let rtp: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        rtp.len(),
        EXPECTED_PACKETS,
        "RtpPacket events mismatch: got {} but expected {}",
        rtp.len(),
        EXPECTED_PACKETS
    );

    Ok(())
}

/// Test that DTLS fingerprint verification works.
///
/// When the remote fingerprint doesn't match the actual certificate,
/// the connection should not become established.
#[test]
pub fn dtls_fingerprint_mismatch_rejected() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_with_wrong_fingerprint();

    // Try to progress the connection for a while
    // With mismatched fingerprints, neither side should become connected
    for _ in 0..500 {
        // Use regular progress (not with replay) to give it a fair chance
        let _ = progress(&mut l, &mut r);

        // If we somehow become connected, that's a security failure
        if l.is_connected() && r.is_connected() {
            panic!("Connection established despite fingerprint mismatch - security vulnerability!");
        }

        if l.duration() > Duration::from_secs(3) {
            break;
        }
    }

    // At least one side should NOT be connected
    let both_connected = l.is_connected() && r.is_connected();
    assert!(
        !both_connected,
        "Both sides connected despite fingerprint mismatch"
    );

    Ok(())
}

/// Test that SRTP authentication tag verification works.
///
/// This test sends valid packets and verifies they are received correctly,
/// implicitly testing that the authentication works.
#[test]
pub fn srtp_authentication_verification() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_l_r();
    let mid = "aud".into();

    let ssrc_tx: Ssrc = 99.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    let pt = params.pt();

    const PACKETS_TO_SEND: usize = 20;
    let mut seq_no: SeqNo = 0_u64.into();
    let mut time = 0;
    let mut send_count = 0;
    const TIME_INTERVAL: u32 = 960;
    let mut write_at = l.last + Duration::from_millis(20);

    loop {
        if l.start + l.duration() > write_at && send_count < PACKETS_TO_SEND {
            seq_no.inc();
            time += TIME_INTERVAL;
            write_at = l.last + Duration::from_millis(20);
            let wallclock = l.start + l.duration();
            let mut direct = l.direct_api();
            let stream = direct.stream_tx(&ssrc).unwrap();
            let exts = ExtensionValues::default();

            // Send recognizable payload
            stream
                .write_rtp(
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![0xDE, 0xAD, 0xBE, 0xEF],
                )
                .expect("write rtp");
            send_count += 1;
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(3) {
            break;
        }
    }

    // Verify all packets arrived with correct payload
    let received: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Some(RawPacket::RtpRx(_header, payload)) = e.as_raw_packet() {
                Some(payload.clone())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        received.len(),
        PACKETS_TO_SEND,
        "Expected {} packets, received {}",
        PACKETS_TO_SEND,
        received.len()
    );

    // Verify payload integrity - each received packet should have our payload
    for (i, payload) in received.iter().enumerate() {
        assert_eq!(
            payload.as_slice(),
            &[0xDE, 0xAD, 0xBE, 0xEF],
            "Packet {} has corrupted payload: {:?}",
            i,
            payload
        );
    }

    Ok(())
}

/// Test SHA-256 fingerprint computation used for DTLS certificate verification.
///
/// This implicitly tests that the SHA-256 implementation works correctly
/// by verifying that two RTCs can complete the DTLS handshake.
#[test]
pub fn sha256_fingerprint_works() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_l_r();

    // The connection is already established by connect_l_r
    // This means fingerprints were computed and verified correctly

    // Progress a bit more to ensure both sides are fully connected
    for _ in 0..50 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    assert!(l.is_connected(), "L should be connected");
    assert!(r.is_connected(), "R should be connected");

    Ok(())
}

/// Test that ICE connectivity checks work, which implicitly tests SHA1-HMAC
/// used for STUN message integrity.
///
/// ICE uses STUN Binding Requests/Responses with MESSAGE-INTEGRITY attribute
/// which is computed using SHA1-HMAC. If SHA1-HMAC doesn't work correctly,
/// the ICE checks would fail and connection wouldn't be established.
#[test]
pub fn stun_sha1_hmac_integrity() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_l_r();

    // Progress until both sides are connected
    for _ in 0..100 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // If we're connected, the STUN messages with MESSAGE-INTEGRITY (SHA1-HMAC)
    // were correctly verified
    assert!(
        l.is_connected(),
        "L should be connected (STUN MESSAGE-INTEGRITY worked)"
    );
    assert!(
        r.is_connected(),
        "R should be connected (STUN MESSAGE-INTEGRITY worked)"
    );

    Ok(())
}
