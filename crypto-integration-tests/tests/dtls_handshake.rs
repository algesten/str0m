//! Integration test: DTLS handshake using Apple crypto provider.
//!
//! This test verifies that the full DTLS handshake completes successfully
//! using the Apple CommonCrypto implementation.

#![cfg(target_vendor = "apple")]

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::RtcError;
use str0m::media::{Direction, MediaKind};
use tracing::info_span;

mod common;
use common::{TestRtc, init_crypto, init_log, progress};

/// Test that DTLS handshake completes successfully with Apple crypto.
#[test]
pub fn dtls_handshake() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Add a media line to trigger DTLS
    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Progress until connected - this requires successful DTLS handshake
    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;

        // Timeout after 5 seconds
        if l.duration() > Duration::from_secs(5) {
            panic!("DTLS handshake did not complete within timeout");
        }
    }

    // Verify both sides are connected
    assert!(l.is_connected(), "Left side should be connected");
    assert!(r.is_connected(), "Right side should be connected");

    Ok(())
}

/// Test DTLS handshake with the direct API (bypassing SDP).
#[test]
pub fn dtls_handshake_direct_api() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = common::connect_l_r();

    // connect_l_r waits until one side is connected, progress more until both are
    for _ in 0..100 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        common::progress(&mut l, &mut r)?;
    }

    // Verify both sides are connected
    assert!(l.is_connected(), "Left side should be connected");
    assert!(r.is_connected(), "Right side should be connected");

    Ok(())
}
