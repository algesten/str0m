//! Tests for ICE candidate handling and configuration.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::ice::IceCreds;
use str0m::RtcConfig;
use str0m::RtcError;
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, progress, Peer, TestRtc};

/// Test connection with only host candidates.
#[test]
fn ice_candidate_types_host_only() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    // Add only host candidates (no srflx or relay)
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

    // Should connect using host candidates
    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect with host-only candidates");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test trickle ICE - adding candidates after initial offer/answer.
#[test]
fn ice_trickle_incremental_candidates() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    // Create offer/answer without candidates first
    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        let _ = change.add_channel("test".into());
        change.apply().unwrap()
    });

    let answer = r.span.in_scope(|| r.rtc.sdp_api().accept_offer(offer))?;
    l.span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending, answer))?;

    // Now add local candidates (trickle ICE)
    let l_cand = l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    let r_cand = r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Exchange candidates between peers (simulating trickle ICE signaling)
    l.rtc.add_remote_candidate(r_cand);
    r.rtc.add_remote_candidate(l_cand);

    // Connection should establish with trickled candidates
    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect with trickled candidates");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test custom ICE credentials via set_local_ice_credentials().
#[test]
fn ice_custom_credentials() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let custom_creds = IceCreds {
        ufrag: "customufrag123".into(),
        pass: "custompassword456789012".into(),
    };

    let rtc = RtcConfig::new()
        .set_local_ice_credentials(custom_creds.clone())
        .build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Verify custom credentials are used
    let actual_creds = l._local_ice_creds();
    assert_eq!(
        actual_creds.ufrag, custom_creds.ufrag,
        "Custom ufrag should be used"
    );
    assert_eq!(
        actual_creds.pass, custom_creds.pass,
        "Custom password should be used"
    );

    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        let _ = change.add_channel("test".into());
        change.apply().unwrap()
    });

    // Verify custom ufrag appears in offer SDP
    let offer_str = offer.to_string();
    assert!(
        offer_str.contains(&custom_creds.ufrag),
        "Offer SDP should contain custom ufrag"
    );

    let answer = r.span.in_scope(|| r.rtc.sdp_api().accept_offer(offer))?;
    l.span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending, answer))?;

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect with custom credentials");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test set_initial_stun_rto() configuration.
#[test]
fn ice_stun_timeout_initial_rto() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut config = RtcConfig::new();
    config.set_initial_stun_rto(Duration::from_millis(100));
    let rtc = config.build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

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
            panic!("Failed to connect with custom initial RTO");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test set_max_stun_rto() configuration.
#[test]
fn ice_stun_timeout_max_rto() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut config = RtcConfig::new();
    config.set_max_stun_rto(Duration::from_millis(1000));
    let rtc = config.build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

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
            panic!("Failed to connect with custom max RTO");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test set_max_stun_retransmits() configuration.
#[test]
fn ice_stun_max_retransmits() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut config = RtcConfig::new();
    config.set_max_stun_retransmits(5);
    let rtc = config.build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc);
    let mut r = TestRtc::new(Peer::Right);

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
            panic!("Failed to connect with custom max retransmits");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test ICE lite mode connectivity.
#[test]
fn ice_lite_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let rtc = RtcConfig::new().set_ice_lite(true).build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

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
            panic!("Failed to connect with ICE lite");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}
