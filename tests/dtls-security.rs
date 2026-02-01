//! Tests for DTLS handshake edge cases and security.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::RtcConfig;
use str0m::RtcError;
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, progress, Peer, TestRtc};

/// Test that connections work when fingerprint verification is disabled.
#[test]
fn dtls_fingerprint_verification_disabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc_l = RtcConfig::new()
        .set_fingerprint_verification(false)
        .build(Instant::now());
    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc_l);

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

/// Test certificate fingerprint format and uniqueness.
#[test]
fn dtls_certificate_fingerprint_format() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Create two instances and verify they have different certificates
    let rtc1 = RtcConfig::new().build(Instant::now());
    let rtc2 = RtcConfig::new().build(Instant::now());

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Get fingerprints
    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    let finger_r = r.direct_api().local_dtls_fingerprint().clone();

    // Fingerprints should be different for different instances
    assert_ne!(
        finger_l, finger_r,
        "Different Rtc instances should have different certificates"
    );

    // Fingerprint should be properly formatted (SHA-256 format)
    let finger_str = format!("{}", finger_l);
    assert!(
        finger_str.starts_with("sha-256 ") || finger_str.contains(':'),
        "Fingerprint should be in SHA-256 format: {}",
        finger_str
    );

    Ok(())
}

/// Test that new Rtc instances get new certificates.
#[test]
fn dtls_certificate_rotation() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Create first connection
    let rtc1a = RtcConfig::new().build(Instant::now());
    let rtc1b = RtcConfig::new().build(Instant::now());

    let mut l1 = TestRtc::new_with_rtc(info_span!("L1"), rtc1a);
    let mut r1 = TestRtc::new_with_rtc(info_span!("R1"), rtc1b);

    let finger1_l = l1.direct_api().local_dtls_fingerprint().clone();
    let finger1_r = r1.direct_api().local_dtls_fingerprint().clone();

    // Create second connection with new certificates
    let rtc2a = RtcConfig::new().build(Instant::now());
    let rtc2b = RtcConfig::new().build(Instant::now());

    let mut l2 = TestRtc::new_with_rtc(info_span!("L2"), rtc2a);
    let mut r2 = TestRtc::new_with_rtc(info_span!("R2"), rtc2b);

    let finger2_l = l2.direct_api().local_dtls_fingerprint().clone();
    let finger2_r = r2.direct_api().local_dtls_fingerprint().clone();

    // All fingerprints should be unique
    assert_ne!(finger1_l, finger1_r, "L1 and R1 should differ");
    assert_ne!(finger2_l, finger2_r, "L2 and R2 should differ");
    assert_ne!(finger1_l, finger2_l, "L1 and L2 should differ");
    assert_ne!(finger1_r, finger2_r, "R1 and R2 should differ");

    Ok(())
}

/// Test DTLS connection with ice-lite mode (passive role).
#[test]
fn dtls_with_ice_lite() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    // R is ice-lite (typically server-side)
    let rtc_r = RtcConfig::new().set_ice_lite(true).build(Instant::now());
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
            panic!("Failed to connect with ice-lite");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test pregenerated DTLS certificate.
#[test]
fn dtls_pregenerated_certificate() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Generate a certificate
    let provider = str0m::crypto::from_feature_flags();
    let cert = provider.dtls_provider.generate_certificate().unwrap();

    // Use the pregenerated certificate
    let rtc = RtcConfig::new().set_dtls_cert(cert).build(Instant::now());

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
            panic!("Failed to connect with pregenerated certificate");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Test that same pregenerated certificate produces same fingerprint.
#[test]
fn dtls_pregenerated_certificate_same_fingerprint() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Generate a certificate
    let provider = str0m::crypto::from_feature_flags();
    let cert = provider.dtls_provider.generate_certificate().unwrap();
    let cert_clone = cert.clone();

    // Create two instances with the same certificate
    let rtc1 = RtcConfig::new().set_dtls_cert(cert).build(Instant::now());
    let rtc2 = RtcConfig::new()
        .set_dtls_cert(cert_clone)
        .build(Instant::now());

    let mut l1 = TestRtc::new_with_rtc(info_span!("L1"), rtc1);
    let mut l2 = TestRtc::new_with_rtc(info_span!("L2"), rtc2);

    let finger1 = l1.direct_api().local_dtls_fingerprint().clone();
    let finger2 = l2.direct_api().local_dtls_fingerprint().clone();

    // Same certificate should produce same fingerprint
    assert_eq!(
        finger1, finger2,
        "Same certificate should produce same fingerprint"
    );

    Ok(())
}
