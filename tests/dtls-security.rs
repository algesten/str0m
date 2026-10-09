//! Tests for DTLS handshake edge cases and security.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput};
use str0m::crypto::dtls::{DtlsProvider, DtlsVersion, ProtocolVersion};
use str0m::crypto::{CryptoError, CryptoProvider};
use str0m::{Candidate, Event, Rtc, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

/// Test certificate fingerprint format and uniqueness.
#[test]
fn dtls_certificate_fingerprint_format() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Create two instances and verify they have different certificates
    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

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

    // Create first connection using L/R peers (respects L_CRYPTO/R_CRYPTO env vars)
    let mut l1 = TestRtc::new(Peer::Left);
    let mut r1 = TestRtc::new(Peer::Right);

    let finger1_l = l1.direct_api().local_dtls_fingerprint().clone();
    let finger1_r = r1.direct_api().local_dtls_fingerprint().clone();

    // Create second connection with new certificates
    let mut l2 = TestRtc::new(Peer::Left);
    let mut r2 = TestRtc::new(Peer::Right);

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

    // R is ice-lite (typically server-side), but still use Peer::Right crypto provider
    let mut rtc_r_builder = Rtc::builder().set_ice_lite(true);
    if let Some(crypto) = Peer::Right.crypto_provider() {
        rtc_r_builder = rtc_r_builder.set_crypto_provider(crypto);
    }
    let mut r = TestRtc::new_with_rtc(Peer::Right.span(), rtc_r_builder.build(Instant::now()));

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

    // Generate a certificate using Peer::Left's crypto provider if set
    let provider = Peer::Left
        .crypto_provider()
        .unwrap_or_else(|| std::sync::Arc::new(str0m::crypto::from_feature_flags()));
    let cert = provider.dtls_provider.generate_certificate().unwrap();

    // Use the pregenerated certificate with the same crypto provider
    let mut rtc_l_builder = Rtc::builder().set_dtls_cert(cert);
    if let Some(crypto) = Peer::Left.crypto_provider() {
        rtc_l_builder = rtc_l_builder.set_crypto_provider(crypto);
    }

    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc_l_builder.build(Instant::now()));
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

    // Generate a certificate using Peer::Left's crypto provider if set
    let provider = Peer::Left
        .crypto_provider()
        .unwrap_or_else(|| std::sync::Arc::new(str0m::crypto::from_feature_flags()));
    let cert = provider.dtls_provider.generate_certificate().unwrap();
    let cert_clone = cert.clone();

    // Create two instances with the same certificate
    let mut rtc1_builder = Rtc::builder().set_dtls_cert(cert);
    let mut rtc2_builder = Rtc::builder().set_dtls_cert(cert_clone);
    if let Some(crypto) = Peer::Left.crypto_provider() {
        rtc1_builder = rtc1_builder.set_crypto_provider(crypto.clone());
        rtc2_builder = rtc2_builder.set_crypto_provider(crypto);
    }

    let mut l1 = TestRtc::new_with_rtc(Peer::Left.span(), rtc1_builder.build(Instant::now()));
    let mut l2 = TestRtc::new_with_rtc(Peer::Left.span(), rtc2_builder.build(Instant::now()));

    let finger1 = l1.direct_api().local_dtls_fingerprint().clone();
    let finger2 = l2.direct_api().local_dtls_fingerprint().clone();

    // Same certificate should produce same fingerprint
    assert_eq!(
        finger1, finger2,
        "Same certificate should produce same fingerprint"
    );

    Ok(())
}

/// Test that a DTLS server refuses a client that never presented a certificate.
///
/// RFC 8827 §6.5 / RFC 5763 §5 require the peer certificate to match the
/// a=fingerprint. A dimpl server accepts a client that answers the
/// CertificateRequest with an empty Certificate message and then reports
/// Connected and KeyingMaterial without PeerCert. R reproduces that here by
/// hiding the peer certificate its DTLS backend reports.
#[test]
fn dtls_server_refuses_client_without_certificate() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_to_server_without_peer_cert(true);

    let err = loop {
        if l.duration() > Duration::from_secs(5) {
            panic!("R did not refuse the client without certificate");
        }
        if let Err(e) = progress(&mut l, &mut r) {
            break e;
        }
    };

    assert!(
        matches!(&err, RtcError::RemoteSdp(msg) if msg == "no remote DTLS certificate"),
        "Unexpected error: {err}"
    );
    assert!(!r.is_alive(), "R must disconnect");
    assert!(!r.is_connected(), "R must not be connected");
    assert!(
        !r.events.iter().any(|(_, e)| matches!(e, Event::Connected)),
        "R must not emit Event::Connected"
    );

    Ok(())
}

/// Test that disabling fingerprint verification still lets a client without
/// certificate connect.
#[test]
fn dtls_server_without_fingerprint_verification_accepts_client_without_certificate()
-> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_to_server_without_peer_cert(false);

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(5) {
            panic!("Failed to connect without fingerprint verification");
        }
        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Set up L as DTLS client and R as DTLS server whose backend never reports
/// the peer certificate.
fn connect_to_server_without_peer_cert(fingerprint_verification: bool) -> (TestRtc, TestRtc) {
    let mut l = TestRtc::new(Peer::Left);

    let base = Peer::Right
        .crypto_provider()
        .map(|c| (*c).clone())
        .unwrap_or_else(str0m::crypto::from_feature_flags);
    let dtls_provider: &'static dyn DtlsProvider =
        Box::leak(Box::new(NoPeerCertProvider(base.dtls_provider)));
    let crypto = CryptoProvider {
        dtls_provider,
        ..base
    };
    let rtc_r = Rtc::builder()
        .set_crypto_provider(Arc::new(crypto))
        .set_fingerprint_verification(fingerprint_verification)
        .build(Instant::now());
    let mut r = TestRtc::new_with_rtc(Peer::Right.span(), rtc_r);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host1.clone());
    l.add_remote_candidate(host2.clone());
    r.add_local_candidate(host2);
    r.add_remote_candidate(host1);

    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    let finger_r = r.direct_api().local_dtls_fingerprint().clone();
    l.direct_api().set_remote_fingerprint(finger_r);
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();
    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);

    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();

    (l, r)
}

/// DTLS provider whose instances never report the peer certificate.
#[derive(Debug)]
struct NoPeerCertProvider(&'static dyn DtlsProvider);

impl DtlsProvider for NoPeerCertProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        self.0.generate_certificate()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let inner = self.0.new_dtls(cert, now, dtls_version, mtu)?;
        Ok(Box::new(NoPeerCert { inner, start: now }))
    }

    fn is_test(&self) -> bool {
        self.0.is_test()
    }
}

#[derive(Debug)]
struct NoPeerCert {
    inner: Box<dyn DtlsInstance>,
    start: Instant,
}

impl DtlsInstance for NoPeerCert {
    fn set_active(&mut self, active: bool) {
        self.inner.set_active(active)
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.inner.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        match self.inner.poll_output(buf) {
            // Drop the certificate and ask to be polled again straight away.
            DtlsOutput::PeerCert(_) => DtlsOutput::Timeout(self.start),
            output => output,
        }
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.inner.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.inner.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.inner.protocol_version()
    }

    fn is_closing(&self) -> bool {
        self.inner.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.inner.close()
    }
}
