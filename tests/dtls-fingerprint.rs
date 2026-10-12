//! The remote certificate fingerprint is verified with the hash function the
//! remote names (RFC 8122 §5): sha-256 or sha-1.
#![cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl",
    feature = "openssl-dimpl",
    feature = "wincrypto",
    feature = "apple-crypto",
))]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use sha1::{Digest, Sha1};
use str0m::crypto::Fingerprint;
use str0m::{Candidate, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, init_crypto_default, init_log, progress};

/// Connects L to R, where L expects R's certificate to have the fingerprint
/// `expected(R's DER certificate)`. Returns L's error, if any.
fn connect(expected: impl Fn(&[u8]) -> Fingerprint) -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let cert = str0m::crypto::from_feature_flags()
        .dtls_provider
        .generate_certificate()
        .expect("the provider generates certificates");
    let finger_r = expected(&cert.certificate);

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(info_span!("L"), RtcConfig::new().build(now));
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        RtcConfig::new().set_dtls_cert(cert).build(now),
    );

    let host_l = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host_r = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host_l.clone()).unwrap();
    l.add_remote_candidate(host_r.clone());
    r.add_local_candidate(host_r).unwrap();
    r.add_remote_candidate(host_l);

    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    l.direct_api().set_remote_fingerprint(finger_r);
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();
    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);
    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    // L is the DTLS client, as towards a media gateway answering `a=setup:passive`.
    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();

    while !(l.is_connected() && r.is_connected()) {
        if l.duration() > Duration::from_secs(5) {
            panic!("DTLS did not connect");
        }
        progress(&mut l, &mut r)?;
    }
    Ok(())
}

fn sha1_fingerprint(hash_func: &str, der: &[u8]) -> Fingerprint {
    Fingerprint {
        hash_func: hash_func.into(),
        bytes: Sha1::digest(der).to_vec(),
    }
}

#[test]
fn sha1_fingerprint_is_verified() -> Result<(), RtcError> {
    connect(|der| sha1_fingerprint("sha-1", der))
}

#[test]
fn hash_function_names_are_case_insensitive() -> Result<(), RtcError> {
    connect(|der| sha1_fingerprint("SHA-1", der))
}

#[test]
fn wrong_sha1_fingerprint_is_rejected() {
    let error = connect(|der| {
        let mut wrong = sha1_fingerprint("sha-1", der);
        wrong.bytes[0] ^= 0xff;
        wrong
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("remote fingerprint no match"),
        "{error}"
    );
}

#[test]
fn unsupported_hash_function_is_rejected() {
    let error = connect(|_| Fingerprint {
        hash_func: "sha-512".into(),
        bytes: vec![0; 64],
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported fingerprint hash function: sha-512"),
        "{error}"
    );
}
