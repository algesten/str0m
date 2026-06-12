//! Test that calling `Rtc::close()` sends a DTLS close_notify alert
//! and marks the Rtc instance as not alive.
#![cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl",
    feature = "openssl-dimpl",
    feature = "wincrypto-dimpl",
    feature = "apple-crypto",
))]

use std::net::Ipv4Addr;
use std::time::Instant;

use str0m::{Candidate, Event, Rtc};
use tracing::info_span;

mod common;
use common::{TestRtc, init_crypto_default, init_log, progress};

#[test]
fn close_notify_received_by_remote() {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(info_span!("L"), Rtc::new(now));
    let mut r = TestRtc::new_with_rtc(info_span!("R"), Rtc::new(now));

    let host_l = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host_r = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host_l.clone());
    l.add_remote_candidate(host_r.clone());
    r.add_local_candidate(host_r);
    r.add_remote_candidate(host_l);

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
    l.direct_api().start_sctp(true);
    r.direct_api().start_sctp(false);

    // Drive both sides until connected.
    let mut iterations = 0;
    while !(l.is_connected() && r.is_connected()) {
        progress(&mut l, &mut r).unwrap();
        iterations += 1;
        assert!(iterations < 500, "DTLS handshake did not complete");
    }
    println!("Both peers connected after {iterations} iterations");

    // L initiates close.
    println!("L calling close()");
    l.rtc.close().expect("L close");

    // Drive the close_notify packet from L to R.
    let mut r_got_closed = false;
    for i in 0..100 {
        progress(&mut l, &mut r).unwrap();
        if r.events.iter().any(|(_, e)| matches!(e, Event::Closed)) {
            println!("R received Event::Closed after {i} progress iterations");
            r_got_closed = true;
            break;
        }
    }

    assert!(
        r_got_closed,
        "R should receive Event::Closed after L sends close_notify"
    );

    // After close, L should no longer be alive
    assert!(!l.rtc.is_alive(), "L should not be alive after close");

    // R also initiates close and drains.
    println!("R calling close()");
    r.rtc.close().expect("R close");
    for _ in 0..10 {
        progress(&mut l, &mut r).unwrap();
    }

    assert!(!r.rtc.is_alive(), "R should not be alive after close");
}
