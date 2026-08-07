//! DTLS handshake run over ICE, inside STUN connectivity checks.
//!
//! See [`str0m::RtcConfig::enable_dtls_over_ice`].

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

/// How much slower than not using the extension at all a fallback may be.
///
/// Zero in principle: the fallback should cost nothing. A small allowance
/// absorbs the harness stepping time in 5ms batches, and stays far below any
/// DTLS retransmission timeout, which is what this guards against.
const FALLBACK_TOLERANCE: Duration = Duration::from_millis(10);

/// Runs a connection to completion, returning how long each side took to reach
/// [`Event::Connected`].
fn connect(left_over_ice: bool, right_over_ice: bool) -> Result<(Duration, Duration), RtcError> {
    let mut l = TestRtc::new_with_config(Peer::Left, |c| c.enable_dtls_over_ice(left_over_ice));
    let mut r = TestRtc::new_with_config(Peer::Right, |c| c.enable_dtls_over_ice(right_over_ice));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        if l.duration() > Duration::from_secs(20) {
            panic!("Did not connect within 20 seconds");
        }
        progress(&mut l, &mut r)?;
    }

    let connected_at = |rtc: &TestRtc| {
        rtc.events
            .iter()
            .find(|(_, e)| matches!(e, Event::Connected))
            .map(|(t, _)| *t - rtc.start)
            .expect("a Connected event")
    };

    Ok((connected_at(&l), connected_at(&r)))
}

#[test]
pub fn dtls_over_ice_connects() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (with_l, with_r) = connect(true, true)?;
    let (without_l, without_r) = connect(false, false)?;

    // The whole point of the extension: the handshake overlaps ICE rather than
    // following it, so the connection as a whole comes up sooner.
    let with = with_l.max(with_r);
    let without = without_l.max(without_r);
    assert!(
        with < without,
        "DTLS over ICE was not faster: {with:?} vs {without:?}"
    );

    Ok(())
}

#[test]
pub fn dtls_over_ice_falls_back_when_peer_does_not_support_it() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // A peer that does not implement the extension echoes neither attribute,
    // which must leave an ordinary handshake working in both directions.
    let (base_l, base_r) = connect(false, false)?;
    let (left_l, left_r) = connect(true, false)?;
    let (right_l, right_r) = connect(false, true)?;

    let baseline = base_l.max(base_r);
    let left_only = left_l.max(left_r);
    let right_only = right_l.max(right_r);

    // Falling back must not cost anything. A handshake packet we already took
    // out of the DTLS engine to ride along in connectivity checks has to reach
    // the peer some other way once we discover the peer ignores it. Waiting for
    // DTLS to retransmit a replacement shows up here as a delay, and on the
    // backends that never retransmit it would not connect at all.
    assert!(
        left_only <= baseline + FALLBACK_TOLERANCE,
        "falling back was slower than never trying: {left_only:?} vs {baseline:?}"
    );
    assert!(
        right_only <= baseline + FALLBACK_TOLERANCE,
        "falling back was slower than never trying: {right_only:?} vs {baseline:?}"
    );

    Ok(())
}

/// A DTLS 1.3 ClientHello only fits in a connectivity check because the DTLS
/// MTU is capped while this extension is enabled.
///
/// Lifting the cap does not break the handshake, which is what makes it worth a
/// test of its own: DTLS just falls back to ordinary datagrams and everything
/// still connects. What is quietly lost is the first flight riding along, which
/// is the whole point of the extension. So this asserts on the packet rather
/// than on the connection.
///
/// One peer is enough. The check goes out as soon as there is a handshake
/// packet to put in it, and nobody has to answer for us to look at what we sent.
///
/// DTLS 1.3 only, so this runs on the dimpl-backed providers.
#[cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl-dimpl",
    feature = "wincrypto-dimpl",
    feature = "apple-crypto",
))]
#[test]
pub fn dtls_13_client_hello_fits_in_a_check() -> Result<(), RtcError> {
    use std::time::Instant;

    use str0m::config::DtlsVersion;
    use str0m::ice::{IceCreds, StunMessage};
    use str0m::{Candidate, Input, Output, Rtc};

    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut rtc = Rtc::builder()
        .enable_dtls_over_ice(true)
        .set_dtls_version(DtlsVersion::Dtls13)
        .build(now);

    let local = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let remote = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    rtc.add_local_candidate(local);
    rtc.add_remote_candidate(remote);

    // Nothing answers, so the remote credentials and fingerprint are never
    // used. They only need to exist for the handshake to start.
    let fingerprint = rtc.direct_api().local_dtls_fingerprint().clone();
    rtc.direct_api().set_remote_fingerprint(fingerprint);
    rtc.direct_api().set_remote_ice_credentials(IceCreds::new());
    rtc.direct_api().set_ice_controlling(true);
    rtc.direct_api().start_dtls(true).unwrap();

    let mut now = now;
    let mut carried_client_hello = false;
    let mut checks_sent = 0;

    for _ in 0..50 {
        now += Duration::from_millis(20);
        rtc.handle_input(Input::Timeout(now))?;

        loop {
            match rtc.poll_output()? {
                Output::Timeout(_) => break,
                Output::Event(_) => continue,
                Output::Transmit(transmit) => {
                    let Ok(message) = StunMessage::parse(&transmit.contents) else {
                        continue;
                    };
                    checks_sent += 1;

                    if message.dtls_packet().is_some_and(is_client_hello) {
                        carried_client_hello = true;
                    }
                }
            }
        }

        if carried_client_hello {
            break;
        }
    }

    assert!(checks_sent > 0, "no connectivity checks were sent at all");
    assert!(
        carried_client_hello,
        "no connectivity check carried the DTLS 1.3 ClientHello, so it is too \
         big to fit in one — has the DTLS MTU cap been removed?"
    );

    Ok(())
}

/// Whether a DTLS packet begins with a ClientHello.
///
/// The record header is 13 bytes and the handshake message type follows it.
#[cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl-dimpl",
    feature = "wincrypto-dimpl",
    feature = "apple-crypto",
))]
fn is_client_hello(packet: &[u8]) -> bool {
    const DTLS_HANDSHAKE_RECORD: u8 = 22;
    const DTLS_CLIENT_HELLO: u8 = 1;

    packet.first() == Some(&DTLS_HANDSHAKE_RECORD) && packet.get(13) == Some(&DTLS_CLIENT_HELLO)
}
