//! DTLS handshake run over ICE, inside STUN connectivity checks.
//!
//! See [`str0m::RtcConfig::enable_dtls_over_ice`].

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

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
    connect(true, false)?;
    connect(false, true)?;

    Ok(())
}
