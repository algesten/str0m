use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use netem::{NetemConfig, Probability, RandomLoss};
use str0m::{Event, IceConnectionState, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

#[test]
pub fn ice_lite_premature_disconnect() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let rtc = RtcConfig::new().set_ice_lite(true).build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

    r.set_netem(NetemConfig::new().latency(Duration::from_millis(5)));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_channel("ch".into());
    let (offer, pending) = change.apply().unwrap();
    let answer = r.sdp_api().accept_offer(offer)?;
    l.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.duration() > Duration::from_secs(5) {
            panic!("Timeout waiting for connection");
        }

        let r_disconnected = r.events.iter().any(|(_, e)| {
            matches!(
                e,
                Event::IceConnectionStateChange(IceConnectionState::Disconnected)
            )
        });

        if r_disconnected {
            panic!("ICE-lite peer disconnected before receiving binding requests");
        }

        if l.is_connected() && r.is_connected() {
            break;
        }

        progress(&mut l, &mut r)?;
    }

    Ok(())
}

/// Connects a full ICE peer to an ice-lite peer, then drops everything sent to
/// the ice-lite peer, and returns how long it took the ice-lite peer to report
/// that it was disconnected.
fn ice_lite_disconnect_delay(ice_lite_timeout: Option<Duration>) -> Result<Duration, RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let mut config = RtcConfig::new().set_ice_lite(true);
    if let Some(timeout) = ice_lite_timeout {
        config.set_ice_lite_timeout(timeout);
    }
    let mut r = TestRtc::new_with_rtc(info_span!("R"), config.build(Instant::now()));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_channel("ch".into());
    let (offer, pending) = change.apply().unwrap();
    let answer = r.sdp_api().accept_offer(offer)?;
    l.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.duration() > Duration::from_secs(5) {
            panic!("Timeout waiting for connection");
        }

        if l.is_connected() && r.is_connected() {
            break;
        }

        progress(&mut l, &mut r)?;
    }

    r.set_netem(NetemConfig::new().loss(RandomLoss::new(Probability::new(1.0))));
    let dropped_at = r.last;

    loop {
        let disconnected_at = r.events.iter().find_map(|(at, e)| {
            matches!(
                e,
                Event::IceConnectionStateChange(IceConnectionState::Disconnected)
            )
            .then_some(*at)
        });

        if let Some(at) = disconnected_at {
            return Ok(at - dropped_at);
        }

        if r.last - dropped_at > Duration::from_secs(120) {
            panic!("The ice-lite peer never noticed that the remote peer was gone");
        }

        progress(&mut l, &mut r)?;
    }
}

#[test]
pub fn ice_lite_disconnects_after_the_default_timeout() -> Result<(), RtcError> {
    let delay = ice_lite_disconnect_delay(None)?;

    assert!(delay >= Duration::from_secs(12), "{delay:?}");
    assert!(delay <= Duration::from_secs(18), "{delay:?}");

    Ok(())
}

#[test]
pub fn ice_lite_disconnects_after_the_configured_timeout() -> Result<(), RtcError> {
    let delay = ice_lite_disconnect_delay(Some(Duration::from_secs(60)))?;

    assert!(delay >= Duration::from_secs(57), "{delay:?}");
    assert!(delay <= Duration::from_secs(63), "{delay:?}");

    Ok(())
}
