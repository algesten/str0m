use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::RtcConfig;
use str0m::{Event, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, Peer, TestRtc};

#[test]
pub fn flappy_ice_lite_state() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let rtc = RtcConfig::new().set_ice_lite(true).build();
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Create offer from L
    let mut offer = None;
    let mut pending = None;
    l.drive(&mut r, |tx| {
        let mut change = tx.sdp_api();
        change.add_channel("My little channel".into());
        let (o, p, tx) = change.apply().unwrap();
        offer = Some(o);
        pending = Some(p);
        Ok((tx, ()))
    })?;
    let offer = offer.unwrap();
    let pending = pending.unwrap();

    // R accepts the offer
    let mut answer = None;
    r.drive(&mut l, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok((tx, ()))
    })?;
    let answer = answer.unwrap();

    // L accepts the answer
    l.drive(&mut r, |tx| {
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        Ok((tx, ()))
    })?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    loop {
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;

        if l.duration() > Duration::from_secs(120) {
            break;
        }
    }

    let ice_events = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::IceConnectionStateChange(_)))
        .count();

    assert!(ice_events < 10);

    Ok(())
}
