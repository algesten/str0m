use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::RtcConfig;
use str0m::RtcError;
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, Peer, TestRtc};

#[test]
pub fn ice_restart() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let rtc = RtcConfig::new().set_ice_lite(true).build();
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut offer = None;
    let mut pending = None;
    l.drive(&mut r, |tx| {
        let mut change = tx.sdp_api();
        let _ = change.add_channel("My little channel".into());
        let (o, p, tx) = change.apply().unwrap();
        offer = Some(o);
        pending = Some(p);
        Ok(tx)
    })?;
    let offer = offer.unwrap();
    let pending = pending.unwrap();
    println!("L Initial Offer: {}", offer);

    let mut answer = None;
    r.drive(&mut l, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok(tx)
    })?;
    let answer = answer.unwrap();
    println!("R Initial answer: {}", answer);

    l.drive(&mut r, |tx| tx.sdp_api().accept_answer(pending, answer))?;

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    let l_creds = l._local_ice_creds();
    let r_creds = r._local_ice_creds();

    let mut offer = None;
    let mut pending = None;
    r.drive(&mut l, |tx| {
        let mut change = tx.sdp_api();
        change.ice_restart(true);
        let (o, p, tx) = change.apply().expect("Should be able to apply changes");
        offer = Some(o);
        pending = Some(p);
        Ok(tx)
    })?;
    let offer = offer.unwrap();
    let pending = pending.unwrap();
    println!("R Offer: {}", offer);

    let mut answer = None;
    l.drive(&mut r, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok(tx)
    })?;
    let answer = answer.unwrap();
    println!("L Answer: {}", answer);

    r.drive(&mut l, |tx| tx.sdp_api().accept_answer(pending, answer))?;

    assert!(!l.rtc.is_connected());
    assert!(!r.rtc.is_connected());

    loop {
        if l.duration() > Duration::from_secs(10) {
            panic!("Failed to re-establish connectivity after ICE restart in 10 seconds");
        }

        if l.is_connected() && r.is_connected() {
            break;
        }

        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    assert_ne!(
        r_creds,
        r._local_ice_creds(),
        "After an ICE restart ICE credentials should have changed"
    );
    assert_ne!(
        l_creds,
        l._local_ice_creds(),
        "After an ICE restart ICE credentials should have changed"
    );

    Ok(())
}
