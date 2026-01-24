use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::RtcConfig;
use str0m::RtcError;
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, poll_to_completion, progress, Peer, TestRtc};

#[test]
pub fn ice_restart() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let rtc = RtcConfig::new().set_ice_lite(true).build();
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let time = l.last;

    let (offer, pending) = {
        let tx = l.rtc.begin(time)?;
        let mut change = tx.sdp_api();
        let _ = change.add_channel("My little channel".into());
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
        (offer, pending)
    };
    println!("L Initial Offer: {}", offer);

    let answer = {
        let tx = r.rtc.begin(time)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
        answer
    };
    println!("R Initial answer: {}", answer);

    {
        let tx = l.rtc.begin(time)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
    }

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let l_creds = l._local_ice_creds();
    let r_creds = r._local_ice_creds();

    let time = r.last;

    let (offer, pending) = {
        let tx = r.rtc.begin(time)?;
        let mut change = tx.sdp_api();
        change.ice_restart(true);
        let (offer, pending, tx) = change.apply().expect("Should be able to apply changes");
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
        (offer, pending)
    };
    println!("R Offer: {}", offer);

    let answer = {
        let tx = l.rtc.begin(time)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
        answer
    };
    println!("L Answer: {}", answer);

    {
        let tx = r.rtc.begin(time)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
    }

    assert!(!l.rtc.is_connected());
    assert!(!r.rtc.is_connected());

    loop {
        if l.duration() > Duration::from_secs(10) {
            panic!("Failed to re-establish connectivity after ICE restart in 10 seconds");
        }

        if l.is_connected() && r.is_connected() {
            break;
        }

        progress(&mut l, &mut r)?;
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
