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

    let (offer, pending) = l.span.in_scope(|| {
        let tx = l.rtc.begin(l.last).unwrap();
        let mut change = tx.sdp_api();
        let _ = change.add_channel("My little channel".into());
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(tx).unwrap();
        (offer, pending)
    });
    println!("L Initial Offer: {}", offer);

    let answer = r.span.in_scope(|| {
        let tx = r.rtc.begin(r.last).unwrap();
        let (answer, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        poll_to_completion(tx).unwrap();
        answer
    });
    println!("R Initial answer: {}", answer);

    l.span.in_scope(|| {
        let tx = l.rtc.begin(l.last).unwrap();
        let tx = tx.sdp_api().accept_answer(pending, answer).unwrap();
        poll_to_completion(tx).unwrap();
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let l_creds = l._local_ice_creds();
    let r_creds = r._local_ice_creds();

    let (offer, pending) = r.span.in_scope(|| {
        let tx = r.rtc.begin(r.last).unwrap();
        let mut change = tx.sdp_api();
        change.ice_restart(true);
        let (offer, pending, tx) = change.apply().expect("Should be able to apply changes");
        poll_to_completion(tx).unwrap();
        (offer, pending)
    });
    println!("R Offer: {}", offer);

    let answer = l.span.in_scope(|| {
        let tx = l.rtc.begin(l.last).unwrap();
        let (answer, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        poll_to_completion(tx).unwrap();
        answer
    });
    println!("L Answer: {}", answer);

    r.span.in_scope(|| {
        let tx = r.rtc.begin(r.last).unwrap();
        let tx = tx.sdp_api().accept_answer(pending, answer).unwrap();
        poll_to_completion(tx).unwrap();
    });

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
