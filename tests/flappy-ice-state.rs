use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::RtcConfig;
use str0m::{Candidate, Event, RtcError};
use tracing::info_span;

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn flappy_ice_lite_state() -> Result<(), RtcError> {
    init_log();

    let mut l = TestRtc::new(info_span!("L"));

    let rtc = RtcConfig::new().set_ice_lite(true).build();
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    let mut change = l.sdp_api();
    let _ = change.add_channel("My little channel".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(120) {
            break;
        }
    }

    let ice_events = r
        .events
        .iter()
        .filter(|e| matches!(e, Event::IceConnectionStateChange(_)))
        .count();

    assert!(ice_events < 10);

    Ok(())
}
