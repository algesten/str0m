use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::change::SdpStrategy;
use str0m::{Candidate, RtcError};
use tracing::info_span;

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn data_channel() -> Result<(), RtcError> {
    init_log();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    let mut change = l.create_change_set(SdpStrategy);
    let cid = change.add_channel("My little channel".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = SdpStrategy.accept_offer(&mut r.rtc, offer)?;
    pending.accept_answer(&mut l.rtc, answer)?;

    loop {
        if l.ice_connection_state().is_connected() || r.ice_connection_state().is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    loop {
        if let Some(mut chan) = l.channel(cid) {
            chan.write(false, "Hello world! ".as_bytes())
                .expect("to write string");
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    assert!(r.events.len() > 120);

    Ok(())
}
