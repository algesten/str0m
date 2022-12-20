use std::net::Ipv4Addr;

use str0m::media::MediaTime;
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

    let mut change = l.create_offer();
    let cid = change.add_channel("My little channel".into());
    let offer = change.apply();

    let answer = r.accept_offer(offer)?;
    l.pending_changes().unwrap().accept_answer(answer)?;

    loop {
        if l.ice_connection_state().is_connected() || r.ice_connection_state().is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let mut time_l: MediaTime = l.duration().into();
    time_l = time_l.rebase(48_000);

    loop {
        if let Some(mut chan) = l.channel(cid) {
            let n = chan
                .write(false, "Hello world! ".as_bytes())
                .expect("to write string");
            println!("wrote {}", n);
        }

        progress(&mut l, &mut r)?;

        if time_l > MediaTime::from_seconds(10) {
            break;
        }
    }

    println!("{:?}", r.events);

    Ok(())
}
