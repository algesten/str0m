use std::convert::TryFrom;
use std::time::Instant;

use ice_common::sock;
use str0m::{Candidate, IceAgent, IceAgentEvent, Receive};

mod ice_common;

fn host(s: impl Into<String>) -> Candidate {
    Candidate::host(sock(s)).unwrap()
}
pub fn progress(
    now: Instant,
    f: &mut IceAgent,
    t: &mut IceAgent,
) -> (Instant, Option<IceAgentEvent>) {
    f.handle_timeout(now);

    if let Some(trans) = f.poll_transmit() {
        println!("forward: {} -> {}", trans.source, trans.destination);
        t.handle_receive(now, Receive::try_from(&trans).unwrap());
    }

    let timeout = f.poll_timeout();

    let event = f.poll_event();

    (timeout.unwrap(), event)
}

#[test]
pub fn host_host() {
    let mut a1 = IceAgent::new();
    let mut a2 = IceAgent::new();
    let h1 = host("1.1.1.1:4000");
    let h1r = Candidate::parse(&h1.to_string()).unwrap();
    let h2 = host("2.2.2.2:5000");
    let h2r = Candidate::parse(&h2.to_string()).unwrap();

    a1.add_local_candidate(h1);
    a2.add_local_candidate(h2);
    a1.add_remote_candidate(h2r);
    a2.add_remote_candidate(h1r);
    a1.set_remote_credentials(a2.local_credentials().clone());
    a2.set_remote_credentials(a1.local_credentials().clone());
    a1.set_controlling(true);
    a2.set_controlling(false);

    let now = Instant::now();

    let (now, event) = progress(now, &mut a1, &mut a2);
}
