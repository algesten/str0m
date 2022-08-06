use std::convert::TryFrom;
use std::time::{Duration, Instant};

use common::init_log;
use ice_common::sock;
use str0m::{Candidate, IceAgent, Receive};
use tracing::{info_span, Span};

mod common;
mod ice_common;

fn host(s: impl Into<String>) -> Candidate {
    Candidate::host(sock(s)).unwrap()
}
pub fn progress(now: Instant, f: &mut IceAgent, t: &mut IceAgent, sf: &Span, st: &Span) -> Instant {
    sf.in_scope(|| f.handle_timeout(now));

    while let Some(trans) = sf.in_scope(|| f.poll_transmit()) {
        println!("forward: {} -> {}", trans.source, trans.destination);
        st.in_scope(|| t.handle_receive(now, Receive::try_from(&trans).unwrap()));
    }

    let tim_f = sf.in_scope(|| f.poll_timeout());
    let tim_t = st.in_scope(|| t.poll_timeout());

    while let Some(v) = sf.in_scope(|| f.poll_event()) {
        println!("Polled event: {:?}", v);
    }

    tim_f.unwrap().min(tim_t.unwrap())
}

#[test]
pub fn host_host() {
    init_log();

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

    a1.set_last_now(now - Duration::from_millis(100));
    a2.set_last_now(now - Duration::from_millis(100));

    let span1 = info_span!("L");
    let span2 = info_span!("R");

    let now = progress(now, &mut a1, &mut a2, &span1, &span2);
    let now = progress(now, &mut a2, &mut a1, &span2, &span1);
    let now = progress(now, &mut a1, &mut a2, &span1, &span2);
    let now = progress(now, &mut a2, &mut a1, &span2, &span1);
    let now = progress(now, &mut a1, &mut a2, &span1, &span2);
    let now = progress(now, &mut a2, &mut a1, &span2, &span1);
    let now = progress(now, &mut a1, &mut a2, &span1, &span2);
}
