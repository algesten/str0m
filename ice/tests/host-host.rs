use std::convert::TryFrom;
use std::time::{Duration, Instant};

use common::{init_log, sock};
use ice::{Candidate, IceAgent, IceAgentStats};
use net::Receive;
use tracing::{info_span, Span};

mod common;

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
    let h2 = host("2.2.2.2:5000");

    a1.add_local_candidate(h1.clone());
    a2.add_local_candidate(h2.clone());
    a1.add_remote_candidate(h2);
    a2.add_remote_candidate(h1);
    a1.set_remote_credentials(a2.local_credentials().clone());
    a2.set_remote_credentials(a1.local_credentials().clone());
    a1.set_controlling(true);
    a2.set_controlling(false);

    let mut now = Instant::now();

    a1.set_last_now(now - Duration::from_millis(100));
    a2.set_last_now(now - Duration::from_millis(100));

    let span1 = info_span!("L");
    let span2 = info_span!("R");

    loop {
        if a1.state().is_connected() && a2.state().is_connected() {
            break;
        }
        now = progress(now, &mut a1, &mut a2, &span1, &span2);
        now = progress(now, &mut a2, &mut a1, &span2, &span1);
    }

    assert_eq!(
        a1.stats(),
        IceAgentStats {
            bind_request_sent: 2,
            bind_success_recv: 2,
            bind_request_recv: 2,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );

    assert_eq!(
        a2.stats(),
        IceAgentStats {
            bind_request_sent: 2,
            bind_success_recv: 1,
            bind_request_recv: 2,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );
}
