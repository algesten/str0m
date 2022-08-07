use std::time::Instant;

use ice::{IceAgent, IceAgentStats};
use tracing::info_span;

mod common;
use common::{host, init_log, progress};

#[test]
pub fn drop_host() {
    init_log();

    let mut a1 = IceAgent::new();
    let mut a2 = IceAgent::new();

    a1.add_local_candidate(host("1.1.1.1:9999")); // no traffic possible
    a2.add_local_candidate(host("2.2.2.2:1000"));
    a1.set_controlling(true);
    a2.set_controlling(false);

    let span1 = info_span!("L");
    let span2 = info_span!("R");

    let mut now = Instant::now();

    loop {
        if a1.state().is_disconnected() && a2.state().is_disconnected() {
            break;
        }
        now = progress(now, &mut a1, &mut a2, &span1, &span2);
        now = progress(now, &mut a2, &mut a1, &span2, &span1);
    }

    assert_eq!(
        a1.stats(),
        IceAgentStats {
            bind_request_sent: 9,
            bind_success_recv: 0,
            bind_request_recv: 0,
            discovered_recv_count: 0,
            nomination_send_count: 0,
        }
    );

    assert_eq!(
        a2.stats(),
        IceAgentStats {
            bind_request_sent: 9,
            bind_success_recv: 0,
            bind_request_recv: 0,
            discovered_recv_count: 0,
            nomination_send_count: 0,
        }
    );
}
