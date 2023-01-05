use ice::IceAgentStats;
use tracing::info_span;

mod common;
use common::{host, init_log, progress, TestAgent};

#[test]
pub fn prflx_host() {
    init_log();

    let mut a1 = TestAgent::new(info_span!("L"));
    let mut a2 = TestAgent::new(info_span!("R"));

    let c1 = host("3.3.3.3:1000"); // will be rewritten to 4.4.4.4
    a1.add_local_candidate(c1.clone());
    a2.add_remote_candidate(c1);
    let c2 = host("2.2.2.2:1000");
    a2.add_local_candidate(c2.clone());
    a1.add_remote_candidate(c2);

    a1.set_controlling(true);
    a2.set_controlling(false);

    loop {
        if a1.state().is_connected() && a2.state().is_connected() {
            break;
        }
        progress(&mut a1, &mut a2);
    }

    assert_eq!(
        a1.stats(),
        IceAgentStats {
            bind_request_sent: 2,
            bind_success_recv: 2,
            bind_request_recv: 1,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );

    assert_eq!(
        a2.stats(),
        IceAgentStats {
            bind_request_sent: 3,
            bind_success_recv: 1,
            bind_request_recv: 2,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );
}
