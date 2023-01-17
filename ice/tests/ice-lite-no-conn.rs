use ice::IceAgentStats;
use tracing::info_span;

mod common;
use common::{host, init_log, progress, TestAgent};

#[test]
pub fn ice_lite_no_connection() {
    init_log();

    let mut a1 = TestAgent::new(info_span!("L"));
    let mut a2 = TestAgent::new(info_span!("R"));

    // a1 acts as "server"
    a1.agent.set_ice_lite(true);

    let c1 = host("1.1.1.1:9999"); // 9999 is just dropped by propagate
    a1.add_local_candidate(c1.clone());
    a2.add_remote_candidate(c1);
    let c2 = host("2.2.2.2:1000");
    a2.add_local_candidate(c2.clone());
    a1.add_remote_candidate(c2);
    a1.set_controlling(true);
    a2.set_controlling(false);

    loop {
        // The bug we try to avoid is that _both sides_ must reach a disconnected state eventually.
        // The ice-lite (server side) should time out after roughly 8 seconds.
        if a1.state().is_disconnected() && a2.state().is_disconnected() {
            break;
        }
        progress(&mut a1, &mut a2);
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
