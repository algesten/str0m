use ice::IceAgentStats;
use tracing::info_span;

mod common;
use common::{host, init_log, progress, TestAgent};

#[test]
pub fn host_local_relay() {
    init_log();

    let mut a1 = TestAgent::new(info_span!("L"));
    let mut a2 = TestAgent::new(info_span!("R"));

    let c1 = host("1.1.1.1:1000");
    a1.add_local_candidate(c1.clone());
    a2.add_remote_candidate(c1);
    let c2a = host("2.2.2.2:1000");
    let c2b = host("2.2.2.3:1000");
    a2.add_local_candidate(c2a.clone());
    a1.add_remote_candidate(c2b);
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
            bind_request_sent: 3,
            bind_success_recv: 3,
            bind_request_recv: 3,
            discovered_recv_count: 2,
            nomination_send_count: 1,
        }
    );

    assert_eq!(
        a2.stats(),
        IceAgentStats {
            bind_request_sent: 4,
            bind_success_recv: 3,
            bind_request_recv: 3,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );
}
