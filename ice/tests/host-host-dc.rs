use std::time::Duration;

use ice::{IceAgentEvent, IceAgentStats, IceConnectionState};
use tracing::info_span;

mod common;
use common::{host, init_log, progress, TestAgent};

#[test]
pub fn host_host_disconnect() {
    init_log();

    let mut a1 = TestAgent::new(info_span!("L"));
    let mut a2 = TestAgent::new(info_span!("R"));

    a1.add_local_candidate(host("1.1.1.1:1000"));
    a2.add_local_candidate(host("2.2.2.2:1000"));
    a1.set_controlling(true);
    a2.set_controlling(false);

    loop {
        if a1.state().is_connected() && a2.state().is_connected() {
            break;
        }
        progress(&mut a1, &mut a2);
    }

    a1.drop_sent_packets = true;

    loop {
        if !a1.state().is_connected() && !a2.state().is_connected() {
            break;
        }
        progress(&mut a1, &mut a2);
    }

    println!("{:?}", a1.events);
    println!("{:?}", a2.events);

    fn assert_last_event(d: &Duration, e: &IceAgentEvent) {
        assert_eq!(
            *e,
            IceAgentEvent::IceConnectionStateChange(IceConnectionState::Disconnected)
        );
        assert!(*d > Duration::from_secs(50));
    }

    let (d, e) = a1.events.last().unwrap();
    assert_last_event(d, e);

    let (d, e) = a2.events.last().unwrap();
    assert_last_event(d, e);

    assert_eq!(
        a1.stats(),
        IceAgentStats {
            bind_request_sent: 11,
            bind_success_recv: 2,
            bind_request_recv: 11,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );

    assert_eq!(
        a2.stats(),
        IceAgentStats {
            bind_request_sent: 11,
            bind_success_recv: 2,
            bind_request_recv: 2,
            discovered_recv_count: 1,
            nomination_send_count: 1,
        }
    );
}
