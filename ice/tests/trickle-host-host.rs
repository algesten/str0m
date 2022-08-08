use tracing::info_span;

mod common;
use common::{host, init_log, progress, TestAgent};

#[test]
pub fn trickle_host_host() {
    init_log();

    let mut a1 = TestAgent::new(info_span!("L"));
    let mut a2 = TestAgent::new(info_span!("R"));

    a1.add_local_candidate(host("3.3.3.3:9999")); // no traffic possible
    a2.add_local_candidate(host("2.2.2.2:1000"));
    a1.set_controlling(true);
    a2.set_controlling(false);

    // this will be going nowhere (tested in drop-host.rs).
    for _ in 0..10 {
        progress(&mut a1, &mut a2);
    }

    // "trickle" a possible candidate
    a1.add_local_candidate(host("1.1.1.1:1000")); // possible

    // loop until we're connected.
    loop {
        if a1.state().is_connected() && a2.state().is_connected() {
            break;
        }
        progress(&mut a1, &mut a2);
    }
}
