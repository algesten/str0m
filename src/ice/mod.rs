#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]

use thiserror::Error;

mod agent;
pub use agent::{IceAgent, IceAgentEvent, IceConnectionState, IceCreds};

mod candidate;
pub use candidate::{Candidate, CandidateKind};

mod pair;

/// Errors from the ICE agent.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum IceError {
    #[error("ICE bad candidate: {0}")]
    BadCandidate(String),
}

#[cfg(test)]
mod test {
    use super::agent::IceAgentStats;
    use super::*;

    #[test]
    pub fn drop_host() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("1.1.1.1:9999", "udp"); // 9999 is just dropped by propagate
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = host("2.2.2.2:1000", "udp");
        a2.add_local_candidate(c2.clone());
        a1.add_remote_candidate(c2);
        a1.set_controlling(true);
        a2.set_controlling(false);

        loop {
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

    use std::net::IpAddr;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::ops::{Deref, DerefMut};
    use std::time::{Duration, Instant};

    use crate::io::{Protocol, StunMessage, StunPacket, STUN_TIMEOUT};
    use tracing::Span;
    use tracing_subscriber::util::SubscriberInitExt;

    pub fn sock(s: impl Into<String>) -> SocketAddr {
        let s: String = s.into();
        s.parse().unwrap()
    }

    pub fn host(s: impl Into<String>, proto: impl TryInto<Protocol>) -> Candidate {
        Candidate::host(sock(s), proto).unwrap()
    }

    pub fn srflx(
        s: impl Into<String>,
        base: impl Into<String>,
        proto: impl TryInto<Protocol>,
    ) -> Candidate {
        Candidate::server_reflexive(sock(s), sock(base), proto).unwrap()
    }

    pub fn relay(s: impl Into<String>, proto: impl TryInto<Protocol>) -> Candidate {
        Candidate::relayed(sock(s), proto).unwrap()
    }

    /// Transform the socket to rig different test scenarios.
    ///
    /// * either port 9999 -> closed (packets dropped)
    /// * from 3.3.3.3 is rewritten to 4.4.4.4
    /// * to 3.3.3.3 is dropped
    /// * to 4.4.4.4 is rewritten to 3.3.3.3
    fn transform(from: SocketAddr, to: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
        if from.port() == 9999 || to.port() == 9999 {
            // drop packet.
            return None;
        }

        const IP3333: Ipv4Addr = Ipv4Addr::new(3, 3, 3, 3);
        const IP4444: Ipv4Addr = Ipv4Addr::new(4, 4, 4, 4);

        let ip_from = match from.ip() {
            IpAddr::V4(v) => {
                if v == IP3333 {
                    // rewrite 3.3.3.3 -> 4.4.4.4
                    IpAddr::V4(IP4444)
                } else {
                    IpAddr::V4(v)
                }
            }
            IpAddr::V6(v) => IpAddr::V6(v),
        };

        let ip_to = match to.ip() {
            IpAddr::V4(v) => {
                if v == IP3333 {
                    // drop packets targeted at 3.3.3.3
                    return None;
                } else if v == IP4444 {
                    // rewrite 4.4.4.4 -> 3.3.3.3
                    IpAddr::V4(IP3333)
                } else {
                    IpAddr::V4(v)
                }
            }
            IpAddr::V6(v) => IpAddr::V6(v),
        };

        Some((
            SocketAddr::new(ip_from, from.port()),
            SocketAddr::new(ip_to, to.port()),
        ))
    }

    #[test]
    pub fn host_host_disconnect() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("1.1.1.1:1000", "udp");
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = host("2.2.2.2:1000", "udp");
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
            assert!(*d > STUN_TIMEOUT);
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

    #[test]
    pub fn host_host() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("1.1.1.1:1000", "udp");
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = host("2.2.2.2:1000", "udp");
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
                bind_request_recv: 2,
                discovered_recv_count: 1,
                nomination_send_count: 1,
            }
        );

        assert_eq!(
            a2.stats(),
            IceAgentStats {
                bind_request_sent: 3,
                bind_success_recv: 2,
                bind_request_recv: 2,
                discovered_recv_count: 1,
                nomination_send_count: 1,
            }
        );
    }

    #[test]
    pub fn no_respond_to_stun_request_on_invalidated_candidate() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("1.1.1.1:1000", "udp");
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1.clone());
        let c2 = host("2.2.2.2:1000", "udp");
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

        a1.agent.invalidate_candidate(&c1);

        let timeout = a2.poll_timeout().unwrap();
        a2.handle_timeout(timeout);
        let transmit = a2.poll_transmit().unwrap();

        assert!(a1.poll_transmit().is_none());

        a1.handle_packet(
            Instant::now(),
            StunPacket {
                proto: Protocol::Udp,
                source: sock("2.2.2.2:1000"),
                destination: sock("1.1.1.1:1000"),
                message: StunMessage::parse(&transmit.contents).unwrap(),
            },
        );

        assert!(a1.poll_transmit().is_none());
    }

    #[test]
    pub fn migrates_to_new_candidates_after_invalidation_without_timeout() {
        let _guard = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .set_default();

        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("1.1.1.1:1000", "udp");
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1.clone());

        let c2 = host("2.2.2.2:1000", "udp");
        a1.add_remote_candidate(c2.clone());
        a2.add_local_candidate(c2.clone());

        a1.set_controlling(true);
        a2.set_controlling(false);

        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        let a1_time = a1.time;
        let a2_time = a2.time;
        let new_sock = sock("8.8.8.8:1000");

        let c3 = Candidate::host(new_sock, Protocol::Udp).unwrap();
        a1.add_local_candidate(c3.clone());
        a2.add_remote_candidate(c3);

        a1.agent.invalidate_candidate(&c1);
        a2.agent.invalidate_candidate(&c1);

        loop {
            let a1_nominated = a1.has_event(
                |e| matches!(e, IceAgentEvent::NominatedSend { source, .. } if source == &new_sock),
            );
            let a2_nominated = a2.has_event(
                |e| matches!(e, IceAgentEvent::NominatedSend { destination, .. } if destination == &new_sock)
            );

            if a1_nominated && a2_nominated {
                break;
            }

            progress(&mut a1, &mut a2);
        }

        assert!(a1.time.duration_since(a1_time) < STUN_TIMEOUT);
        assert!(a2.time.duration_since(a2_time) < STUN_TIMEOUT);
    }

    #[test]
    pub fn ice_lite_no_connection() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        // a1 acts as "server"
        a1.agent.set_ice_lite(true);

        let c1 = host("1.1.1.1:9999", "udp"); // 9999 is just dropped by propagate
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = host("2.2.2.2:1000", "udp");
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

        assert!(a1.time - a1.start_time > Duration::from_secs(8));

        assert_eq!(
            a1.stats(),
            IceAgentStats {
                bind_request_sent: 0,
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

    #[test]
    pub fn prflx_host() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("3.3.3.3:1000", "udp"); // will be rewritten to 4.4.4.4
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = host("2.2.2.2:1000", "udp");
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

    // pub fn init_log() {
    //     use std::env;
    //     use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    //     if env::var("RUST_LOG").is_err() {
    //         env::set_var("RUST_LOG", "trace");
    //     }

    //     tracing_subscriber::registry()
    //         .with(fmt::layer())
    //         .with(EnvFilter::from_default_env())
    //         .init();
    // }

    #[test]
    pub fn ice_lite_disconnect_reconnect() {
        // init_log();

        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("1.1.1.1:1000", "udp");
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1.clone());
        let c2 = host("2.2.2.2:1000", "udp");
        a2.add_local_candidate(c2.clone());
        a1.add_remote_candidate(c2.clone());

        a1.set_controlling(true);
        a2.set_controlling(false);
        a2.set_ice_lite(true);

        // Connect.
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        // Disconnect
        a1.drop_sent_packets = true;

        loop {
            if !a1.state().is_connected() && !a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        // Now reconnect after disconnecting.
        a1.drop_sent_packets = false;

        // Adding back the remote candidate will for new pairs to try.
        // This makes a1 start sending new STUN requests.
        // a2 in ice-lite mode will discover the pair from the STUN
        // request and come out of disconnected.
        a1.add_remote_candidate(c2);

        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }
    }

    #[test]
    pub fn trickle_host_host() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = host("3.3.3.3:9999", "udp"); // no traffic possible
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = host("2.2.2.2:1000", "udp");
        a2.add_local_candidate(c2.clone());
        a1.add_remote_candidate(c2);

        a1.set_controlling(true);
        a2.set_controlling(false);

        // this will be going nowhere (tested in drop-host.rs).
        for _ in 0..10 {
            progress(&mut a1, &mut a2);
        }

        // "trickle" a possible candidate
        a1.add_local_candidate(host("1.1.1.1:1000", "udp")); // possible

        // loop until we're connected.
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }
    }

    #[test]
    pub fn candidate_pair_of_same_kind_does_not_get_nominated() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = relay("1.1.1.1:1000", "udp");
        a1.add_local_candidate(c1.clone());
        a2.add_remote_candidate(c1);
        let c2 = srflx("4.4.4.4:1000", "3.3.3.3:1000", "udp");
        let c3 = host("3.3.3.3:1000", "udp");
        a2.add_local_candidate(c2.clone());
        a1.add_remote_candidate(c2);
        a2.add_local_candidate(c3.clone());
        a1.add_remote_candidate(c3);

        a1.set_controlling(true);
        a2.set_controlling(false);

        // loop until we're connected.
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        a1.add_local_candidate(relay("1.1.1.1:1001", "udp"));
        a2.add_remote_candidate(relay("1.1.1.1:1001", "udp"));

        loop {
            if a2.has_event(|e| {
                matches!(e, IceAgentEvent::DiscoveredRecv { source, .. } if source == &sock("1.1.1.1:1001"))
            }) {
                break;
            }

            progress(&mut a1, &mut a2);
        }

        assert!(!a1.has_event(|e| {
            matches!(e, IceAgentEvent::NominatedSend { source, .. } if source == &sock("1.1.1.1:1001"))
        }));
        assert!(!a2.has_event(|e| {
            matches!(e, IceAgentEvent::NominatedSend { destination, .. } if destination == &sock("1.1.1.1:1001"))
        }));
    }

    pub struct TestAgent {
        pub start_time: Instant,
        pub agent: IceAgent,
        pub span: Span,
        pub events: Vec<(Duration, IceAgentEvent)>,
        pub progress_count: u64,
        pub time: Instant,
        pub drop_sent_packets: bool,
    }

    impl TestAgent {
        pub fn new(span: Span) -> Self {
            let now = Instant::now();
            TestAgent {
                start_time: now,
                agent: IceAgent::new(),
                span,
                events: vec![],
                progress_count: 0,
                time: now,
                drop_sent_packets: false,
            }
        }

        fn has_event(&self, predicate: impl Fn(&IceAgentEvent) -> bool) -> bool {
            self.events.iter().any(|(_, e)| predicate(e))
        }
    }

    pub fn progress(a1: &mut TestAgent, a2: &mut TestAgent) {
        let (f, t) = if a1.progress_count % 2 == a2.progress_count % 2 {
            (a2, a1)
        } else {
            (a1, a2)
        };

        t.progress_count += 1;
        if t.progress_count > 100 {
            panic!("Test looped more than 100 times");
        }

        if let Some(trans) = f.span.in_scope(|| f.agent.poll_transmit()) {
            let message =
                StunMessage::parse(&trans.contents).expect("IceAgent to only emit StunMessages");

            // rewrite receive with test transforms, and potentially drop the packet.
            if let Some((source, destination)) = transform(trans.source, trans.destination) {
                if f.drop_sent_packets {
                    // drop packet
                    t.span.in_scope(|| t.agent.handle_timeout(t.time));
                } else {
                    let packet = StunPacket {
                        proto: trans.proto,
                        source,
                        destination,
                        message,
                    };
                    t.span.in_scope(|| t.agent.handle_packet(t.time, packet));
                }
            } else {
                // drop packet
                t.span.in_scope(|| t.agent.handle_timeout(t.time));
            }
        } else {
            t.span.in_scope(|| t.agent.handle_timeout(t.time));
        }

        let time = t.time;

        let tim_f = f.span.in_scope(|| f.agent.poll_timeout()).unwrap_or(f.time);
        f.time = tim_f;

        let tim_t = t.span.in_scope(|| t.agent.poll_timeout()).unwrap_or(t.time);
        t.time = tim_t;

        while let Some(v) = t.span.in_scope(|| t.agent.poll_event()) {
            println!("Polled event: {v:?}");
            use IceAgentEvent::*;
            f.span.in_scope(|| {
                if let IceRestart(v) = &v {
                    f.agent.set_remote_credentials(v.clone())
                }
            });
            t.events.push((time - t.start_time, v));
        }
    }

    impl Deref for TestAgent {
        type Target = IceAgent;

        fn deref(&self) -> &Self::Target {
            &self.agent
        }
    }

    impl DerefMut for TestAgent {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.agent
        }
    }
}
