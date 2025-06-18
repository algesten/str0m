#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]

use thiserror::Error;

mod agent;
pub use agent::{IceAgent, IceAgentEvent, IceConnectionState, IceCreds, LocalPreference};

mod candidate;
pub use candidate::{Candidate, CandidateKind};

mod pair;

mod preference;
pub use preference::default_local_preference;

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

        // 9999 is just dropped by propagate
        let c1 = a1.add_host_candidate("1.1.1.1:9999");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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

    use crate::io::{Protocol, StunMessage, StunPacket};
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

    pub fn relay(
        s: impl Into<String>,
        proto: impl TryInto<Protocol>,
        l: impl Into<String>,
    ) -> Candidate {
        Candidate::relayed(sock(s), sock(l), proto).unwrap()
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

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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

        fn assert_last_event(d: &Duration, e: &IceAgentEvent, a: &IceAgent) {
            assert_eq!(
                *e,
                IceAgentEvent::IceConnectionStateChange(IceConnectionState::Disconnected)
            );
            assert!(*d > a.ice_timeout());
        }

        let (d, e) = a1.events.last().unwrap();
        assert_last_event(d, e, &a1);

        let (d, e) = a2.events.last().unwrap();
        assert_last_event(d, e, &a2);

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

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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

    // str0m performs calculations on `now` internally
    // To ensure that these never panic, we run a happy-path of `host-host` that uses a very early `Instant`.
    #[test]
    pub fn happy_path_very_early_timestamp() {
        let early_now = find_earliest_now();

        let mut a1 = TestAgent::new(info_span!("L"));
        a1.time = early_now;
        let mut a2 = TestAgent::new(info_span!("R"));
        a2.time = early_now;

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
        a1.add_remote_candidate(c2);

        a1.set_controlling(true);
        a2.set_controlling(false);

        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }
    }

    #[test]
    pub fn no_respond_to_stun_request_on_invalidated_candidate() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1.clone());

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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
        let c1 = a1.add_local_candidate(c1).unwrap().clone();
        a2.add_remote_candidate(c1.clone());

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
        a1.add_remote_candidate(c2);

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
        let c3 = a1.add_local_candidate(c3).unwrap().clone();
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

        assert!(a1.time.duration_since(a1_time) < a1.ice_timeout());
        assert!(a2.time.duration_since(a2_time) < a2.ice_timeout());
    }

    #[test]
    pub fn re_adding_invalidated_local_candidate() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1.clone());

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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

        // Let time pass until it disconnects.
        loop {
            if a1.state().is_disconnected() && a2.state().is_disconnected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        // Add back the invalidated candidate
        a1.add_local_candidate(c1).unwrap();

        // progress() fails after 100 number of polls.
        a1.progress_count = 0;
        a2.progress_count = 0;
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }
    }

    #[test]
    pub fn re_adding_invalidated_remote_candidate() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
        a1.add_remote_candidate(c2.clone());

        a1.set_controlling(true);
        a2.set_controlling(false);

        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        a1.agent.invalidate_candidate(&c2);

        // Let time pass until it disconnects.
        loop {
            if a1.state().is_disconnected() && a2.state().is_disconnected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        // Add back the invalidated candidate
        a1.add_remote_candidate(c2);

        // progress() fails after 100 number of polls.
        a1.progress_count = 0;
        a2.progress_count = 0;
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }
    }

    #[test]
    pub fn ice_lite_no_connection() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        // a1 acts as "server"
        a1.agent.set_ice_lite(true);

        // 9999 is just dropped by propagate
        let c1 = a1.add_host_candidate("1.1.1.1:9999");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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

        // will be rewritten to 4.4.4.4
        let c1 = a1.add_host_candidate("3.3.3.3:1000");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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
    //     use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    //     let env_filter =
    //         EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

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

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1.clone());

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
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

        // no traffic possible
        let c1 = a1.add_host_candidate("3.3.3.3:9999");
        a2.add_remote_candidate(c1);

        let c2 = a2.add_host_candidate("2.2.2.2:1000");
        a1.add_remote_candidate(c2);

        a1.set_controlling(true);
        a2.set_controlling(false);

        // this will be going nowhere (tested in drop-host.rs).
        for _ in 0..10 {
            progress(&mut a1, &mut a2);
        }

        // "trickle" a possible candidate
        a1.add_host_candidate("1.1.1.1:1000");

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

        let c1 = a1
            .add_local_candidate(relay("1.1.1.1:1000", "udp", "9.9.9.9:2000"))
            .unwrap()
            .clone();
        a2.add_remote_candidate(c1);

        let c2 = a2
            .add_local_candidate(srflx("4.4.4.4:1000", "3.3.3.3:1000", "udp"))
            .unwrap()
            .clone();
        a1.add_remote_candidate(c2);
        let c3 = a2.add_host_candidate("3.3.3.3:1000");
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

        a1.add_local_candidate(relay("1.1.1.1:1001", "udp", "9.9.9.9:2000"))
            .unwrap();
        a2.add_remote_candidate(relay("1.1.1.1:1001", "udp", "9.9.9.9:2000"));

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

    #[test]
    pub fn no_disconnect_when_replacing_pflx_with_real_candidate() {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        // We need a 2nd pair of candidates to make sure the agent doesn't go straight into `Completed`.

        // Both agents know their local candidates
        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        let c3 = a1
            .add_local_candidate(relay("2.2.2.2:1000", "udp", "9.9.9.9:2000"))
            .unwrap()
            .clone();

        let c2 = a2.add_host_candidate("1.1.1.1:1001");
        let c4 = a2
            .add_local_candidate(relay("2.2.2.2:1001", "udp", "9.9.9.9:2000"))
            .unwrap()
            .clone();

        // Agent 1 also learns about the remote candidates but agent 2 doesn't (imagine signalling layer being a bit slow)
        a1.add_remote_candidate(c2);
        a1.add_remote_candidate(c4);

        a1.set_controlling(true);
        a2.set_controlling(false);

        // Wait until agent 2 is connected (based on a peer-reflexive candidate)
        loop {
            if a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        // Candidates arrive via signalling layer
        a2.add_remote_candidate(c1.clone());
        a2.add_remote_candidate(c3.clone());

        // Continue normal operation.
        for _ in 0..50 {
            progress(&mut a1, &mut a2);
        }

        // We expect to not disconnect as part of this.
        assert!(!a2.has_event(|e| matches!(
            e,
            IceAgentEvent::IceConnectionStateChange(IceConnectionState::Disconnected)
        )));
    }

    #[test]
    pub fn identical_host_and_server_reflexive_candidates_dont_create_new_pairs_on_inbound_stun_request(
    ) {
        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        let c1 = a1.add_host_candidate("1.1.1.1:1000");
        a2.add_remote_candidate(c1);
        let c2 = a2
            .add_local_candidate(srflx("2.2.2.2:1000", "2.2.2.2:1000", "udp"))
            .unwrap()
            .clone();
        a1.add_remote_candidate(c2);
        let c3 = a2.add_host_candidate("2.2.2.2:1000");
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

        // Each agent should only have a single candidate pair.
        assert_eq!(a1.num_candidate_pairs(), 1);
        assert_eq!(a2.num_candidate_pairs(), 1);
    }

    // In general, ICE prefers IPv6 over IPv4.
    // However, in case our only IPv6 connectivity is via a relay that we are talking to over IPv4,
    // we want to prefer the IPv4 code path.
    #[test]
    fn prefers_ipv4_ipv4_relay_candidate_over_ipv4_ipv6_controlling() {
        let _guard = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .set_default();

        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        a1.set_controlling(true);
        a2.set_controlling(false);

        prefer_ipv4_candidate_over_ipv6_candidate(&mut a1, &mut a2);
    }

    // In general, ICE prefers IPv6 over IPv4.
    // However, in case our only IPv6 connectivity is via a relay that we are talking to over IPv4,
    // we want to prefer the IPv4 code path.
    #[test]
    fn prefers_ipv4_ipv4_relay_candidate_over_ipv4_ipv6_controlled() {
        let _guard = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .set_default();

        let mut a1 = TestAgent::new(info_span!("L"));
        let mut a2 = TestAgent::new(info_span!("R"));

        a1.set_controlling(false);
        a2.set_controlling(true);

        prefer_ipv4_candidate_over_ipv6_candidate(&mut a1, &mut a2);
    }

    fn prefer_ipv4_candidate_over_ipv6_candidate(a1: &mut TestAgent, a2: &mut TestAgent) {
        // Agent 1 only has IPv4 connectivity to a relay but allocates both IPv4 and IPv6 addresses.
        // Agent 2 has no relay but has full IPv4 and IPv6 connectivity.
        let relay_ipv4_ipv4 = a1
            .add_local_candidate(relay("7.7.7.7:5000", "udp", "1.1.1.1:5000"))
            .unwrap()
            .clone();
        let relay_ipv6_ipv4 = a1
            .add_local_candidate(relay("[::7]:5000", "udp", "1.1.1.1:5000"))
            .unwrap()
            .clone();
        a2.add_remote_candidate(relay_ipv4_ipv4);
        a2.add_remote_candidate(relay_ipv6_ipv4);

        let host_ipv4 = a2.add_host_candidate("5.5.5.5:3000");
        let host_ipv6 = a2.add_host_candidate("[::2]:3000");
        a1.add_remote_candidate(host_ipv4);
        a1.add_remote_candidate(host_ipv6);

        // loop until we're connected.
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(a1, a2);
        }

        assert!(a1.has_event(|e| {
            matches!(e, IceAgentEvent::NominatedSend { source, destination, .. }
                         if source == &sock("7.7.7.7:5000") && destination == &sock("5.5.5.5:3000"))
        }));
        assert!(a2.has_event(|e| {
            matches!(e, IceAgentEvent::NominatedSend { source, destination, .. }
                         if source == &sock("5.5.5.5:3000") && destination == &sock("7.7.7.7:5000"))
        }));
    }

    #[test]
    fn changed_timing_config_takes_effect_immediately() {
        let _guard = tracing_subscriber::fmt()
            .with_env_filter("trace")
            .with_test_writer()
            .set_default();

        const IDLE_RTO: Duration = Duration::from_secs(60);
        const NORMAL_RTO: Duration = Duration::from_secs(3);

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

        // loop until we're connected.
        loop {
            if a1.state().is_connected() && a2.state().is_connected() {
                break;
            }
            progress(&mut a1, &mut a2);
        }

        // Move to "idle" mode
        a1.set_initial_stun_rto(IDLE_RTO);
        a1.set_max_stun_rto(IDLE_RTO);
        a2.set_initial_stun_rto(IDLE_RTO);
        a2.set_max_stun_rto(IDLE_RTO);

        // Spin for a bit
        for _ in 0..10 {
            progress(&mut a1, &mut a2);
        }

        // This is a bit of a hack because we use "insider" knowledge here
        // that the next timeout is in fact `IDLE_RTO` away.
        let now = a1.poll_timeout().unwrap() - IDLE_RTO;

        a1.set_initial_stun_rto(NORMAL_RTO);
        a1.set_max_stun_rto(NORMAL_RTO);

        let timeout_after = a1.poll_timeout().unwrap();

        // After applying the new timeout, it should only be `NORMAL_RTO` away.
        assert_eq!(timeout_after, now + NORMAL_RTO);
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

        fn add_host_candidate(&mut self, addr: &str) -> Candidate {
            self.agent
                .add_local_candidate(host(addr, "udp"))
                .unwrap()
                .clone()
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

    /// Performs a binary search for the earliest possible `Instant`.
    fn find_earliest_now() -> Instant {
        const ONE_YEAR: Duration = Duration::from_secs(60 * 60 * 24 * 365);

        let mut now = Instant::now();
        let mut step = ONE_YEAR;

        while step > Duration::from_secs(1) {
            match now.checked_sub(step) {
                Some(earlier) => {
                    now = earlier;
                    step *= 2; // Increase step-count to accelerate finding the earliest possible `Instant`.
                }
                None => {
                    step /= 2; // Decrease step-count to narrow down on the earliest possible `Instant`.
                }
            }
        }

        now
    }
}
