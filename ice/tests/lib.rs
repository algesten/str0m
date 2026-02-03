//! Test utilities and infrastructure for ICE testing

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};
use str0m_ice::*;

pub struct TestAgent {
    pub start_time: Instant,
    pub agent: IceAgent,
    pub events: Vec<IceAgentEvent>,
    pub progress_count: usize,
    pub time: Instant,
    pub drop_sent_packets: bool,
    pub nat: Option<Nat>,
}

impl TestAgent {
    pub fn new() -> Self {
        let now = Instant::now();
        TestAgent {
            start_time: now,
            agent: IceAgent::new(now),
            events: vec![],
            progress_count: 0,
            time: now,
            drop_sent_packets: false,
            nat: None,
        }
    }

    pub fn with_symmetric_nat() -> Self {
        let mut agent = Self::new();
        agent.nat = Some(Nat::new_symmetric("100.100.100.100".parse().unwrap()));
        agent
    }

    pub fn with_port_restricted_nat() -> Self {
        let mut agent = Self::new();
        agent.nat = Some(Nat::new_port_restricted_cone(
            "100.100.100.100".parse().unwrap(),
        ));
        agent
    }

    fn add_host_candidate(&mut self, addr: &str) -> Candidate {
        let addr: SocketAddr = addr.parse().unwrap();
        let c = Candidate::host(addr, "udp").unwrap();
        self.agent.add_local_candidate(c.clone()).unwrap();
        c
    }

    fn add_relay_candidate(&mut self, addr: &str, local: &str) -> Candidate {
        let addr: SocketAddr = addr.parse().unwrap();
        let local: SocketAddr = local.parse().unwrap();
        let c = Candidate::relayed(addr, local, "udp").unwrap();
        self.agent.add_local_candidate(c.clone()).unwrap();
        c
    }

    fn add_remote_candidate(&mut self, c: Candidate) {
        self.agent.add_remote_candidate(c).ok();
    }

    fn server_reflexive_candidate(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Option<Candidate> {
        let nat = self.nat.as_ref()?;
        let external = nat.transform_outbound(from, to);

        Some(Candidate::server_reflexive(external, from, "udp").unwrap())
    }

    fn has_event(&self, event: &IceAgentEvent) -> bool {
        self.events
            .iter()
            .any(|e| std::mem::discriminant(e) == std::mem::discriminant(event))
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

pub fn progress(a1: &mut TestAgent, a2: &mut TestAgent) {
    let now = find_earliest_now(a1, a2);

    a1.time = now;
    a2.time = now;

    a1.agent.handle_timeout(now).ok();
    a2.agent.handle_timeout(now).ok();

    while let Some(e) = a1.agent.poll_event() {
        a1.events.push(e);
    }
    while let Some(e) = a2.agent.poll_event() {
        a2.events.push(e);
    }

    let mut packets = vec![];
    while let Some(t) = a1.agent.poll_transmit() {
        if !a1.drop_sent_packets {
            packets.push((t, 1));
        }
    }
    while let Some(t) = a2.agent.poll_transmit() {
        if !a2.drop_sent_packets {
            packets.push((t, 2));
        }
    }

    for (t, from) in packets {
        let (sender, receiver) = if from == 1 {
            (&mut *a1, &mut *a2)
        } else {
            (&mut *a2, &mut *a1)
        };

        let (source, destination) = if let Some(nat) = &receiver.nat {
            let transformed_source = nat.transform_inbound(t.source, t.destination);
            (transformed_source.unwrap_or(t.source), t.destination)
        } else {
            (t.source, t.destination)
        };

        let input = Receive {
            proto: t.proto,
            source,
            destination,
            contents: &t.contents,
        };

        if let Ok(true) = receiver.agent.accepts_message(&input) {
            receiver.agent.handle_packet(input).ok();
        }
    }

    a1.progress_count += 1;
    a2.progress_count += 1;
}

fn find_earliest_now(a1: &mut TestAgent, a2: &mut TestAgent) -> Instant {
    const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

    let t1 = a1.agent.poll_timeout().unwrap_or(a1.time + ONE_YEAR);
    let t2 = a2.agent.poll_timeout().unwrap_or(a2.time + ONE_YEAR);

    if t1 < t2 {
        t1
    } else {
        t2
    }
}

pub fn sock(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn host(addr: &str) -> Candidate {
    let addr: SocketAddr = addr.parse().unwrap();
    Candidate::host(addr, "udp").unwrap()
}

enum NatType {
    PortRestrictedCone {
        mappings: HashMap<(SocketAddr, SocketAddr), SocketAddr>,
    },
    Symmetric {
        mappings: HashMap<(SocketAddr, SocketAddr), SocketAddr>,
    },
}

pub struct Nat {
    external_ip: IpAddr,
    nat_type: NatType,
}

impl Nat {
    fn new_port_restricted_cone(external_ip: IpAddr) -> Self {
        Nat {
            external_ip,
            nat_type: NatType::PortRestrictedCone {
                mappings: HashMap::new(),
            },
        }
    }

    fn new_symmetric(external_ip: IpAddr) -> Self {
        Nat {
            external_ip,
            nat_type: NatType::Symmetric {
                mappings: HashMap::new(),
            },
        }
    }

    fn transform_outbound(&self, from: SocketAddr, to: SocketAddr) -> SocketAddr {
        match &self.nat_type {
            NatType::PortRestrictedCone { mappings } => {
                let key = (from, SocketAddr::new(to.ip(), 0));
                if let Some(external) = mappings.get(&key) {
                    *external
                } else {
                    let port = 40000 + (mappings.len() as u16);
                    SocketAddr::new(self.external_ip, port)
                }
            }
            NatType::Symmetric { mappings } => {
                let key = (from, to);
                if let Some(external) = mappings.get(&key) {
                    *external
                } else {
                    let port = 40000 + (mappings.len() as u16);
                    SocketAddr::new(self.external_ip, port)
                }
            }
        }
    }

    fn transform_inbound(&self, from: SocketAddr, to: SocketAddr) -> Option<SocketAddr> {
        match &self.nat_type {
            NatType::PortRestrictedCone { mappings } => {
                for ((internal, _), external) in mappings.iter() {
                    if external == &to {
                        return Some(*internal);
                    }
                }
                None
            }
            NatType::Symmetric { mappings } => mappings.get(&(to, from)).copied(),
        }
    }
}
