use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::time::Instant;

use ice::{Candidate, IceAgent, IceAgentEvent};
use net::Receive;
use tracing::Span;

pub fn init_log() {
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "trace");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

pub fn sock(s: impl Into<String>) -> SocketAddr {
    let s: String = s.into();
    s.parse().unwrap()
}

pub fn host(s: impl Into<String>) -> Candidate {
    Candidate::host(sock(s)).unwrap()
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

pub struct TestAgent {
    pub agent: IceAgent,
    pub span: Span,
    pub events: Vec<IceAgentEvent>,
    pub progress_count: u64,
    pub time: Instant,
}

impl TestAgent {
    pub fn new(span: Span) -> Self {
        TestAgent {
            agent: IceAgent::new(),
            span,
            events: vec![],
            progress_count: 0,
            time: Instant::now(),
        }
    }
}

pub fn progress(a1: &mut TestAgent, a2: &mut TestAgent) {
    println!("{} {}", a1.progress_count, a2.progress_count);

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
        let mut receive = Receive::try_from(&trans).unwrap();

        println!("recv 1 {:?}", receive);

        // rewrite receive with test transforms, and potentially drop the packet.
        if let Some((source, destination)) = transform(receive.source, receive.destination) {
            receive.source = source;
            receive.destination = destination;

            println!("recv 2 {:?}", receive);

            t.span.in_scope(|| t.agent.handle_receive(t.time, receive));
        } else {
            // drop packet
            t.span.in_scope(|| t.agent.handle_timeout(t.time));
        }
    } else {
        t.span.in_scope(|| t.agent.handle_timeout(t.time));
    }

    let tim_f = f.span.in_scope(|| f.agent.poll_timeout()).unwrap_or(f.time);
    f.time = tim_f;

    let tim_t = t.span.in_scope(|| t.agent.poll_timeout()).unwrap_or(t.time);
    t.time = tim_t;

    while let Some(v) = t.span.in_scope(|| t.agent.poll_event()) {
        println!("Polled event: {:?}", v);
        use ice::IceAgentEvent::*;
        f.span.in_scope(|| match v {
            IceRestart(v) => f.agent.set_remote_credentials(v),
            NewLocalCandidate(v) => f.agent.add_remote_candidate(v),
            _ => {}
        });
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
