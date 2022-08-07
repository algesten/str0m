use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use ice::{Candidate, IceAgent};
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
/// port 9999 -> closed (packets dropped)
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

pub fn progress(now: Instant, f: &mut IceAgent, t: &mut IceAgent, sf: &Span, st: &Span) -> Instant {
    if let Some(trans) = sf.in_scope(|| f.poll_transmit()) {
        let mut receive = Receive::try_from(&trans).unwrap();

        // rewrite receive with test transforms, and potentially drop the packet.
        if let Some((source, destination)) = transform(receive.source, receive.destination) {
            receive.source = source;
            receive.destination = destination;

            st.in_scope(|| t.handle_receive(now, receive));
        } else {
            // drop packet
        }
    } else {
        st.in_scope(|| t.handle_timeout(now));
    }

    let tim_f = sf.in_scope(|| f.poll_timeout());
    let tim_t = st.in_scope(|| t.poll_timeout());

    while let Some(v) = sf.in_scope(|| f.poll_event()) {
        println!("Polled event: {:?}", v);
        use ice::IceAgentEvent::*;
        st.in_scope(|| match v {
            IceRestart(v) => t.set_remote_credentials(v),
            NewLocalCandidate(v) => t.add_remote_candidate(v),
            _ => {}
        });
    }

    tim_f.unwrap_or(now).min(tim_t.unwrap_or(now))
}
