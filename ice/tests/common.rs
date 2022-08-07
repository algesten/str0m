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

use std::net::SocketAddr;
use std::time::Instant;

use ice::{Candidate, IceAgent};
use net::Receive;
use tracing::Span;

pub fn sock(s: impl Into<String>) -> SocketAddr {
    let s: String = s.into();
    s.parse().unwrap()
}

pub fn host(s: impl Into<String>) -> Candidate {
    Candidate::host(sock(s)).unwrap()
}

pub fn progress(now: Instant, f: &mut IceAgent, t: &mut IceAgent, sf: &Span, st: &Span) -> Instant {
    if let Some(trans) = sf.in_scope(|| f.poll_transmit()) {
        println!("forward: {} -> {}", trans.source, trans.destination);
        st.in_scope(|| t.handle_receive(now, Receive::try_from(&trans).unwrap()));
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
