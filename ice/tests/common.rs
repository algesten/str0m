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

pub fn sock(s: impl Into<String>) -> SocketAddr {
    let s: String = s.into();
    s.parse().unwrap()
}
