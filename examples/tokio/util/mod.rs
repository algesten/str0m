use anyhow::anyhow;
use std::net::IpAddr;
use systemstat::{Platform, System};
pub(super) use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub(super) mod http_client;
pub(super) mod http_server;

type ClientId = usize;

pub(super) fn init_log(default_level: LevelFilter) -> anyhow::Result<()> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy();
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    Ok(())
}

pub fn select_host_address() -> anyhow::Result<IpAddr> {
    let system = System::new();
    let networks = system.networks().unwrap();

    for net in networks.values() {
        for n in &net.addrs {
            if let systemstat::IpAddr::V4(v) = n.addr {
                if !v.is_loopback() && !v.is_link_local() && !v.is_broadcast() {
                    return Ok(IpAddr::V4(v));
                }
            }
        }
    }

    Err(anyhow!("Found no usable network interface"))
}
