pub(super) use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod http_client;
mod http_server;

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
