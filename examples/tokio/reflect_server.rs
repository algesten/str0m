use tokio::signal;
use tracing::{info, level_filters::LevelFilter};
use util::init_log;

mod util;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log(LevelFilter::INFO)?;
    info!("Starting reflect server");

    signal::ctrl_c().await?;
    info!("Ctrl-C received, shutting down");
    Ok(())
}
