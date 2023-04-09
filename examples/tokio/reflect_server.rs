use clap::Parser;
use tokio::signal;
use tracing::{info, level_filters::LevelFilter};
use util::init_log;

mod util;

#[derive(Parser, Debug)]
struct Cli {
    /// Http port
    #[clap(default_value_t = 8081)]
    http_port: usize,
    /// Udp start port
    #[clap(default_value_t = 30000)]
    udp_start_port: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log(LevelFilter::INFO)?;
    info!("Starting reflect server");
    let cli = Cli::parse();
    info!("cli: {:?}", cli);

    signal::ctrl_c().await?;
    info!("Ctrl-C received, shutting down");
    Ok(())
}
