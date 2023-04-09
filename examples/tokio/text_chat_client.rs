use clap::Parser;
use tokio::signal;
use tracing::{info, level_filters::LevelFilter};
use util::init_log;

mod util;

#[derive(Parser, Debug)]
struct Cli {
    /// Server address
    #[clap(default_value = "127.0.0.1:8081")]
    server_addr: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log(LevelFilter::INFO)?;
    info!("Starting chat client");
    let cli = Cli::parse();
    info!("cli: {:?}", cli);

    signal::ctrl_c().await?;
    info!("Ctrl-C received, shutting down");
    Ok(())
}
