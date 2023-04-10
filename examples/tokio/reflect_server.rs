use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use systemstat::Ipv4Addr;
use tokio::signal;
use tracing::{info, level_filters::LevelFilter};
use util::{http_server::run_http_server, init_log};

mod util;

#[derive(Parser, Debug)]
struct Cli {
    /// Http port
    #[clap(default_value_t = 8081)]
    http_port: u16,
    /// Udp start port
    #[clap(default_value_t = 30000)]
    udp_start_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log(LevelFilter::INFO)?;
    info!("Starting reflect server");
    let cli = Cli::parse();
    info!("cli: {:?}", cli);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), cli.http_port);
    run_http_server(addr, cli.udp_start_port).await;

    info!("Started reflect server");

    signal::ctrl_c().await?;
    info!("Ctrl-C received, shutting down");
    Ok(())
}
