use std::net::SocketAddr;

use bytes::Bytes;
use clap::Parser;
use str0m::Rtc;
use tokio::{signal, sync::broadcast};
use tracing::{info, level_filters::LevelFilter};
use util::{
    http_server::{run_http_server, ClientHandler},
    init_log, select_host_address,
};

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

    let ip = select_host_address()?;

    run_http_server(
        ip,
        cli.http_port,
        cli.udp_start_port,
        Box::new(ReflectClientHandler {}),
    )
    .await;

    info!("Started reflect server");

    signal::ctrl_c().await?;
    info!("Ctrl-C received, shutting down");
    Ok(())
}

struct ReflectClientHandler {}

impl ClientHandler for ReflectClientHandler {
    fn run(&mut self, _rtc: Rtc, _addr: SocketAddr, _chunk_channel: broadcast::Sender<Bytes>) {}
}
