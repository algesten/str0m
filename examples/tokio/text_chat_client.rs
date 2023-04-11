use clap::Parser;
use str0m::{Candidate, RtcConfig};
use systemstat::Duration;
use tokio::{net::UdpSocket, signal};
use tracing::{info, level_filters::LevelFilter};
use util::{http_client::ServerConnection, init_log, select_host_address};

mod util;

#[derive(Parser, Debug)]
struct Cli {
    /// Server address
    #[clap(default_value = "http://127.0.0.1:8081")]
    server_addr: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_log(LevelFilter::INFO)?;
    info!("Starting chat client");
    let cli = Cli::parse();
    info!("cli: {:?}", cli);

    let mut server_connection = ServerConnection::new(cli.server_addr.as_str())?;

    let mut rtc = RtcConfig::new()
        .set_ice_lite(false)
        .set_stats_interval(Duration::from_secs(0))
        .build();

    let host_addr = select_host_address()?;
    let socket = UdpSocket::bind(format!("{host_addr}:0")).await?;
    let addr = socket.local_addr()?;
    let candidate = Candidate::host(addr)?;

    let mut change = rtc.sdp_api();
    let chat_channel_id = change.add_channel("chat".into());
    // TODO(xnorpx): unwrap
    let (offer, pending) = change.apply().unwrap();
    let sdp_answer = server_connection.allocate(offer).await?;

    rtc.add_local_candidate(candidate);

    signal::ctrl_c().await?;
    server_connection.free().await?;
    info!("Ctrl-C received, shutting down");
    Ok(())
}
