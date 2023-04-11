use axum::extract;
use axum::{
    extract::{Json, State},
    response::IntoResponse,
    routing::post,
    Router,
};
use bytes::Bytes;
use std::net::IpAddr;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use str0m::change::SdpOffer;
use str0m::{Candidate, Rtc};
use systemstat::{Duration, Ipv4Addr};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

type SessionId = u64;
type Chunk = Bytes;
const BROADCAST_CHANNEL_CAPACITY: usize = 10000;

pub trait ClientHandler: Send {
    fn run(&mut self, rtc: Rtc, addr: SocketAddr, chunk_channel: broadcast::Sender<Bytes>);
}

struct AppState {
    /// holds senders or rather cancellation tokens
    clients: HashMap<SessionId, CancellationToken>,
    /// Channel to send packets between clients
    chunk_channel: broadcast::Sender<Bytes>,
    /// next udp port
    next_udp_port: u16,
    /// ip_addr
    ip: IpAddr,
    /// client handler
    client_handler: Box<dyn ClientHandler>,
}

pub async fn run_http_server(
    ip: IpAddr,
    http_port: u16,
    udp_start_port: u16,
    client_handler: Box<dyn ClientHandler>,
) {
    let (chunk_channel, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);

    let app_state = Arc::new(Mutex::new(AppState {
        clients: HashMap::default(),
        chunk_channel,
        next_udp_port: udp_start_port,
        ip,
        client_handler,
    }));

    let app = Router::new()
        .route("/allocate", post(allocate))
        .route("/free", post(free))
        .with_state(app_state);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), http_port);

    tokio::spawn(axum::Server::bind(&addr).serve(app.into_make_service()));
}

async fn allocate(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(offer): Json<SdpOffer>,
) -> impl IntoResponse {
    info!("allocate");
    debug!("{:#?}", offer);

    let mut app_state = state.lock().await;

    let mut rtc = Rtc::builder()
        .set_ice_lite(true)
        .set_stats_interval(Duration::from_secs(0))
        .build();

    let addr = SocketAddr::new(app_state.ip, app_state.next_udp_port);
    app_state.next_udp_port += 1;

    // Add the shared UDP socket as a host candidate
    let candidate = Candidate::host(addr).expect("a host candidate");
    rtc.add_local_candidate(candidate);

    // Create an SDP Answer.
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .expect("offer to be accepted");

    // parse out session id
    // create cancellation token
    // send answer
    // spawn task with clienthandler
}

async fn free(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    info!("free");
    let mut app_state = state.lock().await;
}
