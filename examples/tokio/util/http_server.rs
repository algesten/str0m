use axum::{extract::State, response::IntoResponse, routing::post, Router};
use bytes::Bytes;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::info;

type ClientId = usize;
type Chunk = Bytes;
const BROADCAST_CHANNEL_CAPACITY: usize = 10000;

pub struct AppState {
    /// holds senders or rather cancellation tokens
    clients: HashMap<ClientId, CancellationToken>,
    /// next_client_id
    next_client_id: ClientId,
    /// Channel to send packets between clients
    chunk_channel: broadcast::Sender<Bytes>,
    /// next udp port
    next_udp_port: usize,
}

pub async fn run_http_server(addr: SocketAddr) {
    let (chunk_channel, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);

    let app_state = Arc::new(Mutex::new(AppState {
        clients: HashMap::default(),
        next_client_id: 0,
        chunk_channel,
        next_udp_port: 1337,
    }));

    let app = Router::new()
        .route("/allocate", post(allocate))
        .route("/free", post(free))
        .with_state(app_state);

    tokio::spawn(axum::Server::bind(&addr).serve(app.into_make_service()));
}

pub async fn allocate(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    info!("allocate");
    let mut app_state = state.lock().await;
}

pub async fn free(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    info!("free");
    let mut app_state = state.lock().await;
}
