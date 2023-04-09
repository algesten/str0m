use axum::{extract::State, response::IntoResponse, routing::post, Router};
use bytes::Bytes;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;

type ClientId = usize;
type Chunk = Bytes;

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

#[tokio::main]
async fn main() {
    let (chunk_channel, _) = broadcast::channel(100);

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
    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    axum::Server::bind(&addr).serve(app.into_make_service());
    signal::ctrl_c().await;
}

pub async fn allocate(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    let mut app_state = state.lock().await;
    app_state.next_client_id += 1;
}

pub async fn free(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    let mut app_state = state.lock().await;
}
