use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use poem::listener::{Listener, RustlsCertificate, RustlsConfig, TcpListener};
use poem::middleware::AddData;
use poem::web::{Data, Html, Json};
use poem::{get, handler, post, EndpointExt, Route, Server};

use rtp::Direction;
use str0m::media::MediaKind;
use str0m::net::Receive;
use str0m::{Answer, Candidate, ChannelId, Event, Input, Mid, Offer, Output, Rtc, RtcError};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::warn;

#[derive(Clone)]
struct AppState {
    id_count: Arc<AtomicU64>,
    handle: Sender<RunLoopInput>,
}

#[derive(Debug)]
enum RunLoopInput {
    NewClient(ClientId, Rtc, Arc<UdpSocket>),
    SocketInput(ClientId, Instant, SocketAddr, Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClientId(u64);

struct Client {
    id: ClientId,
    alive: bool,
    rtc: Rtc,
    cid: Option<ChannelId>,
    socket: Arc<UdpSocket>,
    tracks_in: Vec<Arc<Track>>,
    tracks_out: Vec<TrackState>,
}

enum TrackState {
    ToOpen(Weak<Track>),
    Proposed(Weak<Track>, Mid),
    Open(Weak<Track>, Mid),
}

impl TrackState {
    fn local_track_mid(&self, remote_mid: Mid) -> Option<Mid> {
        if let TrackState::Open(t, local_mid) = self {
            if let Some(t) = t.upgrade() {
                if t.mid == remote_mid {
                    return Some(*local_mid);
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Track {
    origin: ClientId,
    mid: Mid,
    kind: MediaKind,
}

fn init_log() {
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "debug");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
pub async fn main() {
    init_log();

    static CERT: &str = include_str!("cer.pem");
    static KEY: &str = include_str!("key.pem");

    let (tx, rx) = mpsc::channel(10);

    let app_state = AppState {
        id_count: Arc::new(AtomicU64::new(0)),
        handle: tx,
    };

    let app = Route::new()
        .at("/", get(http_index))
        .at("/start", post(http_start).with(AddData::new(app_state)));

    let listener = TcpListener::bind("127.0.0.1:3000")
        .rustls(RustlsConfig::new().fallback(RustlsCertificate::new().key(KEY).cert(CERT)));

    tokio::spawn(async move {
        Server::new(listener).run(app).await.unwrap();
    });

    run_loop(rx).await
}

#[handler]
fn http_index() -> Html<&'static str> {
    Html(include_str!("chat.html"))
}

/// Start a new client. Called on "POST /start" and contains an offer SDP as body, and expects an
/// answer SDP as reply.
#[handler]
async fn http_start(Data(app_state): Data<&AppState>, Json(offer): Json<Offer>) -> Json<Answer> {
    let client_id = ClientId(app_state.id_count.fetch_add(1, Ordering::SeqCst));

    let mut rtc = Rtc::new();

    // Spin up a UDP socket for the RTC
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("binding a random UDP port");
    let socket = Arc::new(socket); // write and read are handled separately
    let addr = socket.local_addr().expect("a local socket adddress");
    let candidate = Candidate::host(addr).expect("a host candidate");
    rtc.add_local_candidate(candidate);

    // Create an SDP Answer.
    let answer = rtc.accept_offer(offer).expect("offer to be accepted");

    // Provide the new Rtc instance and UdpSocket to the run loop. Do this before starting the
    // read_socket_task, since we must ensure the client is inside the run loop before
    // sending socket data for it.
    let msg = RunLoopInput::NewClient(client_id, rtc, socket.clone());
    app_state.handle.send(msg).await.unwrap();

    // Read continuously from the socket and send to run_loop
    let task = read_socket_task(client_id, app_state.handle.clone(), Arc::downgrade(&socket));
    tokio::spawn(task);

    // Return SDP answer to HTTP request.
    Json(answer)
}

async fn read_socket_task(id: ClientId, handle: Sender<RunLoopInput>, socket: Weak<UdpSocket>) {
    // If socket.upgrade() fails, we know the strong reference in Client is gone, and
    // it's time to exit the read task.
    while let Some(socket) = socket.upgrade() {
        let mut buf = vec![0; 2000]; // below MTU

        // Read incoming packet
        let Ok((n, source)) = socket.recv_from(&mut buf).await else {
            return;
        };
        buf.truncate(n);

        // Ship it to the run loop.
        let msg = RunLoopInput::SocketInput(id, Instant::now(), source, buf);
        handle.send(msg).await.unwrap();
    }
}

/// Main run loop. This handles input fromt and to all clients. This might not be the most
/// scalable way since it effectively means all client input and event handling is done
/// on a single thread.
async fn run_loop(mut rx: Receiver<RunLoopInput>) {
    // All current clients.
    let mut clients: Vec<Client> = vec![];

    let mut timeout = Instant::now() + Duration::from_secs(1);

    loop {
        // Housekeeping
        clients.retain(|c| c.alive);

        // Future thing to do, either socket input or a timeout.
        let todo = input_or_timeout(&mut rx, timeout);

        match todo.await {
            InputOrTimeout::Timeout => {} // fall through
            InputOrTimeout::RunLoopInput(r) => match r {
                RunLoopInput::NewClient(id, rtc, socket) => {
                    let mut client = Client::new(id, rtc, socket);

                    // Each new client must get a reference to all open tracks from other clients.
                    for other in clients.iter().filter(|c| c.alive) {
                        for track in &other.tracks_in {
                            client.add_remote_track(Arc::downgrade(track));
                        }
                    }

                    clients.push(client);
                }

                RunLoopInput::SocketInput(id, at, source, data) => {
                    if let Some(client) = clients.iter_mut().find(|c| c.id == id && c.alive) {
                        if let Err(e) = client.handle_socket_input(at, source, &data) {
                            warn!("Client failed: {:?}", e);
                            client.alive = false;
                        }
                    }
                }
            },
        }

        // Poll all clients for things to do. The returned timeout is the smallest value
        // of all polled client timeouts.
        timeout = drive_clients(Instant::now(), &mut clients).await;
    }
}

/// run_loop can wait for either input from any UdpSocket, or a timeout indicating an Rtc
/// instance has some processing to do.
enum InputOrTimeout {
    Timeout,
    RunLoopInput(RunLoopInput),
}

/// This is kind of the whole point of using async for this example. We can
/// _either_ receive UDP socket input from a connected client, or we need to
/// handle a timeout for some client.
async fn input_or_timeout(rx: &mut Receiver<RunLoopInput>, timeout: Instant) -> InputOrTimeout {
    tokio::select! {
        _ = tokio::time::sleep_until(timeout.into()) => {
            InputOrTimeout::Timeout
        }
        v = rx.recv() => {
            InputOrTimeout::RunLoopInput(v.unwrap())
        }
    }
}

/// "drives" Client instances, which calling handle_timeout and then polling
/// the instances until they produce another timeout Instant.
async fn drive_clients(now: Instant, clients: &mut Vec<Client>) -> Instant {
    // Move time in all clients.
    for client in clients.iter_mut().filter(|c| c.alive) {
        if let Err(e) = client.rtc.handle_input(Input::Timeout(now)) {
            warn!("Client failed: {:?}", e);
            client.alive = false;
        }
    }

    #[derive(Debug)]
    enum TrackOrEvent {
        Track(Weak<Track>),
        Event(Event),
    }

    // Collection of all tracks and events to dispatch from all clients.
    let mut to_dispatch = Vec::new();
    // Timeouts collected from clients that are not polling events or transmits.
    let mut timeouts = Vec::new();

    // Continue looping until all clients produce timeouts.
    loop {
        timeouts.clear(); // Every loop start begin with 0 timeouts.

        // Poll each client and decide what to do with transmit, timeout or events
        for client in clients.iter_mut().filter(|c| c.alive) {
            match client.rtc.poll_output() {
                Ok(v) => match v {
                    // Transmits are dispatched on the UdpSocket straight away. We are
                    // trusting there's some buffers that makes this await take almost
                    // no time. Another solution would be to have a spawned sender task
                    // per client.
                    Output::Transmit(v) => {
                        client
                            .socket
                            .send_to(&v.contents, v.destination)
                            .await
                            .unwrap();
                    }

                    // Some kind of event. Track opens are handled separately, rest of
                    // events are just propagated to other clients.
                    Output::Event(v) => {
                        if let Err(e) = client.handle_local_event(&v) {
                            warn!("Client failed: {:?}", e);
                            client.alive = false;
                        }

                        let te = if let Event::MediaAdded(mid, kind, _) = v {
                            // Record of a track being open.
                            let track = Arc::new(Track {
                                origin: client.id,
                                mid,
                                kind,
                            });

                            let weak = Arc::downgrade(&track);

                            // The client holds the strong reference to the track. All other
                            // references are weak.
                            client.add_local_track(track);

                            TrackOrEvent::Track(weak)
                        } else {
                            // An event propagated to other clients.
                            TrackOrEvent::Event(v)
                        };

                        to_dispatch.push((client.id, te));
                    }

                    // State polling reached timeout.
                    Output::Timeout(v) => timeouts.push(v),
                },
                Err(e) => {
                    warn!("Client failed: {:?}", e);
                    client.alive = false;
                }
            }
        }

        // Propagate Tracks/Events Op other connected clients.
        for (from, te) in to_dispatch.drain(..) {
            // All clients but not the originating.
            for client in clients.iter_mut().filter(|c| c.id != from && c.alive) {
                match &te {
                    TrackOrEvent::Track(t) => client.add_remote_track(t.clone()),
                    TrackOrEvent::Event(e) => client.handle_event_from_other(&e),
                }
            }
        }

        // Trigger pending negotiations
        let mut any_negotiation_started = false;
        for client in clients.iter_mut().filter(|c| c.alive) {
            if client.negotiate() {
                any_negotiation_started = true;
            }
        }

        // There might be network traffic to deal with.
        if any_negotiation_started {
            continue;
        }

        // Once all polling above is done, each client will produce a timeout. That means
        // we expect one timeout per _alive_ client. If we don't get this number of
        // timeouts, some client was still producing Transmit or Event.
        let expected_timeouts = clients.iter().filter(|c| c.alive).count();

        if timeouts.len() == expected_timeouts {
            // All clients have timeouts, chose the smallest one, and failing that
            // just fall back on a second from now.
            return timeouts
                .into_iter()
                .min()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
        }
    }
}

impl Client {
    fn new(id: ClientId, rtc: Rtc, socket: Arc<UdpSocket>) -> Self {
        Client {
            id,
            alive: true,
            rtc,
            cid: None,
            socket,
            tracks_in: vec![],
            tracks_out: vec![],
        }
    }

    fn handle_socket_input(
        &mut self,
        at: Instant,
        source: SocketAddr,
        contents: &[u8],
    ) -> Result<(), RtcError> {
        let destination = self.socket.local_addr().unwrap();

        let input = Input::Receive(
            at,
            Receive {
                source,
                destination,
                contents: contents.try_into()?,
            },
        );
        self.rtc.handle_input(input)?;

        Ok(())
    }

    fn add_local_track(&mut self, track: Arc<Track>) {
        self.tracks_in.push(track);
    }

    fn add_remote_track(&mut self, track: Weak<Track>) {
        self.tracks_out.push(TrackState::ToOpen(track));
    }

    fn negotiate(&mut self) -> bool {
        // Can't negotiate until data channel is set up.
        let Some(cid) = self.cid else {
            return false;
        };

        let waiting_for_answer = self
            .tracks_out
            .iter()
            .any(|t| matches!(t, TrackState::Proposed(_, _)));

        // Can't start a negotiation until the current one is done.
        if waiting_for_answer {
            return false;
        }

        let mut change = self.rtc.create_offer();

        for t in &mut self.tracks_out {
            let TrackState::ToOpen(track) = t else {
                continue;
            };

            let Some(track) = track.upgrade() else {
                continue;
            };

            let mid = change.add_media(track.kind, Direction::SendOnly);
            *t = TrackState::Proposed(Arc::downgrade(&track), mid);
        }

        if change.has_changes() {
            let offer = change.apply();
            let Some(mut channel) = self.rtc.channel(cid) else {
                warn!("Client datachannel closed");
                self.alive = false;                
                return false;
            };
            let json = serde_json::to_string(&offer).unwrap();
            // NB this is not great negotiation, because the data channel _might_ be
            // full and we don't manage to send the entire message.
            if let Err(e) = channel.write(false, json.as_bytes()) {
                warn!("Client failed: {:?}", e);
                self.alive = false;
                return false;
            }
            true
        } else {
            false
        }
    }

    fn handle_local_event(&mut self, e: &Event) -> Result<(), RtcError> {
        match e {
            Event::ChannelOpen(cid, _) => {
                self.cid = Some(*cid);
            }
            Event::ChannelData(x) => {
                if let Ok(offer) = serde_json::from_slice::<'_, Offer>(&x.data) {
                    self.handle_offer(offer)?;
                } else if let Ok(answer) = serde_json::from_slice::<'_, Answer>(&x.data) {
                    self.handle_answer(answer)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_offer(&mut self, offer: Offer) -> Result<(), RtcError> {
        // If we tried to offer, but clashed with the client trying to offer. Revert our state.
        for state in &mut self.tracks_out {
            if let TrackState::Proposed(t, _) = state {
                *state = TrackState::ToOpen(t.clone());
            }
        }

        let answer = self.rtc.accept_offer(offer)?;

        let mut channel = self
            .cid
            .and_then(|id| self.rtc.channel(id))
            .ok_or_else(|| RtcError::Other("Expected channel clsoed".into()))?;

        let json = serde_json::to_string(&answer).unwrap();
        channel.write(false, json.as_bytes())?;

        Ok(())
    }

    fn handle_answer(&mut self, answer: Answer) -> Result<(), RtcError> {
        if let Some(pending) = self.rtc.pending_changes() {
            pending.accept_answer(answer)?;

            for state in &mut self.tracks_out {
                if let TrackState::Proposed(t, mid) = state {
                    *state = TrackState::Open(t.clone(), *mid);
                }
            }
        }
        Ok(())
    }

    fn handle_event_from_other(&mut self, e: &Event) {
        let Event::MediaData(d) = e else {
            return;
        };

        let Some(local_mid) = self.tracks_out.iter().find_map(|t| t.local_track_mid(d.mid)) else {
            return;
        };

        let Some(media) = self.rtc.media(local_mid) else {
            return;
        };

        let Some(local_pt) = media.match_codec(d.codec) else {
            return;
        };

        if let Err(e) = media.get_writer(local_pt).write(d.time, &d.data) {
            warn!("Client failed: {:?}", e);
            self.alive = false;
        }
    }
}
