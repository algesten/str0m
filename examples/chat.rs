#[macro_use]
extern crate tracing;

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use rouille::Server;
use rouille::{Request, Response};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelData, ChannelId};
use str0m::crypto::from_feature_flags;
use str0m::media::{Direction, KeyframeRequest, MediaData, Mid, Rid};
use str0m::media::{KeyframeRequestKind, MediaKind};
use str0m::net::Protocol;
use str0m::net::Receive;
use str0m::{Candidate, Event, IceConnectionState, Output, Poll, Rtc, RtcError, RtcTx};

mod util;

/// Poll transaction until timeout, discarding events and transmits.
fn poll_tx(mut tx: RtcTx<'_, Poll>) -> Result<(), RtcError> {
    loop {
        match tx.poll()? {
            Output::Timeout(_) => return Ok(()),
            Output::Transmit(t, _) => tx = t,
            Output::Event(t, _) => tx = t,
        }
    }
}

fn init_log() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("chat=info,str0m=info,dimpl=info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}

pub fn main() {
    init_log();

    // Run with whatever is configured.
    from_feature_flags().install_process_default();

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();

    // Figure out some public IP address, since Firefox will not accept 127.0.0.1 for WebRTC traffic.
    let host_addr = util::select_host_address();

    let (tx, rx) = mpsc::sync_channel(1);

    // Spin up a UDP socket for the RTC. All WebRTC traffic is going to be multiplexed over this single
    // server socket. Clients are identified via their respective remote (UDP) socket address.
    let socket = UdpSocket::bind(format!("{host_addr}:0")).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    info!("Bound UDP port: {}", addr);

    // The run loop is on a separate thread to the web server.
    thread::spawn(move || run(socket, rx));

    let server = Server::new_ssl(
        "0.0.0.0:3000",
        move |request| web_request(request, addr, tx.clone()),
        certificate,
        private_key,
    )
    .expect("starting the web server");

    let port = server.server_addr().port();
    info!("Connect a browser to https://{:?}:{:?}", addr.ip(), port);

    server.run();
}

// Handle a web request.
fn web_request(request: &Request, addr: SocketAddr, tx: SyncSender<Rtc>) -> Response {
    if request.method() == "GET" {
        return Response::html(include_str!("chat.html"));
    }

    // Expected POST SDP Offers.
    let mut data = request.data().expect("body to be available");

    let offer: SdpOffer = serde_json::from_reader(&mut data).expect("serialized offer");
    let mut rtc = Rtc::builder()
        // Uncomment this to see statistics
        // .set_stats_interval(Some(Duration::from_secs(1)))
        // .set_ice_lite(true)
        .build();

    // Add the shared UDP socket as a host candidate
    let candidate = Candidate::host(addr, "udp").expect("a host candidate");
    let now = Instant::now();

    {
        let mut ice = rtc.begin(now).expect("begin").ice();
        ice.add_local_candidate(candidate).unwrap();
        poll_tx(ice.finish()).unwrap();
    }

    // Create an SDP Answer.
    let answer = {
        let tx = rtc.begin(now).expect("begin");
        let (answer, tx) = tx
            .sdp_api()
            .accept_offer(offer)
            .expect("offer to be accepted");
        poll_tx(tx).unwrap();
        answer
    };

    // The Rtc instance is shipped off to the main run loop.
    tx.send(rtc).expect("to send Rtc instance");

    let body = serde_json::to_vec(&answer).expect("answer to serialize");

    Response::from_data("application/json", body)
}

/// This is the "main run loop" that handles all clients, reads and writes UdpSocket traffic,
/// and forwards media data between clients.
fn run(socket: UdpSocket, rx: Receiver<Rtc>) -> Result<(), RtcError> {
    let mut clients: Vec<Client> = vec![];
    let mut to_propagate: VecDeque<Propagated> = VecDeque::new();
    let mut buf = vec![0; 2000];

    loop {
        // Clean out disconnected clients
        clients.retain(|c| c.rtc.is_alive());

        // Spawn new incoming clients from the web server thread.
        if let Some(mut client) = spawn_new_client(&rx) {
            // Add incoming tracks present in other already connected clients.
            for track in clients.iter().flat_map(|c| c.tracks_in.iter()) {
                let weak = Arc::downgrade(&track.id);
                client.handle_track_open(weak);
            }

            clients.push(client);
        }

        // Poll clients until they return timeout
        let mut timeout = Instant::now() + Duration::from_millis(100);
        for client in clients.iter_mut() {
            let t = client.poll_to_timeout(None, &mut to_propagate, &socket);
            timeout = timeout.min(t);
        }

        // If we have an item to propagate, do that
        if let Some(p) = to_propagate.pop_front() {
            propagate(&p, &mut clients);
            continue;
        }

        // The read timeout is not allowed to be 0. In case it is 0, we set 1 millisecond.
        let duration = (timeout - Instant::now()).max(Duration::from_millis(1));

        socket
            .set_read_timeout(Some(duration))
            .expect("setting socket read timeout");

        if let Some((recv_time, recv)) = read_socket_input(&socket, &mut buf) {
            // The rtc.accepts() call is how we demultiplex the incoming packet to know which
            // Rtc instance the traffic belongs to.
            if let Some(client) = clients.iter_mut().find(|c| c.accepts(&recv)) {
                // We found the client that accepts the input.
                client.poll_to_timeout(Some((recv_time, recv)), &mut to_propagate, &socket);
            } else {
                // This is quite common because we don't get the Rtc instance via the mpsc channel
                // quickly enough before the browser send the first STUN.
                debug!("No client accepts UDP input from: {:?}", recv.source);
            }
        }
    }
}

/// Receive new clients from the receiver and create new Client instances.
fn spawn_new_client(rx: &Receiver<Rtc>) -> Option<Client> {
    // try_recv here won't lock up the thread.
    match rx.try_recv() {
        Ok(rtc) => Some(Client::new(rtc)),
        Err(TryRecvError::Empty) => None,
        _ => panic!("Receiver<Rtc> disconnected"),
    }
}

/// Sends one "propagated" to all clients, if relevant
fn propagate(propagated: &Propagated, clients: &mut [Client]) {
    // Do not propagate to originating client.
    let Some(client_id) = propagated.client_id() else {
        // If the event doesn't have a client id, it can't be propagated,
        // (it's either a noop or a timeout).
        return;
    };

    for client in &mut *clients {
        if client.id == client_id {
            // Do not propagate to originating client.
            continue;
        }

        match &propagated {
            Propagated::TrackOpen(_, track_in) => client.handle_track_open(track_in.clone()),
            Propagated::MediaData(_, data) => client.handle_media_data_out(client_id, data),
            Propagated::KeyframeRequest(_, req, origin, mid_in) => {
                // Only one origin client handles the keyframe request.
                if *origin == client.id {
                    client.handle_keyframe_request(*req, *mid_in)
                }
            }
            Propagated::Noop => {}
        }
    }
}

fn read_socket_input<'a>(
    socket: &UdpSocket,
    buf: &'a mut Vec<u8>,
) -> Option<(Instant, Receive<'a>)> {
    buf.resize(2000, 0);

    match socket.recv_from(buf) {
        Ok((n, source)) => {
            buf.truncate(n);

            // Parse data to a DatagramRecv, which help preparse network data to
            // figure out the multiplexing of all protocols on one UDP port.
            let Ok(contents) = buf.as_slice().try_into() else {
                return None;
            };

            let recv_time = Instant::now();
            Some((
                recv_time,
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents,
                    recv_time: Some(recv_time),
                },
            ))
        }

        Err(e) => match e.kind() {
            // Expected error for set_read_timeout(). One for windows, one for the rest.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => None,
            _ => panic!("UdpSocket read failed: {e:?}"),
        },
    }
}

#[derive(Debug)]
struct Client {
    id: ClientId,
    rtc: Rtc,
    pending: Option<SdpPendingOffer>,
    cid: Option<ChannelId>,
    tracks_in: Vec<TrackInEntry>,
    tracks_out: Vec<TrackOut>,
    chosen_rid: Option<Rid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientId(u64);

impl Deref for ClientId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
struct TrackIn {
    origin: ClientId,
    mid: Mid,
    kind: MediaKind,
}

#[derive(Debug)]
struct TrackInEntry {
    id: Arc<TrackIn>,
    last_keyframe_request: Option<Instant>,
}

#[derive(Debug)]
struct TrackOut {
    track_in: Weak<TrackIn>,
    state: TrackOutState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackOutState {
    ToOpen,
    Negotiating(Mid),
    Open(Mid),
}

impl TrackOut {
    fn mid(&self) -> Option<Mid> {
        match self.state {
            TrackOutState::ToOpen => None,
            TrackOutState::Negotiating(m) | TrackOutState::Open(m) => Some(m),
        }
    }
}

impl Client {
    fn new(rtc: Rtc) -> Client {
        static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
        let next_id = ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        Client {
            id: ClientId(next_id),
            rtc,
            pending: None,
            cid: None,
            tracks_in: vec![],
            tracks_out: vec![],
            chosen_rid: None,
        }
    }

    fn accepts(&self, recv: &Receive<'_>) -> bool {
        self.rtc.accepts(recv)
    }

    /// Poll the client to timeout, optionally processing received data first.
    /// Returns the timeout instant.
    fn poll_to_timeout(
        &mut self,
        receive: Option<(Instant, Receive<'_>)>,
        queue: &mut VecDeque<Propagated>,
        socket: &UdpSocket,
    ) -> Instant {
        if !self.rtc.is_alive() {
            return Instant::now();
        }

        // Incoming tracks from other clients cause new entries in track_out that
        // need SDP negotiation with the remote peer.
        self.negotiate_if_needed();

        let now = Instant::now();

        // Collect events during polling - we'll handle them after the transaction completes
        let mut events: Vec<Event> = Vec::new();
        let timeout;

        // Begin transaction, process receive if any, poll to timeout
        {
            let tx = match self.rtc.begin(now) {
                Ok(tx) => tx,
                Err(e) => {
                    warn!("Client ({}) begin failed: {:?}", *self.id, e);
                    return Instant::now();
                }
            };

            // Either process received data or just advance time
            let tx = match receive {
                Some((_recv_time, data)) => match tx.receive(data) {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!("Client ({}) receive failed: {:?}", *self.id, e);
                        // The error already consumed the transaction's inner state,
                        // disconnect is handled by the caller
                        return Instant::now();
                    }
                },
                None => tx.finish(),
            };

            // Poll to timeout, collecting events
            let mut tx = tx;
            timeout = loop {
                match tx.poll() {
                    Ok(Output::Timeout(t)) => break t,
                    Ok(Output::Transmit(t, pkt)) => {
                        tx = t;
                        socket
                            .send_to(&pkt.contents, pkt.destination)
                            .expect("sending UDP data");
                    }
                    Ok(Output::Event(t, evt)) => {
                        tx = t;
                        events.push(evt);
                    }
                    Err(e) => {
                        warn!("Client ({}) poll failed: {:?}", *self.id, e);
                        break Instant::now();
                    }
                }
            };
        }

        // Now handle events after the transaction is complete
        for evt in events {
            let propagated = self.handle_event(evt);
            if !matches!(propagated, Propagated::Noop) {
                queue.push_back(propagated);
            }
        }

        timeout
    }

    fn handle_event(&mut self, evt: Event) -> Propagated {
        match evt {
            Event::IceConnectionStateChange(v) => {
                if v == IceConnectionState::Disconnected {
                    // Ice disconnect could result in trying to establish a new connection,
                    // but this impl just disconnects directly.
                    self.rtc.disconnect();
                }
                Propagated::Noop
            }
            Event::MediaAdded(e) => self.handle_media_added(e.mid, e.kind),
            Event::MediaData(data) => self.handle_media_data_in(data),
            Event::KeyframeRequest(req) => self.handle_incoming_keyframe_req(req),
            Event::ChannelOpen(cid, _) => {
                self.cid = Some(cid);
                Propagated::Noop
            }
            Event::ChannelData(data) => self.handle_channel_data(data),

            // NB: To see statistics, uncomment set_stats_interval() above.
            Event::MediaIngressStats(data) => {
                info!("{:?}", data);
                Propagated::Noop
            }
            Event::MediaEgressStats(data) => {
                info!("{:?}", data);
                Propagated::Noop
            }
            Event::PeerStats(data) => {
                info!("{:?}", data);
                Propagated::Noop
            }
            _ => Propagated::Noop,
        }
    }

    fn handle_media_added(&mut self, mid: Mid, kind: MediaKind) -> Propagated {
        let track_in = TrackInEntry {
            id: Arc::new(TrackIn {
                origin: self.id,
                mid,
                kind,
            }),
            last_keyframe_request: None,
        };

        // The Client instance owns the strong reference to the incoming
        // track, all other clients have a weak reference.
        let weak = Arc::downgrade(&track_in.id);
        self.tracks_in.push(track_in);

        Propagated::TrackOpen(self.id, weak)
    }

    fn handle_media_data_in(&mut self, data: MediaData) -> Propagated {
        if !data.contiguous {
            self.request_keyframe_throttled(data.mid, data.rid, KeyframeRequestKind::Fir);
        }

        Propagated::MediaData(self.id, data)
    }

    fn request_keyframe_throttled(
        &mut self,
        mid: Mid,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) {
        let Some(track_entry) = self.tracks_in.iter_mut().find(|t| t.id.mid == mid) else {
            return;
        };

        if track_entry
            .last_keyframe_request
            .map(|t| t.elapsed() < Duration::from_secs(1))
            .unwrap_or(false)
        {
            return;
        }

        let now = Instant::now();
        let tx = match self.rtc.begin(now) {
            Ok(tx) => tx,
            Err(_) => return,
        };
        let Ok(mut writer) = tx.writer(mid) else {
            return;
        };

        _ = writer.request_keyframe(rid, kind);
        poll_tx(writer.finish()).unwrap();

        track_entry.last_keyframe_request = Some(now);
    }

    fn handle_incoming_keyframe_req(&self, mut req: KeyframeRequest) -> Propagated {
        // Need to figure out the track_in mid that needs to handle the keyframe request.
        let Some(track_out) = self.tracks_out.iter().find(|t| t.mid() == Some(req.mid)) else {
            return Propagated::Noop;
        };
        let Some(track_in) = track_out.track_in.upgrade() else {
            return Propagated::Noop;
        };

        // This is the rid picked from incoming mediadata, and to which we need to
        // send the keyframe request.
        req.rid = self.chosen_rid;

        Propagated::KeyframeRequest(self.id, req, track_in.origin, track_in.mid)
    }

    fn negotiate_if_needed(&mut self) -> bool {
        if self.cid.is_none() || self.pending.is_some() {
            // Don't negotiate if there is no data channel, or if we have pending changes already.
            return false;
        }

        let now = Instant::now();
        let tx = match self.rtc.begin(now) {
            Ok(tx) => tx,
            Err(_) => return false,
        };
        let mut change = tx.sdp_api();

        for track in &mut self.tracks_out {
            if let TrackOutState::ToOpen = track.state {
                if let Some(track_in) = track.track_in.upgrade() {
                    let stream_id = track_in.origin.to_string();
                    let mid = change.add_media(
                        track_in.kind,
                        Direction::SendOnly,
                        Some(stream_id),
                        None,
                        None,
                    );
                    track.state = TrackOutState::Negotiating(mid);
                }
            }
        }

        if !change.has_changes() {
            // Need to poll even when no changes to complete the transaction
            poll_tx(change.finish()).unwrap();
            return false;
        }

        let Some((offer, pending, tx)) = change.apply() else {
            return false;
        };

        // Write offer to channel via DirectApi (outside transaction)
        poll_tx(tx).unwrap();

        // Use a new transaction for channel write
        let tx = match self.rtc.begin(now) {
            Ok(tx) => tx,
            Err(_) => return false,
        };
        let Ok(mut channel) = tx.channel(self.cid.unwrap()) else {
            return false;
        };

        let json = serde_json::to_string(&offer).unwrap();
        channel
            .write(false, json.as_bytes())
            .expect("to write answer");

        poll_tx(channel.finish());

        self.pending = Some(pending);

        true
    }

    fn handle_channel_data(&mut self, d: ChannelData) -> Propagated {
        if let Ok(offer) = serde_json::from_slice::<'_, SdpOffer>(&d.data) {
            self.handle_offer(offer);
        } else if let Ok(answer) = serde_json::from_slice::<'_, SdpAnswer>(&d.data) {
            self.handle_answer(answer);
        }

        Propagated::Noop
    }

    fn handle_offer(&mut self, offer: SdpOffer) {
        let now = Instant::now();
        let tx = self.rtc.begin(now).expect("begin");
        let (answer, tx) = tx
            .sdp_api()
            .accept_offer(offer)
            .expect("offer to be accepted");
        poll_tx(tx).unwrap();

        // Keep local track state in sync, cancelling any pending negotiation
        // so we can redo it after this offer is handled.
        for track in &mut self.tracks_out {
            if let TrackOutState::Negotiating(_) = track.state {
                track.state = TrackOutState::ToOpen;
            }
        }

        let tx = self.rtc.begin(now).expect("begin");
        let Ok(mut channel) = tx.channel(self.cid.expect("channel to exist")) else {
            return;
        };

        let json = serde_json::to_string(&answer).unwrap();
        channel
            .write(false, json.as_bytes())
            .expect("to write answer");
        poll_tx(channel.finish());
    }

    fn handle_answer(&mut self, answer: SdpAnswer) {
        if let Some(pending) = self.pending.take() {
            let now = Instant::now();
            let tx = self.rtc.begin(now).expect("begin");
            let tx = tx
                .sdp_api()
                .accept_answer(pending, answer)
                .expect("answer to be accepted");
            poll_tx(tx).unwrap();

            for track in &mut self.tracks_out {
                if let TrackOutState::Negotiating(m) = track.state {
                    track.state = TrackOutState::Open(m);
                }
            }
        }
    }

    fn handle_track_open(&mut self, track_in: Weak<TrackIn>) {
        let track_out = TrackOut {
            track_in,
            state: TrackOutState::ToOpen,
        };
        self.tracks_out.push(track_out);
    }

    fn handle_media_data_out(&mut self, origin: ClientId, data: &MediaData) {
        // Figure out which outgoing track maps to the incoming media data.
        let Some(mid) = self
            .tracks_out
            .iter()
            .find(|o| {
                o.track_in
                    .upgrade()
                    .filter(|i| i.origin == origin && i.mid == data.mid)
                    .is_some()
            })
            .and_then(|o| o.mid())
        else {
            return;
        };

        if data.rid.is_some() && data.rid != Some("h".into()) {
            // This is where we plug in a selection strategy for simulcast. For
            // now either let rid=None through (which would be no simulcast layers)
            // or "h" if we have simulcast (see commented out code in chat.html).
            return;
        }

        // Remember this value for keyframe requests.
        if self.chosen_rid != data.rid {
            self.chosen_rid = data.rid;
        }

        let now = Instant::now();
        let tx = match self.rtc.begin(now) {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Client ({}) begin failed: {:?}", *self.id, e);
                return;
            }
        };
        let Ok(writer) = tx.writer(mid) else {
            return;
        };

        // Match outgoing pt to incoming codec.
        let Some(pt) = writer.match_params(data.params) else {
            poll_tx(writer.finish()).unwrap();
            return;
        };

        let tx = match writer.write(pt, data.network_time, data.time, data.data.clone()) {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Client ({}) failed: {:?}", *self.id, e);
                return;
            }
        };
        poll_tx(tx).unwrap();
    }

    fn handle_keyframe_request(&mut self, req: KeyframeRequest, mid_in: Mid) {
        let has_incoming_track = self.tracks_in.iter().any(|i| i.id.mid == mid_in);

        // This will be the case for all other client but the one where the track originates.
        if !has_incoming_track {
            return;
        }

        let now = Instant::now();
        let tx = match self.rtc.begin(now) {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Client ({}) begin failed: {:?}", *self.id, e);
                return;
            }
        };
        let Ok(mut writer) = tx.writer(mid_in) else {
            return;
        };

        if let Err(e) = writer.request_keyframe(req.rid, req.kind) {
            // This can fail if the rid doesn't match any media.
            info!("request_keyframe failed: {:?}", e);
        }
        poll_tx(writer.finish()).unwrap();
    }
}

/// Events propagated between client.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Propagated {
    /// When we have nothing to propagate.
    Noop,

    /// A new incoming track opened.
    TrackOpen(ClientId, Weak<TrackIn>),

    /// Data to be propagated from one client to another.
    MediaData(ClientId, MediaData),

    /// A keyframe request from one client to the source.
    KeyframeRequest(ClientId, KeyframeRequest, ClientId, Mid),
}

impl Propagated {
    /// Get client id, if the propagated event has a client id.
    fn client_id(&self) -> Option<ClientId> {
        match self {
            Propagated::TrackOpen(c, _)
            | Propagated::MediaData(c, _)
            | Propagated::KeyframeRequest(c, _, _, _) => Some(*c),
            _ => None,
        }
    }
}
