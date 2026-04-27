//! Example: RTC event log capture with BWE in a 2-client SFU.
//!
//! Two browser tabs connect and send camera/mic. Media is forwarded between
//! them, which makes str0m's send-side BWE active on each outgoing path.
//! Each client produces a separate event log file (`rtc_event_log_0.log`,
//! `rtc_event_log_1.log`, etc.) containing RTP, RTCP, BWE estimates,
//! probe clusters, and stream configs.
//!
//! # Usage
//!
//! ```text
//! cargo run --example rtc-event-log
//! ```
//!
//! 1. Open **two** browser tabs to the URL shown in the console
//!    (e.g. `https://192.168.x.x:3000`).
//! 2. Accept the self-signed certificate warning in each tab.
//! 3. In **Tab 1**: click **Connect**, then click **Cam** and **Mic**.
//! 4. In **Tab 2**: click **Connect**, then click **Cam** and **Mic**.
//! 5. You should see the remote video/audio appear in each tab.
//!    BWE probing starts automatically once media flows between clients.
//! 6. Close one or both tabs to disconnect. The event log files are
//!    written to the current directory on disconnect.
//!
//! # Output
//!
//! - `rtc_event_log_0.log` — event log for the first client
//! - `rtc_event_log_1.log` — event log for the second client
//!
//! Analyze the event logs with libWebRTC's `event_log_visualizer`
//!
//! The generated HTML shows BWE estimates, probe results, RTP packet
//! timelines, RTCP feedback, and stream configurations.

#[macro_use]
extern crate tracing;

use std::collections::VecDeque;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use rouille::Server;
use rouille::{Request, Response};
use str0m::bwe::Bitrate;
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelData, ChannelId};
use str0m::crypto::from_feature_flags;
use str0m::media::{Direction, KeyframeRequest, MediaData, Mid, Rid};
use str0m::media::{KeyframeRequestKind, MediaKind};
use str0m::net::Protocol;
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig, RtcError};
use str0m::net::Receive;

mod util;

fn init_log() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("rtc_event_log=info,str0m=info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}

pub fn main() {
    init_log();

    from_feature_flags().install_process_default();

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();

    let (tx, rx) = mpsc::sync_channel(1);

    // Single UDP socket for all clients (multiplexed).
    let host_addr = util::select_host_address();
    let socket = UdpSocket::bind(format!("{host_addr}:0")).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    info!("Bound UDP port: {}", addr);

    thread::spawn(move || {
        if let Err(e) = run(socket, rx) {
            eprintln!("Run loop exited: {e:?}");
        }
    });

    let server = Server::new_ssl(
        "0.0.0.0:3000",
        move |request| web_request(request, addr, tx.clone()),
        certificate,
        private_key,
    )
    .expect("starting the web server");

    let port = server.server_addr().port();
    info!("Connect TWO browser tabs to https://{:?}:{:?}", addr.ip(), port);
    info!("Steps: Tab1: Connect → Cam → Mic | Tab2: Connect → Cam → Mic");
    info!("Close a tab to disconnect and write the event log file.");

    server.run();
}

fn web_request(request: &Request, addr: SocketAddr, tx: SyncSender<Rtc>) -> Response {
    if request.method() == "GET" {
        return Response::html(include_str!("chat.html"));
    }

    let mut data = request.data().expect("body to be available");
    let offer: SdpOffer = serde_json::from_reader(&mut data).expect("serialized offer");

    // Build Rtc with event logging and BWE enabled.
    let mut rtc = RtcConfig::new()
        .enable_rtc_event_log(true)
        .enable_bwe(Some(Bitrate::kbps(300)))
        .build(Instant::now());

    let candidate = Candidate::host(addr, "udp").expect("a host candidate");
    rtc.add_local_candidate(candidate).unwrap();

    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .expect("offer to be accepted");

    tx.send(rtc).expect("to send Rtc instance");

    let body = serde_json::to_vec(&answer).expect("answer to serialize");
    Response::from_data("application/json", body)
}

/// Main run loop: polls all clients, forwards media, writes event logs.
fn run(socket: UdpSocket, rx: Receiver<Rtc>) -> Result<(), RtcError> {
    let mut clients: Vec<Client> = vec![];
    let mut to_propagate: VecDeque<Propagated> = VecDeque::new();
    let mut buf = vec![0; 2000];

    loop {
        // Clean out disconnected clients and flush their event logs.
        clients.retain_mut(|c| {
            if !c.rtc.is_alive() {
                c.flush_event_log();
                false
            } else {
                true
            }
        });

        // Spawn new incoming clients.
        if let Some(mut client) = spawn_new_client(&rx) {
            for track in clients.iter().flat_map(|c| c.tracks_in.iter()) {
                let weak = Arc::downgrade(&track.id);
                client.handle_track_open(weak);
            }
            clients.push(client);
        }

        // Poll clients until they return timeout.
        let mut timeout = Instant::now() + Duration::from_millis(100);
        for client in clients.iter_mut() {
            let t = poll_until_timeout(client, &mut to_propagate, &socket);
            timeout = timeout.min(t);
        }

        // Propagate events between clients.
        if let Some(p) = to_propagate.pop_front() {
            propagate(&p, &mut clients);
            continue;
        }

        let duration = (timeout - Instant::now()).max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(duration))
            .expect("setting socket read timeout");

        if let Some(input) = read_socket_input(&socket, &mut buf) {
            if let Some(client) = clients.iter_mut().find(|c| c.rtc.accepts(&input)) {
                client.handle_input(input);
            }
        }

        let now = Instant::now();
        for client in &mut clients {
            client.handle_input(Input::Timeout(now));
        }
    }
}

fn spawn_new_client(rx: &Receiver<Rtc>) -> Option<Client> {
    match rx.try_recv() {
        Ok(rtc) => Some(Client::new(rtc)),
        Err(TryRecvError::Empty) => None,
        _ => panic!("Receiver<Rtc> disconnected"),
    }
}

fn poll_until_timeout(
    client: &mut Client,
    queue: &mut VecDeque<Propagated>,
    socket: &UdpSocket,
) -> Instant {
    loop {
        if !client.rtc.is_alive() {
            return Instant::now();
        }

        let propagated = client.poll_output(socket);

        if let Propagated::Timeout(t) = propagated {
            return t;
        }

        queue.push_back(propagated)
    }
}

fn propagate(propagated: &Propagated, clients: &mut [Client]) {
    let Some(client_id) = propagated.client_id() else {
        return;
    };

    for client in &mut *clients {
        if client.id == client_id {
            continue;
        }

        match &propagated {
            Propagated::TrackOpen(_, track_in) => client.handle_track_open(track_in.clone()),
            Propagated::MediaData(_, data) => client.handle_media_data_out(client_id, data),
            Propagated::KeyframeRequest(_, req, origin, mid_in) => {
                if *origin == client.id {
                    client.handle_keyframe_request(*req, *mid_in)
                }
            }
            Propagated::Noop | Propagated::Timeout(_) => {}
        }
    }
}

fn read_socket_input<'a>(socket: &UdpSocket, buf: &'a mut Vec<u8>) -> Option<Input<'a>> {
    buf.resize(2000, 0);

    match socket.recv_from(buf) {
        Ok((n, source)) => {
            buf.truncate(n);
            let Ok(contents) = buf.as_slice().try_into() else {
                return None;
            };
            Some(Input::Receive(
                Instant::now(),
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents,
                },
            ))
        }
        Err(e) => match e.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => None,
            _ => panic!("UdpSocket read failed: {e:?}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Client {
    id: ClientId,
    rtc: Rtc,
    pending: Option<SdpPendingOffer>,
    cid: Option<ChannelId>,
    tracks_in: Vec<TrackInEntry>,
    tracks_out: Vec<TrackOut>,
    chosen_rid: Option<Rid>,
    log_file: Option<File>,
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

struct TrackInEntry {
    id: Arc<TrackIn>,
    last_keyframe_request: Option<Instant>,
}

struct TrackOut {
    track_in: Weak<TrackIn>,
    state: TrackOutState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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

        let log_path = format!("rtc_event_log_{next_id}.log");
        let log_file = File::create(&log_path).expect("creating event log file");
        info!("Client {next_id}: event log → {log_path}");

        Client {
            id: ClientId(next_id),
            rtc,
            pending: None,
            cid: None,
            tracks_in: vec![],
            tracks_out: vec![],
            chosen_rid: None,
            log_file: Some(log_file),
        }
    }

    fn handle_input(&mut self, input: Input) {
        if !self.rtc.is_alive() {
            return;
        }
        if let Err(e) = self.rtc.handle_input(input) {
            warn!("Client ({}) disconnected: {:?}", *self.id, e);
            self.rtc.disconnect();
        }
    }

    fn poll_output(&mut self, socket: &UdpSocket) -> Propagated {
        if !self.rtc.is_alive() {
            return Propagated::Noop;
        }

        if self.negotiate_if_needed() {
            return Propagated::Noop;
        }

        match self.rtc.poll_output() {
            Ok(output) => self.handle_output(output, socket),
            Err(e) => {
                warn!("Client ({}) poll_output failed: {:?}", *self.id, e);
                self.rtc.disconnect();
                Propagated::Noop
            }
        }
    }

    fn handle_output(&mut self, output: Output, socket: &UdpSocket) -> Propagated {
        match output {
            Output::Transmit(transmit) => {
                socket
                    .send_to(&transmit.contents, transmit.destination)
                    .expect("sending UDP data");
                Propagated::Noop
            }
            Output::Timeout(t) => Propagated::Timeout(t),
            Output::Event(e) => match e {
                Event::RtcEventLog(data) => {
                    if let Some(f) = &mut self.log_file {
                        f.write_all(&data).expect("writing event log");
                    }
                    Propagated::Noop
                }
                Event::IceConnectionStateChange(v) => {
                    if v == IceConnectionState::Disconnected {
                        self.rtc.disconnect();
                    }
                    Propagated::Noop
                }
                Event::MediaAdded(e) => {
                    // First media track added — set desired bitrate to trigger probing.
                    if self.tracks_in.is_empty() {
                        self.rtc.bwe().set_desired_bitrate(Bitrate::mbps(3));
                        info!("Client ({}): BWE desired bitrate set to 3 Mbps", *self.id);
                    }
                    self.handle_media_added(e.mid, e.kind)
                }
                Event::MediaData(data) => self.handle_media_data_in(data),
                Event::KeyframeRequest(req) => self.handle_incoming_keyframe_req(req),
                Event::ChannelOpen(cid, _) => {
                    self.cid = Some(cid);
                    Propagated::Noop
                }
                Event::ChannelData(data) => self.handle_channel_data(data),
                Event::EgressBitrateEstimate(bwe) => {
                    info!("Client ({}): BWE estimate: {:?}", *self.id, bwe);
                    Propagated::Noop
                }
                _ => Propagated::Noop,
            },
        }
    }

    /// Stop event logging and write remaining data to the log file.
    fn flush_event_log(&mut self) {
        self.rtc.stop_rtc_event_log();

        // Drain final event log chunks.
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Event(Event::RtcEventLog(data))) => {
                    if let Some(f) = &mut self.log_file {
                        f.write_all(&data).expect("writing event log");
                    }
                }
                Ok(Output::Timeout(_)) | Err(_) => break,
                _ => {}
            }
        }

        if let Some(f) = self.log_file.take() {
            drop(f);
            info!("Client ({}): event log written", *self.id);
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
        let Some(mut writer) = self.rtc.writer(mid) else {
            return;
        };

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

        _ = writer.request_keyframe(rid, kind);
        track_entry.last_keyframe_request = Some(Instant::now());
    }

    fn handle_incoming_keyframe_req(&self, mut req: KeyframeRequest) -> Propagated {
        let Some(track_out) = self.tracks_out.iter().find(|t| t.mid() == Some(req.mid)) else {
            return Propagated::Noop;
        };
        let Some(track_in) = track_out.track_in.upgrade() else {
            return Propagated::Noop;
        };

        req.rid = self.chosen_rid;

        Propagated::KeyframeRequest(self.id, req, track_in.origin, track_in.mid)
    }

    fn negotiate_if_needed(&mut self) -> bool {
        if self.cid.is_none() || self.pending.is_some() {
            return false;
        }

        let mut change = self.rtc.sdp_api();

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
            return false;
        }

        let Some((offer, pending)) = change.apply() else {
            return false;
        };

        let Some(mut channel) = self.cid.and_then(|id| self.rtc.channel(id)) else {
            return false;
        };

        let json = serde_json::to_string(&offer).unwrap();
        channel
            .write(false, json.as_bytes())
            .expect("to write offer");

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
        let answer = self
            .rtc
            .sdp_api()
            .accept_offer(offer)
            .expect("offer to be accepted");

        for track in &mut self.tracks_out {
            if let TrackOutState::Negotiating(_) = track.state {
                track.state = TrackOutState::ToOpen;
            }
        }

        let mut channel = self
            .cid
            .and_then(|id| self.rtc.channel(id))
            .expect("channel to be open");

        let json = serde_json::to_string(&answer).unwrap();
        channel
            .write(false, json.as_bytes())
            .expect("to write answer");
    }

    fn handle_answer(&mut self, answer: SdpAnswer) {
        if let Some(pending) = self.pending.take() {
            self.rtc
                .sdp_api()
                .accept_answer(pending, answer)
                .expect("answer to be accepted");

            for track in &mut self.tracks_out {
                if let TrackOutState::Negotiating(m) = track.state {
                    track.state = TrackOutState::Open(m);
                }
            }
        }
    }

    fn handle_track_open(&mut self, track_in: Weak<TrackIn>) {
        self.tracks_out.push(TrackOut {
            track_in,
            state: TrackOutState::ToOpen,
        });
    }

    fn handle_media_data_out(&mut self, origin: ClientId, data: &MediaData) {
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
            return;
        }

        if self.chosen_rid != data.rid {
            self.chosen_rid = data.rid;
        }

        let Some(writer) = self.rtc.writer(mid) else {
            return;
        };

        let Some(pt) = writer.match_params(data.params) else {
            return;
        };

        if let Err(e) = writer.write(pt, data.network_time, data.time, data.data.clone()) {
            warn!("Client ({}) failed: {:?}", *self.id, e);
            self.rtc.disconnect();
        }
    }

    fn handle_keyframe_request(&mut self, req: KeyframeRequest, mid_in: Mid) {
        if !self.tracks_in.iter().any(|i| i.id.mid == mid_in) {
            return;
        }

        let Some(mut writer) = self.rtc.writer(mid_in) else {
            return;
        };

        if let Err(e) = writer.request_keyframe(req.rid, req.kind) {
            info!("request_keyframe failed: {:?}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Propagated events between clients
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum Propagated {
    Noop,
    Timeout(Instant),
    TrackOpen(ClientId, Weak<TrackIn>),
    MediaData(ClientId, MediaData),
    KeyframeRequest(ClientId, KeyframeRequest, ClientId, Mid),
}

impl Propagated {
    fn client_id(&self) -> Option<ClientId> {
        match self {
            Propagated::TrackOpen(id, _)
            | Propagated::MediaData(id, _)
            | Propagated::KeyframeRequest(id, _, _, _) => Some(*id),
            _ => None,
        }
    }
}
