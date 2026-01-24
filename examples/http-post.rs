#[macro_use]
extern crate tracing;

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::process;
use std::thread;
use std::time::Instant;

use rouille::Server;
use rouille::{Request, Response};

use str0m::change::SdpOffer;
use str0m::crypto::from_feature_flags;
use str0m::net::Protocol;
use str0m::net::Receive;
use str0m::{Candidate, Event, IceConnectionState, Output, Rtc, RtcConfig, RtcError};

mod util;

fn init_log() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("http_post=debug,str0m=debug,dimpl=debug"));

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

    let server = Server::new_ssl("0.0.0.0:3000", web_request, certificate, private_key)
        .expect("starting the web server");

    let port = server.server_addr().port();
    info!("Connect a browser to https://{:?}:{:?}", host_addr, port);

    server.run();
}

// Handle a web request.
fn web_request(request: &Request) -> Response {
    if request.method() == "GET" {
        return Response::html(include_str!("http-post.html"));
    }

    // Expected POST SDP Offers.
    let mut data = request.data().expect("body to be available");

    let offer: SdpOffer = serde_json::from_reader(&mut data).expect("serialized offer");
    let mut rtc = RtcConfig::new()
        // .set_ice_lite(true)
        .build();

    let addr = util::select_host_address();

    // Spin up a UDP socket for the RTC
    let socket = UdpSocket::bind(format!("{addr}:0")).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    let candidate = Candidate::host(addr, "udp").expect("a host candidate");
    rtc.add_local_candidate(candidate).unwrap();

    // Create an SDP Answer.
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .expect("offer to be accepted");

    // Launch WebRTC in separate thread.
    thread::spawn(|| {
        if let Err(e) = run(rtc, socket) {
            eprintln!("Exited: {e:?}");
            process::exit(1);
        }
    });

    let body = serde_json::to_vec(&answer).expect("answer to serialize");

    Response::from_data("application/json", body)
}

fn run(mut rtc: Rtc, socket: UdpSocket) -> Result<(), RtcError> {
    // Buffer for incoming data.
    let mut buf = Vec::new();

    loop {
        let now = Instant::now();

        // Begin a transaction and poll to timeout
        let tx = rtc.begin(now);
        let mut tx = tx.finish();

        let timeout = loop {
            match tx.poll() {
                Output::Timeout(t) => break t,
                Output::Transmit(t, pkt) => {
                    tx = t;
                    socket.send_to(&pkt.contents, pkt.destination)?;
                }
                Output::Event(t, evt) => {
                    tx = t;
                    if evt == Event::IceConnectionStateChange(IceConnectionState::Disconnected) {
                        return Ok(());
                    }
                }
            }
        };

        let duration = timeout.saturating_duration_since(Instant::now());

        // socket.set_read_timeout(Some(0)) is not ok
        if duration.is_zero() {
            continue;
        }

        socket.set_read_timeout(Some(duration))?;
        buf.resize(2000, 0);

        match socket.recv_from(&mut buf) {
            Ok((n, source)) => {
                buf.truncate(n);
                let recv_time = Instant::now();
                let recv = Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents: buf.as_slice().try_into()?,
                    timestamp: Some(recv_time),
                };

                // Handle the received data
                let tx = rtc.begin(recv_time);
                let mut tx = tx.receive(recv_time, recv)?;
                loop {
                    match tx.poll() {
                        Output::Timeout(_) => break,
                        Output::Transmit(t, pkt) => {
                            tx = t;
                            socket.send_to(&pkt.contents, pkt.destination)?;
                        }
                        Output::Event(t, evt) => {
                            tx = t;
                            if evt
                                == Event::IceConnectionStateChange(IceConnectionState::Disconnected)
                            {
                                return Ok(());
                            }
                        }
                    }
                }
            }

            Err(e) => match e.kind() {
                // Expected error for set_read_timeout(). One for windows, one for the rest.
                ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                    // Timeout - continue loop
                }
                _ => return Err(e.into()),
            },
        };
    }
}
