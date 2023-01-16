#[macro_use]
extern crate tracing;

use std::io::{self, ErrorKind};
use std::net::UdpSocket;
use std::process;
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use std::time::Instant;

use rouille::Server;
use rouille::{Request, Response};

use scrap::{Capturer, Display};
use str0m::media::{Codec, MediaTime};
use str0m::net::Receive;
use str0m::IceConnectionState;
use str0m::{Candidate, Event, Input, Offer, Output, Rtc, RtcError};
use systemstat::Duration;

mod util;

fn init_log() {
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "screen=debug,str0m=info");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

pub fn main() {
    init_log();

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();
    let server = Server::new_ssl("0.0.0.0:3000", web_request, certificate, private_key)
        .expect("starting the web server");
    info!("Listening on {:?}", server.server_addr().port());
    server.run();
}

// Handle a web request.
fn web_request(request: &Request) -> Response {
    if request.method() == "GET" {
        return Response::html(include_str!("screen.html"));
    }

    // Expected POST SDP Offers.
    let mut data = request.data().expect("body to be available");

    let offer: Offer = serde_json::from_reader(&mut data).expect("serialized offer");
    let mut rtc = Rtc::builder()
        .ice_lite(true)
        .clear_codecs()
        .enable_vp8()
        .build();

    let addr = util::select_host_address();

    // Spin up a UDP socket for the RTC
    let socket = UdpSocket::bind(format!("{}:0", addr)).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket adddress");
    let candidate = Candidate::host(addr).expect("a host candidate");
    rtc.add_local_candidate(candidate);

    // Create an SDP Answer.
    let answer = rtc.accept_offer(offer).expect("offer to be accepted");

    // Launch WebRTC in separate thread.
    thread::spawn(|| {
        if let Err(e) = run(rtc, socket) {
            eprintln!("Exited: {:?}", e);
            process::exit(1);
        }
    });

    let body = serde_json::to_vec(&answer).expect("answer to serialize");

    Response::from_data("application/json", body)
}

fn run(mut rtc: Rtc, socket: UdpSocket) -> Result<(), RtcError> {
    // Buffer for incoming data.
    let mut buf = Vec::new();

    let mut mid = None;
    let mut pt = None;

    let (tx, rx) = mpsc::sync_channel::<(MediaTime, Vec<u8>)>(5);

    loop {
        if let Some((pts, data)) = rx.try_recv().ok() {
            let media = rtc.media(mid.unwrap()).unwrap().writer(pt.unwrap());
            media.write(pts, &data).unwrap();
        }

        // Poll output until we get a timeout. The timeout means we are either awaiting UDP socket input
        // or the timeout to happen.
        let timeout = match rtc.poll_output()? {
            Output::Timeout(v) => v,

            Output::Transmit(v) => {
                socket.send_to(&v.contents, v.destination)?;
                continue;
            }

            Output::Event(v) => {
                if v == Event::IceConnectionStateChange(IceConnectionState::Disconnected) {
                    return Ok(());
                }
                if let Event::MediaAdded(m) = v {
                    // Figure out the Vp8 PT.
                    let p = rtc
                        .media(m.mid)
                        .unwrap()
                        .payload_params()
                        .iter()
                        .find(|p| p.codec() == Codec::Vp8)
                        .map(|p| p.pt())
                        .unwrap();

                    mid = Some(m.mid);
                    pt = Some(p);

                    let tx = tx.clone();
                    thread::spawn(move || encoder(tx));
                }
                continue;
            }
        };

        let timeout = timeout - Instant::now();

        // Socket timeout is not allowed to be 0. Set 1ms if it is 0.
        let timeout = timeout.clamp(Duration::from_millis(1), Duration::from_millis(5));

        socket.set_read_timeout(Some(timeout))?;
        buf.resize(2000, 0);

        let input = match socket.recv_from(&mut buf) {
            Ok((n, source)) => {
                buf.truncate(n);
                Input::Receive(
                    Instant::now(),
                    Receive {
                        source,
                        destination: socket.local_addr().unwrap(),
                        contents: buf.as_slice().try_into()?,
                    },
                )
            }

            Err(e) => match e.kind() {
                // Expected error for set_read_timeout(). One for windows, one for the rest.
                ErrorKind::WouldBlock | ErrorKind::TimedOut => Input::Timeout(Instant::now()),
                _ => return Err(e.into()),
            },
        };

        rtc.handle_input(input)?;
    }
}

fn encoder(tx: SyncSender<(MediaTime, Vec<u8>)>) {
    let display = Display::primary().unwrap();
    let mut capture = Capturer::new(display).unwrap();

    let width = capture.width();
    let height = capture.height();

    let config = vpx_encode::Config {
        width: width as u32,
        height: height as u32,
        timebase: [1, 90_000],
        bitrate: 5 * 1024,
        codec: vpx_encode::VideoCodecId::VP8,
    };

    let mut encoder = vpx_encode::Encoder::new(config).unwrap();
    let start = Instant::now();

    let fps = 60;
    let spf = Duration::from_nanos(1_000_000_000 / fps);

    let mut yuv = Vec::new();

    loop {
        let now = Instant::now();
        let time = now - start;

        let grab = match capture.frame() {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let dt = now.elapsed();
                if dt < spf {
                    thread::sleep(spf - dt);
                }
                continue;
            }
            Err(e) => {
                eprintln!("Failed: {:?}", e);
                return;
            }
        };

        let pts = MediaTime::from(time);

        argb_to_i420(width as usize, height as usize, &grab, &mut yuv);

        for frame in encoder.encode(pts.numer() as i64, &yuv).unwrap() {
            if let Err(_) = tx.send((pts, frame.data.to_vec())) {
                // receiver gone, shut down
                return;
            }
        }
    }
}

fn argb_to_i420(width: usize, height: usize, src: &[u8], dest: &mut Vec<u8>) {
    fn clamp(x: i32) -> u8 {
        x.min(255).max(0) as u8
    }

    let row = ((width / 16) + if width % 16 > 0 { 1 } else { 0 }) * 16;
    let stride = row * 4; // 4 planes.

    // let stride = 5770 - 1 * 16 + 6; // src.len() / height;

    dest.clear();

    for y in 0..height {
        for x in 0..width {
            let o = y * stride + 4 * x;

            let b = src[o] as i32;
            let g = src[o + 1] as i32;
            let r = src[o + 2] as i32;

            let y = (66 * r + 129 * g + 25 * b + 128) / 256 + 16;
            dest.push(clamp(y));
        }
    }

    for y in (0..height).step_by(2) {
        for x in (0..width).step_by(2) {
            let o = y * stride + 4 * x;

            let b = src[o] as i32;
            let g = src[o + 1] as i32;
            let r = src[o + 2] as i32;

            let u = (-38 * r - 74 * g + 112 * b + 128) / 256 + 128;
            dest.push(clamp(u));
        }
    }

    for y in (0..height).step_by(2) {
        for x in (0..width).step_by(2) {
            let o = y * stride + 4 * x;

            let b = src[o] as i32;
            let g = src[o + 1] as i32;
            let r = src[o + 2] as i32;

            let v = (112 * r - 94 * g - 18 * b + 128) / 256 + 128;
            dest.push(clamp(v));
        }
    }
}
