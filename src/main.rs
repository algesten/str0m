#![warn(clippy::all)]
#![allow(clippy::inefficient_to_string)]
#![allow(clippy::new_without_default)]

#[macro_use]
extern crate log;

use crate::rt::{mpsc, oneshot, spawn, UdpSocket};
use hreq::http;
use hreq::prelude::*;
use pnet::datalink;
use serde::{Deserialize, Serialize};
use std::env;

#[macro_use]
mod error;

mod config;
mod dtls;
mod format;
mod media;
mod peer;
mod rt;
mod rtc;
mod rtcp;
mod rtp;
mod sdp;
mod sdp_parse;
mod sdp_ser;
mod server;
mod srtp;
mod stun;
mod util;

// use dtls::Dtls;
use error::{Error, ErrorKind};
use sdp::Candidate;
use server::{Server, ServerIn, ServerOut, SignalIn, UdpSend};

#[derive(Clone)]
struct WebServer {
    tx_signal: mpsc::Sender<SignalIn>,
}

#[derive(Debug, Serialize)]
pub struct JoinResp {
    sdp: String,
}

#[derive(Debug, Deserialize)]
pub struct JoinReq {
    room_id: String,
    sdp: String,
}

#[tokio::main]
async fn main() {
    rt::init();

    if env::var("LOG").ok().is_none() {
        env::set_var("LOG", "str0m=trace");
    }
    pretty_env_logger::init_custom_env("LOG");

    openssl::init();

    let mut host_ips = datalink::interfaces()
        .into_iter()
        .filter(|n| n.is_up() && !n.is_point_to_point())
        .map(|n| n.ips)
        .flatten()
        .map(|f| f.ip())
        .filter(|ip| ip.is_ipv4()) // TODO handle ipv6.
        .collect::<Vec<_>>();
    host_ips.sort(); // ipv4 first, then ipv6
    info!("Host IPs: {:?}", host_ips);

    let udp_socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .expect("Bind UdpSocket");
    let udp_port = udp_socket.local_addr().unwrap().port();
    info!("UDP port: {}", udp_port);

    let candidates: Vec<_> = host_ips
        .iter()
        .map(|addr| Candidate::host_udp(1, addr, udp_port))
        .collect();

    let (rx_udp_sock, tx_udp_sock) = udp_socket.split();
    let (tx_udp, rx_udp) = mpsc::channel(10);
    let (tx_signal, rx_signal) = mpsc::channel(10);

    let mut udp_send = UdpSend(rx_udp, tx_udp_sock);
    spawn(async move {
        udp_send.handle().await;
    });

    let server_in = ServerIn {
        signal: rx_signal,
        udp: rx_udp_sock,
    };
    let server_out = ServerOut { udp: tx_udp };
    let mut server = Server::new(candidates, server_in, server_out);

    spawn(async move {
        server.handle().await;
    });

    let mut web = hreq::server::Server::with_state(WebServer {
        tx_signal: tx_signal.clone(),
    });

    web.at("/test.js").get(|_| async {
        const TEST_JS: &str = include_str!("../www/test.js");

        http::Response::builder()
            .header("content-type", "application/javascript")
            .body(TEST_JS)
            .unwrap()
    });

    web.at("/").get(|_| async {
        const INDEX_HTML: &str = include_str!("../www/index.html");

        http::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(INDEX_HTML)
            .unwrap()
    });

    web.at("/join").with_state().post(handle_post_join);

    let port: u16 = config::get_config_as_or("PORT", 3000);

    const CERT_PEM: &[u8] = include_bytes!("../cert.pem");

    let tls = hreq::server::TlsConfig::new().cert(CERT_PEM).key(CERT_PEM);

    let (handle, addr) = web.listen_tls(port, tls).await.expect("Bind web port");

    info!("Listening to {} (HTTPS)", addr.port());
    handle.keep_alive().await;
}

async fn handle_post_join(
    mut state: WebServer,
    req: http::Request<Body>,
) -> Result<http::Response<Body>, hreq::Error> {
    let mut body = req.into_body();

    let jreq: JoinReq = body.read_to_json().await?;

    trace!("JOIN RECV: {:?}", jreq);

    let (tx, rx) = oneshot::channel();

    state
        .tx_signal
        .send(SignalIn::JoinReq(jreq, tx))
        .await
        .expect("tx_signal.send join req");

    let jres = rx.await.expect("join resp rx");

    trace!("JOIN SEND: {:?}", jres);

    let body = Body::from_json(&jres);
    let res = http::Response::builder().body(body).unwrap();

    Ok(res)
}
