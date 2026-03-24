use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::config::{DtlsVersion, Fingerprint};
use str0m::ice::IceCreds;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig, RtcError};
use tracing::{Span, info_span};

mod common;
use common::{Peer, init_crypto_default, init_log};

/// Pre-negotiated data channel SCTP stream ID
const DATA_CHANNEL_ID: u16 = 0;

/// Set to `true` to save packet captures to `target/pcap/` for Wireshark analysis.
const SAVE_PCAP: bool = false;

#[test]
pub fn handshake_dtls_auto_to_12() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Auto, DtlsVersion::Dtls12)
}

#[test]
pub fn handshake_dtls_auto_to_13() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Auto, DtlsVersion::Dtls13)
}

#[test]
pub fn handshake_dtls_auto_to_auto() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Auto, DtlsVersion::Auto)
}

#[test]
pub fn handshake_dtls_12_to_auto() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Dtls12, DtlsVersion::Auto)
}

#[test]
pub fn handshake_dtls_13_to_auto() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Dtls13, DtlsVersion::Auto)
}

#[test]
pub fn handshake_dtls_12_to_12() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Dtls12, DtlsVersion::Dtls12)
}

#[test]
pub fn handshake_dtls_13_to_13() -> Result<(), RtcError> {
    run_handshake_test(DtlsVersion::Dtls13, DtlsVersion::Dtls13)
}

/// Returns the name of the default crypto provider based on compile-time feature flags.
/// Mirrors the priority order in `str0m::crypto::from_feature_flags()`.
#[allow(unreachable_code)]
fn default_crypto_name() -> &'static str {
    #[cfg(feature = "aws-lc-rs")]
    return "aws-lc-rs";
    #[cfg(feature = "rust-crypto")]
    return "rust-crypto";
    #[cfg(feature = "openssl")]
    return "openssl";
    #[cfg(all(feature = "wincrypto", target_os = "windows"))]
    return "wincrypto";
    #[cfg(all(feature = "apple-crypto", target_vendor = "apple"))]
    return "apple-crypto";
    "unknown"
}

fn run_handshake_test(client_dtls: DtlsVersion, server_dtls: DtlsVersion) -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let test_start = Instant::now();

    let client_crypto_name =
        std::env::var("L_CRYPTO").unwrap_or_else(|_| default_crypto_name().into());
    let server_crypto_name =
        std::env::var("R_CRYPTO").unwrap_or_else(|_| default_crypto_name().into());

    // wincrypto only support DTLS 1.2 — skip tests requiring 1.3/Auto.
    // openssl only supports DTLS 1.2 unless prefer_dimpl is enabled.
    // Also skip Auto client → 1.2-only server: dimpl advertises X25519 in the hybrid
    // ClientHello but its DTLS 1.2 engine can't process X25519 in ServerKeyExchange.
    let dtls12_only = |name: &str| match name {
        "wincrypto" => true,
        #[cfg(not(feature = "prefer_dimpl"))]
        "openssl" => true,
        _ => false,
    };
    let needs_13 = |v: DtlsVersion| matches!(v, DtlsVersion::Dtls13);

    if (dtls12_only(&client_crypto_name) && needs_13(client_dtls))
        || (dtls12_only(&server_crypto_name) && needs_13(server_dtls))
    {
        println!(
            "\n=== SKIPPED: client={} ({}), server={} ({}) — DTLS 1.3/Auto not supported ===",
            client_dtls, client_crypto_name, server_dtls, server_crypto_name
        );
        return Ok(());
    }

    println!(
        "\n=== Test: client={} ({}), server={} ({}) ===",
        client_dtls, client_crypto_name, server_dtls, server_crypto_name
    );

    // Channels for communication between threads
    // client -> server
    let (client_tx, server_rx) = mpsc::channel::<Message>();
    // server -> client
    let (server_tx, client_rx) = mpsc::channel::<Message>();

    let client_addr: SocketAddr = (Ipv4Addr::new(192, 168, 1, 1), 5000).into();
    let server_addr: SocketAddr = (Ipv4Addr::new(192, 168, 1, 2), 5001).into();

    // Test name for pcap files
    let test_name = format!(
        "handshake_dtls_{}_to_{}",
        dtls_version_short(client_dtls),
        dtls_version_short(server_dtls)
    );

    // Spawn server thread
    // Returns (packets, Result) so pcap is available even on failure.
    let server_handle = thread::spawn(
        move || -> (Vec<PcapPacket>, Result<TimingReport, RtcError>) {
            let span = info_span!("SERVER");
            let _guard = span.enter();
            let mut timing = TimingReport::new();
            let mut packets = Vec::new();

            let result = (|| -> Result<TimingReport, RtcError> {
                // Initialize server (is_client = false)
                let (mut rtc, local_creds, local_fingerprint) =
                    init_rtc(false, server_addr, server_dtls, Peer::Right, &mut timing)?;

                // Send server's credentials to client
                server_tx
                    .send(Message::Credentials {
                        ice_ufrag: local_creds.ufrag.clone(),
                        ice_pwd: local_creds.pass.clone(),
                        dtls_fingerprint: local_fingerprint,
                    })
                    .expect("Failed to send server credentials");

                // Wait for client's credentials
                let (remote_ice_ufrag, remote_ice_pwd, remote_fingerprint) =
                    match server_rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(Message::Credentials {
                            ice_ufrag,
                            ice_pwd,
                            dtls_fingerprint,
                        }) => {
                            timing.got_offer = Some(Instant::now());
                            (ice_ufrag, ice_pwd, dtls_fingerprint)
                        }
                        Ok(_) => panic!("Server expected Credentials, got something else"),
                        Err(e) => panic!("Server failed to receive credentials: {:?}", e),
                    };

                // Configure with remote credentials (is_client = false)
                configure_rtc(
                    &mut rtc,
                    false,
                    client_addr,
                    remote_ice_ufrag,
                    remote_ice_pwd,
                    remote_fingerprint,
                )?;
                timing.sent_answer = Some(Instant::now());

                // Run the event loop with message exchange
                run_rtc_loop_with_exchange(
                    &mut rtc,
                    &span,
                    &server_rx,
                    &server_tx,
                    &mut timing,
                    false,
                    &mut packets,
                )?;

                Ok(timing)
            })();

            (packets, result)
        },
    );

    // Spawn client thread
    // Returns (packets, Result) so pcap is available even on failure.
    let client_handle = thread::spawn(
        move || -> (Vec<PcapPacket>, Result<TimingReport, RtcError>) {
            let span = info_span!("CLIENT");
            let _guard = span.enter();
            let mut timing = TimingReport::new();
            let mut packets = Vec::new();

            let result = (|| -> Result<TimingReport, RtcError> {
                // Initialize client (is_client = true)
                let (mut rtc, local_creds, local_fingerprint) =
                    init_rtc(true, client_addr, client_dtls, Peer::Left, &mut timing)?;

                // Wait for server's credentials first
                let (remote_ice_ufrag, remote_ice_pwd, remote_fingerprint) =
                    match client_rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(Message::Credentials {
                            ice_ufrag,
                            ice_pwd,
                            dtls_fingerprint,
                        }) => (ice_ufrag, ice_pwd, dtls_fingerprint),
                        Ok(_) => panic!("Client expected Credentials, got something else"),
                        Err(e) => panic!("Client failed to receive server credentials: {:?}", e),
                    };

                // Send client's credentials to server
                client_tx
                    .send(Message::Credentials {
                        ice_ufrag: local_creds.ufrag.clone(),
                        ice_pwd: local_creds.pass.clone(),
                        dtls_fingerprint: local_fingerprint,
                    })
                    .expect("Failed to send client credentials");
                timing.sent_offer = Some(Instant::now());

                // Configure with remote credentials (is_client = true)
                configure_rtc(
                    &mut rtc,
                    true,
                    server_addr,
                    remote_ice_ufrag,
                    remote_ice_pwd,
                    remote_fingerprint,
                )?;
                timing.got_answer = Some(Instant::now());

                // Run the event loop with message exchange
                run_rtc_loop_with_exchange(
                    &mut rtc,
                    &span,
                    &client_rx,
                    &client_tx,
                    &mut timing,
                    true,
                    &mut packets,
                )?;

                Ok(timing)
            })();

            (packets, result)
        },
    );

    // Wait for both threads to complete
    let (server_packets, server_result) = server_handle.join().expect("Server thread panicked");
    let (client_packets, client_result) = client_handle.join().expect("Client thread panicked");

    // Save pcap files BEFORE checking errors so we capture failing handshakes
    if SAVE_PCAP {
        let pcap_dir = std::path::Path::new("target/pcap");
        std::fs::create_dir_all(pcap_dir).expect("Failed to create target/pcap directory");

        let client_path = pcap_dir.join(format!("{test_name}_client.pcap"));
        let server_path = pcap_dir.join(format!("{test_name}_server.pcap"));

        write_pcap(&client_path, &client_packets).expect("Failed to write client pcap");
        write_pcap(&server_path, &server_packets).expect("Failed to write server pcap");

        println!("  PCAP saved: {}", client_path.display());
        println!("  PCAP saved: {}", server_path.display());
    }

    let server_timing = server_result.expect("Server returned error");
    let client_timing = client_result.expect("Client returned error");

    let total_time = test_start.elapsed();

    // Print timing reports
    client_timing.print("CLIENT");
    server_timing.print("SERVER");

    println!(
        "\n=== Total Test Time: {:.3}ms ===",
        total_time.as_secs_f64() * 1000.0
    );

    // Verify the exchange happened
    assert!(
        client_timing.sent_data.is_some(),
        "Client should have sent data"
    );
    assert!(
        client_timing.received_data.is_some(),
        "Client should have received reply"
    );
    assert!(
        server_timing.received_data.is_some(),
        "Server should have received data"
    );
    assert!(
        server_timing.sent_data.is_some(),
        "Server should have sent reply"
    );

    Ok(())
}

/// Initialize an Rtc instance configured for client or server role.
///
/// Returns the Rtc instance and the local ICE credentials/DTLS fingerprint for exchange.
fn init_rtc(
    is_client: bool,
    local_addr: SocketAddr,
    dtls_version: DtlsVersion,
    peer: Peer,
    timing: &mut TimingReport,
) -> Result<(Rtc, IceCreds, String), RtcError> {
    let ice_creds = IceCreds::new();

    let mut rtc_config = RtcConfig::new()
        .set_local_ice_credentials(ice_creds.clone())
        .set_dtls_version(dtls_version);
    if !is_client {
        rtc_config = rtc_config.set_ice_lite(true);
    }
    if let Some(crypto) = peer.crypto_provider() {
        rtc_config = rtc_config.set_crypto_provider(crypto);
    }
    let mut rtc = rtc_config.build(Instant::now());
    timing.rtc_built = Some(Instant::now());

    // Get DTLS fingerprint
    let fingerprint = rtc.direct_api().local_dtls_fingerprint().to_string();

    // Add local candidate
    let local_candidate = Candidate::host(local_addr, "udp")?;
    rtc.add_local_candidate(local_candidate);

    Ok((rtc, ice_creds, fingerprint))
}

/// Configure the Rtc instance with remote credentials and start DTLS/SCTP.
fn configure_rtc(
    rtc: &mut Rtc,
    is_client: bool,
    remote_addr: SocketAddr,
    remote_ice_ufrag: String,
    remote_ice_pwd: String,
    remote_fingerprint: String,
) -> Result<(), RtcError> {
    // Add remote candidate
    let remote_candidate = Candidate::host(remote_addr, "udp")?;
    rtc.add_remote_candidate(remote_candidate);

    {
        let mut direct_api = rtc.direct_api();

        // Set ICE parameters
        // Client: not ice-lite, IS controlling
        // Server: ice-lite, NOT controlling
        direct_api.set_ice_lite(!is_client);
        direct_api.set_ice_controlling(is_client);

        // Set remote ICE credentials
        direct_api.set_remote_ice_credentials(IceCreds {
            ufrag: remote_ice_ufrag,
            pass: remote_ice_pwd,
        });

        // Set remote DTLS fingerprint
        let fingerprint: Fingerprint = remote_fingerprint
            .parse()
            .expect("Failed to parse remote fingerprint");
        direct_api.set_remote_fingerprint(fingerprint);

        // Start DTLS - client IS the DTLS client, server is NOT
        direct_api.start_dtls(is_client)?;

        // Start SCTP - client IS the SCTP client, server is NOT
        direct_api.start_sctp(is_client);

        // Create pre-negotiated data channel
        direct_api.create_data_channel(ChannelConfig {
            label: "test-channel".into(),
            negotiated: Some(DATA_CHANNEL_ID),
            ordered: true,
            reliability: Reliability::Reliable,
            protocol: "".into(),
        });
    }

    // Initialize with a timeout
    rtc.handle_input(Input::Timeout(Instant::now()))?;

    Ok(())
}

/// Messages exchanged between client and server threads.
#[derive(Debug)]
enum Message {
    /// ICE and DTLS credentials exchange
    Credentials {
        ice_ufrag: String,
        ice_pwd: String,
        dtls_fingerprint: String,
    },
    /// RTP/DTLS/SCTP packet
    Packet {
        proto: Protocol,
        source: SocketAddr,
        destination: SocketAddr,
        contents: Vec<u8>,
    },
    /// Signal to exit (sent by client to server)
    Exit,
}

/// Timing report for major events
#[derive(Debug, Default)]
struct TimingReport {
    start: Option<Instant>,
    rtc_built: Option<Instant>,
    sent_offer: Option<Instant>,
    got_offer: Option<Instant>,
    sent_answer: Option<Instant>,
    got_answer: Option<Instant>,
    ice_checking: Option<Instant>,
    ice_completed: Option<Instant>,
    channel_open: Option<Instant>,
    sent_data: Option<Instant>,
    received_data: Option<Instant>,
}

impl TimingReport {
    fn new() -> Self {
        Self {
            start: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn print(&self, name: &str) {
        let start = self.start.unwrap();
        println!("\n=== {} Timing Report ===", name);
        if let Some(t) = self.rtc_built {
            println!(
                "  Rtc built:       {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.sent_offer {
            println!(
                "  Sent offer:      {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.got_offer {
            println!(
                "  Got offer:       {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.sent_answer {
            println!(
                "  Sent answer:     {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.got_answer {
            println!(
                "  Got answer:      {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.ice_checking {
            println!(
                "  ICE Checking:    {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.ice_completed {
            println!(
                "  ICE Completed:   {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.channel_open {
            println!(
                "  Channel Open:    {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.sent_data {
            println!(
                "  Sent data:       {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
        if let Some(t) = self.received_data {
            println!(
                "  Received data:   {:>8.3}ms",
                (t - start).as_secs_f64() * 1000.0
            );
        }
    }
}

/// State for managing message exchange
#[derive(Debug, PartialEq)]
enum DataExchangeState {
    WaitingForChannelOpen,
    ChannelOpen,
    SentMessage,
    Complete,
}

/// Run the Rtc event loop with message exchange capability
fn run_rtc_loop_with_exchange(
    rtc: &mut Rtc,
    span: &Span,
    incoming: &Receiver<Message>,
    outgoing: &Sender<Message>,
    timing: &mut TimingReport,
    is_client: bool,
    packets: &mut Vec<PcapPacket>,
) -> Result<(), RtcError> {
    let mut state = DataExchangeState::WaitingForChannelOpen;
    let mut channel_id: Option<ChannelId> = None;
    let role = if is_client { "CLIENT" } else { "SERVER" };

    loop {
        // Check if we're done
        if state == DataExchangeState::Complete {
            break;
        }

        // Safety timeout - don't run forever
        if timing.start.unwrap().elapsed() > Duration::from_secs(10) {
            println!("[{}] Overall timeout reached", role);
            break;
        }

        // Poll all outputs until we get a timeout
        let timeout = loop {
            match span.in_scope(|| rtc.poll_output())? {
                Output::Timeout(t) => break t,
                Output::Transmit(t) => {
                    let data = t.contents.to_vec();
                    if SAVE_PCAP {
                        packets.push(PcapPacket {
                            src: t.source,
                            dst: t.destination,
                            data: data.clone(),
                        });
                    }
                    // Send packet to other peer
                    let _ = outgoing.send(Message::Packet {
                        proto: t.proto,
                        source: t.source,
                        destination: t.destination,
                        contents: data,
                    });
                }
                Output::Event(e) => {
                    handle_event(
                        rtc,
                        &e,
                        timing,
                        is_client,
                        &mut state,
                        &mut channel_id,
                        outgoing,
                    );
                    if state == DataExchangeState::Complete {
                        return Ok(());
                    }
                }
            }
        };

        // Calculate wait duration - this is when we NEED to wake up
        let now = Instant::now();
        let wait = timeout.saturating_duration_since(now);
        println!("[{}] poll_output returned timeout in {:?}", role, wait);

        // Wait for incoming message or timeout
        match incoming.recv_timeout(wait) {
            Ok(Message::Packet {
                proto,
                source,
                destination,
                contents,
            }) => {
                println!("[{}] Received packet ({} bytes)", role, contents.len());
                if SAVE_PCAP {
                    packets.push(PcapPacket {
                        src: source,
                        dst: destination,
                        data: contents.clone(),
                    });
                }
                let receive = Receive {
                    proto,
                    source,
                    destination,
                    contents: contents.as_slice().try_into()?,
                };
                span.in_scope(|| rtc.handle_input(Input::Receive(Instant::now(), receive)))?;
            }
            Ok(Message::Exit) => {
                println!("[{}] Received Exit signal", role);
                state = DataExchangeState::Complete;
            }
            Ok(_) => {
                unreachable!("Unexpected message type");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                println!("[{}] Timeout fired, calling handle_input(Timeout)", role);
                span.in_scope(|| rtc.handle_input(Input::Timeout(Instant::now())))?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                println!("[{}] Channel disconnected", role);
                break;
            }
        }
    }

    Ok(())
}

fn handle_event(
    rtc: &mut Rtc,
    event: &Event,
    timing: &mut TimingReport,
    is_client: bool,
    state: &mut DataExchangeState,
    channel_id: &mut Option<ChannelId>,
    outgoing: &Sender<Message>,
) {
    match event {
        Event::IceConnectionStateChange(ice_state) => match ice_state {
            IceConnectionState::Checking => {
                if timing.ice_checking.is_none() {
                    timing.ice_checking = Some(Instant::now());
                }
            }
            IceConnectionState::Completed => {
                timing.ice_completed = Some(Instant::now());
            }
            _ => {}
        },
        Event::ChannelOpen(cid, label) => {
            println!(
                "[{}] Channel opened: {:?} - {}",
                if is_client { "CLIENT" } else { "SERVER" },
                cid,
                label
            );
            timing.channel_open = Some(Instant::now());
            *channel_id = Some(*cid);
            *state = DataExchangeState::ChannelOpen;

            // Client sends first message
            if is_client {
                if let Some(mut chan) = rtc.channel(*cid) {
                    chan.write(true, b"sixseven").expect("Failed to write");
                    println!("[CLIENT] Sent 'sixseven'");
                    timing.sent_data = Some(Instant::now());
                    *state = DataExchangeState::SentMessage;
                }
            }
        }
        Event::ChannelData(data) => {
            let msg = String::from_utf8_lossy(&data.data);
            println!(
                "[{}] Received data: '{}'",
                if is_client { "CLIENT" } else { "SERVER" },
                msg
            );
            if is_client {
                // Client expects "sevenofnine" reply
                if msg == "sevenofnine" {
                    println!("[CLIENT] Got reply 'sevenofnine' - sending Exit and completing");
                    timing.received_data = Some(Instant::now());
                    // Send Exit signal to server
                    let _ = outgoing.send(Message::Exit);
                    *state = DataExchangeState::Complete;
                }
            } else {
                // Server receives "sixseven" and replies
                if msg == "sixseven" {
                    timing.received_data = Some(Instant::now());
                    // Use channel id from the data event (works for pre-negotiated channels)
                    let cid = data.id;
                    if let Some(mut chan) = rtc.channel(cid) {
                        chan.write(true, b"sevenofnine").expect("Failed to write");
                        println!("[SERVER] Sent reply 'sevenofnine'");
                        timing.sent_data = Some(Instant::now());
                        *state = DataExchangeState::SentMessage;
                    }
                }
            }
        }
        _ => {}
    }
}

// --- PCAP support ---

fn dtls_version_short(v: DtlsVersion) -> &'static str {
    match v {
        DtlsVersion::Auto => "auto",
        DtlsVersion::Dtls12 => "12",
        DtlsVersion::Dtls13 => "13",
        _ => "unknown",
    }
}

/// A captured packet for pcap output.
struct PcapPacket {
    src: SocketAddr,
    dst: SocketAddr,
    data: Vec<u8>,
}

/// Write packets to a pcap file using the standard pcap format.
/// Uses raw IPv4 link type so Wireshark can dissect the UDP/DTLS layers.
fn write_pcap(path: &std::path::Path, packets: &[PcapPacket]) -> std::io::Result<()> {
    use std::io::Write;

    let mut f = std::fs::File::create(path)?;

    // Global header (24 bytes)
    // magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
    f.write_all(&2u16.to_le_bytes())?; // version major
    f.write_all(&4u16.to_le_bytes())?; // version minor
    f.write_all(&0i32.to_le_bytes())?; // thiszone
    f.write_all(&0u32.to_le_bytes())?; // sigfigs
    f.write_all(&65535u32.to_le_bytes())?; // snaplen
    f.write_all(&228u32.to_le_bytes())?; // LINKTYPE_IPV4 (228 = raw IPv4)

    for (i, pkt) in packets.iter().enumerate() {
        // Build a minimal IPv4 + UDP frame around the payload
        let udp_len = 8 + pkt.data.len();
        let ip_total_len = 20 + udp_len;

        // IPv4 header (20 bytes, no options)
        let mut ip_header = [0u8; 20];
        ip_header[0] = 0x45; // version=4, IHL=5
        ip_header[1] = 0; // DSCP/ECN
        ip_header[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&(i as u16).to_be_bytes()); // identification
        ip_header[8] = 64; // TTL
        ip_header[9] = 17; // protocol = UDP
        // checksum left as 0 (Wireshark will flag but still parse)
        match pkt.src {
            SocketAddr::V4(a) => ip_header[12..16].copy_from_slice(&a.ip().octets()),
            _ => {}
        }
        match pkt.dst {
            SocketAddr::V4(a) => ip_header[16..20].copy_from_slice(&a.ip().octets()),
            _ => {}
        }

        // UDP header (8 bytes)
        let mut udp_header = [0u8; 8];
        udp_header[0..2].copy_from_slice(&pkt.src.port().to_be_bytes());
        udp_header[2..4].copy_from_slice(&pkt.dst.port().to_be_bytes());
        udp_header[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // checksum left as 0

        let frame_len = ip_total_len as u32;

        // Packet record header (16 bytes)
        // Use packet index as fake timestamp (1ms apart)
        let ts_sec = i as u32;
        let ts_usec = 0u32;
        f.write_all(&ts_sec.to_le_bytes())?;
        f.write_all(&ts_usec.to_le_bytes())?;
        f.write_all(&frame_len.to_le_bytes())?; // incl_len
        f.write_all(&frame_len.to_le_bytes())?; // orig_len

        // Frame data
        f.write_all(&ip_header)?;
        f.write_all(&udp_header)?;
        f.write_all(&pkt.data)?;
    }

    Ok(())
}
