use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use str0m::bwe::Bitrate;
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::config::{DtlsVersion, Fingerprint};
use str0m::crypto::dtls::ProtocolVersion;
use str0m::ice::IceCreds;
use str0m::media::{MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::RawPacket;
use str0m::{
    Candidate, Event, IceConnectionState, Input, Output, Reason, Rtc, RtcConfig, RtcError,
};
use tracing::{Span, info_span};

mod common;
use common::{Peer, init_crypto_default, init_log, snap_init_data};

/// Maximum total packets expected when using SNAP.
///
/// SNAP skips the 4-way SCTP handshake (INIT, INIT-ACK, COOKIE-ECHO,
/// COOKIE-ACK), so the total packet count should be well under this limit.
/// The exact number depends on ICE/DTLS setup specifics.
const MAX_SNAP_PACKETS: usize = 20;

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

/// Standard direct API handshake (no SNAP).
#[test]
pub fn handshake_direct_api() -> Result<(), RtcError> {
    run_direct_handshake(DtlsVersion::Auto, DtlsVersion::Auto, false)
}

/// Direct API handshake with SNAP (out-of-band SCTP INIT exchange, skips 4-way handshake).
#[test]
pub fn handshake_direct_api_snap() -> Result<(), RtcError> {
    run_direct_handshake(DtlsVersion::Auto, DtlsVersion::Auto, true)
}

/// 0.24 client with BWE against a server that still schedules SSRC 0 receiver reports.
///
/// Both sides use DTLS 1.2. The server is current code with the pre-0.24 scheduling
/// bug restored, matching a 0.23 receive thread. It must busy-loop on `Timeout(now)`.
#[test]
pub fn handshake_direct_dtls12_legacy_server_spins_on_ssrc0() -> Result<(), RtcError> {
    run_ssrc_zero_rollout(true)
}

/// Same DTLS 1.2 peers after the server has the 0.24 receiver-report fix.
#[test]
pub fn handshake_direct_dtls12_current_server_does_not_spin_on_ssrc0() -> Result<(), RtcError> {
    run_ssrc_zero_rollout(false)
}

/// Returns the name of the default crypto provider based on compile-time feature flags.
/// Mirrors the priority order in `str0m::crypto::from_feature_flags()`.
#[allow(unreachable_code)]
fn default_crypto_name() -> &'static str {
    #[cfg(feature = "aws-lc-rs")]
    return "aws-lc-rs";
    #[cfg(feature = "rust-crypto")]
    return "rust-crypto";
    #[cfg(feature = "openssl-dimpl")]
    return "openssl-dimpl";
    #[cfg(feature = "openssl")]
    return "openssl";
    #[cfg(all(feature = "wincrypto", target_os = "windows"))]
    return "wincrypto";
    #[cfg(all(feature = "apple-crypto", target_vendor = "apple"))]
    return "apple-crypto";
    "unknown"
}

fn run_handshake_test(client_dtls: DtlsVersion, server_dtls: DtlsVersion) -> Result<(), RtcError> {
    run_direct_handshake(client_dtls, server_dtls, false)
}

/// Consecutive already-due feedback timeouts required to call the receive thread stuck.
const RECEIVE_SPIN_TIMEOUTS: u32 = 300;

/// 0.24 client (BWE / SSRC 0 probes) against either a legacy or current server.
///
/// Both peers negotiate DTLS 1.2. Real `Instant` timeouts and two threads match the
/// application receive loop: when the timeout is already due, `recv_timeout(0)` does
/// not block and the thread calls `handle_input(Timeout(now))` again.
fn run_ssrc_zero_rollout(legacy_server: bool) -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let test_start = Instant::now();
    println!(
        "\n=== DTLS 1.2 rollout: 0.24 client, {} server ===",
        if legacy_server {
            "0.23 receiver-report"
        } else {
            "0.24"
        }
    );

    let (client_tx, server_rx) = mpsc::channel::<Message>();
    let (server_tx, client_rx) = mpsc::channel::<Message>();
    let client_packets_sent = Arc::new(AtomicUsize::new(0));
    let server_packets_sent = Arc::new(AtomicUsize::new(0));
    let client_packets_sent_clone = client_packets_sent.clone();
    let server_packets_sent_clone = server_packets_sent.clone();

    let client_addr: SocketAddr = (Ipv4Addr::new(192, 168, 1, 1), 5000).into();
    let server_addr: SocketAddr = (Ipv4Addr::new(192, 168, 1, 2), 5001).into();
    let client_setup = PeerSetup {
        enable_bwe: true,
        raw_packets: true,
        declare_audio: true,
        ..PeerSetup::default()
    };
    let server_setup = PeerSetup {
        legacy_ssrc_zero_receiver_reports: legacy_server,
        raw_packets: true,
        declare_audio: true,
        enable_twcc: true,
        ..PeerSetup::default()
    };

    let server_handle = thread::spawn(move || {
        let span = info_span!("SERVER");
        let _guard = span.enter();
        let mut timing = TimingReport::new();
        let mut packets = Vec::new();
        let result = (|| -> Result<TimingReport, RtcError> {
            let (mut rtc, local_creds, local_fingerprint) = init_rtc(
                false,
                server_addr,
                DtlsVersion::Dtls12,
                Peer::Right,
                &mut timing,
                server_setup,
            )?;
            server_tx
                .send(Message::Credentials {
                    ice_ufrag: local_creds.ufrag.clone(),
                    ice_pwd: local_creds.pass.clone(),
                    dtls_fingerprint: local_fingerprint,
                    sctp_init: None,
                })
                .expect("Failed to send server credentials");
            let (remote_ice_ufrag, remote_ice_pwd, remote_fingerprint, _) =
                match server_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(Message::Credentials {
                        ice_ufrag,
                        ice_pwd,
                        dtls_fingerprint,
                        sctp_init,
                    }) => {
                        timing.got_offer = Some(Instant::now());
                        (ice_ufrag, ice_pwd, dtls_fingerprint, sctp_init)
                    }
                    Ok(_) => panic!("Server expected Credentials, got something else"),
                    Err(e) => panic!("Server failed to receive credentials: {e:?}"),
                };
            configure_rtc(
                &mut rtc,
                false,
                client_addr,
                IceCreds {
                    ufrag: remote_ice_ufrag,
                    pass: remote_ice_pwd,
                },
                remote_fingerprint,
                None,
                None,
            )?;
            timing.sent_answer = Some(Instant::now());
            run_rtc_loop_with_exchange(
                &mut rtc,
                &mut timing,
                false,
                RtcLoopIo {
                    span: &span,
                    incoming: &server_rx,
                    outgoing: &server_tx,
                    packets: &mut packets,
                    packets_sent: &server_packets_sent_clone,
                },
                LoopControl {
                    stop_on_receive_spin: true,
                    hold_until_peer_disconnect: false,
                    settle_after_complete: Duration::ZERO,
                },
            )?;
            timing.dtls_protocol_version = rtc.direct_api().dtls_protocol_version();
            Ok(timing)
        })();
        (packets, result)
    });

    let client_handle = thread::spawn(move || {
        let span = info_span!("CLIENT");
        let _guard = span.enter();
        let mut timing = TimingReport::new();
        let mut packets = Vec::new();
        let result = (|| -> Result<TimingReport, RtcError> {
            let (mut rtc, local_creds, local_fingerprint) = init_rtc(
                true,
                client_addr,
                DtlsVersion::Dtls12,
                Peer::Left,
                &mut timing,
                client_setup,
            )?;
            let (remote_ice_ufrag, remote_ice_pwd, remote_fingerprint, _) =
                match client_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(Message::Credentials {
                        ice_ufrag,
                        ice_pwd,
                        dtls_fingerprint,
                        sctp_init,
                    }) => (ice_ufrag, ice_pwd, dtls_fingerprint, sctp_init),
                    Ok(_) => panic!("Client expected Credentials, got something else"),
                    Err(e) => panic!("Client failed to receive server credentials: {e:?}"),
                };
            client_tx
                .send(Message::Credentials {
                    ice_ufrag: local_creds.ufrag.clone(),
                    ice_pwd: local_creds.pass.clone(),
                    dtls_fingerprint: local_fingerprint,
                    sctp_init: None,
                })
                .expect("Failed to send client credentials");
            timing.sent_offer = Some(Instant::now());
            configure_rtc(
                &mut rtc,
                true,
                server_addr,
                IceCreds {
                    ufrag: remote_ice_ufrag,
                    pass: remote_ice_pwd,
                },
                remote_fingerprint,
                None,
                None,
            )?;
            timing.got_answer = Some(Instant::now());
            rtc.bwe().set_desired_bitrate(Bitrate::mbps(2));
            run_rtc_loop_with_exchange(
                &mut rtc,
                &mut timing,
                true,
                RtcLoopIo {
                    span: &span,
                    incoming: &client_rx,
                    outgoing: &client_tx,
                    packets: &mut packets,
                    packets_sent: &client_packets_sent_clone,
                },
                LoopControl {
                    stop_on_receive_spin: false,
                    // Stay up after the data exchange. The legacy server exits on the
                    // spin and disconnects this thread. The fixed server needs a short
                    // settle so SSRC 0 probes are delivered before we tear down.
                    hold_until_peer_disconnect: legacy_server,
                    settle_after_complete: if legacy_server {
                        Duration::ZERO
                    } else {
                        Duration::from_millis(500)
                    },
                },
            )?;
            timing.dtls_protocol_version = rtc.direct_api().dtls_protocol_version();
            Ok(timing)
        })();
        (packets, result)
    });

    let (_server_packets, server_result) = server_handle.join().expect("Server thread panicked");
    let (_client_packets, client_result) = client_handle.join().expect("Client thread panicked");
    let server_timing = server_result.expect("Server returned error");
    let client_timing = client_result.expect("Client returned error");
    client_timing.print("CLIENT (DTLS 1.2)");
    server_timing.print("SERVER (DTLS 1.2)");
    println!(
        "\n=== Rollout test time: {:.3}ms ===",
        test_start.elapsed().as_secs_f64() * 1000.0
    );
    println!(
        "  Client packets sent: {}",
        client_packets_sent.load(Ordering::SeqCst)
    );
    println!(
        "  Server packets sent: {}",
        server_packets_sent.load(Ordering::SeqCst)
    );

    assert_eq!(
        client_timing.dtls_protocol_version,
        Some(ProtocolVersion::DTLS1_2)
    );
    assert_eq!(
        server_timing.dtls_protocol_version,
        Some(ProtocolVersion::DTLS1_2)
    );
    assert!(
        server_timing.ssrc0_rx > 0,
        "server should receive an SSRC 0 probe from the 0.24 client"
    );

    if legacy_server {
        assert!(
            server_timing.receive_spin,
            "0.23-style server should busy-loop on an already-due feedback timeout, got {} immediate timeouts",
            server_timing.immediate_feedback_timeouts
        );
        let spin_elapsed = server_timing
            .spin_elapsed
            .expect("spin should record elapsed time");
        assert!(
            spin_elapsed < Duration::from_secs(2),
            "receive thread spin should be a tight now-loop, took {spin_elapsed:?}"
        );
        println!(
            "\n=== SERVER receive thread stuck: {} already-due Feedback timeouts in {:?} ===",
            server_timing.immediate_feedback_timeouts, spin_elapsed
        );
    } else {
        assert!(
            !server_timing.receive_spin,
            "0.24 server should not busy-loop after SSRC 0 probes ({} immediate timeouts)",
            server_timing.immediate_feedback_timeouts
        );
        assert!(
            server_timing.immediate_feedback_timeouts < RECEIVE_SPIN_TIMEOUTS,
            "fixed server still rearmed feedback immediately"
        );
        assert!(
            client_timing.sent_data.is_some() && client_timing.received_data.is_some(),
            "fixed peers should still exchange data"
        );
        assert!(
            server_timing.received_data.is_some() && server_timing.sent_data.is_some(),
            "fixed server should answer the data channel"
        );
    }

    Ok(())
}

/// Shared implementation for both standard and SNAP direct API handshake tests.
fn run_direct_handshake(
    client_dtls: DtlsVersion,
    server_dtls: DtlsVersion,
    use_snap: bool,
) -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let test_start = Instant::now();

    let client_crypto_name =
        std::env::var("L_CRYPTO").unwrap_or_else(|_| default_crypto_name().into());
    let server_crypto_name =
        std::env::var("R_CRYPTO").unwrap_or_else(|_| default_crypto_name().into());

    // Native openssl only supports DTLS 1.2 - skip tests requiring 1.3/Auto.
    // Also skip Auto client -> 1.2-only server: dimpl advertises X25519 in the hybrid
    // ClientHello but its DTLS 1.2 engine can't process X25519 in ServerKeyExchange.
    let dtls12_only = |name: &str| matches!(name, "openssl");
    let needs_13 = |v: DtlsVersion| matches!(v, DtlsVersion::Auto | DtlsVersion::Dtls13);

    if (dtls12_only(&client_crypto_name) && needs_13(client_dtls))
        || (dtls12_only(&server_crypto_name) && needs_13(server_dtls))
        || (matches!(client_dtls, DtlsVersion::Auto) && dtls12_only(&server_crypto_name))
    {
        println!(
            "\n=== SKIPPED: client={} ({}), server={} ({}) - DTLS 1.3/Auto not supported ===",
            client_dtls, client_crypto_name, server_dtls, server_crypto_name
        );
        return Ok(());
    }

    println!(
        "\n=== Test: client={} ({}), server={} ({}) ===",
        client_dtls, client_crypto_name, server_dtls, server_crypto_name
    );

    // Channels for communication between threads
    let (client_tx, server_rx) = mpsc::channel::<Message>();
    let (server_tx, client_rx) = mpsc::channel::<Message>();

    let client_packets_sent = Arc::new(AtomicUsize::new(0));
    let server_packets_sent = Arc::new(AtomicUsize::new(0));
    let client_packets_sent_clone = client_packets_sent.clone();
    let server_packets_sent_clone = server_packets_sent.clone();

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
                let (mut rtc, local_creds, local_fingerprint) = init_rtc(
                    false,
                    server_addr,
                    server_dtls,
                    Peer::Right,
                    &mut timing,
                    PeerSetup::default(),
                )?;

                // If SNAP, generate local SCTP INIT for out-of-band exchange
                let snap = snap_init_data(use_snap);
                let local_sctp_init = snap.as_ref().map(|(init, _)| init.clone());

                // Send server's credentials to client
                server_tx
                    .send(Message::Credentials {
                        ice_ufrag: local_creds.ufrag.clone(),
                        ice_pwd: local_creds.pass.clone(),
                        dtls_fingerprint: local_fingerprint,
                        sctp_init: local_sctp_init,
                    })
                    .expect("Failed to send server credentials");

                // Wait for client's credentials
                let (remote_ice_ufrag, remote_ice_pwd, remote_fingerprint, remote_sctp_init) =
                    match server_rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(Message::Credentials {
                            ice_ufrag,
                            ice_pwd,
                            dtls_fingerprint,
                            sctp_init,
                        }) => {
                            timing.got_offer = Some(Instant::now());
                            (ice_ufrag, ice_pwd, dtls_fingerprint, sctp_init)
                        }
                        Ok(_) => panic!("Server expected Credentials, got something else"),
                        Err(e) => panic!("Server failed to receive credentials: {:?}", e),
                    };

                // Configure with remote credentials (is_client = false)
                configure_rtc(
                    &mut rtc,
                    false,
                    client_addr,
                    IceCreds {
                        ufrag: remote_ice_ufrag,
                        pass: remote_ice_pwd,
                    },
                    remote_fingerprint,
                    snap.map(|(_, d)| d),
                    remote_sctp_init,
                )?;
                timing.sent_answer = Some(Instant::now());

                // Run the event loop with message exchange
                run_rtc_loop_with_exchange(
                    &mut rtc,
                    &mut timing,
                    false,
                    RtcLoopIo {
                        span: &span,
                        incoming: &server_rx,
                        outgoing: &server_tx,
                        packets: &mut packets,
                        packets_sent: &server_packets_sent_clone,
                    },
                    LoopControl::default(),
                )?;

                timing.dtls_protocol_version = rtc.direct_api().dtls_protocol_version();

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
                let (mut rtc, local_creds, local_fingerprint) = init_rtc(
                    true,
                    client_addr,
                    client_dtls,
                    Peer::Left,
                    &mut timing,
                    PeerSetup::default(),
                )?;

                // If SNAP, generate local SCTP INIT for out-of-band exchange
                let snap = snap_init_data(use_snap);
                let local_sctp_init = snap.as_ref().map(|(init, _)| init.clone());

                // Wait for server's credentials first
                let (remote_ice_ufrag, remote_ice_pwd, remote_fingerprint, remote_sctp_init) =
                    match client_rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(Message::Credentials {
                            ice_ufrag,
                            ice_pwd,
                            dtls_fingerprint,
                            sctp_init,
                        }) => (ice_ufrag, ice_pwd, dtls_fingerprint, sctp_init),
                        Ok(_) => panic!("Client expected Credentials, got something else"),
                        Err(e) => panic!("Client failed to receive server credentials: {:?}", e),
                    };

                // Send client's credentials to server
                client_tx
                    .send(Message::Credentials {
                        ice_ufrag: local_creds.ufrag.clone(),
                        ice_pwd: local_creds.pass.clone(),
                        dtls_fingerprint: local_fingerprint,
                        sctp_init: local_sctp_init,
                    })
                    .expect("Failed to send client credentials");
                timing.sent_offer = Some(Instant::now());

                // Configure with remote credentials (is_client = true)
                configure_rtc(
                    &mut rtc,
                    true,
                    server_addr,
                    IceCreds {
                        ufrag: remote_ice_ufrag,
                        pass: remote_ice_pwd,
                    },
                    remote_fingerprint,
                    snap.map(|(_, d)| d),
                    remote_sctp_init,
                )?;
                timing.got_answer = Some(Instant::now());

                // Run the event loop with message exchange
                run_rtc_loop_with_exchange(
                    &mut rtc,
                    &mut timing,
                    true,
                    RtcLoopIo {
                        span: &span,
                        incoming: &client_rx,
                        outgoing: &client_tx,
                        packets: &mut packets,
                        packets_sent: &client_packets_sent_clone,
                    },
                    LoopControl::default(),
                )?;

                timing.dtls_protocol_version = rtc.direct_api().dtls_protocol_version();

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
    let variant = if use_snap { "SNAP" } else { "standard" };

    client_timing.print(&format!("CLIENT ({})", variant));
    server_timing.print(&format!("SERVER ({})", variant));

    println!(
        "\n=== Total Test Time ({}): {:.3}ms ===",
        variant,
        total_time.as_secs_f64() * 1000.0
    );

    let client_sent = client_packets_sent.load(Ordering::SeqCst);
    let server_sent = server_packets_sent.load(Ordering::SeqCst);
    let total_packets = client_sent + server_sent;
    println!("\n=== Packet Counts ({}) ===", variant);
    println!("  Client packets sent: {}", client_sent);
    println!("  Server packets sent: {}", server_sent);
    println!("  Total packets: {}", total_packets);

    if use_snap {
        // SNAP skips the 4-way SCTP handshake, so it must use strictly fewer
        // packets than a standard connection.
        assert!(
            total_packets < MAX_SNAP_PACKETS,
            "SNAP should use fewer packets, got {total_packets}"
        );
    }

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

    // Verify the negotiated DTLS protocol version matches the expected outcome
    // for the requested (client, server) version combination. DTLS 1.3 and Auto
    // variants are tested only with dimpl.
    let expected = match (client_dtls, server_dtls) {
        (DtlsVersion::Dtls12, _) | (_, DtlsVersion::Dtls12) => ProtocolVersion::DTLS1_2,
        (DtlsVersion::Dtls13, _) | (_, DtlsVersion::Dtls13) => ProtocolVersion::DTLS1_3,
        (DtlsVersion::Auto, DtlsVersion::Auto) => ProtocolVersion::DTLS1_3,
        _ => unreachable!("unexpected DTLS version combo: {client_dtls:?}/{server_dtls:?}"),
    };
    assert_eq!(
        client_timing.dtls_protocol_version,
        Some(expected),
        "Client negotiated DTLS version mismatch"
    );
    assert_eq!(
        server_timing.dtls_protocol_version,
        Some(expected),
        "Server negotiated DTLS version mismatch"
    );

    Ok(())
}

#[derive(Clone, Copy)]
struct PeerSetup {
    enable_bwe: bool,
    legacy_ssrc_zero_receiver_reports: bool,
    raw_packets: bool,
    declare_audio: bool,
    enable_twcc: bool,
}

impl Default for PeerSetup {
    fn default() -> Self {
        Self {
            enable_bwe: false,
            legacy_ssrc_zero_receiver_reports: false,
            raw_packets: false,
            declare_audio: false,
            enable_twcc: false,
        }
    }
}

#[derive(Clone, Copy)]
struct LoopControl {
    /// Exit once the receive thread has rearmed an already-due feedback timeout.
    stop_on_receive_spin: bool,
    /// After the data exchange, keep polling until the peer disconnects.
    hold_until_peer_disconnect: bool,
    /// After the data exchange, keep polling this long, then tell the peer to exit.
    settle_after_complete: Duration,
}

impl Default for LoopControl {
    fn default() -> Self {
        Self {
            stop_on_receive_spin: false,
            hold_until_peer_disconnect: false,
            settle_after_complete: Duration::ZERO,
        }
    }
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
    setup: PeerSetup,
) -> Result<(Rtc, IceCreds, String), RtcError> {
    let ice_creds = IceCreds::new();

    let mut rtc_config = RtcConfig::new()
        .set_local_ice_credentials(ice_creds.clone())
        .set_dtls_version(dtls_version)
        .set_legacy_ssrc_zero_receiver_reports(setup.legacy_ssrc_zero_receiver_reports)
        .enable_raw_packets(setup.raw_packets);
    if !is_client {
        rtc_config = rtc_config.set_ice_lite(true);
    }
    if setup.enable_bwe {
        rtc_config = rtc_config.enable_bwe(Some(Bitrate::kbps(300)));
    }
    if let Some(crypto) = peer.crypto_provider() {
        rtc_config = rtc_config.set_crypto_provider(crypto);
    }
    let mut rtc = rtc_config.build(Instant::now());
    timing.rtc_built = Some(Instant::now());

    if setup.declare_audio {
        rtc.direct_api()
            .declare_media(Mid::from("aud"), MediaKind::Audio);
    }
    if setup.enable_twcc {
        rtc.direct_api().enable_twcc_feedback();
    }

    let fingerprint = rtc.direct_api().local_dtls_fingerprint().to_string();

    let local_candidate = Candidate::host(local_addr, "udp")?;
    rtc.add_local_candidate(local_candidate);

    Ok((rtc, ice_creds, fingerprint))
}

/// Configure the Rtc instance with remote credentials and start DTLS/SCTP.
///
/// If `local_init_data` and `remote_sctp_init` are both provided, SNAP is used
/// to skip the 4-way SCTP handshake.
///
/// `local_init_data` is expected to already contain the local INIT chunk from
/// `local_init_chunk()`. This function adds the remote INIT chunk and then calls
/// `start_sctp_with_snap()`. If either side of that exchange is missing, it
/// falls back to the normal `start_sctp()` path.
fn configure_rtc(
    rtc: &mut Rtc,
    is_client: bool,
    remote_addr: SocketAddr,
    remote_ice_credentials: IceCreds,
    remote_fingerprint: String,
    local_init_data: Option<str0m::channel::SctpInitData>,
    remote_sctp_init: Option<Vec<u8>>,
) -> Result<(), RtcError> {
    let remote_candidate = Candidate::host(remote_addr, "udp")?;
    rtc.add_remote_candidate(remote_candidate);

    // Build SctpInitData with remote INIT if both sides provided SNAP data
    let sctp_init_data = match (local_init_data, remote_sctp_init) {
        (Some(mut data), Some(remote_init)) => {
            data.set_remote_init_chunk(remote_init);
            Some(data)
        }
        _ => None,
    };

    {
        let mut direct_api = rtc.direct_api();

        direct_api.set_ice_lite(!is_client);
        direct_api.set_ice_controlling(is_client);

        direct_api.set_remote_ice_credentials(remote_ice_credentials);

        let fingerprint: Fingerprint = remote_fingerprint
            .parse()
            .expect("Failed to parse remote fingerprint");
        direct_api.set_remote_fingerprint(fingerprint);

        direct_api.start_dtls(is_client)?;

        if let Some(sctp_init_data) = sctp_init_data {
            direct_api.start_sctp_with_snap(is_client, sctp_init_data)?;
        } else {
            direct_api.start_sctp(is_client);
        }

        direct_api.create_data_channel(ChannelConfig {
            label: "test-channel".into(),
            negotiated: Some(DATA_CHANNEL_ID),
            ordered: true,
            reliability: Reliability::Reliable,
            protocol: "".into(),
        });
    }

    rtc.handle_input(Input::Timeout(Instant::now()))?;

    Ok(())
}

/// Messages exchanged between client and server threads.
#[derive(Debug)]
enum Message {
    /// ICE, DTLS, and optionally SCTP credentials exchange
    Credentials {
        ice_ufrag: String,
        ice_pwd: String,
        dtls_fingerprint: String,
        /// SCTP INIT chunk for SNAP (`None` when not using SNAP)
        sctp_init: Option<Vec<u8>>,
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
    dtls_protocol_version: Option<ProtocolVersion>,
    ssrc0_rx: u32,
    immediate_feedback_timeouts: u32,
    receive_spin: bool,
    spin_elapsed: Option<Duration>,
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
        if self.ssrc0_rx > 0 {
            println!("  SSRC 0 packets:  {:>8}", self.ssrc0_rx);
        }
        if self.immediate_feedback_timeouts > 0 {
            println!("  Immediate RR:    {:>8}", self.immediate_feedback_timeouts);
        }
        if let Some(t) = self.spin_elapsed {
            println!("  Receive spin:    {:>8.3}ms", t.as_secs_f64() * 1000.0);
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

struct RtcLoopIo<'a> {
    span: &'a Span,
    incoming: &'a Receiver<Message>,
    outgoing: &'a Sender<Message>,
    packets: &'a mut Vec<PcapPacket>,
    packets_sent: &'a AtomicUsize,
}

/// Run the Rtc event loop with message exchange capability
fn run_rtc_loop_with_exchange(
    rtc: &mut Rtc,
    timing: &mut TimingReport,
    is_client: bool,
    io: RtcLoopIo<'_>,
    control: LoopControl,
) -> Result<(), RtcError> {
    let mut state = DataExchangeState::WaitingForChannelOpen;
    let mut channel_id: Option<ChannelId> = None;
    let mut spin_started: Option<Instant> = None;
    let mut completed_at: Option<Instant> = None;
    let role = if is_client { "CLIENT" } else { "SERVER" };
    let hold = control.hold_until_peer_disconnect;
    let settle = control.settle_after_complete;

    loop {
        if state == DataExchangeState::Complete {
            if completed_at.is_none() {
                completed_at = Some(Instant::now());
            }
            if hold {
                // Keep the peer alive until it disconnects, so a spinning
                // receiver is not torn down by the data-channel Exit.
            } else if settle.is_zero() {
                break;
            } else if completed_at.unwrap().elapsed() >= settle {
                let _ = io.outgoing.send(Message::Exit);
                break;
            }
        }

        if timing.start.unwrap().elapsed() > Duration::from_secs(10) {
            println!("[{}] Overall timeout reached", role);
            break;
        }

        let timeout = loop {
            match io.span.in_scope(|| rtc.poll_output())? {
                Output::Timeout(t) => break t,
                Output::Transmit(t) => {
                    let data = t.contents.to_vec();
                    io.packets_sent.fetch_add(1, Ordering::SeqCst);
                    if SAVE_PCAP {
                        io.packets.push(PcapPacket {
                            src: t.source,
                            dst: t.destination,
                            data: data.clone(),
                        });
                    }
                    // Send packet to other peer
                    let _ = io.outgoing.send(Message::Packet {
                        proto: t.proto,
                        source: t.source,
                        destination: t.destination,
                        contents: data,
                    });
                }
                Output::Event(e) => {
                    if let Event::RawPacket(packet) = &e {
                        if matches!(packet.as_ref(), RawPacket::RtpRx(header, _) if *header.ssrc == 0)
                        {
                            timing.ssrc0_rx += 1;
                            if timing.ssrc0_rx == 1 {
                                println!("[{role}] Received first SSRC 0 probe");
                            }
                        }
                    }
                    handle_event(
                        rtc,
                        &e,
                        timing,
                        is_client,
                        &mut state,
                        &mut channel_id,
                        io.outgoing,
                        !hold && settle.is_zero(),
                    );
                    if state == DataExchangeState::Complete && !hold && settle.is_zero() {
                        return Ok(());
                    }
                }
            }
        };

        let now = Instant::now();
        let wait = timeout.saturating_duration_since(now);
        if wait >= Duration::from_millis(1) {
            println!("[{role}] poll_output returned timeout in {wait:?}");
        }

        // An already-due Feedback timeout means the next loop turn will not block.
        // After an SSRC 0 probe, a legacy receiver never advances that deadline.
        if timing.ssrc0_rx > 0 && wait.is_zero() && rtc.last_timeout_reason() == Reason::Feedback {
            if spin_started.is_none() {
                spin_started = Some(Instant::now());
            }
            timing.immediate_feedback_timeouts += 1;
            if timing.immediate_feedback_timeouts == RECEIVE_SPIN_TIMEOUTS {
                timing.receive_spin = true;
                timing.spin_elapsed = spin_started.map(|started| started.elapsed());
                println!(
                    "[{role}] receive thread stuck: {} Feedback timeouts already due ({:?})",
                    timing.immediate_feedback_timeouts,
                    timing.spin_elapsed.unwrap_or_default()
                );
                if control.stop_on_receive_spin {
                    break;
                }
            }
        }

        match io.incoming.recv_timeout(wait) {
            Ok(Message::Packet {
                proto,
                source,
                destination,
                contents,
            }) => {
                if wait >= Duration::from_millis(1) {
                    println!("[{role}] Received packet ({} bytes)", contents.len());
                }
                if SAVE_PCAP {
                    io.packets.push(PcapPacket {
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
                io.span
                    .in_scope(|| rtc.handle_input(Input::Receive(Instant::now(), receive)))?;
            }
            Ok(Message::Exit) => {
                println!("[{}] Received Exit signal", role);
                state = DataExchangeState::Complete;
            }
            Ok(_) => {
                unreachable!("Unexpected message type");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if wait >= Duration::from_millis(1) {
                    println!("[{role}] Timeout fired, calling handle_input(Timeout)");
                }
                io.span
                    .in_scope(|| rtc.handle_input(Input::Timeout(Instant::now())))?;
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
    send_exit: bool,
) {
    match event {
        Event::IceConnectionStateChange(ice_state) => match ice_state {
            IceConnectionState::Checking if timing.ice_checking.is_none() => {
                timing.ice_checking = Some(Instant::now());
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
                if msg == "sevenofnine" {
                    println!("[CLIENT] Got reply 'sevenofnine' - sending Exit and completing");
                    timing.received_data = Some(Instant::now());
                    if send_exit {
                        let _ = outgoing.send(Message::Exit);
                    }
                    *state = DataExchangeState::Complete;
                }
            } else if msg == "sixseven" {
                timing.received_data = Some(Instant::now());
                let cid = data.id;
                if let Some(mut chan) = rtc.channel(cid) {
                    chan.write(true, b"sevenofnine").expect("Failed to write");
                    println!("[SERVER] Sent reply 'sevenofnine'");
                    timing.sent_data = Some(Instant::now());
                    *state = DataExchangeState::SentMessage;
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
        if let SocketAddr::V4(a) = pkt.src {
            ip_header[12..16].copy_from_slice(&a.ip().octets());
        }
        if let SocketAddr::V4(a) = pkt.dst {
            ip_header[16..20].copy_from_slice(&a.ip().octets());
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
