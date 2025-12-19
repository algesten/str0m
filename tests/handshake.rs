use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer};
use str0m::channel::{ChannelConfig, ChannelId};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig, RtcError};
use tracing::{info_span, Span};

mod common;
use common::{init_crypto_default, init_log};

/// Messages exchanged between client and server threads.
#[derive(Debug)]
enum Message {
    /// SDP offer from client to server
    Offer(String),
    /// SDP answer from server to client
    Answer(String),
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
                    // Send packet to other peer
                    let _ = outgoing.send(Message::Packet {
                        proto: t.proto,
                        source: t.source,
                        destination: t.destination,
                        contents: t.contents.to_vec(),
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
                // Unexpected message type
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

#[test]
pub fn handshake_two_threads() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let test_start = Instant::now();

    // Channels for communication between threads
    // client -> server
    let (client_tx, server_rx) = mpsc::channel::<Message>();
    // server -> client
    let (server_tx, client_rx) = mpsc::channel::<Message>();

    let client_addr: SocketAddr = (Ipv4Addr::new(192, 168, 1, 1), 5000).into();
    let server_addr: SocketAddr = (Ipv4Addr::new(192, 168, 1, 2), 5001).into();

    // Spawn server thread
    let server_handle = thread::spawn(move || -> Result<TimingReport, RtcError> {
        let span = info_span!("SERVER");
        let _guard = span.enter();
        let mut timing = TimingReport::new();

        // Server uses ICE lite
        let mut rtc = RtcConfig::new().set_ice_lite(true).build();

        // Add candidates
        let local_candidate = Candidate::host(server_addr, "udp")?;
        rtc.add_local_candidate(local_candidate);
        let remote_candidate = Candidate::host(client_addr, "udp")?;
        rtc.add_remote_candidate(remote_candidate);

        // Wait for offer from client
        let offer = match server_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Message::Offer(sdp)) => {
                timing.got_offer = Some(Instant::now());
                sdp
            }
            Ok(_) => panic!("Server expected Offer, got something else"),
            Err(e) => panic!("Server failed to receive offer: {:?}", e),
        };

        // Parse and accept the offer
        let offer = SdpOffer::from_sdp_string(&offer).expect("Failed to parse offer SDP");

        // Add pre-negotiated data channel with id 0 using SDP API
        // For pre-negotiated channels, apply() returns None and confirms the channel
        let mut changes = rtc.sdp_api();
        changes.add_channel_with_config(ChannelConfig {
            label: "test-channel".into(),
            negotiated: Some(0),
            ..Default::default()
        });
        // Accept the offer using the same SdpApi instance
        let answer = changes.accept_offer(offer)?;

        // Send answer back to client
        server_tx
            .send(Message::Answer(answer.to_sdp_string()))
            .expect("Failed to send answer");
        timing.sent_answer = Some(Instant::now());

        // Run the event loop with message exchange
        run_rtc_loop_with_exchange(&mut rtc, &span, &server_rx, &server_tx, &mut timing, false)?;

        Ok(timing)
    });

    // Spawn client thread
    let client_handle = thread::spawn(move || -> Result<TimingReport, RtcError> {
        let span = info_span!("CLIENT");
        let _guard = span.enter();
        let mut timing = TimingReport::new();

        let mut rtc = RtcConfig::new().build();

        // Add candidates
        let local_candidate = Candidate::host(client_addr, "udp")?;
        rtc.add_local_candidate(local_candidate);
        let remote_candidate = Candidate::host(server_addr, "udp")?;
        rtc.add_remote_candidate(remote_candidate);

        // Create pre-negotiated data channel with id 0 and generate offer
        let mut change = rtc.sdp_api();
        let _channel_id = change.add_channel_with_config(ChannelConfig {
            label: "test-channel".into(),
            negotiated: Some(0),
            ..Default::default()
        });
        let (offer, pending) = change.apply().expect("Failed to apply SDP changes");

        // Send offer to server
        client_tx
            .send(Message::Offer(offer.to_sdp_string()))
            .expect("Failed to send offer");
        timing.sent_offer = Some(Instant::now());

        // Wait for answer from server
        let answer = match client_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Message::Answer(sdp)) => {
                timing.got_answer = Some(Instant::now());
                sdp
            }
            Ok(_) => panic!("Client expected Answer, got something else"),
            Err(e) => panic!("Client failed to receive answer: {:?}", e),
        };

        // Apply the answer
        let answer = SdpAnswer::from_sdp_string(&answer).expect("Failed to parse answer SDP");
        rtc.sdp_api().accept_answer(pending, answer)?;

        // Run the event loop with message exchange
        run_rtc_loop_with_exchange(&mut rtc, &span, &client_rx, &client_tx, &mut timing, true)?;

        Ok(timing)
    });

    // Wait for both threads to complete
    let server_timing = server_handle
        .join()
        .expect("Server thread panicked")
        .expect("Server returned error");
    let client_timing = client_handle
        .join()
        .expect("Client thread panicked")
        .expect("Client returned error");

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
