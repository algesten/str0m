//! Integration test: Data channels using Apple crypto provider.
//!
//! Data channels require DTLS + SCTP, so this tests the full encryption stack.

#![cfg(target_vendor = "apple")]

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::{Event, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto, init_log, progress, TestRtc};

/// Test data channel communication.
#[test]
pub fn data_channel() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("Test Channel".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Wait for connection
    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Send data over channel
    loop {
        if let Some(mut chan) = l.channel(cid) {
            chan.write(false, "Hello from Apple crypto!".as_bytes())
                .expect("to write data");
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Verify receiver got channel data
    let channel_data_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::ChannelData(_)))
        .count();

    assert!(
        channel_data_count > 50,
        "Expected at least 50 ChannelData events, got {}",
        channel_data_count
    );

    Ok(())
}

/// Test bidirectional data channel.
#[test]
pub fn data_channel_bidirectional() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("Bidirectional Channel".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Wait for channel to open on R side
    let mut r_channel_id = None;
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
        for (_, event) in &r.events {
            if let Event::ChannelOpen(id, _) = event {
                r_channel_id = Some(*id);
                break;
            }
        }
        if r_channel_id.is_some() {
            break;
        }
    }

    let r_cid = r_channel_id.expect("R should have received ChannelOpen event");

    // Both sides send
    loop {
        if let Some(mut chan) = l.channel(cid) {
            chan.write(false, "From L".as_bytes()).ok();
        }
        if let Some(mut chan) = r.channel(r_cid) {
            chan.write(false, "From R".as_bytes()).ok();
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Verify both received
    let l_received = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::ChannelData(_)))
        .count();

    let r_received = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::ChannelData(_)))
        .count();

    assert!(
        l_received > 10,
        "L expected at least 10 ChannelData events, got {}",
        l_received
    );
    assert!(
        r_received > 10,
        "R expected at least 10 ChannelData events, got {}",
        r_received
    );

    Ok(())
}
