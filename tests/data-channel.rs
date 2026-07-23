use std::net::Ipv4Addr;
use std::time::Duration;

use netem::NetemConfig;
use str0m::channel::ChannelConfig;
use str0m::{Event, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

#[test]
pub fn data_channel() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("My little channel".into());
    change.add_channel("My little channel 2".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    loop {
        if let Some(mut chan) = l.channel(cid) {
            chan.write(false, "Hello world! ".as_bytes())
                .expect("to write string");
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    assert!(r.events.len() > 120);

    Ok(())
}

/// Closing a data channel must propagate to the remote peer (via the SCTP
/// stream reset handshake), and once the handshake completes the freed stream
/// id must be reusable by a new in-band channel.
#[test]
pub fn data_channel_close_reopen() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("churn".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Wait until both sides see the channel open.
    loop {
        progress(&mut l, &mut r)?;

        let l_open = l
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelOpen(id, _) if *id == cid));
        let r_open = r
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelOpen(_, _)));

        if l_open && r_open {
            break;
        }
        assert!(
            l.duration() < Duration::from_secs(10),
            "first channel should open on both sides"
        );
    }

    let stream_id = l
        .direct_api()
        .sctp_stream_id_by_channel_id(cid)
        .expect("stream id for open channel");

    // Close locally. The reset handshake must inform the remote, which
    // previously never received ChannelClose.
    l.direct_api().close_data_channel(cid);

    loop {
        progress(&mut l, &mut r)?;

        let l_closed = l
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelClose(id) if *id == cid));
        let r_closed = r
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelClose(_)));

        if l_closed && r_closed {
            break;
        }
        assert!(
            l.duration() < Duration::from_secs(20),
            "both sides should see ChannelClose"
        );
    }

    // The reset handshake finishes with round-trips (reciprocal reset and
    // RECONFIG-RESPONSEs) that carry no public events, so there is nothing to
    // wait on here. Creating the next channel immediately is fine: its stream
    // id allocation happens on a later timeout, by which time the handshake
    // rounds have been ferried through. The stream id assertion below fails
    // loudly if the allocator did not release the id in time.
    let cid2 = l.direct_api().create_data_channel(ChannelConfig {
        label: "churn2".into(),
        ..Default::default()
    });
    assert_ne!(cid, cid2);

    loop {
        progress(&mut l, &mut r)?;

        let l_open = l.events.iter().any(
            |(_, e)| matches!(e, Event::ChannelOpen(id, label) if *id == cid2 && label == "churn2"),
        );
        let r_open = r
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelOpen(_, label) if label == "churn2"));

        if l_open && r_open {
            break;
        }
        assert!(
            l.duration() < Duration::from_secs(30),
            "reopened channel should open on both sides"
        );
    }

    // The freed stream id must have been reused, proving the allocator
    // released it when the reset handshake completed.
    assert_eq!(
        l.direct_api().sctp_stream_id_by_channel_id(cid2),
        Some(stream_id),
        "reopened channel should reuse the freed stream id"
    );

    // Data flows on the reopened channel.
    loop {
        if let Some(mut chan) = l.channel(cid2) {
            chan.write(false, b"hello again").expect("write to succeed");
        }

        progress(&mut l, &mut r)?;

        let got_data = r.events.iter().any(
            |(_, e)| matches!(e, Event::ChannelData(d) if d.data.as_slice() == b"hello again"),
        );
        if got_data {
            break;
        }
        assert!(
            l.duration() < Duration::from_secs(40),
            "data should flow on the reopened channel"
        );
    }

    Ok(())
}

#[test]
pub fn data_channel_flood() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("My little channel".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    while l.channel(cid).is_none() {
        progress(&mut l, &mut r)?;
    }

    r.set_netem(NetemConfig::new().latency(Duration::from_millis(1000)));

    let mut count = 0;

    for _ in 0..10_000 {
        let mut chan = l.channel(cid).unwrap();
        let did_write = chan.write(true, &[0u8; 1400]).expect("to write string");
        if did_write {
            count += 1;
        }
        progress(&mut l, &mut r)?;
    }

    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }
    assert!(count > 9000, "Too few events: {}", count);

    Ok(())
}

#[test]
pub fn channel_config_inband() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Create in-band negotiated channel (DCEP)
    let mut change = l.sdp_api();
    let cid = change.add_channel("DCEP Channel".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Wait for connection
    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let mut l_channel_opened = false;
    let mut r_channel_opened = false;
    let mut l_config_available_on_open = false;
    let mut r_config_available_on_open = false;

    // Process events and verify config availability immediately when ChannelOpen is fired
    loop {
        progress(&mut l, &mut r)?;

        // Check L side events and collect channel ID if found
        let mut l_found_id = None;
        for (_, event) in &l.events {
            if let Event::ChannelOpen(id, label) = event {
                if *id == cid && label == "DCEP Channel" {
                    l_channel_opened = true;
                    l_found_id = Some(*id);
                    break;
                }
            }
        }

        // Check R side events and collect channel ID if found
        let mut r_found_id = None;
        for (_, event) in &r.events {
            if let Event::ChannelOpen(id, label) = event {
                if label == "DCEP Channel" {
                    r_channel_opened = true;
                    r_found_id = Some(*id);
                    break;
                }
            }
        }

        // Verify config is available immediately when ChannelOpen is emitted
        if let Some(id) = l_found_id {
            if let Some(channel) = l.channel(id) {
                l_config_available_on_open = channel.config().is_some();
            }
        }

        if let Some(id) = r_found_id {
            if let Some(channel) = r.channel(id) {
                r_config_available_on_open = channel.config().is_some();
            }
        }

        if (l_channel_opened && r_channel_opened) || l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    assert!(l_channel_opened, "L side should receive ChannelOpen event");
    assert!(r_channel_opened, "R side should receive ChannelOpen event");
    assert!(
        l_config_available_on_open,
        "L side config should be available on ChannelOpen"
    );
    assert!(
        r_config_available_on_open,
        "R side config should be available on ChannelOpen"
    );

    Ok(())
}

#[test]
pub fn channel_config_outband_local() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Enable SCTP by adding a temporary channel (will be removed)
    let mut change_l = l.sdp_api();
    let _temp_cid = change_l.add_channel("temp".into());
    let (offer, pending) = change_l.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Wait for connection
    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Wait for SCTP to be established first
    loop {
        progress(&mut l, &mut r)?;

        // Check for SCTP connection via any channel events
        let connected = l
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelOpen(_, _)))
            || r.events
                .iter()
                .any(|(_, e)| matches!(e, Event::ChannelOpen(_, _)));

        if connected || l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Create out-of-band negotiated channel on both sides
    let config = ChannelConfig {
        negotiated: Some(10),
        label: "OutOfBand Local".into(),
        ..Default::default()
    };

    let cid_l = l.direct_api().create_data_channel(config.clone());
    let cid_r = r.direct_api().create_data_channel(config);

    // Allow some time for channels to be established
    for _ in 0..10 {
        progress(&mut l, &mut r)?;
    }

    // Verify config is immediately available for locally created out-of-band channels
    let l_channel = l.channel(cid_l).expect("L channel should be available");
    let r_channel = r.channel(cid_r).expect("R channel should be available");

    assert!(
        l_channel.config().is_some(),
        "L side config should be immediately available for local out-of-band channel"
    );
    assert!(
        r_channel.config().is_some(),
        "R side config should be immediately available for local out-of-band channel"
    );

    let l_config = l_channel.config().unwrap();
    let r_config = r_channel.config().unwrap();

    assert_eq!(l_config.label, "OutOfBand Local");
    assert_eq!(r_config.label, "OutOfBand Local");
    assert_eq!(l_config.negotiated, Some(10));
    assert_eq!(r_config.negotiated, Some(10));

    Ok(())
}

#[test]
pub fn channel_config_with_protocol() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let _temp_cid = change.add_channel("temp".into());
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Wait for connection
    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Wait for SCTP to be established
    loop {
        progress(&mut l, &mut r)?;
        let connected = l
            .events
            .iter()
            .any(|(_, e)| matches!(e, Event::ChannelOpen(_, _)));
        if connected || l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Create channels with custom protocol
    let custom_protocol = "my-custom-protocol";
    let config = ChannelConfig {
        negotiated: Some(20),
        protocol: custom_protocol.into(),
        ..Default::default()
    };

    let cid_l = l.direct_api().create_data_channel(config.clone());
    let cid_r = r.direct_api().create_data_channel(config);

    for _ in 0..10 {
        progress(&mut l, &mut r)?;
    }

    // Verify protocol is correctly set on both sides
    let l_channel = l.channel(cid_l).unwrap();
    let r_channel = r.channel(cid_r).unwrap();
    let l_config = l_channel.config().unwrap();
    let r_config = r_channel.config().unwrap();

    assert_eq!(l_config.protocol, custom_protocol);
    assert_eq!(r_config.protocol, custom_protocol);

    Ok(())
}
