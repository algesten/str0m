use std::net::Ipv4Addr;
use std::time::Duration;

use netem::NetemConfig;
use str0m::channel::ChannelConfig;
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, progress, Peer, TestRtc};

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

    for _ in 0..10_000 {
        let mut chan = l.channel(cid).unwrap();
        chan.write(true, &[0u8; 1400]).expect("to write string");
        progress(&mut l, &mut r)?;
    }

    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }
    assert!(r.events.len() > 80);

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
