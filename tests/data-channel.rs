use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::channel::ChannelConfig;
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, poll_to_completion, progress, Peer, TestRtc};

#[test]
pub fn data_channel() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Create offer from L using transaction API
    let (cid, offer, pending) = {
        let tx = l.rtc.begin(l.last)?;
        let mut change = tx.sdp_api();
        let cid = change.add_channel("My little channel".into());
        change.add_channel("My little channel 2".into());
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(tx)?;
        (cid, offer, pending)
    };

    // R accepts the offer
    let answer = {
        let tx = r.rtc.begin(r.last)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(tx)?;
        answer
    };

    // L accepts the answer
    {
        let tx = l.rtc.begin(l.last)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(tx)?;
    }

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
        l.try_write_channel(cid, false, "Hello world! ".as_bytes());

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    assert!(r.events.len() > 120);

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
    let (cid, offer, pending) = {
        let tx = l.rtc.begin(l.last)?;
        let mut change = tx.sdp_api();
        let cid = change.add_channel("DCEP Channel".into());
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(tx)?;
        (cid, offer, pending)
    };

    // R accepts the offer
    let answer = {
        let tx = r.rtc.begin(r.last)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(tx)?;
        answer
    };

    // L accepts the answer
    {
        let tx = l.rtc.begin(l.last)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(tx)?;
    }

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
            l_config_available_on_open = l.channel_config(id).is_some();
        }

        if let Some(id) = r_found_id {
            r_config_available_on_open = r.channel_config(id).is_some();
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
    let (offer, pending) = {
        let tx = l.rtc.begin(l.last)?;
        let mut change = tx.sdp_api();
        let _temp_cid = change.add_channel("temp".into());
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(tx)?;
        (offer, pending)
    };

    // R accepts the offer
    let answer = {
        let tx = r.rtc.begin(r.last)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(tx)?;
        answer
    };

    // L accepts the answer
    {
        let tx = l.rtc.begin(l.last)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(tx)?;
    }

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

    let cid_l = l.with_direct_api(|api| api.create_data_channel(config.clone()));
    let cid_r = r.with_direct_api(|api| api.create_data_channel(config));

    // Allow some time for channels to be established
    for _ in 0..10 {
        progress(&mut l, &mut r)?;
    }

    // Verify config is immediately available for locally created out-of-band channels
    let l_config = l
        .channel_config(cid_l)
        .expect("L channel config should be available");
    let r_config = r
        .channel_config(cid_r)
        .expect("R channel config should be available");

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

    let (offer, pending) = {
        let tx = l.rtc.begin(l.last)?;
        let mut change = tx.sdp_api();
        let _temp_cid = change.add_channel("temp".into());
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(tx)?;
        (offer, pending)
    };

    // R accepts the offer
    let answer = {
        let tx = r.rtc.begin(r.last)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(tx)?;
        answer
    };

    // L accepts the answer
    {
        let tx = l.rtc.begin(l.last)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(tx)?;
    }

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

    let cid_l = l.with_direct_api(|api| api.create_data_channel(config.clone()));
    let cid_r = r.with_direct_api(|api| api.create_data_channel(config));

    for _ in 0..10 {
        progress(&mut l, &mut r)?;
    }

    // Verify protocol is correctly set on both sides
    let l_config = l.channel_config(cid_l).expect("L channel config");
    let r_config = r.channel_config(cid_r).expect("R channel config");

    assert_eq!(l_config.protocol, custom_protocol);
    assert_eq!(r_config.protocol, custom_protocol);

    Ok(())
}
