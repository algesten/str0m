use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::channel::ChannelConfig;
use str0m::{Candidate, Event, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, Peer, TestRtc};

#[test]
pub fn data_channel_direct() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let rtc_r = RtcConfig::new().set_ice_lite(true).build();
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp")?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp")?;

    // Add candidates via Ice API
    l.drive(&mut r, |tx| {
        let mut ice = tx.ice();
        ice.add_local_candidate(host1.clone()).unwrap();
        ice.add_remote_candidate(host2.clone());
        Ok((ice.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut ice = tx.ice();
        ice.add_local_candidate(host2).unwrap();
        ice.add_remote_candidate(host1);
        Ok((ice.finish(), ()))
    })?;

    // Exchange DTLS fingerprints
    let mut finger_l = None;
    l.drive(&mut r, |tx| {
        let api = tx.direct_api();
        finger_l = Some(api.local_dtls_fingerprint().clone());
        Ok((api.finish(), ()))
    })?;
    let finger_l = finger_l.unwrap();

    let mut finger_r = None;
    r.drive(&mut l, |tx| {
        let api = tx.direct_api();
        finger_r = Some(api.local_dtls_fingerprint().clone());
        Ok((api.finish(), ()))
    })?;
    let finger_r = finger_r.unwrap();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_fingerprint(finger_r);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_fingerprint(finger_l);
        Ok((api.finish(), ()))
    })?;

    // Exchange ICE credentials
    let mut creds_l = None;
    l.drive(&mut r, |tx| {
        let api = tx.direct_api();
        creds_l = Some(api.local_ice_credentials());
        Ok((api.finish(), ()))
    })?;
    let creds_l = creds_l.unwrap();

    let mut creds_r = None;
    r.drive(&mut l, |tx| {
        let api = tx.direct_api();
        creds_r = Some(api.local_ice_credentials());
        Ok((api.finish(), ()))
    })?;
    let creds_r = creds_r.unwrap();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_ice_credentials(creds_r);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_ice_credentials(creds_l);
        Ok((api.finish(), ()))
    })?;

    // Set controlling/controlled roles
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.set_ice_controlling(true);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.set_ice_controlling(false);
        Ok((api.finish(), ()))
    })?;

    // Start DTLS and SCTP
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.start_dtls(true).unwrap();
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.start_dtls(false).unwrap();
        Ok((api.finish(), ()))
    })?;

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.start_sctp(true);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.start_sctp(false);
        Ok((api.finish(), ()))
    })?;

    let config = ChannelConfig {
        negotiated: Some(1),
        label: "my-chan".into(),
        ..Default::default()
    };

    let mut cid = None;
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        cid = Some(api.create_data_channel(config.clone()));
        Ok((api.finish(), ()))
    })?;
    let cid = cid.unwrap();

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.create_data_channel(config);
        Ok((api.finish(), ()))
    })?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    loop {
        // Try to write to channel
        l.drive(&mut r, |tx| match tx.channel(cid) {
            Ok(mut chan) => {
                let _ = chan.write(false, "Hello world! ".as_bytes());
                Ok((chan.finish(), ()))
            }
            Err(tx) => Ok((tx.finish(), ())),
        })?;

        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    // Close channel
    l.drive(&mut r, |tx| match tx.channel(cid) {
        Ok(mut chan) => {
            chan.close();
            Ok((chan.finish(), ()))
        }
        Err(tx) => Ok((tx.finish(), ())),
    })?;

    loop {
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;

        if l.duration() > Duration::from_secs(12) {
            break;
        }
    }

    assert!(l
        .events
        .iter()
        .any(|(_, event)| event == &Event::ChannelOpen(cid, "my-chan".into())));
    assert!(r.events.len() > 120);
    assert!(l
        .events
        .iter()
        .any(|(_, event)| event == &Event::ChannelClose(cid)));

    // Assert that ChannelOpen happens quickly after IceConnectionStateChange(Completed)
    let ice_completed_time = l
        .events
        .iter()
        .find_map(|(t, e)| match e {
            Event::IceConnectionStateChange(str0m::IceConnectionState::Completed) => Some(*t),
            _ => None,
        })
        .expect("IceConnectionStateChange(Completed) event");
    let channel_open_time = l
        .events
        .iter()
        .find_map(|(t, e)| match e {
            Event::ChannelOpen(_, _) => Some(*t),
            _ => None,
        })
        .expect("ChannelOpen event");
    let channel_open_delay = channel_open_time.duration_since(ice_completed_time);
    assert!(
        channel_open_delay < Duration::from_millis(250),
        "ChannelOpen should happen within 250ms of ICE completing, but took {:?}",
        channel_open_delay
    );

    Ok(())
}
