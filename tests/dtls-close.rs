//! Tests for the Rtc shutdown states.
#![cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl",
    feature = "openssl-dimpl",
    feature = "wincrypto",
    feature = "apple-crypto",
))]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::channel::{ChannelConfig, ChannelId};
use str0m::media::MediaKind;
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{RawPacket, Ssrc};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, init_crypto_default, init_log, progress};

fn direct_pair() -> (TestRtc, TestRtc) {
    direct_pair_with_config(|c| c)
}

fn direct_pair_with_config(configure: impl Fn(RtcConfig) -> RtcConfig) -> (TestRtc, TestRtc) {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(info_span!("L"), configure(Rtc::builder()).build(now));
    let mut r = TestRtc::new_with_rtc(info_span!("R"), configure(Rtc::builder()).build(now));

    let host_l = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host_r = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host_l.clone());
    l.add_remote_candidate(host_r.clone());
    r.add_local_candidate(host_r);
    r.add_remote_candidate(host_l);

    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    let finger_r = r.direct_api().local_dtls_fingerprint().clone();
    l.direct_api().set_remote_fingerprint(finger_r);
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();
    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);

    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();
    l.direct_api().start_sctp(true);
    r.direct_api().start_sctp(false);

    progress_until(&mut l, &mut r, "DTLS handshake", |l, r| {
        l.is_connected() && r.is_connected()
    });

    (l, r)
}

fn progress_until(
    l: &mut TestRtc,
    r: &mut TestRtc,
    label: &str,
    mut done: impl FnMut(&TestRtc, &TestRtc) -> bool,
) {
    for _ in 0..500 {
        if done(l, r) {
            return;
        }
        progress(l, r).unwrap();
    }

    panic!("{label} did not complete");
}

fn open_channel(l: &mut TestRtc, r: &mut TestRtc) -> ChannelId {
    let config = ChannelConfig {
        negotiated: Some(1),
        label: "chan".into(),
        ..Default::default()
    };
    let cid = l.direct_api().create_data_channel(config.clone());
    r.direct_api().create_data_channel(config);

    progress_until(l, r, "channel open", |l, r| {
        let is_open = |rtc: &TestRtc| {
            rtc.events
                .iter()
                .any(|(_, event)| matches!(event, Event::ChannelOpen(..)))
        };
        is_open(l) && is_open(r)
    });

    cid
}

fn next_transmit(rtc: &mut TestRtc) -> str0m::net::Transmit {
    for _ in 0..100 {
        match rtc.rtc.poll_output().unwrap() {
            Output::Transmit(transmit) => return transmit,
            Output::Event(event) => rtc.events.push((rtc.last, event)),
            Output::Timeout(_) => {}
        }
    }

    panic!("expected transmit");
}

fn deliver(transmit: &str0m::net::Transmit, rtc: &mut TestRtc) -> Result<(), RtcError> {
    rtc.rtc
        .handle_input(Input::Receive(rtc.last, transmit.try_into()?))
}

fn deliver_until_closed_event(
    sender: &mut TestRtc,
    receiver: &mut TestRtc,
) -> Result<(), RtcError> {
    for _ in 0..100 {
        let transmit = next_transmit(sender);
        deliver(&transmit, receiver)?;

        for _ in 0..100 {
            match receiver.rtc.poll_output()? {
                Output::Event(Event::Closed) => return Ok(()),
                Output::Event(event) => receiver.events.push((receiver.last, event)),
                Output::Transmit(_) => {}
                Output::Timeout(_) => break,
            }
        }
    }

    panic!("expected remote closed event");
}

/// Whether `rtc` had an event matching `first` before one matching `second`.
fn is_before(
    rtc: &TestRtc,
    first: impl Fn(&Event) -> bool,
    second: impl Fn(&Event) -> bool,
) -> bool {
    let first_at = rtc.events.iter().position(|(_, event)| first(event));
    let second_at = rtc.events.iter().position(|(_, event)| second(event));
    first_at.is_some_and(|first_at| Some(first_at) < second_at)
}

#[test]
fn local_dtls_close_drains_before_rtc_closes() -> Result<(), RtcError> {
    let (mut l, mut r) = direct_pair();

    l.rtc.close()?;

    assert!(
        l.rtc.is_alive(),
        "local close_notify still needs to be emitted"
    );

    progress_until(&mut l, &mut r, "local DTLS close", |l, r| {
        !l.rtc.is_alive()
            && r.events
                .iter()
                .any(|(_, event)| matches!(event, Event::Closed))
    });

    assert!(!l.rtc.is_alive());

    Ok(())
}

#[test]
fn remote_dtls_close_auto_replies_before_rtc_closes() -> Result<(), RtcError> {
    let (mut l, mut r) = direct_pair();

    l.rtc.close()?;
    deliver_until_closed_event(&mut l, &mut r)?;

    assert!(
        r.rtc.is_alive(),
        "remote close_notify should leave Rtc alive until the response close_notify drains"
    );

    progress_until(&mut l, &mut r, "remote DTLS close reply", |_, r| {
        !r.rtc.is_alive()
    });

    assert!(!r.rtc.is_alive());

    Ok(())
}

#[test]
fn close_sends_rtcp_bye_for_local_senders() -> Result<(), RtcError> {
    let (mut l, mut r) = direct_pair_with_config(|c| c.enable_raw_packets(true));
    let mid = "aud".into();
    let ssrc: Ssrc = 42.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);

    l.rtc.close()?;

    progress_until(&mut l, &mut r, "RTCP BYE", |l, _| {
        l.events.iter().any(|(_, event)| {
            matches!(
                event.as_raw_packet(),
                Some(RawPacket::RtcpTx(Rtcp::Goodbye(bye))) if bye.reports.iter().any(|s| *s == ssrc)
            )
        })
    });

    Ok(())
}

#[test]
fn close_sends_rtcp_bye_before_dtls_close_notify() -> Result<(), RtcError> {
    let (mut l, mut r) = direct_pair_with_config(|c| c.enable_raw_packets(true));
    let mid = "aud".into();
    let ssrc: Ssrc = 42.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);

    l.rtc.close()?;

    progress_until(&mut l, &mut r, "remote close", |_, r| {
        r.events
            .iter()
            .any(|(_, event)| matches!(event, Event::Closed))
    });

    let is_bye = |event: &Event| {
        matches!(
            event.as_raw_packet(),
            Some(RawPacket::RtcpRx(Rtcp::Goodbye(bye))) if bye.reports.iter().any(|s| *s == ssrc)
        )
    };
    assert!(
        is_before(&r, is_bye, |event| matches!(event, Event::Closed)),
        "the peer must have the RTCP BYE before the DTLS close_notify"
    );

    Ok(())
}

#[test]
fn close_delivers_queued_channel_data() -> Result<(), RtcError> {
    let (mut l, mut r) = direct_pair();
    let cid = open_channel(&mut l, &mut r);

    l.channel(cid).expect("open channel").write(true, b"bye")?;
    l.rtc.close()?;

    progress_until(&mut l, &mut r, "local close", |l, r| {
        !l.rtc.is_alive()
            && r.events
                .iter()
                .any(|(_, event)| matches!(event, Event::Closed))
    });

    assert!(
        is_before(
            &r,
            |event| matches!(event, Event::ChannelData(data) if data.data == b"bye"),
            |event| matches!(event, Event::Closed),
        ),
        "data queued before close must reach the peer before the DTLS close_notify"
    );

    Ok(())
}

#[test]
fn close_waits_for_the_peer_to_acknowledge_written_data() -> Result<(), RtcError> {
    let (mut l, mut r) = direct_pair();
    let cid = open_channel(&mut l, &mut r);

    l.channel(cid).expect("open channel").write(true, b"bye")?;
    l.rtc.close()?;

    // Nothing reaches the peer, so it does not acknowledge the write.
    let resume_at = l.last + Duration::from_secs(10);
    for _ in 0..100_000 {
        if l.last >= resume_at {
            break;
        }
        if let Output::Timeout(t) = l.rtc.poll_output()? {
            l.last = t.clamp(l.last, resume_at);
            l.rtc.handle_input(Input::Timeout(l.last))?;
        }
    }

    assert_eq!(l.last, resume_at);
    assert!(l.rtc.is_alive(), "close must wait for the acknowledgement");

    // An SCTP retransmission reaches the peer once the network is back.
    for _ in 0..10_000 {
        if !l.rtc.is_alive() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    assert!(!l.rtc.is_alive());
    assert!(
        r.events
            .iter()
            .any(|(_, event)| matches!(event, Event::ChannelData(data) if data.data == b"bye")),
        "data written before close must reach the peer"
    );

    Ok(())
}
