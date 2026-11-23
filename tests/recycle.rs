//! Handing a sent datagram back with `Rtc::recycle` changes no output and no
//! timeout, and keeps what other operations made ready. The shared test
//! harness recycles every datagram it sends, so the rest of the suite covers
//! the reuse itself.

use std::time::Instant;

use str0m::media::{KeyframeRequestKind, MediaKind};
use str0m::net::DatagramSend;
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Event, Input, Output, Rtc, RtcError};

mod common;
use common::{connect_l_r_with_rtc, init_crypto_default, init_log, progress};

#[test]
fn recycling_changes_no_output_and_no_timeout() -> Result<(), RtcError> {
    init_crypto_default();
    let now = Instant::now();
    let mut rtc = Rtc::new(now);
    rtc.handle_input(Input::Timeout(now))?;
    let deadline = loop {
        if let Output::Timeout(t) = rtc.poll_output()? {
            break t;
        }
    };

    rtc.recycle(DatagramSend::from(vec![0_u8; 1200]));
    rtc.recycle(DatagramSend::from(Vec::new()));

    match rtc.poll_output()? {
        Output::Timeout(t) => assert_eq!(t, deadline, "the deadline stays"),
        output => panic!("recycling must make no output ready: {output:?}"),
    }
    Ok(())
}

/// A keyframe request schedules an immediate timeout. A `recycle` after it
/// keeps that wake.
#[test]
fn recycling_keeps_a_pending_timeout() -> Result<(), RtcError> {
    init_crypto_default();
    let now = Instant::now();
    let mut rtc = Rtc::new(now);
    let mid = "video".into();
    rtc.direct_api().declare_media(mid, MediaKind::Video);
    rtc.direct_api()
        .expect_stream_rx(42.into(), None, mid, None);
    rtc.handle_input(Input::Timeout(now))?;
    while !matches!(rtc.poll_output()?, Output::Timeout(_)) {}

    rtc.writer(mid)
        .unwrap()
        .request_keyframe(None, KeyframeRequestKind::Pli)?;
    rtc.recycle(DatagramSend::from(vec![0_u8; 1200]));

    match rtc.poll_output()? {
        Output::Timeout(deadline) => assert_eq!(deadline, now, "the wake stays"),
        output => panic!("the keyframe request must still wake: {output:?}"),
    }
    Ok(())
}

/// A packet written on a drained sender is ready at once. A `recycle` before
/// the next poll keeps it ready, and the packet reaches the peer.
#[test]
fn recycling_keeps_a_pending_write() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let rtc1 = Rtc::builder().set_rtp_mode(true).build(now);
    let rtc2 = Rtc::builder().set_rtp_mode(true).build(now);
    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    let mid = "audio".into();
    let ssrc: Ssrc = 1337.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;
    for _ in 0..20 {
        progress(&mut l, &mut r)?;
    }
    let pt = l.params_opus().pt();

    // Drain the sender's readiness. A few control packets drop here, which
    // the connection survives.
    let at = l.last;
    l.rtc.handle_input(Input::Timeout(at))?;
    let deadline = loop {
        if let Output::Timeout(t) = l.rtc.poll_output()? {
            break t;
        }
    };
    assert!(deadline > at, "the sender waits on a later timer");

    l.direct_api()
        .stream_tx(&ssrc)
        .unwrap()
        .write_rtp(RtpWrite::new(pt, 7000.into(), 960, at, [3_u8; 80]));
    l.rtc.recycle(DatagramSend::from(vec![0_u8; 1200]));

    match l.rtc.poll_output()? {
        Output::Timeout(t) => assert!(t <= at, "the write still wakes the sender"),
        Output::Transmit(_) | Output::Event(_) => {}
    }

    for _ in 0..50 {
        progress(&mut l, &mut r)?;
    }
    let got = r.events.iter().any(|(_, e)| {
        matches!(e, Event::RtpPacket(p) if *p.seq_no == 7000 && p.payload[..] == [3_u8; 80])
    });
    assert!(got, "the written packet reaches the peer");
    Ok(())
}
