use std::net::Ipv4Addr;

use str0m::media::{Direction, MediaKind};
use str0m::rtp::Ssrc;
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto_default, init_log, Peer, TestRtc};

#[test]
pub fn direct_declare_media_no_media_added_event() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();

    // In this example we are using MID only (no RID) to identify the incoming media.
    let ssrc_tx: Ssrc = 42.into();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Audio);
        Ok((api.finish(), ()))
    })?;

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.declare_stream_tx(ssrc_tx, None, mid, None);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Audio);
        Ok((api.finish(), ()))
    })?;

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;
    }

    let found_local = l
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::MediaAdded(_)));

    let found_remote = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::MediaAdded(_)));

    assert!(!found_local, "declare_media with local MediaAdded");
    assert!(!found_remote, "declare_media found remote MediaAdded");

    Ok(())
}

#[test]
pub fn sdp_no_media_added_event() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Create offer from L
    let (offer, pending) = l.drive(&mut r, |tx| {
        let mut change = tx.sdp_api();
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (o, p, tx) = change.apply().unwrap();
        Ok((tx, (o, p)))
    })?;

    // R accepts the offer
    let answer = r.drive(&mut l, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer)?;
        Ok((tx, a))
    })?;

    // L accepts the answer
    l.drive(&mut r, |tx| {
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        Ok((tx, ()))
    })?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;
    }

    let found_local = l
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::MediaAdded(_)));

    let found_remote = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::MediaAdded(_)));

    assert!(!found_local, "declare_media with local MediaAdded");
    assert!(found_remote, "declare_media found remote MediaAdded");

    Ok(())
}
