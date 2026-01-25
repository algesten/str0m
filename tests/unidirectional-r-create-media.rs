use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, Peer, TestRtc};

#[test]
pub fn unidirectional_r_create_media() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the R (not sending side) with Direction::RecvOnly.
    let mut mid = None;
    let mut offer = None;
    let mut pending = None;
    r.drive(&mut l, |tx| {
        let mut change = tx.sdp_api();
        mid = Some(change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None));
        let (o, p, tx) = change.apply().unwrap();
        offer = Some(o);
        pending = Some(p);
        Ok((tx, ()))
    })?;
    let mid = mid.unwrap();
    let offer = offer.unwrap();
    let pending = pending.unwrap();

    // str0m always produces a=ssrc lines, also for RecvOnly (since direction can change).
    // We munge the a=ssrc lines away.
    let mut offer_str = offer.to_sdp_string();
    let start = offer_str.find("a=ssrc").unwrap();
    offer_str.replace_range(start..offer_str.len(), "");

    let offer = SdpOffer::from_sdp_string(&offer_str).unwrap();

    // L accepts the offer
    let mut answer = None;
    l.drive(&mut r, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok((tx, ()))
    })?;
    let answer = answer.unwrap();

    // R accepts the answer
    r.drive(&mut l, |tx| {
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        Ok((tx, ()))
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

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let data_a = vec![1_u8; 80];

    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        l.drive(&mut r, |tx| {
            let writer = tx.writer(mid).expect("writer");
            let tx = writer.write(pt, wallclock, time, data_a.clone())?;
            Ok((tx, ()))
        })?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let media_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(media_count > 80, "Not enough MediaData: {}", media_count);

    Ok(())
}
